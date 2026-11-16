"""The request pipeline: every proxied request goes through `Gateway.handle`.

Checks run cheapest first, and every check before the proxy step is local (no network), so a
request that breaks a rule never reaches an upstream. Exactly one audit line is written per
request, from a `finally` block.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import httpx
import structlog
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from gateway.audit import AuditRecord, truncate
from gateway.auth import Claims, TokenService, bearer_token
from gateway.config import Settings
from gateway.errors import GatewayError, error_response, from_error
from gateway.models import Route, RoutesFile, Tenant, TenantsFile
from gateway.paths import has_prefix, normalize_path
from gateway.proxy import downstream_response_headers, upstream_request_headers, upstream_url
from gateway.ratelimit import RateDecision, SlidingWindowLimiter
from gateway.routes import RouteTable, TenantStore
from gateway.ssrf import Resolver, system_resolver, validate_upstream

Clock = Callable[[], float]


def build_http_client(settings: Settings) -> httpx.AsyncClient:
    """One shared client: pooled keep-alive connections, bounded size, never follows redirects."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=settings.connect_timeout_seconds,
            read=10.0,
            write=settings.write_timeout_seconds,
            pool=settings.pool_timeout_seconds,
        ),
        limits=httpx.Limits(
            max_connections=settings.max_connections,
            max_keepalive_connections=min(20, settings.max_connections),
        ),
        follow_redirects=False,
        trust_env=False,  # never pick up HTTP(S)_PROXY from the environment
    )


class Gateway:
    def __init__(
        self,
        *,
        settings: Settings,
        tenants: TenantStore,
        routes: RouteTable,
        client: httpx.AsyncClient,
        resolver: Resolver = system_resolver,
        wall_clock: Clock = time.time,
        monotonic_clock: Clock = time.monotonic,
    ) -> None:
        self.settings = settings
        self.tenants = tenants
        self.routes = routes
        self.client = client
        self.resolver = resolver
        self.tokens = TokenService(settings, wall_clock)
        self.limiter = SlidingWindowLimiter(wall_clock)
        self._monotonic = monotonic_clock
        self._log = structlog.get_logger("gateway")

    @classmethod
    async def from_settings(cls, settings: Settings) -> Gateway:
        """Production wiring: load and validate the committed seed files, then build the client."""
        tenants = load_tenants(settings.tenants_file)
        routes = load_routes(settings.routes_file)
        gateway = cls(
            settings=settings,
            tenants=TenantStore(tenants),
            routes=RouteTable(routes),
            client=build_http_client(settings),
        )
        for route in routes:
            await gateway.validate_route(route)
        return gateway

    async def aclose(self) -> None:
        await self.client.aclose()

    async def validate_route(self, route: Route) -> None:
        """Raise UnsafeUpstream if any upstream of the route fails the SSRF guard."""
        for url in route.upstreams():
            await validate_upstream(
                url,
                allowed_private_hosts=self.settings.upstream_allowed_private_hosts,
                resolver=self.resolver,
            )

    def client_ip(self, request: Request) -> str | None:
        if self.settings.trust_proxy_headers:
            # App Platform's edge sets do-connecting-ip, and appends the client IP to
            # X-Forwarded-For. Only the right-most XFF entry was added by a trusted hop.
            direct = request.headers.get("do-connecting-ip")
            if direct:
                return direct.strip()
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[-1].strip()
        return request.client.host if request.client else None

    # --- the pipeline -------------------------------------------------------------------------

    async def handle(self, request: Request, request_id: str) -> Response:
        started = time.perf_counter()
        raw_path: bytes = request.scope.get("raw_path") or request.url.path.encode()
        record = AuditRecord(
            request_id=request_id,
            method=request.method,
            path=truncate(raw_path.decode("latin-1")) or "",
            client_ip=self.client_ip(request),
        )
        try:
            response = await self._process(request, record, raw_path)
        except GatewayError as err:
            record.reason = err.code
            response = from_error(err, request_id)
        except Exception:
            self._log.exception("unhandled_error", request_id=request_id)
            record.reason = "internal_error"
            response = error_response(500, "internal_error", "Internal gateway error.", request_id)
        finally:
            record.latency_ms = (time.perf_counter() - started) * 1000
        record.status = response.status_code
        record.emit()
        return response

    async def _process(self, request: Request, record: AuditRecord, raw_path: bytes) -> Response:
        # 1. Body size. Content-Length is checked first so a large upload is refused unread.
        body = await self._read_body(request)

        # 2. One canonical path for every later step.
        path = normalize_path(raw_path)
        record.path = path

        # 3. Identity comes only from a verified token.
        claims = self.tokens.verify_tenant_token(bearer_token(request.headers.get("authorization")))
        record.tenant_id, record.jti = claims.sub, claims.jti

        # 4. Tenant must exist and be enabled.
        tenant = self.tenants.get(claims.sub)
        if tenant is None or not tenant.enabled:
            raise GatewayError(403, "tenant_disabled", "Tenant is unknown or disabled.")

        # 5. Allowlist before route lookup: the answer is the same whether or not a route exists.
        if not any(has_prefix(path, allowed) for allowed in tenant.allowed_paths):
            raise GatewayError(
                403,
                "path_not_allowed",
                f"Path is not in the allowlist for tenant {tenant.tenant_id!r}.",
            )

        # 6. Route match on one consistent snapshot of the table.
        route = self.routes.snapshot.match(path)
        if route is None:
            raise GatewayError(404, "route_not_found", "No route matches this path.")
        record.route_id = route.route_id

        # 7. Scopes. A token's scopes are capped by what the tenant may hold *today*.
        effective = claims.scopes & set(tenant.max_scopes)
        missing = sorted(set(route.required_scopes) - effective)
        if missing:
            raise GatewayError(
                403,
                "insufficient_scope",
                f"Token is missing required scope(s): {', '.join(missing)}.",
            )

        # 8. Quota last, so requests rejected above never use it up.
        quota = self.limiter.hit(tenant.tenant_id, tenant.rate_limit_per_minute)
        if not quota.allowed:
            raise GatewayError(
                429,
                "rate_limited",
                f"Tenant {tenant.tenant_id!r} exceeded {quota.limit} requests per minute.",
                headers={"Retry-After": str(quota.retry_after), **_quota_headers(quota)},
            )

        # 9. Proxy.
        upstream = route.upstream
        record.upstream = upstream
        return await self._forward(request, record, route, upstream, path, body, claims, quota)

    async def _read_body(self, request: Request) -> bytes:
        limit = self.settings.max_body_bytes
        too_large = GatewayError(413, "payload_too_large", f"Request body exceeds {limit} bytes.")
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            raise too_large
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                raise too_large
            chunks.append(chunk)
        return b"".join(chunks)

    async def _forward(
        self,
        request: Request,
        record: AuditRecord,
        route: Route,
        upstream: str,
        path: str,
        body: bytes,
        claims: Claims,
        quota: RateDecision,
    ) -> Response:
        url = upstream_url(upstream, route, path, request.url.query)
        headers = upstream_request_headers(
            request.headers.items(),
            request_id=record.request_id,
            tenant_id=claims.sub,
            client_ip=record.client_ip,
            scheme=request.headers.get("x-forwarded-proto", request.url.scheme)
            if self.settings.trust_proxy_headers
            else request.url.scheme,
        )
        upstream_request = self.client.build_request(
            request.method,
            url,
            headers=headers,
            content=body,
            timeout=httpx.Timeout(
                connect=self.settings.connect_timeout_seconds,
                read=route.timeout_seconds,
                write=self.settings.write_timeout_seconds,
                pool=self.settings.pool_timeout_seconds,
            ),
        )
        try:
            upstream_response = await self.client.send(upstream_request, stream=True)
        except httpx.TimeoutException:
            raise GatewayError(
                504, "upstream_timeout", "Upstream did not respond in time."
            ) from None
        except httpx.HTTPError:
            raise GatewayError(502, "upstream_error", "Could not reach the upstream.") from None

        record.upstream_status = upstream_response.status_code
        response = StreamingResponse(
            upstream_response.aiter_raw(),
            status_code=upstream_response.status_code,
            background=BackgroundTask(upstream_response.aclose),
        )
        response.raw_headers = downstream_response_headers(upstream_response.headers.raw)
        for name, value in _quota_headers(quota).items():
            response.raw_headers.append((name.lower().encode(), value.encode()))
        return response


def _quota_headers(quota: RateDecision) -> dict[str, str]:
    return {"X-RateLimit-Limit": str(quota.limit), "X-RateLimit-Remaining": str(quota.remaining)}


def load_routes(path: Path) -> list[Route]:
    return list(RoutesFile.model_validate_json(path.read_bytes()).routes)


def load_tenants(path: Path) -> list[Tenant]:
    return list(TenantsFile.model_validate_json(path.read_bytes()).tenants)
