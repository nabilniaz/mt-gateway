"""Integration harness: the real gateway app in front of real in-process upstream apps.

No sockets or network: httpx's ASGITransport calls the apps directly. Fake DNS makes the test
hostnames pass the SSRF guard. Every upstream transport counts its calls, so tests can prove a
rejected request never reached an upstream.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx

from demo_upstream.app import create_app as create_upstream
from gateway.app import create_app
from gateway.config import Settings
from gateway.models import Route, Tenant
from gateway.pipeline import Gateway
from gateway.routes import RouteTable, TenantStore
from tests.conftest import FakeClock, make_settings

DNS = {
    "primary.test": ["93.184.216.34"],
    "canary.test": ["93.184.216.35"],
    "down.test": ["93.184.216.36"],
    "slow.test": ["93.184.216.37"],
    "flaky.test": ["93.184.216.38"],
    "metadata.test": ["169.254.169.254"],
    "internal.test": ["10.0.0.5"],
}


async def fake_resolver(host: str, port: int) -> list[str]:
    if host not in DNS:
        raise OSError("NXDOMAIN")
    return DNS[host]


TENANTS = [
    Tenant(
        tenant_id="acme",
        allowed_paths=("/echo", "/down", "/slow", "/flaky", "/canary", "/unrouted"),
        rate_limit_per_minute=1000,
        max_scopes=("echo:read", "echo:write", "flaky:read"),
    ),
    Tenant(
        tenant_id="globex",
        allowed_paths=("/echo", "/canary"),
        rate_limit_per_minute=3,
        max_scopes=("echo:read",),
    ),
    Tenant(tenant_id="initech", enabled=False, allowed_paths=("/echo",), max_scopes=("echo:read",)),
]

ROUTES = [
    Route(route_id="echo", prefix="/echo", upstream="http://primary.test/v1",
          required_scopes=("echo:read",)),
    Route(route_id="echo_admin", prefix="/echo/admin", upstream="http://primary.test/admin",
          required_scopes=("echo:write",)),
    Route(route_id="hidden", prefix="/hidden", upstream="http://primary.test/hidden"),
    Route(route_id="down", prefix="/down", upstream="http://down.test"),
    Route(route_id="slow", prefix="/slow", upstream="http://slow.test", timeout_seconds=1),
    Route(route_id="flaky", prefix="/flaky", upstream="http://flaky.test",
          required_scopes=("flaky:read",),
          circuit_breaker={"failure_threshold": 3, "cooldown_seconds": 10}),  # type: ignore[arg-type]
]  # fmt: skip


class CountingTransport(httpx.AsyncBaseTransport):
    def __init__(self, name: str, inner: httpx.AsyncBaseTransport, calls: Counter[str]) -> None:
        self.name, self.inner, self.calls = name, inner, calls

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls[self.name] += 1
        return await self.inner.handle_async_request(request)


@dataclass
class Flaky:
    """Controls the flaky.test upstream: the status it answers with."""

    status: int = 500

    def handler(self, request: httpx.Request) -> httpx.Response:
        # stream= (not json=) so the body arrives unread, as it does from a real socket.
        body = json.dumps({"flaky": self.status}).encode()
        return httpx.Response(
            self.status,
            headers={"content-type": "application/json", "content-length": str(len(body))},
            stream=httpx.ByteStream(body),
        )


def _raise_connect(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


def _raise_timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("read timed out", request=request)


@dataclass
class Harness:
    gateway: Gateway
    client: httpx.AsyncClient
    clock: FakeClock
    calls: Counter[str]
    flaky: Flaky
    _tokens: dict[str, str] = field(default_factory=dict)

    def token(self, tenant: str = "acme", scopes: list[str] | None = None) -> str:
        scopes = ["echo:read"] if scopes is None else scopes
        return self.gateway.tokens.issue_tenant_token(tenant, scopes).token

    def admin_token(self) -> str:
        return self.gateway.tokens.issue_admin_token("alice").token

    async def call(
        self, method: str, path: str, token: str | None = "default", **kwargs: Any
    ) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        if token == "default":
            token = self.token()
        if token is not None:
            headers.setdefault("Authorization", f"Bearer {token}")
        return await self.client.request(method, path, headers=headers, **kwargs)

    async def get(self, path: str, token: str | None = "default", **kwargs: Any) -> httpx.Response:
        return await self.call("GET", path, token, **kwargs)

    async def admin(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return await self.call(method, path, self.admin_token(), **kwargs)


@asynccontextmanager
async def build_harness(
    settings: Settings | None = None,
    routes: list[Route] | None = None,
    tenants: list[Tenant] | None = None,
) -> AsyncIterator[Harness]:
    settings = settings or make_settings()
    clock = FakeClock()
    calls: Counter[str] = Counter()
    flaky = Flaky()
    transports: dict[str, httpx.AsyncBaseTransport] = {
        "primary.test": httpx.ASGITransport(app=create_upstream("primary")),
        "canary.test": httpx.ASGITransport(app=create_upstream("canary")),
        "down.test": httpx.MockTransport(_raise_connect),
        "slow.test": httpx.MockTransport(_raise_timeout),
        "flaky.test": httpx.MockTransport(flaky.handler),
    }
    mounts: dict[str, httpx.AsyncBaseTransport | None] = {
        f"all://{host}": CountingTransport(host, t, calls) for host, t in transports.items()
    }
    upstream_client = httpx.AsyncClient(mounts=mounts, follow_redirects=False)
    gateway = Gateway(
        settings=settings,
        tenants=TenantStore(TENANTS if tenants is None else tenants),
        routes=RouteTable(ROUTES if routes is None else routes),
        client=upstream_client,
        resolver=fake_resolver,
        wall_clock=clock,
        monotonic_clock=clock,
    )
    app = create_app(gateway=gateway)
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway.test") as client:
        yield Harness(gateway, client, clock, calls, flaky)
    await upstream_client.aclose()


async def raw_asgi_get(app: Any, raw_path: bytes, token: str) -> tuple[int, dict[str, Any]]:
    """Send a request with an exact raw path. httpx would normalize `/../` before sending,
    but an attacker using a raw socket would not, so traversal tests bypass httpx."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": raw_path.decode("latin-1"),
        "raw_path": raw_path,
        "query_string": b"",
        "headers": [(b"host", b"gateway.test"), (b"authorization", f"Bearer {token}".encode())],
        "client": ("203.0.113.9", 50000),
        "server": ("gateway.test", 80),
    }
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(body)
