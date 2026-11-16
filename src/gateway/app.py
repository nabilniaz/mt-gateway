"""FastAPI application: wires the request-id middleware, error handlers, health check and the
catch-all proxy route. Run with `gateway-serve` (or `uvicorn gateway.app:create_app --factory`).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from gateway.audit import configure_logging
from gateway.config import Settings
from gateway.errors import GatewayError, error_response, from_error
from gateway.pipeline import Gateway


class RequestIdMiddleware:
    """Gives every request a fresh UUID and echoes it in `X-Request-ID`.

    The caller's own X-Request-ID is ignored: an ID the caller chose could collide with or
    impersonate another request in the audit log.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() != b"x-request-id"
                ]
                headers.append((b"x-request-id", request_id.encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_id)


def request_id_of(request: Request) -> str:
    return str(getattr(request.state, "request_id", "")) or str(uuid.uuid4())


def gateway_of(request: Request) -> Gateway:
    gateway: Gateway = request.app.state.gateway
    return gateway


def create_app(settings: Settings | None = None, *, gateway: Gateway | None = None) -> FastAPI:
    """Build the app. Tests pass a ready `gateway`; production builds one from settings."""
    if gateway is not None:
        settings = gateway.settings
    elif settings is None:
        settings = Settings()
    configure_logging(settings.log_level)
    resolved_settings = settings

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = app.state.gateway is None
        if owned:
            app.state.gateway = await Gateway.from_settings(resolved_settings)
        try:
            yield
        finally:
            if owned:
                await app.state.gateway.aclose()

    app = FastAPI(
        title="mt-gateway",
        summary="Multi-tenant API gateway",
        lifespan=lifespan,
        docs_url="/admin/docs",
        openapi_url="/admin/openapi.json",
        redoc_url=None,
    )
    app.state.gateway = gateway
    app.add_middleware(RequestIdMiddleware)

    @app.exception_handler(GatewayError)
    async def _gateway_error(request: Request, exc: GatewayError) -> Response:
        return from_error(exc, request_id_of(request))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> Response:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        return error_response(422, "validation_error", problems[:1000], request_id_of(request))

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> Response:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return error_response(exc.status_code, code, str(exc.detail), request_id_of(request))

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        # No dependencies on purpose: a slow upstream must not make the gateway look dead.
        return {"status": "ok"}

    async def proxy(scope: Scope, receive: Receive, send: Send) -> None:
        # The router's fallback rather than a `/{path:path}` route: Starlette's path regex does
        # not match every possible path (e.g. one containing an encoded newline), and every
        # request must still reach the pipeline and be audited.
        request = Request(scope, receive)
        response = await gateway_of(request).handle(request, request_id_of(request))
        await response(scope, receive, send)

    app.router.default = proxy
    return app
