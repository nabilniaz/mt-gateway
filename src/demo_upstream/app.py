"""Demo upstream: echoes what it received, so you can see exactly what the gateway forwarded.

Endpoints:
  /healthz            -> 200
  /status/{code}      -> responds with that status (use it to trip the circuit breaker)
  /delay/{seconds}    -> sleeps up to 30 s, then echoes (use it to trigger 504)
  /anything/else      -> echoes method, path, query, headers and body size
"""

from __future__ import annotations

import asyncio
import os

import uvicorn
from fastapi import FastAPI, Path, Request
from fastapi.responses import JSONResponse

ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def create_app(name: str | None = None) -> FastAPI:
    upstream_name = name or os.environ.get("UPSTREAM_NAME", "demo-upstream")
    app = FastAPI(title="demo-upstream", docs_url=None, redoc_url=None, openapi_url=None)

    async def echo(request: Request, status: int = 200) -> JSONResponse:
        body = await request.body()
        return JSONResponse(
            {
                "upstream": upstream_name,
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query,
                "headers": dict(request.headers),
                "body_bytes": len(body),
            },
            status_code=status,
            headers={"X-Upstream": upstream_name},
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.api_route("/status/{code}", methods=ALL_METHODS)
    async def status(request: Request, code: int = Path(ge=200, le=599)) -> JSONResponse:
        return await echo(request, code)

    @app.api_route("/delay/{seconds}", methods=ALL_METHODS)
    async def delay(request: Request, seconds: float = Path(ge=0, le=30)) -> JSONResponse:
        await asyncio.sleep(seconds)
        return await echo(request)

    @app.api_route("/{path:path}", methods=ALL_METHODS)
    async def catch_all(request: Request) -> JSONResponse:
        return await echo(request)

    return app


def serve_main() -> None:
    uvicorn.run(
        create_app(),
        host=os.environ.get("HOST", "0.0.0.0"),  # noqa: S104  (container listens on all interfaces)
        port=int(os.environ.get("PORT", "8080")),
        access_log=False,
    )
