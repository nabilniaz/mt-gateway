"""The gateway's single error format.

Every error the gateway itself produces looks like
`{"error": {"code": "...", "message": "...", "request_id": "..."}}`.
Errors returned by an upstream are passed through untouched, so clients can tell them apart.
"""

from __future__ import annotations

from fastapi.responses import JSONResponse


class GatewayError(Exception):
    """An expected, client-visible failure. `code` is stable; `message` is for humans."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


def error_response(
    status: int,
    code: str,
    message: str,
    request_id: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "request_id": request_id}}
    return JSONResponse(body, status_code=status, headers=headers)


def from_error(err: GatewayError, request_id: str) -> JSONResponse:
    return error_response(err.status, err.code, err.message, request_id, err.headers)
