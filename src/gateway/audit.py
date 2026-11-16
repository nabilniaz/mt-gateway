"""Structured audit logging: one JSON line per request on stdout.

structlog's JSON renderer escapes every value, so a newline or quote inside a path or header
becomes `\\n` or `\\"` in the output and cannot forge a second log line. Free-text fields are
also truncated. Tokens, bodies, query strings and cookies are never passed in.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from typing import Any

import structlog

MAX_FIELD_CHARS = 512


def configure_logging(level: str = "INFO") -> None:
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        ),
        logger_factory=structlog.WriteLoggerFactory(sys.stdout),
        cache_logger_on_first_use=False,
    )


def truncate(value: str | None, limit: int = MAX_FIELD_CHARS) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


@dataclass
class AuditRecord:
    request_id: str
    method: str
    path: str
    client_ip: str | None
    tenant_id: str | None = None
    jti: str | None = None
    route_id: str | None = None
    upstream: str | None = None
    canary: bool = False
    reason: str | None = None
    upstream_status: int | None = None
    status: int = 500
    latency_ms: float = 0.0

    @property
    def decision(self) -> str:
        """allow: the upstream answered. error: upstream failure or gateway bug. deny: blocked."""
        if self.upstream_status is not None:
            return "allow"
        if self.status in (500, 502, 504):
            return "error"
        return "deny"

    def emit(self) -> None:
        structlog.get_logger("audit").info(
            "request",
            request_id=self.request_id,
            tenant_id=self.tenant_id,
            jti=self.jti,
            method=truncate(self.method, 16),
            path=truncate(self.path),
            route_id=self.route_id,
            upstream=self.upstream,
            canary=self.canary,
            decision=self.decision,
            reason=self.reason,
            upstream_status=self.upstream_status,
            status=self.status,
            latency_ms=round(self.latency_ms, 1),
            client_ip=truncate(self.client_ip, 64),
        )


def audit_admin(request_id: str, actor: str, action: str, target: str, **detail: Any) -> None:
    structlog.get_logger("audit").info(
        "admin",
        request_id=request_id,
        actor=actor,
        action=action,
        target=truncate(target),
        **detail,
    )
