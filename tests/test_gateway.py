"""End-to-end behavior of the proxy pipeline: one test per row of the error contract, plus the
happy path, header hygiene and audit logging."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import jwt
import pytest
from structlog.testing import capture_logs

from tests.conftest import TENANT_KEY
from tests.harness import Harness, build_harness, raw_asgi_get


@pytest.fixture
async def h() -> AsyncIterator[Harness]:
    async with build_harness() as harness:
        yield harness


@pytest.fixture
def audit(h: Harness) -> Any:
    with capture_logs() as logs:
        yield logs


def requests_in(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entry for entry in logs if entry.get("event") == "request"]


def assert_error(resp: Any, status: int, code: str) -> dict[str, Any]:
    assert resp.status_code == status, resp.text
    body: dict[str, Any] = resp.json()
    assert body["error"]["code"] == code
    assert body["error"]["request_id"] == resp.headers["x-request-id"]
    assert body["error"]["message"]
    return body


# --- happy path -------------------------------------------------------------------------------


async def test_healthz(h: Harness) -> None:
    resp = await h.get("/healthz", token=None)
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_proxies_to_upstream_with_prefix_stripped(h: Harness) -> None:
    resp = await h.get("/echo/hello/world?x=1&y=two")
    assert resp.status_code == 200
    body = resp.json()
    assert body["upstream"] == "primary"
    assert body["path"] == "/v1/hello/world"
    assert body["query"] == "x=1&y=two"
    assert resp.headers["x-upstream"] == "primary"  # upstream headers come back
    assert resp.headers["x-ratelimit-limit"] == "1000"
    assert resp.headers["x-ratelimit-remaining"] == "999"


async def test_exact_prefix_maps_to_upstream_base(h: Harness) -> None:
    assert (await h.get("/echo")).json()["path"] == "/v1"


async def test_post_body_is_forwarded(h: Harness) -> None:
    resp = await h.call("POST", "/echo/items", content=b"x" * 1000)
    assert resp.json()["method"] == "POST"
    assert resp.json()["body_bytes"] == 1000


async def test_encoded_characters_survive_one_decode_and_reencode(h: Harness) -> None:
    resp = await h.get("/echo/caf%C3%A9/a%20b")
    assert resp.json()["path"] == "/v1/café/a b"


async def test_longest_prefix_route_and_its_scope(h: Harness) -> None:
    resp = await h.get("/echo/admin/x", token=h.token(scopes=["echo:read", "echo:write"]))
    assert resp.json()["path"] == "/admin/x"


async def test_upstream_errors_pass_through_untouched(h: Harness) -> None:
    h.flaky.status = 418
    resp = await h.get("/flaky/x", token=h.token(scopes=["flaky:read"]))
    assert resp.status_code == 418
    assert resp.json() == {"flaky": 418}  # not wrapped in the gateway error format


# --- header hygiene ---------------------------------------------------------------------------


async def test_spoofable_and_hop_by_hop_headers_are_replaced(h: Harness) -> None:
    resp = await h.get(
        "/echo/headers",
        headers={
            "X-Tenant-ID": "globex",
            "X-Tenant-Plan": "enterprise",
            "X-Forwarded-For": "10.0.0.1",
            "X-Real-IP": "10.0.0.1",
            "X-Request-ID": "attacker-chosen",
            "Forwarded": "for=10.0.0.1",
            "Connection": "keep-alive, X-Secret-Hop",
            "X-Secret-Hop": "must-not-pass",
            "Keep-Alive": "timeout=5",
            "X-Custom": "kept",
            "Cookie": "session=abc",
        },
    )
    seen = resp.json()["headers"]
    assert "authorization" not in seen  # upstreams never see the gateway token
    assert seen["x-tenant-id"] == "acme"
    assert "x-tenant-plan" not in seen
    assert seen["x-forwarded-for"] == "203.0.113.9"
    assert "x-real-ip" not in seen
    assert "forwarded" not in seen
    assert "x-secret-hop" not in seen
    assert "keep-alive" not in seen
    assert seen["x-request-id"] == resp.headers["x-request-id"] != "attacker-chosen"
    assert seen["x-custom"] == "kept"
    assert seen["cookie"] == "session=abc"
    assert seen["host"] == "primary.test"


# --- 400 / 413 --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_path",
    [b"/echo/../admin", b"/echo/%2e%2e/admin", b"/echo%2fadmin", b"//echo", b"/echo/%00",
     b"/echo/./x", b"/echo/%252e%252e/x"],
)  # fmt: skip
async def test_400_ambiguous_paths_never_reach_upstream(h: Harness, raw_path: bytes) -> None:
    status, body = await raw_asgi_get(h.client._transport.app, raw_path, h.token())  # type: ignore[attr-defined]
    assert status == 400
    assert body["error"]["code"] == "invalid_path"
    assert h.calls["primary.test"] == 0


async def test_413_declared_body_too_large(h: Harness) -> None:
    resp = await h.call("POST", "/echo/x", content=b"x" * (1_048_576 + 1))
    assert_error(resp, 413, "payload_too_large")
    assert h.calls["primary.test"] == 0


async def test_413_streamed_body_too_large() -> None:
    async with build_harness(_small_body_settings()) as h:

        async def chunks() -> AsyncIterator[bytes]:
            for _ in range(10):
                yield b"x" * 50

        resp = await h.call("POST", "/echo/x", content=chunks())  # no Content-Length: chunked
        assert_error(resp, 413, "payload_too_large")


def _small_body_settings() -> Any:
    from tests.conftest import make_settings

    return make_settings(max_body_bytes=100)


# --- 401 --------------------------------------------------------------------------------------


async def test_401_missing_token(h: Harness) -> None:
    resp = await h.get("/echo/x", token=None)
    assert_error(resp, 401, "missing_token")
    assert resp.headers["www-authenticate"] == 'Bearer error="invalid_token"'


@pytest.mark.parametrize("header", ["Basic dXNlcjpwYXNz", "Bearer not.a.jwt", "Token abc"])
async def test_401_invalid_token(h: Harness, header: str) -> None:
    resp = await h.get("/echo/x", token=None, headers={"Authorization": header})
    assert_error(resp, 401, "invalid_token")


async def test_401_forged_token(h: Harness) -> None:
    good = jwt.decode(h.token(), options={"verify_signature": False})
    forged = jwt.encode(good, "attacker-key-attacker-key-attacker-key!", headers={"kid": "k1"})
    assert_error(await h.get("/echo/x", token=forged), 401, "invalid_token")


async def test_401_expired_token(h: Harness) -> None:
    claims = jwt.decode(h.token(), options={"verify_signature": False})
    claims["iat"] -= 2000
    claims["exp"] = claims["iat"] + 900
    expired = jwt.encode(claims, TENANT_KEY, headers={"kid": "k1"})
    assert_error(await h.get("/echo/x", token=expired), 401, "token_expired")


async def test_401_revoked_token(h: Harness) -> None:
    issued = h.gateway.tokens.issue_tenant_token("acme", ["echo:read"])
    h.gateway.tokens.revocations.revoke(issued.jti)
    assert_error(await h.get("/echo/x", token=issued.token), 401, "token_revoked")


async def test_401_admin_token_on_proxy_path(h: Harness) -> None:
    assert_error(await h.get("/echo/x", token=h.admin_token()), 401, "invalid_token")


# --- 403 --------------------------------------------------------------------------------------


async def test_403_disabled_tenant(h: Harness) -> None:
    resp = await h.get("/echo/x", token=h.token("initech"))
    assert_error(resp, 403, "tenant_disabled")


async def test_403_unknown_tenant(h: Harness) -> None:
    resp = await h.get("/echo/x", token=h.token("ghost-corp"))
    assert_error(resp, 403, "tenant_disabled")


async def test_403_path_not_allowed(h: Harness) -> None:
    resp = await h.get("/down/x", token=h.token("globex"))
    assert_error(resp, 403, "path_not_allowed")
    assert h.calls["down.test"] == 0


async def test_403_same_answer_whether_or_not_route_exists(h: Harness) -> None:
    """A tenant cannot probe the route table: /hidden exists, /nope does not, both are 403."""
    exists = await h.get("/hidden/x")
    missing = await h.get("/nope/x")
    assert_error(exists, 403, "path_not_allowed")
    assert_error(missing, 403, "path_not_allowed")
    assert exists.json()["error"]["message"] == missing.json()["error"]["message"]


async def test_403_allowlist_respects_segment_boundary(h: Harness) -> None:
    assert_error(await h.get("/echoes/x", token=h.token("globex")), 403, "path_not_allowed")


async def test_403_insufficient_scope(h: Harness) -> None:
    resp = await h.get("/echo/admin/x")  # needs echo:write; default token has echo:read
    body = assert_error(resp, 403, "insufficient_scope")
    assert "echo:write" in body["error"]["message"]
    assert h.calls["primary.test"] == 0


async def test_403_scope_removed_from_tenant_after_token_was_issued(h: Harness) -> None:
    token = h.token(scopes=["echo:read", "echo:write"])
    acme = h.gateway.tenants.get("acme")
    assert acme is not None
    await h.gateway.tenants.put(acme.model_copy(update={"max_scopes": ("echo:read",)}))
    assert_error(await h.get("/echo/admin/x", token=token), 403, "insufficient_scope")


# --- 404 --------------------------------------------------------------------------------------


async def test_404_allowed_path_without_route(h: Harness) -> None:
    assert_error(await h.get("/unrouted/x"), 404, "route_not_found")


# --- 429 --------------------------------------------------------------------------------------


async def test_429_with_retry_after(h: Harness) -> None:
    token = h.token("globex")
    for expected_remaining in ("2", "1", "0"):
        ok = await h.get("/echo/x", token=token)
        assert ok.status_code == 200
        assert ok.headers["x-ratelimit-remaining"] == expected_remaining
    resp = await h.get("/echo/x", token=token)
    assert_error(resp, 429, "rate_limited")
    assert int(resp.headers["retry-after"]) >= 1
    assert resp.headers["x-ratelimit-remaining"] == "0"
    assert h.calls["primary.test"] == 3


async def test_quota_is_shared_by_all_tokens_of_a_tenant(h: Harness) -> None:
    for _ in range(3):
        assert (await h.get("/echo/x", token=h.token("globex"))).status_code == 200
    assert_error(await h.get("/echo/x", token=h.token("globex")), 429, "rate_limited")


async def test_rejected_requests_do_not_consume_quota(h: Harness) -> None:
    token = h.token("globex")
    for _ in range(10):
        assert (await h.get("/down/x", token=token)).status_code == 403
    assert (await h.get("/echo/x", token=token)).headers["x-ratelimit-remaining"] == "2"


async def test_quota_recovers_after_window(h: Harness) -> None:
    token = h.token("globex")
    for _ in range(3):
        await h.get("/echo/x", token=token)
    resp = await h.get("/echo/x", token=token)
    h.clock.advance(int(resp.headers["retry-after"]))
    assert (await h.get("/echo/x", token=token)).status_code == 200


# --- 502 / 504 / 500 --------------------------------------------------------------------------


async def test_502_connect_error(h: Harness) -> None:
    assert_error(await h.get("/down/x"), 502, "upstream_error")
    assert h.calls["down.test"] == 1


async def test_504_timeout(h: Harness) -> None:
    assert_error(await h.get("/slow/x"), 504, "upstream_timeout")


async def test_500_unexpected_error_is_contained(
    h: Harness, audit: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setattr("gateway.pipeline.upstream_url", boom)
    resp = await h.get("/echo/x")
    body = assert_error(resp, 500, "internal_error")
    assert "bug" not in body["error"]["message"]  # internals stay in the log
    line = requests_in(audit)[-1]
    assert line["decision"] == "error"
    assert line["status"] == 500


# --- audit log --------------------------------------------------------------------------------


async def test_audit_line_for_allowed_request(h: Harness, audit: list[dict[str, Any]]) -> None:
    token = h.token()
    resp = await h.get("/echo/x?secret=hunter2", token=token)
    [line] = requests_in(audit)
    assert line["request_id"] == resp.headers["x-request-id"]
    assert line["tenant_id"] == "acme"
    assert line["jti"] == jwt.decode(token, options={"verify_signature": False})["jti"]
    assert line["method"] == "GET"
    assert line["path"] == "/echo/x"
    assert line["route_id"] == "echo"
    assert line["upstream"] == "http://primary.test/v1"
    assert line["canary"] is False
    assert line["decision"] == "allow"
    assert line["reason"] is None
    assert line["upstream_status"] == 200
    assert line["status"] == 200
    assert line["latency_ms"] >= 0
    assert line["client_ip"] == "203.0.113.9"
    flat = str(line)
    assert token not in flat
    assert "hunter2" not in flat  # query strings are never logged


@pytest.mark.parametrize(
    ("path", "token_kind", "status", "reason", "decision"),
    [
        ("/echo/x", "none", 401, "missing_token", "deny"),
        ("/down/x", "globex", 403, "path_not_allowed", "deny"),
        ("/unrouted/x", "acme", 404, "route_not_found", "deny"),
        ("/down/x", "acme", 502, "upstream_error", "error"),
        ("/slow/x", "acme", 504, "upstream_timeout", "error"),
    ],
)
async def test_every_outcome_writes_exactly_one_audit_line(
    h: Harness,
    audit: list[dict[str, Any]],
    path: str,
    token_kind: str,
    status: int,
    reason: str,
    decision: str,
) -> None:
    token = None if token_kind == "none" else h.token(token_kind)
    resp = await h.get(path, token=token)
    assert resp.status_code == status
    [line] = requests_in(audit)
    assert (line["status"], line["reason"], line["decision"]) == (status, reason, decision)
    assert line["upstream_status"] is None


async def test_audit_log_for_bad_path_records_raw_path(
    h: Harness, audit: list[dict[str, Any]]
) -> None:
    """A log-injection attempt: an encoded newline followed by a fake JSON audit line."""
    raw = b'/echo/x%0a{"event":"request","tenant_id":"globex"}'
    status, _ = await raw_asgi_get(h.client._transport.app, raw, h.token())  # type: ignore[attr-defined]
    assert status == 400
    [line] = requests_in(audit)
    assert line["reason"] == "invalid_path"
    assert line["tenant_id"] is None  # rejected before auth; identity never comes from the path
    assert line["path"] == raw.decode()  # kept as an inert string value


def test_json_renderer_escapes_newlines() -> None:
    import json

    import structlog

    rendered = structlog.processors.JSONRenderer()(None, "info", {"path": '/x\n{"fake":1}'})
    assert "\n" not in rendered  # one physical line
    assert json.loads(rendered)["path"] == '/x\n{"fake":1}'


async def test_long_paths_are_truncated_in_audit(h: Harness, audit: list[dict[str, Any]]) -> None:
    await h.get("/echo/" + "a" * 3000)
    [line] = requests_in(audit)
    assert len(line["path"]) < 600
