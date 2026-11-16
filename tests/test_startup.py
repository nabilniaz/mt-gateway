"""Startup wiring, seed files, CLI tools and proxy-header trust."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from gateway.app import create_app
from gateway.cli import init_env_main, token_main
from gateway.config import Settings
from gateway.pipeline import Gateway, load_routes, load_tenants
from gateway.ssrf import UnsafeUpstream
from tests.conftest import ADMIN_KEY, TENANT_KEY, make_settings
from tests.harness import build_harness, fake_resolver

ROOT = Path(__file__).resolve().parent.parent


async def public_dns(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


@pytest.mark.parametrize("routes_file", ["config/routes.json", "config/routes.local.json"])
def test_seed_files_are_valid(routes_file: str) -> None:
    routes = load_routes(ROOT / routes_file)
    tenants = load_tenants(ROOT / "config/tenants.json")
    assert {r.route_id for r in routes} == {"echo", "flaky", "slow", "httpbin"}
    assert {t.tenant_id for t in tenants} == {"acme", "globex", "initech"}
    paths = {p for t in tenants for p in t.allowed_paths}
    assert paths <= {r.prefix for r in routes}  # every allowlisted path has a route


async def test_from_settings_loads_and_validates_seed_files() -> None:
    settings = make_settings(
        routes_file=ROOT / "config/routes.json",
        tenants_file=ROOT / "config/tenants.json",
        upstream_allowed_private_hosts=frozenset({"demo-upstream"}),
    )
    gateway = await Gateway.from_settings(settings, resolver=public_dns)
    try:
        assert gateway.routes.snapshot.get("httpbin") is not None
        assert gateway.tenants.get("acme") is not None
    finally:
        await gateway.aclose()


async def test_startup_fails_on_unsafe_seed_route() -> None:
    settings = make_settings(
        routes_file=ROOT / "config/routes.json",
        tenants_file=ROOT / "config/tenants.json",
        upstream_allowed_private_hosts=frozenset(),  # demo-upstream not allowlisted
    )
    with pytest.raises(UnsafeUpstream, match="demo-upstream"):
        await Gateway.from_settings(settings, resolver=fake_resolver)


async def test_lifespan_builds_and_closes_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = make_settings(
        routes_file=ROOT / "config/routes.local.json",
        tenants_file=ROOT / "config/tenants.json",
        upstream_allowed_private_hosts=frozenset({"127.0.0.1"}),
    )

    original = Gateway.from_settings

    async def from_settings(s: Settings) -> Gateway:
        return await original(s, resolver=public_dns)

    monkeypatch.setattr(Gateway, "from_settings", staticmethod(from_settings))
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        gateway = app.state.gateway
        assert isinstance(gateway, Gateway)
        assert not gateway.client.is_closed
    assert gateway.client.is_closed


# --- proxy-header trust -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("trust", "headers", "expected"),
    [
        (False, {"do-connecting-ip": "198.51.100.7"}, "203.0.113.9"),
        (False, {"x-forwarded-for": "198.51.100.7"}, "203.0.113.9"),
        (True, {"do-connecting-ip": "198.51.100.7"}, "198.51.100.7"),
        (True, {"x-forwarded-for": "6.6.6.6, 198.51.100.7"}, "198.51.100.7"),  # right-most
        (True, {}, "203.0.113.9"),
    ],
)
async def test_client_ip_only_from_trusted_headers(
    trust: bool, headers: dict[str, str], expected: str
) -> None:
    async with build_harness(make_settings(trust_proxy_headers=trust)) as h:
        seen = (await h.get("/echo/x", headers=headers)).json()["headers"]
        assert seen["x-forwarded-for"] == expected
        assert "do-connecting-ip" not in seen


async def test_forwarded_proto_trusted_only_behind_proxy() -> None:
    async with build_harness(make_settings(trust_proxy_headers=True)) as h:
        seen = (await h.get("/echo/x", headers={"x-forwarded-proto": "https"})).json()["headers"]
        assert seen["x-forwarded-proto"] == "https"
    async with build_harness() as h:
        seen = (await h.get("/echo/x", headers={"x-forwarded-proto": "https"})).json()["headers"]
        assert seen["x-forwarded-proto"] == "http"


# --- CLI --------------------------------------------------------------------------------------


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("GATEWAY_JWT_KEYS", json.dumps({"k1": TENANT_KEY}))
    monkeypatch.setenv("GATEWAY_ADMIN_KEY", ADMIN_KEY)
    monkeypatch.setenv("UPSTREAM_ALLOWED_PRIVATE_HOSTS", "127.0.0.1")
    monkeypatch.setattr("gateway.config.Settings.model_config", {
        **Settings.model_config, "env_file": None,
    })  # fmt: skip


@pytest.mark.usefixtures("cli_env")
async def test_cli_tenant_token_works_against_gateway(capsys: pytest.CaptureFixture[str]) -> None:
    assert token_main(["--tenant", "acme", "--scopes", "echo:read"]) == 0
    token = capsys.readouterr().out.strip()
    async with build_harness(make_settings(jwt_keys={"k1": TENANT_KEY})) as h:
        assert (await h.get("/echo/x", token=token)).status_code == 200


@pytest.mark.usefixtures("cli_env")
async def test_cli_admin_token(capsys: pytest.CaptureFixture[str]) -> None:
    assert token_main(["--admin", "alice", "--ttl", "60"]) == 0
    token = capsys.readouterr().out.strip()
    async with build_harness(make_settings(jwt_keys={"k1": TENANT_KEY})) as h:
        assert (await h.get("/admin/routes", token=token)).status_code == 200


@pytest.mark.usefixtures("cli_env")
@pytest.mark.parametrize(
    "argv",
    [
        ["--tenant", "acme", "--scopes", "admin"],
        ["--tenant", "globex", "--scopes", "httpbin:read"],
        ["--tenant", "initech", "--scopes", "echo:read"],
        ["--tenant", "nobody"],
        ["--tenant", "acme", "--ttl", "3600"],
    ],
)
def test_cli_refuses_over_grant(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert token_main(argv) == 2
    assert "error:" in capsys.readouterr().err


def test_init_env_writes_valid_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = tmp_path / ".env"
    assert init_env_main(["--path", str(env)]) == 0
    assert env.stat().st_mode & 0o777 == 0o600
    assert init_env_main(["--path", str(env)]) == 1  # refuses to overwrite
    for var in ("GATEWAY_JWT_KEYS", "GATEWAY_ADMIN_KEY", "UPSTREAM_ALLOWED_PRIVATE_HOSTS"):
        monkeypatch.delenv(var, raising=False)
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert settings.signing_kid == "k1"
    assert "127.0.0.1" in settings.upstream_allowed_private_hosts
    assert str(settings.routes_file) == "config/routes.local.json"


async def test_demo_upstream_endpoints() -> None:
    from demo_upstream.app import create_app as upstream_app

    transport = httpx.ASGITransport(app=upstream_app("demo"))
    async with httpx.AsyncClient(transport=transport, base_url="http://u") as c:
        assert (await c.get("/healthz")).json() == {"status": "ok"}
        assert (await c.get("/status/503")).status_code == 503
        assert (await c.get("/status/99")).status_code == 422
        delayed = await c.get("/delay/0")
        assert delayed.json()["path"] == "/delay/0"
        assert (await c.get("/delay/31")).status_code == 422
