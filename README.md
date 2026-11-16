# mt-gateway

A multi-tenant API gateway. It authenticates callers with JWTs, routes requests by path prefix to upstreams that can change at runtime, enforces per-tenant policy (path allowlist, required scopes, per-minute quota), and writes one structured audit line per request. Extensions: per-upstream circuit breaker with half-open probes, canary traffic split, and deployment to DigitalOcean App Platform.

Python 3.12, FastAPI, httpx, PyJWT, pydantic, structlog. The reasons for each choice are in [docs/TECH_STACK.md](docs/TECH_STACK.md).

## Documentation

| Doc | What it covers |
| --- | --- |
| [docs/GUIDE.md](docs/GUIDE.md) | Glossary, request lifecycle, every feature, admin API, error contract, data models, deployment |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Flow diagram with every failure branch |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Authenticated-but-malicious tenant; security assumptions and known gaps |
| [docs/TECH_STACK.md](docs/TECH_STACK.md) | Each tool choice, why, and what was rejected |

## Setup

Requirements: [uv](https://docs.astral.sh/uv/) (it installs Python 3.12 itself) and, for containers, Docker.

```bash
git clone https://github.com/nabilniaz/mt-gateway.git && cd mt-gateway
uv sync                    # creates .venv with Python 3.12 and every dependency from uv.lock
uv run gateway-init-env    # writes .env with fresh random signing keys (git-ignored)
```

## Run locally

Two terminals:

```bash
PORT=9000 uv run demo-upstream   # terminal 1: the echo service routes point at
uv run gateway-serve             # terminal 2: the gateway on http://localhost:8080
```

`.env` points the gateway at `config/routes.local.json` (upstream `127.0.0.1:9000`) and allowlists loopback past the SSRF guard.

## Issue a token

Tokens are HS256 JWTs that live at most 15 minutes. There are two ways to get one.

```bash
# 1. Offline, with the CLI (reads keys from .env, tenants from config/tenants.json)
TOKEN=$(uv run gateway-token --tenant acme --scopes echo:read,httpbin:read)
ADMIN=$(uv run gateway-token --admin alice)

# 2. Through the admin API
curl -s -X POST localhost:8080/admin/tokens -H "Authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' -d '{"tenant_id":"acme","scopes":["echo:read"]}'
```

The CLI and the API both refuse scopes outside the tenant's `max_scopes`. The `admin` scope can never be issued to a tenant.

## Try it

```bash
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/echo/orders/42 | jq   # 200, upstream echo
curl -s localhost:8080/echo/x | jq                                          # 401 missing_token
curl -s --path-as-is -H "Authorization: Bearer $TOKEN" localhost:8080/echo/../admin | jq   # 400
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/slow/5 | jq           # 504 (route timeout 2 s)
for i in 1 2 3 4; do curl -s -o /dev/null -w "%{http_code} " \
  -H "Authorization: Bearer $TOKEN" localhost:8080/flaky/500; done           # 500 500 500 503
curl -s -H "Authorization: Bearer $ADMIN" localhost:8080/admin/upstreams | jq # breaker state

# Add a route at runtime; it serves traffic immediately
curl -s -X PUT localhost:8080/admin/routes/headers -H "Authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"prefix":"/echo/headers","upstream":"http://127.0.0.1:9000/v3","required_scopes":["echo:read"]}'
```

The gateway prints one JSON audit line per request to stdout. Interactive admin API docs are at http://localhost:8080/admin/docs.

Seeded tenants are in `config/tenants.json`:

| Tenant | Status | Allowed paths | Quota |
| --- | --- | --- | --- |
| `acme` | enabled | `/echo`, `/flaky`, `/slow`, `/httpbin` | 60/min |
| `globex` | enabled | `/echo` only | 5/min |
| `initech` | disabled | | |

## Run with Docker

```bash
docker compose up --build      # gateway on :8080, demo-upstream reachable only by the gateway
./scripts/smoke.sh             # end-to-end checks against the running stack
docker compose down
```

The image is the one App Platform builds. Inside the stack, tokens can be minted with `docker compose exec gateway gateway-token --tenant acme --scopes echo:read`.

## Tests and quality checks

```bash
./scripts/check.sh             # ruff lint + format check, mypy --strict, pytest
uv run pytest --cov            # with a coverage report
```

- **Unit tests:** path normalization, JWT, rate limiter, breaker, canary, SSRF guard, route table, header rewriting and settings.
- **Integration tests:** the real gateway in front of the real demo upstream, running in-process through httpx's ASGI transport. They cover every status code in the error contract, header hygiene, the audit log, the admin API, breaker transitions and the canary split.
- **CI:** GitHub Actions (`.github/workflows/ci.yml`) runs everything on every push, then builds the Docker stack and runs `scripts/smoke.sh`.

## Configuration

All settings are environment variables. Locally they come from `.env`; on App Platform they come from the app spec.

| Variable | Default | Purpose |
| --- | --- | --- |
| `GATEWAY_JWT_KEYS` | required | Tenant signing keys as JSON `{"kid": "secret"}`, each at least 32 bytes. To rotate, add a key; new tokens use the last one. |
| `GATEWAY_JWT_ACTIVE_KID` | last key | Override which key signs new tokens |
| `GATEWAY_ADMIN_KEY` | required | Admin-token key, at least 32 bytes, different from every tenant key |
| `PORT` / `HOST` | `8080` / `0.0.0.0` | Listen address |
| `ROUTES_FILE` / `TENANTS_FILE` | `config/routes.json` / `config/tenants.json` | Seed files loaded at startup |
| `UPSTREAM_ALLOWED_PRIVATE_HOSTS` | empty | Comma-separated hosts allowed to resolve to private IPs |
| `TRUST_PROXY_HEADERS` | `false` | Read the client IP from `do-connecting-ip` / `X-Forwarded-For` (only behind App Platform) |
| `MAX_BODY_BYTES` | `1048576` | Request body limit |
| `CONNECT_TIMEOUT_SECONDS`, `WRITE_TIMEOUT_SECONDS`, `POOL_TIMEOUT_SECONDS`, `MAX_CONNECTIONS` | 3, 10, 2, 100 | Upstream client limits (read timeout is per route) |
| `BREAKER_FAILURE_THRESHOLD`, `BREAKER_COOLDOWN_SECONDS`, `BREAKER_HALF_OPEN_MAX_PROBES` | 5, 30, 1 | Breaker defaults; routes can override them |
| `LOG_LEVEL` | `INFO` | |

## Deploy to DigitalOcean App Platform

The app spec is `.do/app.yaml`. It defines two components:

- `gateway`: public, HTTPS at the app's `ondigitalocean.app` URL.
- `demo-upstream`: internal only.

App Platform builds the Dockerfile itself on x86-64 servers, so it doesn't matter that this Mac is Apple Silicon.

1. Push the repo to GitHub:
   ```bash
   gh auth login
   gh repo create mt-gateway --public --source . --push
   ```
2. Connect DigitalOcean to GitHub once. In the DigitalOcean control panel, go to **Apps → Create App → GitHub** and grant access to `mt-gateway`, then cancel the wizard.
3. Run these commands. The script creates `.env.do` with production keys on first run (git-ignored, so keep a backup) and creates or updates the app.
   ```bash
   doctl auth init
   ./scripts/deploy_do.sh
   ```
4. Test the deployment. Mint tokens with the production keys, then point the smoke test at the public URL:
   ```bash
   set -a; . ./.env.do; set +a; export ROUTES_FILE=config/routes.json
   TENANT_TOKEN=$(uv run gateway-token --tenant acme --scopes echo:read) \
   GLOBEX_TOKEN=$(uv run gateway-token --tenant globex --scopes echo:read) \
     ./scripts/smoke.sh https://<your-app>.ondigitalocean.app
   doctl apps logs <app-id> gateway --type run --follow   # the audit log
   ```

After that, every push to `main` redeploys. The spec uses two `apps-s-1vcpu-0.5gb` instances, about US$10 a month in total.

## Security assumptions and known gaps

**Assumptions:**

- TLS terminates in front of the gateway. App Platform does this.
- Signing keys are random, at least 32 bytes, and stored only as secrets.
- Upstreams accept traffic only from the gateway and trust only gateway-set headers.
- Admin-key holders are trusted.
- Clocks are accurate to within 30 s.

**Known gaps, by impact:**

1. All state is per instance (quotas, breakers, routes, revocations), so the app runs exactly one instance. Scaling out needs Redis.
2. Bearer tokens can be replayed within their 15-minute life.
3. There is no per-tenant concurrency cap.
4. DNS rebinding can bypass the SSRF check after an upstream is saved.
5. One shared admin key, served on the public port.
6. HS256 lets any verifier mint tokens.
7. The gateway does not inspect request-body content.
8. A failing canary is not rolled back automatically.
9. Runtime admin changes are lost on restart until committed to the seed files.

The full reasoning, per threat, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Layout

| Path | Feature |
| --- | --- |
| `src/gateway/pipeline.py` | Request lifecycle: the ordered checks, proxying, audit |
| `src/gateway/auth.py` | JWT issue/verify, key rotation, revocation |
| `src/gateway/paths.py` | Path normalization, segment-boundary prefix match |
| `src/gateway/routes.py` | Copy-on-write route table and tenant store |
| `src/gateway/ratelimit.py` | Sliding-window quota |
| `src/gateway/breaker.py` / `canary.py` | Circuit breaker / canary split |
| `src/gateway/ssrf.py` | Upstream URL validation |
| `src/gateway/proxy.py` | Header and URL rewriting |
| `src/gateway/admin.py` | Admin API |
| `src/gateway/audit.py` | Structured audit log |
| `src/gateway/config.py` / `models.py` / `errors.py` | Settings, data models, error format |
| `src/gateway/cli.py` | `gateway-serve`, `gateway-token`, `gateway-init-env` |
| `src/demo_upstream/app.py` | Echo service used in tests, Compose and App Platform |
