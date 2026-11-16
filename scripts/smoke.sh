#!/bin/sh
# End-to-end smoke test against a running gateway (docker compose or App Platform).
# Usage: ./scripts/smoke.sh [base_url]   (default http://localhost:8080)
# Tokens are minted inside the gateway container, or taken from $TENANT_TOKEN / $GLOBEX_TOKEN.
set -eu
BASE="${1:-http://localhost:8080}"
mint() { docker compose exec -T gateway gateway-token "$@"; }
TENANT_TOKEN="${TENANT_TOKEN:-$(mint --tenant acme --scopes echo:read)}"
GLOBEX_TOKEN="${GLOBEX_TOKEN:-$(mint --tenant globex --scopes echo:read)}"

fail=0
expect() {  # expect <status> <description> <curl args...>
  want="$1"; what="$2"; shift 2
  got=$(curl -s -o /dev/null -w "%{http_code}" --path-as-is "$@")
  if [ "$got" = "$want" ]; then echo "ok   $want  $what"; else echo "FAIL $what: want $want, got $got"; fail=1; fi
}

expect 200 "health check"               "$BASE/healthz"
expect 200 "proxied request"            -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/echo/smoke"
expect 401 "missing token"              "$BASE/echo/smoke"
expect 401 "garbage token"              -H "Authorization: Bearer nope" "$BASE/echo/smoke"
expect 403 "path outside allowlist"     -H "Authorization: Bearer $GLOBEX_TOKEN" "$BASE/flaky/200"
expect 400 "path traversal"             -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/echo/../admin"
expect 403 "tenant token on admin API"  -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/admin/routes"
expect 504 "upstream timeout"           -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/slow/5"
exit $fail
