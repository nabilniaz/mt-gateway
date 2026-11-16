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
expect() {  # expect <status[|status]> <description> <curl args...>
  want="$1"; what="$2"; shift 2
  got=$(curl -s -o /dev/null -w "%{http_code}" --path-as-is "$@")
  case "|$want|" in
    *"|$got|"*) echo "ok   $got  $what" ;;
    *) echo "FAIL $what: want $want, got $got"; fail=1 ;;
  esac
}

expect 200 "health check"               "$BASE/healthz"
expect 200 "proxied request"            -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/echo/smoke"
expect 401 "missing token"              "$BASE/echo/smoke"
expect 401 "garbage token"              -H "Authorization: Bearer nope" "$BASE/echo/smoke"
expect 403 "path outside allowlist"     -H "Authorization: Bearer $GLOBEX_TOKEN" "$BASE/flaky/200"
# Locally the gateway sees the dots and answers 400. Behind App Platform's edge the dots are
# resolved first, so the gateway sees /admin and answers 403. Either way the request is blocked.
expect "400|403" "path traversal (../)"  -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/echo/../admin"
expect 400 "encoded slash"              -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/echo%2fadmin"
expect 403 "tenant token on admin API"  -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/admin/routes"
expect 504 "upstream timeout"           -H "Authorization: Bearer $TENANT_TOKEN" "$BASE/slow/5"
exit $fail
