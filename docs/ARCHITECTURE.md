# Architecture flow

A request moves down the main path only while every check passes. Any failed check exits to an error response (red). No red node ever contacts the upstream, except 502/504, which are the upstream call itself failing. Every outcome writes exactly one audit line.

```mermaid
flowchart TD
    A([Inbound request]) --> B[Assign request_id, start timer]
    B --> C{Body size within limit?}
    C -- no --> E413[413 payload_too_large]
    C -- yes --> D{Path normalizes cleanly?}
    D -- no --> E400[400 invalid_path]
    D -- yes --> F{Valid JWT? HS256, iss, aud, exp}
    F -- no --> E401[401 missing / invalid / expired / revoked token]
    F -- yes --> G{Tenant enabled?}
    G -- no --> E403a[403 tenant_disabled]
    G -- yes --> H{Path in tenant allowlist?}
    H -- no --> E403b[403 path_not_allowed]
    H -- yes --> I{Route matches? longest prefix}
    I -- no --> E404[404 route_not_found]
    I -- yes --> J{Token has required scopes?}
    J -- no --> E403c[403 insufficient_scope]
    J -- yes --> K{Under per-minute quota?}
    K -- no --> E429[429 rate_limited + Retry-After]
    K -- yes --> L[Pick primary or canary: hash mod 100]
    L --> M{Circuit breaker allows call?}
    M -- no --> E503[503 circuit_open]
    M -- yes --> N[Proxy: strip hop-by-hop and spoofable headers, add X-Request-ID]
    N -- connect error --> E502[502 upstream_error]
    N -- timeout --> E504[504 upstream_timeout]
    N -- response --> O([Return upstream status, headers, body])

    E413 & E400 & E401 & E403a & E403b & E404 & E403c & E429 & E503 & E502 & E504 & O --> Z[(Audit log: one JSON line)]

    classDef err fill:#fde8e8,stroke:#c0392b,color:#000
    classDef ok fill:#e3f0fc,stroke:#1f6fbf,color:#000
    class E413,E400,E401,E403a,E403b,E404,E403c,E429,E503,E502,E504 err
    class O ok
```

## How to read it

| Node | What happens | Why it is here |
| --- | --- | --- |
| Body size | Reject bodies over `MAX_BODY_BYTES` | Cheapest check; stops memory abuse before any parsing |
| Path normalize | Decode once; reject `..`, `%2e`, `%2f`, `//`, control chars | Every later step must agree on one path, or the allowlist can be bypassed |
| JWT | Pinned HS256, check `iss`, `aud`, `exp`, `jti` denylist | Establishes tenant identity; nothing else may set it |
| Tenant enabled | Look up tenant config | Lets an operator cut off a tenant instantly |
| Allowlist | Segment-boundary prefix match against `allowed_paths` | Before route lookup, so tenants cannot probe which routes exist |
| Route match | Longest prefix on an immutable route-table snapshot | Runtime updates never show a half-applied table |
| Scopes | Route's `required_scopes` ⊆ token `scopes` | Fine-grained permission per route |
| Quota | Sliding-window counter per tenant | Last policy check, so rejected requests never consume quota |
| Canary | Deterministic hash split | Reproducible in tests, no shared state |
| Breaker | Per-upstream closed / open / half-open | Fail fast instead of piling onto a dying upstream |
| Proxy | Shared `httpx.AsyncClient`, strict timeouts, no redirects | Faithful response, bounded resources, no SSRF via redirect |
| Audit | `finally` block writes one structlog JSON line | Every request is accounted for, including crashes |

The circuit breaker state machine is drawn in [GUIDE.md](GUIDE.md#feature-circuit-breaker).
