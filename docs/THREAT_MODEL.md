# Threat model: an authenticated-but-malicious tenant

The attacker holds a valid, unexpired token for their own tenant and controls every byte they send. They can use their own allowed routes and quota. They cannot act as another tenant, reach a route outside their allowlist, change routes, or make the gateway call an address the operator did not configure.

| Threat | What the attacker tries | Why it fails | Remaining gap |
| --- | --- | --- | --- |
| SSRF via route config | Point a route at `http://169.254.169.254/` (cloud metadata) or `http://localhost:8080/admin` | Tenants cannot write routes at all; `/admin/*` needs a separately signed admin token. Even admins are checked: upstreams must be http/https, contain no credentials, and resolve to a public IP unless the host is on the explicit private allowlist. The gateway never follows upstream redirects, so a public URL cannot bounce it to a private one. | DNS rebinding: a hostname validated at write time could later resolve to a private IP. Mitigation would be re-checking the resolved IP on each connect. |
| Path traversal and normalization tricks | `/orders/../admin`, `/orders/%2e%2e/admin`, `/orders%2fadmin`, `//admin`, `/orders/%00` to slip past the allowlist | The path is decoded exactly once and rejected with 400 if it contains any of these. The allowlist check, route match and forwarded URL all use the same normalized string, so the gateway and upstream cannot disagree about what path was requested. | Upstreams that apply their own extra decoding (double-decoding) are outside the gateway's control. On App Platform the edge resolves `..` before the gateway sees it, so such requests are refused by the allowlist (403) rather than the path check (400); verified against the live deployment. |
| Header spoofing | Send `X-Tenant-ID: globex` or `X-Forwarded-For: 10.0.0.1` to impersonate another tenant or trusted network | Identity comes only from the verified token. Inbound `X-Tenant-*`, `X-Forwarded-*`, `X-Real-IP` and `X-Request-ID` are stripped and rewritten by the gateway. `Authorization` is removed before forwarding, so upstreams never see the gateway token. | Upstreams must trust only gateway-set headers, which requires them to be unreachable except through the gateway. |
| Token replay | Reuse a captured token, or keep using one after being cut off | Tokens live at most 15 minutes. Production is HTTPS-only. Disabling a tenant takes effect on the next request. A specific `jti` can be revoked through `POST /admin/tokens/revoke`. | Within its lifetime, a stolen token works for whoever holds it. Binding tokens to a client key (mTLS or DPoP) would close this. The denylist is in memory. |
| Rate-limit evasion | Rotate tokens, IPs or `jti` values to get a fresh quota | The quota key is `tenant_id` from the verified `sub`, so every token and IP for a tenant shares one counter. The sliding window removes the burst at minute boundaries. | Counters are per instance and reset on restart. With N instances a tenant gets up to N times its quota. Redis fixes this. |
| Noisy neighbor | Saturate the gateway or an upstream with slow requests or huge bodies so other tenants suffer | Per-tenant quota; 1 MiB body limit; strict connect/read/write timeouts; a bounded shared connection pool (max 100 connections); per-upstream circuit breaker. | No per-tenant cap on concurrent in-flight requests, so one tenant can hold many pool slots within its quota. A per-tenant semaphore would fix this. |
| Log injection | Put newlines or fake JSON in the path or User-Agent to forge audit lines | Every field is JSON-encoded by structlog, so a newline becomes the two characters `\n`. Free-text fields are truncated to 512 characters. The tenant identity in the log comes from the token, not the request. | Downstream log viewers that render HTML could still be vulnerable to stored XSS. |
| Admin-API abuse | Call `/admin/routes` or mint tokens with a tenant token | Admin tokens are signed with a different key and need the `admin` scope, which can never be issued to a tenant. A tenant token on `/admin/*` gets 403 `admin_required`. Every admin action is audited with who did it. | A single shared admin key; no per-operator accounts or MFA. The admin API is on the same port as tenant traffic; it could be split onto an internal-only port. |

## Security assumptions and known gaps

The design is secure for a single-instance deployment behind TLS, with upstreams that are reachable only through the gateway.

**Assumptions**

- TLS terminates in front of the gateway (App Platform does this). Locally, plain HTTP is acceptable.
- Signing keys are at least 32 random bytes, stored as platform secrets, and rotated with `kid`.
- Upstreams accept traffic only from the gateway and trust only gateway-set headers.
- Operators holding the admin key are trusted.
- The gateway's clock is accurate to within the 30 s leeway.

**Known gaps**, ordered by impact

1. **Single-instance state.** Quotas, breakers, the route table and the revocation list are in memory. Scaling out needs Redis (or similar) for counters and a shared store for routes.
2. **Bearer tokens can be replayed** within their 15-minute life. Sender-constrained tokens (mTLS, DPoP) would fix this.
3. **No per-tenant concurrency limit**, so one tenant can tie up connection-pool slots within its quota.
4. **DNS rebinding** could bypass the SSRF check after an upstream is saved.
5. **One shared admin key** with no per-operator identity or MFA; the admin API shares the public port.
6. **Symmetric signing (HS256)** means any service that verifies tokens can also mint them. Fine while the gateway is the only verifier; switch to an asymmetric algorithm (EdDSA or ES256) if other services verify tokens.
7. **No request-body inspection.** The gateway enforces size, not content; payload validation is the upstream's job.
8. **Canary failure is not automatically rolled back.** An open canary breaker returns 503 instead of falling back to the primary.
9. **Runtime admin changes are not durable.** Route and tenant changes made through the admin API live in memory and are lost on restart or redeploy until committed to the seed files. DigitalOcean Managed Postgres or Redis would make them durable.
