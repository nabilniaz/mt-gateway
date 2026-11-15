# mt-gateway

A multi-tenant API gateway. It authenticates callers with JWTs, routes requests by path prefix to upstreams that can change at runtime, enforces per-tenant policy (path allowlist, required scopes, per-minute quota), and writes one structured audit line per request. Extensions: circuit breaker, canary routing, DigitalOcean deployment.

**Status:** design phase. Implementation comes next.

## Documentation

| Doc | What it covers |
| --- | --- |
| [docs/GUIDE.md](docs/GUIDE.md) | Part 1: glossary, request lifecycle, every feature, error contract, data models |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Mermaid flow diagram with every failure branch |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Authenticated-but-malicious tenant; security assumptions and known gaps |
| [docs/TECH_STACK.md](docs/TECH_STACK.md) | Part 2: each tool choice, why, and what was rejected |

Setup, token issuance and run instructions will be added with the implementation.
