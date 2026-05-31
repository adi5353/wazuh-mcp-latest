# Technical Requirements Document (TRD) — Wazuh MCP Server

| | |
|---|---|
| **Product** | Wazuh MCP — AI-Powered Security Operations |
| **Document type** | Technical Requirements Document |
| **Status** | Living document |
| **Related docs** | [PRD](./PRD.md) · [Tool Flow](./TOOL_FLOW.md) · [LLM Testing Guide](./LLM_TESTING_GUIDE.md) |

---

## 1. Scope

This document describes the technical architecture, components, data flows,
interfaces, and constraints that satisfy the requirements in the [PRD](./PRD.md).
It is the engineering reference for how the Wazuh MCP server is built.

## 2. Technology stack

| Concern | Choice |
|---|---|
| Language | Python ≥ 3.10 (CI matrix 3.10 / 3.11 / 3.12) |
| MCP framework | `mcp` SDK — `FastMCP("wazuh")` |
| HTTP server (http mode) | Starlette + Uvicorn (ASGI) |
| HTTP client | `httpx.AsyncClient` (shared pooled clients) |
| Validation | Pydantic schema parsers (`schemas.py`) + custom validators |
| Logging | `structlog` (JSON) with stdlib fallback, secret redaction |
| Metrics | Prometheus text exposition (`/metrics`) |
| Packaging | `pyproject.toml`, `wazuh-mcp` console entry point, Docker image |
| Tests | `pytest` (~248 tests), `ruff`, `mypy`, `bandit`, `pip-audit` |

## 3. High-level architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          LLM Client (MCP host)                             │
│        Claude Desktop  ·  Open WebUI + Ollama  ·  any MCP client           │
└───────────────┬───────────────────────────────────────────┬──────────────┘
                │ stdio (local)            http / SSE (remote)│
                ▼                                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          Wazuh MCP Server (FastMCP "wazuh")                │
│                                                                            │
│  HTTP middleware stack (http mode, outer → inner):                         │
│    MaxBodySize → SecurityHeaders → [IPFilter] → [APIKey] →                 │
│    OriginValidation → RateLimit → Audit → ASGI app                         │
│                                                                            │
│  Tool middleware (per call): identity → RBAC → context-gating →            │
│    input sanitize → rate/quota → circuit/failure breaker → cache →         │
│    handler → response sanitize → size cap → audit                          │
│                                                                            │
│  ~239 @mcp.tool()s (54 modules)   MCP prompts   MCP resources              │
│                                                                            │
│  Cross-cutting: config · identity/RBAC/ABAC · audit · cache ·              │
│    state_store · circuit/failure breakers · secrets backend                │
└───────────────┬──────────────────────────────┬───────────────────────────┘
                │ WazuhClient (Manager REST)    │ WazuhIndexer (OpenSearch)
                ▼                                ▼
        Wazuh Manager API :55000        Wazuh Indexer :9200
                                                 │
                ┌────────────────────────────────┴───────────────────┐
                ▼  Optional outbound integrations (httpx)             ▼
   Threat intel: VirusTotal, AbuseIPDB, ipinfo, HIBP/Hunter
   SOAR/ticketing: Jira, TheHive, ServiceNow, PagerDuty, Azure DevOps
   Chat/email: Slack, Microsoft Teams, SMTP        Secrets: Vault
```

## 4. Component breakdown

### 4.1 Server core (`wazuh_mcp/server.py`)
- Instantiates `mcp = FastMCP("wazuh")`.
- Builds a `ToolContext` (shared `WazuhClient`, `WazuhIndexer`, `Config`, helper
  callbacks) and calls each module's `register(ctx)` to attach its tools.
- Defines a small set of inline tools (`enrich_alert_full`, `enrich_alerts_batch`,
  `set_session_role_tool`, `list_tenants`, `switch_tenant`).
- `main()` selects transport: `stdio` (default for local) or `http` (Starlette +
  Uvicorn) based on `WAZUH_MCP_TRANSPORT`.
- Wraps the ASGI app in the HTTP middleware stack (see §6) and exposes
  `/health`, `/metrics`, and the MCP `/sse` + `/messages` endpoints.
- Registers SIGTERM handler + `timeout_graceful_shutdown=30`.

### 4.2 Tool modules (`wazuh_mcp/tools/*.py`)
- Each module exposes `register(ctx: ToolContext) -> None` and declares its tools
  with `@mcp.tool()` inside that function (closures capture `wz`, `idx`, `cfg`).
- Modules are grouped into **operational contexts** in `tool_contexts.py`
  (`threat_hunting`, `active_response`, `compliance`, `system_health`); modules
  not listed are **CORE** (always on).
- Tool docstrings are the LLM-facing contract (when to call, params, payload
  shape) — they are surfaced to the model via `tools/list`.

### 4.3 Upstream clients
- **`wazuh_client.py`** — Wazuh Manager REST API. Handles auth token lifecycle,
  retries (`_MAX_RETRIES=3`, exponential backoff base 1.0s cap 10.0s), retryable
  classification (`_is_retryable`), shared pooled `httpx.AsyncClient`.
- **`wazuh_indexer.py`** — OpenSearch queries against alert indices; pooled client,
  DSL execution, `_validate/query` dry-run for NL-generated DSL.
- Pool sizing via `WAZUH_HTTP_POOL_SIZE` (100) / `WAZUH_HTTP_MAX_KEEPALIVE` (40).

### 4.4 Enrichment pipeline (`enrichment/pipeline.py`, `geo.py`, `mitre_data.py`, `triage.py`)
- MITRE technique ID → name enrichment, GeoIP/ASN lookup, incident
  recommendations, full-alert enrichment combining the above.

### 4.5 MCP prompts (`prompts.py`) & resources (`resources.py`)
- **Prompts** = parameterized natural-language workflows registered via
  `register_prompts(mcp)` (morning briefing, triage, handover, CISO briefing,
  compliance review, onboarding, etc.).
- **Resources** = live read-only context (`agents`, `mitre techniques`, `rules
  summary`, `health`) registered via `register(mcp, wz, idx, cfg)`.

## 5. Identity, RBAC, ABAC, multi-tenancy

| Module | Responsibility |
|---|---|
| `identity.py` | Resolves a caller identity/role from API key; records injection attempts; per-session role binding |
| `rbac.py` | 4-tier role model `viewer(10) < analyst(20) < responder(30) < admin(40)`; `@rbac.require(ROLE.X)` decorator; returns descriptive error (not silent failure) on insufficient role |
| `abac.py` | Attribute-based gating (e.g. status checks) layered on RBAC |
| `tool_contexts.py` | Optional operational-context gating (`WAZUH_MCP_CONTEXT_GATING`) — shrinks the *effective* tool surface per caller identity |
| MSSP | `list_tenants` / `switch_tenant` route a session to a tenant config; queries support `group_filter` for tenant scoping |

Role default is `analyst`. Set globally via `WAZUH_MCP_USER_ROLE` or per-session
via `set_session_role_tool(api_key)` mapping keys → roles.

## 6. HTTP middleware stack (http mode)

Applied outer→inner so each `app = Middleware(app)` adds an outer layer.
Order is security-critical (**auth before audit** so unauthenticated requests are
never logged as tool calls):

1. `MaxBodySizeMiddleware` — rejects oversized bodies with **413** (`body_limit.py`)
2. `SecurityHeadersMiddleware` — HSTS/CSP/etc., TLS-aware (`security_headers.py`)
3. `IPFilterMiddleware` *(optional)* — allow/deny lists (`ip_filter.py`)
4. `APIKeyMiddleware` *(when `WAZUH_MCP_API_KEY` set)* — `hmac.compare_digest`
   timing-safe bearer check → **401** on mismatch (`server.py`)
5. `OriginValidationMiddleware` — CSRF/origin checks
6. `RateLimitMiddleware` — per-client limits → **429** (`rate_limit.py`)
7. `AuditMiddleware` — structured request audit (`audit.py`)

**Binding rule:** a non-loopback `WAZUH_MCP_HOST` *requires* `WAZUH_MCP_API_KEY`
or the server refuses to start (no insecure override).

## 7. Per-tool call pipeline (`middleware/tool_middleware.py`)

Every `tools/call` passes through, in order:
1. **Identity / role resolution** + context-gating check (`is_tool_allowed`)
2. **Input sanitization** (`input_sanitizer.py`) and per-arg validation
   (`validators.py`: time ranges, agent IDs, IPs, rule IDs, limits)
3. **RBAC / ABAC** enforcement
4. **Rate / quota** and **circuit breaker** + **per-tool failure breaker**
   (`circuit_breaker.py`, `tool_failure_breaker.py`)
5. **Cache** lookup (`cache.py`, with hit/miss stats, per-tool invalidation)
6. **Handler** execution (the actual tool)
7. **Response sanitization** (`sanitize_response` strips secrets + prompt-injection
   tokens), **size cap** (`cap_response_size`), **token-budget trimming**
8. **Audit** record (HMAC-signed)

## 8. Safety model for writes

- **Dry-run first:** destructive tools (`restart_agent`, `run_active_response`,
  CDB writes, playbooks) default to `dry_run=True` and return a preview.
- **Approval workflow** (`approval.py`): `propose_active_response` → `approve_response`/`deny_response`;
  auto-suppression proposals require `approve_suppression`/`reject_suppression`.
- **Role gating:** writes require `responder`; fleet/cluster/rule-push/autonomous require `admin`.
- **Rollback:** `rollback_custom_rule`, `rollback_agent_upgrade`, CDB backup import.

## 9. Persistence & state

No parallel alert store. Small durable state only:
- `state_store.py` — JSON-on-disk for compliance baselines, rule backups,
  schedules, watchlists; survives restarts/redeploys.
- Investigation workspaces — JSON under `WAZUH_WORKSPACE_DIR` (default `/app/workspaces`).
- Audit log — `logs/audit.jsonl`, HMAC-signed, auto-rotated
  (`WAZUH_AUDIT_MAX_BYTES` default 50MB, `WAZUH_AUDIT_BACKUP_COUNT` default 7).
- CVE watchlist persisted in a CDB list (`WAZUH_CVE_WATCHLIST_NAME`).

## 10. Configuration (`config.py`)

- Centralized `Config`; all secrets resolved via `get_secret()` (`secrets_backend.py`)
  so Vault or env are interchangeable (`WAZUH_SECRET_BACKEND`).
- Key env groups: Wazuh connections, transport, security/access (API key, role,
  IP filter, body cap, rate limits), TLS, index patterns, secrets backend,
  threat-intel circuit breaker, optional integrations. Full table in the README.
- Wazuh Cloud mode (`WAZUH_CLOUD=true`) swaps connection inputs for cloud URL/key.

## 11. Reliability & performance

| Mechanism | Detail |
|---|---|
| Connection pooling | Shared pooled `httpx.AsyncClient`s for Manager + Indexer |
| Retries | 3 attempts, exponential backoff (base 1s, cap 10s), retryable-only |
| Circuit breaker | Trips on repeated upstream failures; per-tool failure breaker isolates a flaky tool |
| Caching | TTL cache with hit/miss/ratio stats; single-tool invalidation |
| Payload bounds | `WAZUH_MAX_RESULTS_GLOBAL` cap, response size cap, token-budget trimming, `search_after` cursor pagination |
| Graceful shutdown | SIGTERM handler + 30s graceful timeout; compose `stop_grace_period: 35s` |

## 12. Observability

- **`/health`** — unauthenticated, returns `status`/`timestamp`/`version` only
  (no role/write-state leakage).
- **`/metrics`** — Prometheus text: `wazuh_mcp_requests_total`,
  `wazuh_mcp_request_duration`, `wazuh_mcp_active_sessions`, etc.
- In-product tools: `get_mcp_server_metrics`, `get_tool_usage_stats` (p50/p95/p99),
  `get_slow_queries`.
- Structured JSON logs to **stderr** (never stdout in stdio mode — would corrupt
  the JSON-RPC stream); secrets redacted by a logging processor.

## 13. Deployment topologies

| Mode | How | Notes |
|---|---|---|
| **Docker (http/SSE)** | `compose.yaml`; `docker compose up -d` | Default remote/server deploy; behind API key |
| **Local stdio** | `wazuh-mcp` or `python -m wazuh_mcp` | Claude Desktop on same machine |
| **Air-gapped** | `docker-compose.ollama.yaml` | Ollama + Open WebUI + MCP on an isolated network |
| **systemd** | install + unit file | Long-running local service |
| **Wazuh Cloud** | `WAZUH_CLOUD=true` + cloud creds | No local Manager/Indexer needed |
| **MSSP** | tenant configs + `switch_tenant` | One server, many client contexts |

Container hardening: non-root `wazuhmcp` (uid 1001), read-only root FS, all
capabilities dropped, `no-new-privileges`, writable `/tmp` only.

## 14. Interfaces

- **MCP (to LLM):** `tools/list`, `tools/call`, `prompts/*`, `resources/*` over
  stdio or SSE (`/sse` + `/messages`).
- **Wazuh Manager:** REST `/security/user/authenticate`, `/agents`, `/rules`,
  `/decoders`, `/manager/*`, `/active-response`, `/lists` (CDB), etc.
- **Wazuh Indexer:** OpenSearch `_search`, `_validate/query`, aggregations.
- **Third-party:** documented per-integration REST APIs (Jira `/rest/api/2/issue`,
  VirusTotal v3, AbuseIPDB, Slack/Teams webhooks, etc.).

## 15. Quality gates (CI)

`ruff` (lint) · `mypy` (types) · `bandit` + `pip-audit` (security) · `pytest`
with 70% coverage gate across Python 3.10/3.11/3.12 · Docker build · tool-count
drift check (`generate_tool_table.py --check`). Live integration contract tests
run against a real Wazuh stack in CI.

## 16. Constraints & assumptions

- The LLM client is responsible for model behavior; the server only constrains
  *what tools can do*, not what the model says.
- Stdout is reserved for JSON-RPC in stdio mode — all human logging goes to stderr.
- Third-party integrations are inert until their env vars are configured; tools
  return a clear "not configured" error otherwise.
- FastMCP's tool registry is process-global; per-caller scoping (context gating,
  tenancy) is keyed on caller identity rather than mutating the registry.
