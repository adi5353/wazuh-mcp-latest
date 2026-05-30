# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Code-Review Response (2026-05-30)

Addressed actionable findings from an external architecture/security review.

**Path-traversal hardening** — `_validate_manager_file_path` in `wazuh_client.py`
now repeatedly URL-decodes the route (defeating `%2e%2e` and double-encoded
`%252e` traversal), normalises backslashes, and rejects scheme-relative (`//host`)
paths before the allowlist-prefix check. Added regression cases for each vector.

**Prompt extraction** — The 15 MCP prompt builders were moved out of the
1,600-line `server.py` god-module into a dedicated `wazuh_mcp/prompts.py`. They
are re-exported from `server` (and registered via `register_prompts(mcp)`), so
behaviour and the `server.<prompt>` import surface are unchanged.

**Deterministic test suite** — Added an autouse `reset_session_identity` fixture
in `tests/conftest.py` that clears the task-local role / injection-counter
ContextVars between tests, fixing an order-dependent RBAC state leak.

**Test hygiene** — Renamed the ambiguously-named `test_security_hardening_new.py`,
`_new2.py`, and `_prod.py` to `_severity.py`, `_approval_rbac.py`, and
`_regressions.py` respectively (history preserved via `git mv`).

**Docs** — Removed the duplicate `.env.example`; `env.example` (referenced by the
README, CONTRIBUTING, pre-commit, and tests) is now the single source of truth.

### Security Fixes — Security-Hardening Branch (2026-05-29)

Second hardening pass addressing 15 additional findings from the security review.

**H1 — /health pre-auth reconnaissance** — Unauthenticated `/health` now returns
only `{status, uptime_seconds}`. Detailed payload (`checks`, `latency_ms`,
`manager_version`) is gated behind a valid `WAZUH_MCP_API_KEY` bearer token.
Added module-level `_health_caller_is_authenticated_fn` for testability.

**M2 — Persistent injection counter per identity** — The prompt-injection lockout
counter now accumulates across MCP requests for the same authenticated caller,
keyed by a SHA-256 hash of their bearer token. Previously, a ContextVar reset on
each new asyncio task, allowing an attacker to stay just below the 3-attempt
lockout threshold by making separate requests.

**M3 — Active-response default allowlist narrowed** — `_AR_DEFAULT_COMMANDS`
reduced from `firewall-drop,restart-wazuh` to `firewall-drop` only. `restart-wazuh`
can interrupt security monitoring and must be explicitly opted-in via
`WAZUH_MCP_AR_ALLOWED_COMMANDS`.

**M4 — Central indexer field validation** — `WazuhIndexer.search()` and
`.count()` now accept `validate_fields=True` to enforce the validators allow-list
for user-supplied field names inside DSL term/match/range clauses.

**M5 — MSSP credential guidance** — Removed misleading "version-controlled JSON"
wording from `config.py`. Added startup warning when inline `WAZUH_INSTANCES` env
var is used, advising migration to `WAZUH_INSTANCES_FILE` pointing at a
secrets-manager-mounted path.

**L2 — CI test markers** — Added `requires_indexer` and `integration` pytest
markers to `pyproject.toml` so pytest does not warn about unknown markers and CI
can filter properly.

**L3 — OpenAPI private SDK attribute** — `/openapi.json` endpoint now uses
`mcp.get_tools()` public API first, falls back to `mcp._tools` wrapped in
`try/except AttributeError`, and uses `_TOOL_REGISTRY` as a last resort.
Prevents breakage when SDK drops the private attribute.

**L4 — Middleware ordering comment** — Fixed comment to accurately reflect actual
ASGI execution order (last-wrapped = outermost = runs first on incoming requests).

**L5 — Supply-chain: Trivy image scan** — Added `trivy` CI job that builds the
image, scans for HIGH/CRITICAL CVEs (exit 1 on findings), and uploads a
CycloneDX SBOM artifact. `pip-audit` was already present.

---

### Security Fixes — Production Hardening Pass (previous)

Production-hardening pass addressing 14 review findings. Secure-by-default: with only
Wazuh credentials configured, the server now binds loopback, runs as `viewer`, keeps
writes off, and requires authentication before any non-loopback exposure.

1. **Insecure default bind** — `WAZUH_MCP_HOST` now defaults to `127.0.0.1`. HTTP mode
   refuses to start on a non-loopback host without `WAZUH_MCP_API_KEY`, unless
   `WAZUH_MCP_ALLOW_INSECURE_BIND=true` (logs a loud warning).
2. **DNS-rebinding protection enabled** — `enable_dns_rebinding_protection=True` with
   `allowed_hosts`/`allowed_origins` populated from the bind host plus
   `WAZUH_MCP_ALLOWED_HOSTS` / `WAZUH_MCP_ALLOWED_ORIGINS`.
3. **Role no longer settable via tool argument** — in HTTP mode the session role is
   derived from the authenticated bearer token in middleware before dispatch; the
   `set_session_role` tool is a no-op error in HTTP and works only in stdio.
4. **Fail-closed roles** — unknown/typo role names resolve to `viewer` (was `analyst`)
   in both `identity.effective_role()` and `rbac._current_role()`; env default unified
   to `viewer`.
5. **Origin/CSRF** — on a non-loopback bind with no `WAZUH_MCP_ALLOWED_ORIGINS`, browser
   `Origin` requests are denied by default; Origin-less requests require API-key auth.
   Loopback binds keep permissive passthrough.
6. **Autonomous monitor** — auto-resume on startup is gated behind
   `WAZUH_MCP_AUTO_RESUME_MONITOR` (default false); a reusable guard requires both
   `WAZUH_ALLOW_WRITES=true` and `WAZUH_MCP_AUTONOMOUS_AR=true` plus a never-block
   IP allowlist (`WAZUH_MCP_AR_SAFE_IPS`) before any automated active response. (The
   monitor performs no auto-blocking today; the guard hardens current and future paths.)
7. **Dependencies pinned** — compatible-release ranges with upper bounds in
   `pyproject.toml`; committed `requirements.lock`; `.github/dependabot.yml` added.
   (CI already ran `bandit` + `pip-audit`; pip-audit now targets the lockfile.)
8. **PII scrubbing is opt-in** — `WAZUH_MCP_SCRUB_PII` (default false). Secret redaction
   and prompt-injection filtering remain always on.
9. **Global input sanitizer relaxed** — removed the shell-metacharacter check and base64
   variant-decoding (false positives on CEF `|`, Lucene `&&`/`||`, base64-like hashes);
   kept size caps, prompt-override tags, path-traversal, and URL-decode checks. Verified
   no tool feeds user input into a shell (no `subprocess`/`os.system`/`shell=True`).
10. **Active-response command allowlist** — `WAZUH_MCP_AR_ALLOWED_COMMANDS`
    (default `firewall-drop,restart-wazuh`) enforced in `run_active_response` and
    `approve_response`.
11. **XML upload path validation** — `upload_xml_file` rejects paths outside the
    `/rules/files/`, `/decoders/files/`, and `/lists/files/` Manager file-API routes
    and any `..`.
12. **README tool count corrected** — now "239 tools across 52 modules", with
    `scripts/generate_tool_table.py` to regenerate and a `--check` mode for CI.
13. **`WAZUH_VERIFY_SSL` docs** — README Docker block now matches `env.example` (`true`).
14. **`requirements.txt`** — converted to an authoritative pinned runtime export.

> **Process note:** the project history was squashed into a single commit, which cannot be
> reconstructed retroactively. Going forward, changes must be committed granularly (one
> logical change per commit) so security-relevant edits are individually reviewable.

### Added
- `wazuh_mcp/mitre_data.py` — full MITRE ATT&CK technique map expanded from 21 to 149 techniques; `enrich_mitre_ids()` and `get_technique()` helpers
- `wazuh_mcp/geo.py` — dedicated GeoIP module with `geoip_lookup()` (HTTPS only) and new `geoip_batch()` for async concurrent enrichment
- `wazuh_mcp/triage.py` — incident recommendation engine covering exfiltration, token abuse, and defense evasion techniques
- `wazuh_mcp/middleware/tool_middleware.py` — `ToolMiddleware` class replacing the brittle double monkey-patch of `mcp.tool` with a single composable decorator
- `Config.redacted()` method — safe dict representation for logging with passwords replaced by `[REDACTED]`
- CSRF/Origin validation middleware — rejects browser requests from disallowed origins (configurable via `WAZUH_MCP_ALLOWED_ORIGINS`)
- `wazuh_mcp/py.typed` marker — enables downstream type checking with mypy
- `CONTRIBUTING.md` — tool development guide, RBAC annotation requirements, test conventions
- `SECURITY.md` — vulnerability disclosure policy and supported versions
- `Makefile` — standard targets: `lint`, `test`, `test-cov`, `security`, `docker`, `dev`
- CI: coverage gate raised 35% → 50%; coverage XML artifact upload; integration test job added
- JWT token is now cleared from memory before re-authentication (reduces token-in-memory window)

### Changed
- `server.py` refactored: 1329 → 1132 lines; inline MITRE map, GeoIP, and triage logic extracted to dedicated modules
- Test files renamed from phase-based (`test_phase2.py`) to feature-based names (`test_retry_resilience.py`)

### Fixed
- GeoIP lookups now use HTTPS exclusively (ipinfo.io primary, ip-api.com HTTPS fallback); plain HTTP `ip-api.com` endpoint removed

---

## [1.0.0] — 2025-05-01

### Added
- Initial release with 100+ MCP tools across 40+ modules
- RBAC with 4 tiers: viewer, analyst, responder, admin
- HTTP/SSE and stdio transports
- Docker, systemd, and pip install deployment options
- Integrations: Jira, TheHive, Slack, SMTP, PagerDuty, ServiceNow, Azure DevOps, VirusTotal, AbuseIPDB
- Audit trail with rotating JSONL and optional HMAC signing
- Rate limiting, API-key authentication, IP allowlist/blocklist
- MSSP multi-tenant support via `WAZUH_INSTANCES`
- Prometheus `/metrics` endpoint
- OpenAPI `/openapi.json` spec auto-generated from registered tools
- 4 MCP prompts: `morning_briefing`, `incident_triage`, `shift_handover`, `threat_hunt_session`
- Autonomous SOC monitor with configurable thresholds
- Wazuh Cloud support via `WAZUH_CLOUD=true`
