# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

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
