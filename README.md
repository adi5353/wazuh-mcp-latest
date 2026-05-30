# Wazuh MCP — AI-Powered Security Operations

> **Connect Wazuh SIEM to Claude AI via the Model Context Protocol (MCP), enabling natural-language security operations directly inside Claude Desktop, Open WebUI, and any MCP-compatible client.**

<!-- auto-generated: run scripts/generate_tool_table.py to update -->
**239 tools** across 54 domain modules — alerts, vulnerabilities, FIM, compliance (**PCI-DSS v4.0**, **HIPAA**, GDPR, NIST 800-53, ISO 27001, **NIST CSF 2.0**, **SOC 2 Type II**, **compliance drift detection**), MITRE ATT&CK, threat hunting, active response, fleet inventory, SCA, CDB lists, rules (**decoder testing**, **rule rollback**), threat intel (**domain/URL/bulk IOC enrichment**), incidents, reporting (**HTML/PDF-ready exports, JSON/NDJSON**), notifications (**Slack + Microsoft Teams**), onboarding, cluster health, archive search, alert suppression, network topology, behavioral baselining, UEBA, investigation workspaces, CVE watchlist, detection rule wizard, autonomous SOC monitor, threat feeds, **server metrics**, MSSP multi-tenant, Wazuh Cloud, and more.

[![CI](https://github.com/adi5353/wazuh-mcp-latest/actions/workflows/ci.yml/badge.svg)](https://github.com/adi5353/wazuh-mcp-latest/actions/workflows/ci.yml)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-listed-blue)](https://github.com/modelcontextprotocol/servers)
[![Wazuh Cloud](https://img.shields.io/badge/Wazuh%20Cloud-supported-green)](#wazuh-cloud-setup)
[![MSSP](https://img.shields.io/badge/MSSP-multi--tenant-purple)](#mssp-multi-tenant-setup)
[![Tools](https://img.shields.io/badge/tools-239-brightgreen)](#tool-reference)

---

## What's New

### v2.4 — Quick Wins: Depth & Persistence

Eight targeted improvements across triage quality, export scalability, and persistent storage. No breaking changes.

| Area | Change | Details |
|---|---|---|
| **KEV triage boost** | `auto_triage_alert` checks CISA KEV | If the alert's `data.cve` field matches a CISA Known Exploited Vulnerability, confidence score is raised +25 — nearly guarantees TRUE_POSITIVE classification for exploited CVEs |
| **Pre-fetched batch triage** | `batch_auto_triage` accepts `alert_ids` | Pass a list of alert document IDs to skip the indexer search step — useful when chaining with `search_alerts` page results |
| **Persistent compliance baselines** | `compliance_drift` survives restarts | Baselines are now saved to `state_store` (JSON file on disk) rather than in-memory — survives server restarts and container redeploys |
| **Persistent rule backups** | `rollback_custom_rule` reads from disk | `push_custom_rule` now persists the pre-push backup to `state_store`. `rollback_custom_rule` loads from disk with fallback to legacy in-memory backup |
| **Attacker IP enrichment** | `blast_radius_analysis` auto-enriches IPs | When `WAZUH_VT_API_KEY` is set, discovered source IPs are auto-enriched via VirusTotal (capped at 5 IPs to protect quota). Returns `attacker_ip_enrichment` with malicious count, country, ASN |
| **Sortable alert search** | `search_alerts` `sort_by` param | New `sort_by` option: `timestamp_desc` (default), `level_desc` (highest severity first), `agent_name_asc` (alphabetical by agent) |
| **Per-rule trend** | `alert_summary` per-rule `delta_pct` | Each entry in `top_rules` now includes `delta_pct` — percentage change vs the prior equivalent period (same logic as the fleet-level trend arrow) |
| **Streaming CSV export** | `export_alerts_csv` `stream=True` | New `stream=True` mode uses `search_after` cursor pagination to export all matching alerts page-by-page — avoids OOM on large exports. Prepends a metadata comment row with total row count |

---

### v2.3 — Existing Feature Improvements

Targeted improvements across performance, alert quality, rules, compliance, and security hardening. No breaking changes.

#### Performance & Reliability

| Area | Change | Details |
|---|---|---|
| **Connection pool** | Configurable via env vars | `WAZUH_HTTP_POOL_SIZE` (default 100) and `WAZUH_HTTP_MAX_KEEPALIVE` (default 40) — sized for 130+ concurrent tools under real SOC load; tune down for low-resource deployments |
| **Cache observability** | Hit/miss counters | `cache_stats()` now returns `hits`, `misses`, `hit_ratio` — see actual cache effectiveness. New `invalidate_tool(name)` flushes a single tool's cache without clearing everything |
| **Alert pagination** | Cursor-based paging | `search_alerts` now accepts `page_token` (opaque base64 cursor using `search_after`) and returns `next_page_token` + `has_more` — safe to walk millions of alerts without memory spikes |

#### Alert & Investigation Quality

| Area | Change | Details |
|---|---|---|
| **Deduplication** | Smarter fingerprinting | `deduplicate_alerts` now keys on `rule_id + agent_id + srcip + target_user + 5-min bucket` — prevents merging events from different users or separate attack waves into the same group |
| **Auto-triage** | Float confidence | `auto_triage_alert` now returns `confidence: 0.0–1.0` float alongside `confidence_pct` string — downstream tools can filter and sort numerically |
| **NL query** | DSL validation | `nl_to_opensearch_query` with `execute=True` now dry-runs the generated DSL via `/_validate/query` before executing — returns a clear error instead of a cryptic OpenSearch exception on malformed queries |
| **Blast radius** | Lateral movement pivot | `blast_radius_analysis` now aggregates `data.win.eventdata.targetUserName` and `data.dstuser` — detects credential-reuse lateral movement even when source IPs differ. Returns `pivot_usernames` and auto-generated tip |

#### Rule & Decoder Management

| Area | Change | Details |
|---|---|---|
| **Log testing** | Batch mode | `test_log_against_rules` now accepts `log_samples: list` — tests up to 20 lines in one call and returns per-line results plus overall coverage % |
| **Rule rollback** | New tool: `rollback_custom_rule` | `push_custom_rule` now auto-saves the existing file before overwriting. Call `rollback_custom_rule(filename)` to restore — no need to manually re-upload |
| **Decoder testing** | New tool: `test_decoder` | Shows which decoder fired, the parent chain, and every extracted field for a sample log line. Optionally asserts the expected decoder name matched |

#### Compliance

| Area | Change | Details |
|---|---|---|
| **PCI-DSS v4.0** | New tool: `pci_dss_compliance_summary` | Dedicated PCI-DSS report across all 12 requirements — combines native `rule.pci_dss` field data with rule-group heuristics. Returns per-requirement status and audit readiness verdict |
| **HIPAA** | New tool: `hipaa_compliance_summary` | HIPAA Security Rule report across Administrative, Physical, Technical, and Organizational safeguards — combines native `rule.hipaa` field with heuristics |
| **Drift detection** | New tool: `compliance_drift` | Saves a point-in-time baseline, then diffs current vs baseline on subsequent calls. Returns worsened/improved/new-failing controls with delta counts. Call `save_baseline=True` after a remediation sprint to reset |

#### Security Hardening

| Area | Change | Details |
|---|---|---|
| **Credential rotation** | Post-rotation verification | `rotate_wazuh_api_password` now probes `GET /manager/info` after rotation to confirm the new token works. Returns `connectivity_verified: true/false` and fails safely if the probe fails |
| **Audit log integrity** | New function: `verify_audit_log_integrity` | Re-computes HMAC-SHA256 on every audit log record and compares to stored value. Returns `integrity: OK/COMPROMISED` and a list of tampered lines. Works with the existing `WAZUH_AUDIT_LOG_SIGNING_KEY` env var |

---

### v2.2 — Phase 1 Foundation Improvements

Infrastructure hardening and performance improvements. No breaking changes.

| Area | Change | Details |
|---|---|---|
| **CI/CD** | GitHub Actions pipeline | Lint (ruff + mypy), security scan (bandit + pip-audit), pytest across Python 3.10/3.11/3.12 with 70% coverage gate, Docker build — runs on every push and PR |
| **Performance** | HTTP connection pooling | `WazuhClient` and `WazuhIndexer` now share persistent `httpx.AsyncClient` pools (100 max connections, 40 keepalive) — eliminates per-request TCP handshake overhead and prevents pool saturation under concurrent SOC load |
| **Security** | HTTPS GeoIP | `enrich_ip_geo` now uses **ipinfo.io over HTTPS** by default (was `http://ip-api.com`). Configurable via `WAZUH_GEOIP_PROVIDER`. Set `IPINFO_TOKEN` for 50k/mo free lookups |
| **Operations** | Audit log rotation | `logs/audit.jsonl` now auto-rotates at 50 MB (configurable via `WAZUH_AUDIT_MAX_BYTES`), keeping 7 backups (`WAZUH_AUDIT_BACKUP_COUNT`) — prevents unbounded disk growth in production SOCs |

---

### v2.1 — 7 high-impact tools (cross-fleet correlation, Sigma pipeline, IOC enrichment)

| Area | New Tools | Details |
|---|---|---|
| **Cross-fleet correlation** | `correlate_multi_agent_incident` | 5-phase graph expansion: seed alert → pivot on attacker IPs/usernames → related agents → MITRE kill-chain → confidence score 0–99 with tier (LOW/MEDIUM/HIGH/CRITICAL) |
| **Sigma rule pipeline** | `sigma_bulk_import`, `sigma_coverage_gap`, `test_sigma_rule_against_archive`, `suggest_rule_tuning` | Bulk import multi-doc Sigma YAML, find ATT&CK technique gaps, backtest a rule against archive logs, and get noise score + XML tuning snippets for any rule |
| **IOC enrichment** | `enrich_email`, `ioc_to_alert_match` | Email breach check via HaveIBeenPwned + Hunter.io deliverability; scan 12 alert fields across the last N days for live IOC hits, grouped by IOC with ACTIVE_THREATS_DETECTED verdict |

### v2.0 — 18 new tools across 6 areas

| Area | New Tools | Details |
|---|---|---|
| **Quick wins** | `get_recent_alerts_7d`, `get_recent_alerts_30d`, `deduplicate_alerts` | 7-day/30-day alert windows; collapse repeated alerts into groups with occurrence counts and dedup ratio |
| **Export formats** | `export_alerts_json`, `export_alerts_ndjson`, `export_report_html` | JSON array, NDJSON (Logstash/Vector/Fluent Bit), and print-ready HTML reports (open in browser → Ctrl+P → PDF) |
| **Threat intel** | `enrich_domain`, `enrich_url`, `bulk_enrich_iocs` | Domain & URL reputation via VirusTotal; batch up to 20 mixed IOCs (IP/domain/hash/URL) with auto-type detection |
| **Compliance** | `nist_csf2_compliance_summary`, `soc2_compliance_summary` | Full NIST CSF 2.0 (6 functions) and SOC 2 Type II (5 trust service criteria) with audit readiness verdict |
| **Notifications** | `send_alert_to_teams`, `send_critical_alert_to_teams`, `send_weekly_summary_to_teams` | Microsoft Teams Adaptive Cards — mirrors all existing Slack tools |
| **Server metrics** | `get_mcp_server_metrics`, `get_tool_usage_stats`, `get_slow_queries` | Uptime, per-tool p50/p95/p99 latency, error rates, circuit breaker states, Prometheus text output |

---

## Table of Contents

- [What's New](#whats-new)
- [5-Minute Quickstart](#5-minute-quickstart)
- [Wazuh Cloud Setup](#wazuh-cloud-setup)
- [MSSP Multi-Tenant Setup](#mssp-multi-tenant-setup)
- [Quick Start — Docker](#quick-start--docker)
- [Quick Start — Local (systemd)](#quick-start--local-systemd)
- [Quick Start — Open WebUI + Ollama (Air-Gapped)](#quick-start--open-webui--ollama-air-gapped)
- [Connect Claude Desktop](#connect-claude-desktop)
- [Environment Variables](#environment-variables)
- [Role-Based Access Control](#role-based-access-control)
- [Tool Reference](#tool-reference)
- [MCP Prompts](#mcp-prompts)
- [Architecture](#architecture)
- [Security Hardening](#security-hardening)
- [Optional Integrations](#optional-integrations)
- [Common Issues](#common-issues)

---

## 5-Minute Quickstart

The fastest path to a working Wazuh MCP server:

```bash
pip install wazuh-mcp
wazuh-mcp init      # interactive wizard — writes .env in 2 minutes
wazuh-mcp verify    # test connectivity to your Wazuh instance
wazuh-mcp           # start the server
```

Then open Claude Desktop and ask:
> *"Summarize the last 24 hours of alerts"*
> *"Explain alert \<id\> for my CISO"*
> *"Hunt for lateral movement in the last 48 hours"*

---

## Wazuh Cloud Setup

If you are using [Wazuh Cloud](https://wazuh.com/cloud/) (SaaS), set:

```env
WAZUH_CLOUD=true
WAZUH_CLOUD_URL=https://your-cloud-id.cloud.wazuh.com:55000
WAZUH_CLOUD_API_KEY=your_api_key
WAZUH_CLOUD_INDEXER_PASS=your_indexer_password
```

No `WAZUH_HOST`, `WAZUH_USER`, or `WAZUH_PASS` needed in Cloud mode.  
Run `wazuh-mcp init` and choose option **2** for a guided setup.

---

## MSSP Multi-Tenant Setup

MSSPs managing multiple client Wazuh instances can configure all tenants in one server:

```env
# Default connection (used until switch_tenant is called)
WAZUH_HOST=https://client-a-wazuh:55000
WAZUH_USER=wazuh-wui
WAZUH_PASS=secret
WAZUH_INDEXER_HOST=https://client-a-indexer:9200
WAZUH_INDEXER_PASS=secret

# All tenants
WAZUH_INSTANCES=[
  {"name":"client-a","host":"https://wazuh-a:55000","user":"u","pass":"p","indexer_host":"https://idx-a:9200","indexer_pass":"p"},
  {"name":"client-b","host":"https://wazuh-b:55000","user":"u","pass":"p","indexer_host":"https://idx-b:9200","indexer_pass":"p"}
]
```

Switch tenants at runtime using Claude:
> *"Switch to client-b and show me their recent alerts"*

This calls `switch_tenant("client-b")` and immediately redirects all tool calls to that Wazuh instance. Use `list_tenants()` to see all configured tenants.

Run `wazuh-mcp init` and choose option **3** for a guided MSSP setup.

---

## MCP Registry

This server is listed in the [MCP Registry](https://github.com/modelcontextprotocol/servers).  
Claude Desktop users can discover and install it directly from the registry.

To install via the registry:
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "wazuh-mcp",
      "env": {
        "WAZUH_HOST": "https://your-wazuh:55000",
        "WAZUH_USER": "wazuh-wui",
        "WAZUH_PASS": "your-password",
        "WAZUH_INDEXER_HOST": "https://your-indexer:9200",
        "WAZUH_INDEXER_PASS": "your-password"
      }
    }
  }
}
```

---

## Quick Start — Docker

The recommended deployment. The container bundles all dependencies, runs as a non-root user, and exposes the MCP server on port 8000.

### 1. Clone the repository

```bash
git clone https://github.com/adi5353/wazuh-mcp-latest.git
cd wazuh-mcp-latest
```

### 2. Create your environment file

```bash
cp env.example .env
nano .env
```

Fill in at minimum:

```dotenv
WAZUH_HOST=https://your-wazuh-manager:55000
WAZUH_USER=wazuh-mcp
WAZUH_PASS=YourPassword

WAZUH_INDEXER_HOST=https://your-wazuh-indexer:9200
WAZUH_INDEXER_USER=wazuh-readonly
WAZUH_INDEXER_PASS=YourPassword

WAZUH_VERIFY_SSL=true          # set false only in a lab with self-signed certs
WAZUH_MCP_TRANSPORT=http
WAZUH_MCP_HOST=127.0.0.1        # loopback default; see note below to expose remotely
WAZUH_MCP_PORT=8000
WAZUH_MCP_API_KEY=              # REQUIRED before binding to a non-loopback host
```

> **Exposing beyond localhost:** the server binds to `127.0.0.1` by default and
> **refuses to start** on a non-loopback host (e.g. `0.0.0.0`) unless
> `WAZUH_MCP_API_KEY` is set. This is mandatory and cannot be overridden — the
> former `WAZUH_MCP_ALLOW_INSECURE_BIND` escape hatch has been **removed**. When
> reaching the server via a hostname/proxy, add that host to
> `WAZUH_MCP_ALLOWED_HOSTS` so DNS-rebinding protection allows it.

### 3. Start the container

```bash
docker compose up -d
```

### 4. Verify it's running

```bash
docker compose ps
curl -si http://localhost:8000/sse | head -3
# Expected: HTTP/1.1 200 OK
```

```bash
docker compose logs -f wazuh-mcp   # stream logs
docker compose down                 # stop
docker compose up -d                # restart
```

---

## Quick Start — Local (systemd)

Run directly on the Wazuh server without Docker.

### 1. Clone and install

```bash
git clone https://github.com/adi5353/wazuh-mcp-latest.git
cd wazuh-mcp-latest
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. Configure

```bash
cp env.example .env
nano .env   # fill in WAZUH_HOST, WAZUH_USER, WAZUH_PASS, indexer credentials
```

### 3. Run as a systemd service

```bash
sudo tee /etc/systemd/system/wazuh-mcp.service << 'EOF'
[Unit]
Description=Wazuh MCP Server
After=network.target

[Service]
Type=simple
User=wazuh-mcp
WorkingDirectory=/opt/wazuh-mcp-latest
EnvironmentFile=/opt/wazuh-mcp-latest/.env
ExecStart=/opt/wazuh-mcp-latest/.venv/bin/python -m wazuh_mcp
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-mcp
sudo systemctl status wazuh-mcp
```

Verify:

```bash
ss -tlnp | grep 8000   # shows 127.0.0.1:8000 by default (0.0.0.0:8000 if exposed)
curl -si http://localhost:8000/sse | head -3
```

---

## Quick Start — Open WebUI + Ollama (Air-Gapped)

Run a fully local, air-gapped SOC assistant with Open WebUI and Ollama — no Claude Desktop or internet required.

### 1. Start the stack

```bash
docker compose -f docker-compose.ollama.yaml up -d
docker exec ollama ollama pull llama3.1:8b
```

### 2. Open the dashboard

Navigate to `http://localhost:3000`. Open WebUI is pre-wired to:
- Use Ollama (`llama3.1:8b`) as the LLM
- Connect to wazuh-mcp as the MCP tool server with all 100+ tools auto-injected

### 3. Connect an existing Open WebUI instance (v0.6.31+)

1. Go to **Settings → Tools → Add Tool Server**
2. Set **URL** to `http://localhost:8000/sse` and **API Key** to your `WAZUH_MCP_API_KEY` value
3. Click **Connect** — all tools appear automatically

---

## Connect Claude Desktop

### Option A — HTTP/SSE (Docker or remote server)

Install `mcp-remote` on the machine running Claude Desktop (requires Node.js 18+):

```bash
npm install -g mcp-remote
```

Edit `claude_desktop_config.json`:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "mcp-remote",
      "args": [
        "http://YOUR_SERVER_IP:8000/sse",
        "--allow-http"
      ]
    }
  }
}
```

Fully quit Claude Desktop (tray icon → **Quit**) and relaunch. You should see the tools icon in the chat input.

### Option B — stdio (local, same machine)

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "wazuh_mcp"],
      "env": {
        "WAZUH_HOST": "https://your-wazuh:55000",
        "WAZUH_USER": "wazuh-mcp",
        "WAZUH_PASS": "YourPassword",
        "WAZUH_INDEXER_HOST": "https://your-indexer:9200",
        "WAZUH_INDEXER_USER": "wazuh-readonly",
        "WAZUH_INDEXER_PASS": "YourPassword",
        "WAZUH_VERIFY_SSL": "false",
        "WAZUH_MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

### Option C — Docker on same machine (stdio)

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--env-file", "/absolute/path/to/wazuh-mcp-latest/.env",
        "wazuh-mcp:latest"
      ]
    }
  }
}
```

See `claude_desktop_config.example.json` for annotated examples of all three options.

---

## Environment Variables

### Core — Wazuh Connections

| Variable | Description |
|---|---|
| `WAZUH_HOST` | Wazuh Manager API URL, e.g. `https://<WAZUH_MANAGER_IP>:55000` |
| `WAZUH_USER` | Wazuh Manager API username |
| `WAZUH_PASS` | Wazuh Manager API password |
| `WAZUH_INDEXER_HOST` | Wazuh Indexer (OpenSearch) URL, e.g. `https://<WAZUH_INDEXER_IP>:9200` |
| `WAZUH_INDEXER_USER` | Indexer username |
| `WAZUH_INDEXER_PASS` | Indexer password |

### Transport

| Variable | Default | Description |
|---|---|---|
| `WAZUH_MCP_TRANSPORT` | `http` | `http` for Docker/remote, `stdio` for local Claude Desktop |
| `WAZUH_MCP_HOST` | `127.0.0.1` | Bind address for HTTP mode. Non-loopback values **always require** `WAZUH_MCP_API_KEY` or the server refuses to start (no insecure override) |
| `WAZUH_MCP_PORT` | `8000` | Port for HTTP mode |

### Security & Access

| Variable | Default | Description |
|---|---|---|
| `WAZUH_VERIFY_SSL` | `true` | Set `false` only in lab/dev with self-signed certs |
| `WAZUH_CA_BUNDLE` | — | Path to custom CA cert bundle (PEM) for private CAs |
| `WAZUH_ALLOW_WRITES` | `false` | Enable write tools (restart, active response, CDB edits) |
| `WAZUH_MCP_API_KEY` | — | Bearer token required on all HTTP requests (recommended). Also maps to a session role via `WAZUH_MCP_KEY_MAP` |
| `WAZUH_MCP_ALLOWED_HOSTS` | — | Comma-separated extra Host header values permitted by DNS-rebinding protection (add your server hostname for mcp-remote) |
| `WAZUH_MCP_USER_ROLE` | `viewer` | RBAC tier: `viewer` \| `analyst` \| `responder` \| `admin`. Unknown values fail closed to `viewer` |
| `WAZUH_MCP_SCRUB_PII` | `false` | Redact emails/SSNs/credit-card numbers from tool output. Off by default so IPs/emails that are the analyst's answer aren't mangled (secret + prompt-injection filtering are always on). When off **and** a remote cloud LLM is suspected, the server logs a loud compliance warning on boot |
| `WAZUH_MCP_LOCAL_LLM` | `false` | Declare that an on-prem/local model (e.g. Ollama) consumes output — suppresses the PII boot warning |
| `WAZUH_MCP_PII_SCRUB_ACK` | `false` | Explicitly acknowledge running with PII scrubbing off to a cloud LLM — downgrades the boot error to a warning |
| `WAZUH_MCP_AR_ALLOWED_COMMANDS` | `firewall-drop,restart-wazuh` | Allowlist of permitted active-response command names |
| `WAZUH_MCP_AR_SAFE_IPS` | — | Comma-separated never-block IP allowlist for active response |
| `WAZUH_MCP_AUTO_RESUME_MONITOR` | `false` | Resume the autonomous monitor on startup if it was running before restart |
| `WAZUH_MCP_AUTONOMOUS_AR` | `false` | Permit automated active-response actions by the monitor (also requires `WAZUH_ALLOW_WRITES=true`) |
| `WAZUH_MCP_RATE_LIMIT_RPM` | `60` | Max requests per minute per API-key identity |
| `WAZUH_MCP_RATE_LIMIT_BURST` | `10` | Burst allowance above RPM limit |
| `WAZUH_AUDIT_LOG` | `logs/audit.jsonl` | Path for structured JSONL audit trail |
| `WAZUH_AUDIT_MAX_BYTES` | `52428800` | Audit log max size before rotation (default 50 MB) |
| `WAZUH_AUDIT_BACKUP_COUNT` | `7` | Number of rotated audit log backups to keep |
| `WAZUH_GEOIP_PROVIDER` | `ipinfo` | GeoIP provider: `ipinfo` (HTTPS, default) or `ip-api` (HTTPS fallback) |
| `IPINFO_TOKEN` | — | ipinfo.io token for 50k/mo free lookups (optional — works without token at lower limits) |
| `WAZUH_REQUEST_TIMEOUT` | `30` | Per-request API timeout in seconds |
| `WAZUH_MAX_RESULTS_GLOBAL` | `500` | Hard cap on results from any list tool |
| `WAZUH_HTTP_POOL_SIZE` | `100` | Max simultaneous HTTP connections to Wazuh Manager |
| `WAZUH_HTTP_MAX_KEEPALIVE` | `40` | Max keepalive connections in the Manager pool |
| `WAZUH_INDEXER_POOL_SIZE` | `100` | Max simultaneous HTTP connections to Wazuh Indexer |
| `WAZUH_INDEXER_MAX_KEEPALIVE` | `40` | Max keepalive connections in the Indexer pool |
| `WAZUH_MCP_MAX_TOKENS` | `4000` | Token budget per tool response; list results are pruned to fit (0 = disabled) |
| `WAZUH_AUDIT_LOG_SIGNING_KEY` | — | HMAC-SHA256 signing key for audit log tamper detection (enables `verify_audit_log_integrity`) |

### TLS for the MCP Endpoint

| Variable | Description |
|---|---|
| `WAZUH_MCP_TLS_CERT` | Path to server TLS certificate (enables HTTPS) |
| `WAZUH_MCP_TLS_KEY` | Path to server TLS private key |
| `WAZUH_MCP_CLIENT_CA` | Path to CA cert for mutual TLS (optional) |

### Index Patterns

| Variable | Default | Description |
|---|---|---|
| `WAZUH_ALERTS_INDEX` | `wazuh-alerts-*` | Alert index pattern |
| `WAZUH_VULN_INDEX` | `wazuh-states-vulnerabilities-*` | Vulnerability state index |
| `WAZUH_ARCHIVES_INDEX` | `wazuh-archives-*` | Archive index (all ingested logs) |
| `WAZUH_INV_PACKAGES_INDEX` | `wazuh-states-inventory-packages-*` | Package inventory (Wazuh 4.10+) |
| `WAZUH_INV_PROCESSES_INDEX` | `wazuh-states-inventory-processes-*` | Process inventory (Wazuh 4.10+) |
| `WAZUH_INV_PORTS_INDEX` | `wazuh-states-inventory-ports-*` | Port inventory (Wazuh 4.10+) |

### Secrets Backend

| Variable | Default | Description |
|---|---|---|
| `WAZUH_SECRET_BACKEND` | `` (env vars) | `vault` for HashiCorp Vault, `aws` for AWS Secrets Manager |
| `VAULT_ADDR` | — | Vault server URL (when `WAZUH_SECRET_BACKEND=vault`) |
| `VAULT_TOKEN` | — | Vault token |
| `VAULT_SECRET_PATH` | — | KV v2 path containing all secrets |
| `AWS_SECRET_NAME` | — | AWS Secrets Manager secret name/ARN |
| `AWS_REGION` | — | AWS region |

### Threat Intel Circuit Breaker

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_DAILY_LIMIT` | `450` | Daily VT lookup cap (free tier: 500/day) |
| `ABUSEIPDB_DAILY_LIMIT` | `900` | Daily AbuseIPDB cap (free tier: 1000/day) |
| `TI_CIRCUIT_FAIL_THRESHOLD` | `5` | Consecutive failures to open circuit |
| `TI_CIRCUIT_RESET_SECONDS` | `300` | Seconds before retrying after circuit opens |

### Optional Integrations

| Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal enrichment |
| `ABUSEIPDB_API_KEY` | AbuseIPDB enrichment |
| `IPINFO_TOKEN` | ipinfo.io token for extended GeoIP/ASN data (optional) |
| `JIRA_URL` | Jira base URL |
| `JIRA_USER` | Jira username (email) |
| `JIRA_API_TOKEN` | Jira API token |
| `JIRA_PROJECT_KEY` | Jira project key, e.g. `SOC` |
| `THEHIVE_URL` | TheHive base URL |
| `THEHIVE_API_KEY` | TheHive API key |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook |
| `SLACK_BOT_TOKEN` | Slack bot token (alternative to webhook) |
| `SLACK_DEFAULT_CHANNEL` | Default Slack channel, e.g. `#soc-alerts` |
| `TEAMS_WEBHOOK_URL` | **New** — Microsoft Teams incoming webhook (channel → Connectors → Incoming Webhook) |
| `SMTP_HOST` | SMTP server for email reports |
| `SMTP_PORT` | SMTP port (default `587`) |
| `SMTP_USER` | SMTP username |
| `SMTP_PASS` | SMTP password |
| `REPORT_EMAIL_FROM` | Sender address |
| `REPORT_EMAIL_TO` | Recipient(s) — comma-separated |
| `WAZUH_WORKSPACE_DIR` | `/app/workspaces` | Directory for investigation workspace JSON files |
| `WAZUH_CVE_WATCHLIST_NAME` | `cve-watchlist` | CDB list name for CVE watchlist |
| `WAZUH_CRED_CREATED_AT` | — | Unix timestamp when `WAZUH_PASS` was last rotated |

---

## Role-Based Access Control

Set `WAZUH_MCP_USER_ROLE` to control which tools are available for a given server instance. Each tier includes all tools from lower tiers.

| Role | Tier | Included Capabilities |
|---|---|---|
| `viewer` | 10 | Read-only summaries, searches, listings |
| `analyst` | 20 | viewer + enrichment, threat hunting, compliance, incidents, rules *(default)* |
| `responder` | 30 | analyst + active response, CDB writes, alert suppression, threat feed sync |
| `admin` | 40 | responder + cluster management, agent restart, rule push, autonomous monitor |

Tools requiring elevated roles return a descriptive error rather than failing silently:

```json
{
  "error": "Insufficient role. This tool requires 'responder' or above. Current role: 'analyst'.",
  "required_role": "responder",
  "current_role": "analyst"
}
```

---

## Tool Reference

> Counts are generated, not hand-maintained. Run
> `python scripts/generate_tool_table.py` to regenerate `docs/TOOL_TABLE.md` and
> the headline totals (**239 tools across 54 modules**), or
> `python scripts/generate_tool_table.py --check` in CI to fail the build if the
> README count drifts.

### Agents (6 tools)

| Tool | Description |
|---|---|
| `list_agents` | List agents by status (active, disconnected, pending) |
| `get_agent` | Detailed info for one agent by ID |
| `restart_agent` | Restart an agent *(admin)* |
| `list_groups` | All groups with member counts |
| `get_group_agents` | Agents belonging to a group |
| `add_agent_to_group` | Assign an agent to a group *(responder)* |

### Agent Health Scoring (1 tool)

Composite 0–100 health score per agent across five dimensions: connectivity, event throughput, SCA pass rate, vulnerability load, and FIM activity. Bands: HEALTHY (90–100), WARNING (70–89), DEGRADED (50–69), CRITICAL (0–49).

| Tool | Description |
|---|---|
| `get_agent_health_score` | Composite health score with per-dimension breakdown |

### Alerts (12 tools)

| Tool | Description |
|---|---|
| `alert_summary` | Aggregated overview — top rules, agents, MITRE, groups |
| `search_alerts` | Filtered alert search with trimmed payloads; supports cursor-based `page_token` pagination |
| `search_by_mitre` | Alerts mapped to a specific ATT&CK technique |
| `search_by_source_ip` | All alerts from a given IP — IoC pivoting |
| `search_authentication_failures` | Brute-force candidate sources |
| `alert_timeline` | Date histogram — spot spikes and quiet periods |
| `get_alert_by_id` | Full alert detail by document ID |
| `compare_alert_volume` | This period vs last period — volume deltas |
| `detect_rule_anomalies` | NEW, SPIKE, DROP, GONE rules vs baseline |
| `get_recent_alerts_7d` | Last 7 days of alerts; optional agent filter |
| `get_recent_alerts_30d` | Last 30 days of alerts for monthly review |
| `deduplicate_alerts` | Collapse repeated alerts into groups — keyed on rule+agent+srcip+target_user+5min bucket |

### Vulnerabilities (4 tools)

| Tool | Description |
|---|---|
| `vulnerability_summary` | Fleet-wide unpatched CVE overview |
| `get_agent_vulnerabilities_detailed` | Per-agent CVE list, worst CVSS first |
| `search_cve` | Every agent affected by a specific CVE |
| `prioritize_patches` | Patch queue ranked by agents × CVSS |

### CVE Watchlist (4 tools)

Persistent watchlist of SOC-critical CVEs stored in a Wazuh CDB list. Continuously tracks exposure across the fleet.

| Tool | Description |
|---|---|
| `add_cve_to_watchlist` | Add a CVE to the SOC watchlist with optional annotation |
| `list_cve_watchlist` | All watched CVEs with status (active/patched/monitoring) |
| `mark_patched` | Mark a CVE as patched across the fleet |
| `get_watchlist_exposure` | Count of affected agents per active CVE |

### Active Response (4 tools)

| Tool | Description |
|---|---|
| `get_active_responses` | Recent AR actions with triggering alert context |
| `correlate_alert_with_response` | Did Wazuh act on this attack? |
| `active_response_effectiveness` | Did automated blocks stop traffic? |
| `run_active_response` | Trigger an AR command on an agent *(responder)* |

### File Integrity Monitoring (4 tools)

| Tool | Description |
|---|---|
| `get_recent_fim_changes` | Recent FIM events for an agent (Manager API) |
| `search_fim_alerts` | Indexer-side FIM alerts with optional path filter |
| `fim_summary` | Aggregated FIM activity by agent, event type, path |
| `critical_file_changes` | FIM events on sensitive paths only |

### Compliance (10 tools)

Supported frameworks: **PCI-DSS v4.0**, **HIPAA**, GDPR, NIST 800-53, TSC, ISO 27001:2022, **NIST CSF 2.0**, **SOC 2 Type II**. Plus compliance drift detection across all frameworks.

| Tool | Description |
|---|---|
| `compliance_summary` | Alerts by control for PCI-DSS, HIPAA, GDPR, NIST 800-53, TSC |
| `compliance_control_details` | Drill into alerts for one specific control |
| `generate_compliance_report` | Full compliance report for a framework |
| `iso27001_compliance_summary` | ISO 27001:2022 Annex A posture report (derived from rule groups) |
| `nist_csf2_compliance_summary` | NIST CSF 2.0: GOVERN / IDENTIFY / PROTECT / DETECT / RESPOND / RECOVER with NIST 800-53 cross-references |
| `soc2_compliance_summary` | SOC 2 Type II: Common Criteria / Availability / Processing Integrity / Confidentiality / Privacy; includes audit readiness verdict and P1–P4 remediation priorities |
| `pci_dss_compliance_summary` | **v2.3** — Dedicated PCI-DSS v4.0 report across all 12 requirements; combines native `rule.pci_dss` field + rule-group heuristics; per-requirement status and audit readiness |
| `hipaa_compliance_summary` | **v2.3** — Dedicated HIPAA Security Rule report across Administrative / Physical / Technical / Organizational safeguards; combines native `rule.hipaa` field + heuristics |
| `compliance_drift` | **v2.3** — Saves a compliance baseline, then diffs current vs baseline on subsequent calls — returns worsened, improved, and new-failing controls with delta counts |
| `email_compliance_report` | Email the compliance report as HTML *(requires SMTP config)* |

### Fleet Inventory (7 tools)

| Tool | Description |
|---|---|
| `get_agent_packages` | Installed packages per agent |
| `get_agent_processes` | Currently-tracked processes per agent |
| `get_agent_open_ports` | Listening ports per agent |
| `get_agent_hardware_os` | Hardware + OS info in one call |
| `fleet_find_package` | Every agent with a given package |
| `fleet_find_process` | Every agent running a given process |
| `fleet_find_listening_port` | Every agent with a given port open |

### Network Topology (3 tools)

Live network map built from Wazuh agent inventory — agents grouped by subnet, exposed ports per node, peer communications from alert data. Renderable as Mermaid diagrams in Open WebUI.

| Tool | Description |
|---|---|
| `get_network_topology` | Fleet topology grouped by subnet with port exposure |
| `get_agent_neighbors` | Peers a specific agent has communicated with |
| `map_subnet_exposure` | All listening services visible within a subnet |

### SCA (4 tools)

| Tool | Description |
|---|---|
| `get_agent_sca_policies` | CIS benchmark policies and scores per agent |
| `get_sca_failed_checks` | Failing checks with rationale and remediation |
| `sca_alerts_summary` | Fleet-wide SCA aggregation from Indexer |
| `fleet_sca_weakest_agents` | Agents ranked by failing check count |

### CDB Lists (5 tools)

| Tool | Description |
|---|---|
| `list_cdb_lists` | All configured CDB lists |
| `get_cdb_list_contents` | Raw key:value contents of a list |
| `preview_cdb_list_impact` | Preview how many alerts a list entry would match |
| `add_to_cdb_list` | Add an IP, domain, or hash *(responder)* |
| `remove_from_cdb_list` | Remove an entry *(responder)* |

### Rules & Decoders (9 tools)

| Tool | Description |
|---|---|
| `search_rules` | Search rules by description, group, level, or MITRE |
| `list_rule_files` | All rule files — built-in and custom |
| `get_custom_rules` | Rules from custom files only |
| `list_decoders` | All loaded decoders |
| `get_rule_details` | Full metadata for a rule ID |
| `test_log_against_rules` | Test one log line or a batch of up to 20 lines (`log_samples: list`) against the rule engine — returns per-line results and overall coverage % |
| `test_rule_coverage` | Test up to 20 log samples, report detection % |
| `test_decoder` | **v2.3** — Shows which decoder fired, parent chain, and all extracted fields for a sample log line; optionally asserts the expected decoder name matched |
| `rollback_custom_rule` | **v2.3** — Restore a custom rule file to its previous version (auto-backed-up by `push_custom_rule`) *(admin)* |

### Detection Rule Wizard (3 tools)

AI-assisted tool for creating, validating, and deploying Wazuh XML detection rules from natural language.

| Tool | Description |
|---|---|
| `generate_rule_xml` | Generate Wazuh XML rule from a natural language description |
| `validate_rule_xml` | Parse and validate rule XML before upload |
| `push_custom_rule` | Push validated rule XML to Manager's custom_rules.xml; auto-saves backup for `rollback_custom_rule` *(admin)* |

### Threat Intelligence (7 tools)

All enrichment tools degrade gracefully when API keys are absent and use a shared circuit breaker to protect free-tier daily quotas.

| Tool | Description |
|---|---|
| `enrich_ip` | VirusTotal + AbuseIPDB verdict for an IP |
| `enrich_file_hash` | VirusTotal lookup for MD5/SHA1/SHA256 |
| `enrich_ip_geo` | GeoIP lookup — ASN, country, city (no key required) |
| `enrich_domain` | **New** — Domain reputation via VirusTotal (creation date, registrar, categories, verdict) |
| `enrich_url` | **New** — URL reputation via VirusTotal with redirect tracking and HTTP response code |
| `bulk_enrich_iocs` | **New** — Batch enrich up to 20 mixed IOCs (IP/domain/hash/URL) in one call with auto-type detection; parallel enrichment |
| `get_threat_intel_status` | Daily quota usage and circuit breaker state for all TI providers |

### Extended GeoIP & Infrastructure (2 tools)

Full ASN, hosting-provider classification, Tor/VPN/datacenter detection via ipinfo.io and ip-api.com.

| Tool | Description |
|---|---|
| `enrich_ip_extended` | Full ASN + GeoIP + infrastructure classification |
| `classify_ip_infrastructure` | Fast infrastructure type classification (datacenter/Tor/VPN/residential) |

### Threat Feeds (3 tools)

Pulls IOC lists from free public feeds (Feodo Tracker C2 IPs, URLhaus malicious domains, Tor exit nodes) and populates Wazuh CDB lists.

| Tool | Description |
|---|---|
| `sync_threat_feed` | Pull a named feed and update its CDB list *(responder)* |
| `list_threat_feeds` | Show all configured feeds with last-sync status |
| `correlate_alerts_with_feed` | Check active alerts against a threat feed IOC list |

### Threat Hunting (4 tools)

| Tool | Description |
|---|---|
| `hunt_lateral_movement` | Detect internal pivoting between agents |
| `hunt_persistence_mechanisms` | Detect persistence (cron, registry, startup) |
| `hunt_data_exfiltration` | Detect large outbound transfers and DNS exfil |
| `get_agent_login_history` | Login audit log for a specific agent |

### Behavioral Baselining (3 tools)

7-day rolling baselines per agent across alert volume, critical alerts, login patterns, and port activity. Scores real-time deviations as anomaly severity.

| Tool | Description |
|---|---|
| `compute_agent_baseline` | Build a behavioral baseline for an agent |
| `score_agent_deviation` | Score current behavior against stored baseline |
| `list_anomalous_agents` | All agents with deviation above threshold |

### User Entity Behavior Analytics / UEBA (3 tools)

Cross-agent user behavior correlation — tracks login patterns, privilege escalation, and lateral movement by username, surfacing T1078 attacks invisible to per-agent rules.

| Tool | Description |
|---|---|
| `get_user_activity_profile` | Login history and patterns for a username across all agents |
| `detect_user_anomalies` | Anomalous login times, new source IPs, off-hours access |
| `list_privileged_escalations` | All sudo/privilege escalation events across the fleet |

### MITRE ATT&CK (2 tools)

| Tool | Description |
|---|---|
| `mitre_coverage_analysis` | Technique coverage across the ruleset |
| `get_mitre_gaps` | Techniques firing with only 1 rule (gap detection) |

### Incidents (5 tools)

| Tool | Description |
|---|---|
| `incident_timeline` | Chronological kill-chain reconstruction |
| `blast_radius_analysis` | Everything a compromised IP/agent touched |
| `create_incident_report` | Generate a structured incident report |
| `tag_alert` | Tag an alert with analyst verdict and notes *(analyst)* |
| `get_alert_by_id` | Full alert detail by document ID |

### Automated Playbooks (3 tools)

Pre-defined YAML playbooks that chain multiple tools in sequence with approval gates. Built-in playbooks: isolate-compromised-host, brute-force-response.

| Tool | Description |
|---|---|
| `list_playbooks` | All available playbooks with descriptions and required params |
| `run_playbook` | Execute a playbook by ID with parameters |
| `get_playbook_status` | Status and results of a running/completed playbook |

### Scheduled Reports (3 tools)

Cron-style background jobs that auto-run reporting tools and deliver via Slack or email. Schedules persist across server restarts.

| Tool | Description |
|---|---|
| `create_report_schedule` | Schedule a report type (daily/weekly/monthly) to a delivery channel |
| `list_report_schedules` | All active schedules with next-run time |
| `delete_report_schedule` | Remove a schedule |

### Reporting (3 tools)

| Tool | Description |
|---|---|
| `generate_shift_handover` | Structured SOC shift handover report |
| `generate_weekly_summary` | Weekly executive summary |
| `create_incident_report` | Incident report with MITRE mapping |

### Alert Suppression (3 tools)

| Tool | Description |
|---|---|
| `list_suppressed_rules` | Rules tagged as false_positive with FP rate and tuning advice |
| `expire_suppression` | Remove false_positive tags older than N hours *(responder)* |
| `noise_score_rule` | 0–100 noise score — CRITICAL/HIGH/MEDIUM/LOW tier |

### Integrations (3 tools)

| Tool | Description |
|---|---|
| `create_jira_ticket` | Create a Jira issue from an alert |
| `create_thehive_case` | Create a TheHive case |
| `update_ticket_status` | Update a Jira ticket status |

### Notifications (8 tools)

Slack and Microsoft Teams are both fully supported with equivalent feature sets.

**Slack (4 tools)**

| Tool | Description |
|---|---|
| `send_alert_to_slack` | Send a formatted alert to Slack (webhook or bot token) |
| `send_shift_handover_to_slack` | Post shift handover report to Slack |
| `send_weekly_summary_to_slack` | Post weekly summary to Slack |
| `send_critical_alert_notify` | Immediate critical alert Slack notification |

**Microsoft Teams (3 tools) — New**

| Tool | Description |
|---|---|
| `send_alert_to_teams` | Send a formatted Adaptive Card to Teams (severity colour, fields, ticket link) |
| `send_critical_alert_to_teams` | Immediate critical alert Teams card with CRITICAL/HIGH/MEDIUM tier |
| `send_weekly_summary_to_teams` | Weekly security summary card with alert counts and MITRE breakdown |

**Email (1 tool)**

| Tool | Description |
|---|---|
| `email_compliance_report` | Email compliance report as HTML *(requires SMTP config)* |

### Agent Onboarding (3 tools)

| Tool | Description |
|---|---|
| `generate_enrollment_command` | Install command for Ubuntu/Debian/CentOS/RHEL/Windows/macOS |
| `list_never_connected_agents` | Agents that enrolled but never sent a heartbeat |
| `agent_onboarding_checklist` | 6-point health check for a newly enrolled agent |

### Cluster Health (2 tools)

| Tool | Description |
|---|---|
| `get_cluster_health` | Wazuh cluster nodes + Indexer cluster health |
| `check_event_queue_health` | Detect silent event loss from queue pressure |

### Archive Search (2 tools)

| Tool | Description |
|---|---|
| `search_archive_logs` | Search all ingested logs (not just alerts) — forensic |
| `search_archive_logs_by_agent` | Chronological event timeline for a specific agent |

### Investigation Workspaces (4 tools)

Named investigation sessions that persist context across Claude conversations. Each workspace stores typed evidence entries (notes, alert IDs, agent IDs, artifacts, timelines, CVEs, IPs) as JSON on the server.

| Tool | Description |
|---|---|
| `create_workspace` | Start a new named investigation workspace |
| `add_to_workspace` | Add a note, alert ID, or artifact to a workspace |
| `get_workspace` | Retrieve workspace contents |
| `export_workspace` | Export workspace as JSON or Markdown |

### Autonomous SOC Monitor (3 tools)

Background asyncio loop that polls for high-severity alerts, automatically chains investigative tool calls, and sends Slack notifications. Requires `admin` role.

| Tool | Description |
|---|---|
| `start_autonomous_monitor` | Start the background alert monitor *(admin)* |
| `stop_autonomous_monitor` | Stop the monitor *(admin)* |
| `get_autonomous_status` | Current monitor state, alert count, recent actions |

### Quick Wins & NL Query (5 tools)

| Tool | Description |
|---|---|
| `get_abac_status` | Show current Attribute-Based Access Control configuration |
| `nl_to_opensearch_query` | Translate natural-language queries to OpenSearch DSL; optional `execute=true` |
| `auto_triage_alert` | Heuristic True Positive / False Positive / Needs Review classification for one alert |
| `batch_auto_triage` | Auto-triage all alerts in a time window — morning triage in one call |
| `deduplicate_alerts` | **New** — Collapse repeated rule+agent alert groups with dedup ratio reporting |

### Data Export (6 tools)

Export alert, vulnerability, and compliance data in multiple formats for offline analysis, SIEM ingestion, or audit evidence.

| Tool | Format | Description |
|---|---|---|
| `export_alerts_csv` | CSV | Alerts with timestamp, agent, rule, srcip, MITRE tactics |
| `export_alerts_json` | **JSON** | **New** — JSON array; optional `pretty=true` for human readability |
| `export_alerts_ndjson` | **NDJSON** | **New** — Newline-delimited JSON for Logstash, Fluent Bit, Vector bulk import |
| `export_report_html` | **HTML** | **New** — Print-ready self-contained HTML with inline CSS; open in browser → Ctrl+P → Save as PDF. Supports `report_type='compliance'` or `'vulnerabilities'` |
| `export_vulnerabilities_csv` | CSV | Vulnerability findings with CVE, severity, CVSS, package, version |
| `export_compliance_csv` | CSV | Compliance alerts with control mappings for auditor evidence packages |

> **PDF tip:** `export_report_html` generates HTML with `@media print` CSS. Open the returned HTML in any browser and press **Ctrl+P → Save as PDF** for a formatted compliance/vulnerability PDF report.

### Server Metrics (3 tools) — New

Self-monitoring tools for production observability of the MCP server itself. The Prometheus text output is also available at the HTTP `GET /metrics` endpoint.

| Tool | Description |
|---|---|
| `get_mcp_server_metrics` | Uptime, total calls, per-tool p50/p95/p99 latency, error rates, circuit breaker states, Prometheus-format text |
| `get_tool_usage_stats` | Sortable usage table (by calls/errors/latency/error_rate); shows never-called tools |
| `get_slow_queries` | Tools exceeding a configurable p95 latency threshold with remediation suggestions |

### Credential Management (2 tools)

| Tool | Description |
|---|---|
| `get_credential_age` | Report credential age and rotation recommendation |
| `rotate_wazuh_password` | Rotate the Wazuh Manager API user password *(admin + writes)* |

---

## MCP Prompts

Available as `/` commands in Claude Code and prompt-aware clients.

| Prompt | What it does |
|---|---|
**Investigation workflows:**

| Prompt | What it does |
|---|---|
| `investigate_brute_force` | 5-step guided brute force investigation |
| `weekly_soc_briefing` | Executive briefing — trends, CVEs, patches, SCA, MITRE |
| `triage_alert` | True/false positive triage for any alert ID |
| `cve_emergency_response` | CVE impact assessment — scope, evidence, patch priority |
| `threat_hunt_session` | Guided lateral movement and persistence hunt |
| `morning_briefing` | Start-of-shift risk summary and recommended actions |
| `incident_triage_full` | Full 48h IR chain for agent or source IP |
| `end_of_shift_handover` | Structured handover with open incidents and watch list |

**Role-optimized prompts** *(tailored output per audience)*:

| Prompt | Audience | What it does |
|---|---|---|
| `tier1_analyst_guide` | Tier 1 / junior | Step-by-step walkthrough with explanations — builds analyst skill |
| `tier2_analyst_deep_dive` | Tier 2 / IR | Evidence collection, lateral movement, MITRE mapping, containment |
| `ciso_security_briefing` | CISO / leadership | Business-risk framing, no jargon, action items with owners |
| `compliance_officer_review` | Compliance / audit | Framework control mapping, evidence export, audit trail |

---

## Architecture

```
┌─────────────────────────────┐        ┌──────────────────────────────────────┐
│      Claude Desktop         │        │       Wazuh Server / Docker Host     │
│                             │        │                                      │
│  ┌───────────────────────┐  │  HTTP  │  ┌────────────────────────────────┐  │
│  │    Claude Desktop     │◄─┼────────┼─►│   wazuh-mcp container          │  │
│  │  (mcp-remote bridge)  │  │  /sse  │  │   port 8000, HTTP/SSE          │  │
│  └───────────────────────┘  │        │  └────────────┬───────────────────┘  │
└─────────────────────────────┘        │               │                      │
                                       │     ┌─────────┴──────────┐          │
                                       │     │                    │          │
                                       │  :55000             :9200           │
                                       │  Wazuh Manager    Wazuh Indexer     │
                                       │  REST API         (OpenSearch)      │
                                       └────────────────────────────────────┘
```

### Project Layout

```
wazuh-mcp-latest/
├── .github/
│   └── workflows/
│       └── ci.yml               # lint → security → test (py3.10/3.11/3.12) → docker build
├── wazuh_mcp/
│   ├── __main__.py          # entry point — transport selection
│   ├── server.py            # FastMCP app, shared helpers, MCP prompts
│   ├── config.py            # Config dataclass, env loading
│   ├── helpers.py           # trim_alert, time_window utilities
│   ├── rbac.py              # role tiers: viewer/analyst/responder/admin
│   ├── audit.py             # JSONL audit trail + response sanitization
│   ├── rate_limit.py        # sliding-window rate limiter middleware
│   ├── secrets_backend.py   # Vault / AWS Secrets Manager adapters
│   ├── tls_config.py        # TLS/mTLS configuration
│   ├── circuit_breaker.py   # threat intel circuit breaker
│   ├── validators.py        # input validation (CVE IDs, IPs, free text)
│   ├── wazuh_client.py      # Wazuh Manager REST API client
│   ├── wazuh_indexer.py     # OpenSearch client
│   └── tools/               # 30+ domain modules
│       ├── agents.py        ├── alerts.py          ├── vulnerabilities.py
│       ├── active_response.py ├── fim.py           ├── compliance.py
│       ├── fleet.py         ├── sca.py             ├── cdb.py
│       ├── rules.py         ├── threat_intel.py    ├── threat_hunting.py
│       ├── mitre.py         ├── incidents.py       ├── reporting.py
│       ├── integrations.py  ├── notifications.py   ├── onboarding.py
│       ├── cluster.py       ├── archive.py         ├── suppression.py
│       ├── network_topology.py  ├── baseline.py    ├── ueba.py
│       ├── agent_health.py  ├── cve_watchlist.py   ├── rule_wizard.py
│       ├── geo_intel.py     ├── threat_feeds.py    ├── playbooks.py
│       ├── scheduler.py     ├── autonomous_soc.py  ├── workspaces.py
│       ├── credential_mgmt.py  ├── quick_wins.py  ├── export.py
│       └── metrics.py       # NEW — server self-monitoring (uptime, latency, usage)
├── docs/
│   ├── open-webui-integration.md
│   └── testing-guide.md
├── compose.yaml
├── docker-compose.ollama.yaml
├── Dockerfile
├── env.example
├── claude_desktop_config.example.json
├── pyproject.toml
└── requirements.txt
```

---

## Security Hardening

### Dedicated read-only accounts

Create separate Wazuh Manager API and Indexer users with minimum permissions. Never use `admin`. The helper script at `scripts/create_api_user.sh` provisions a least-privilege `wazuh-mcp` API user.

### Write guard

`WAZUH_ALLOW_WRITES=false` (default) disables `restart_agent`, `run_active_response`, `add_to_cdb_list`, `remove_from_cdb_list`, `tag_alert`, `expire_suppression`, `bulk_suppress_rule`, and `push_custom_rule`. Enable only when explicitly delegating remediation.

### RBAC

Set `WAZUH_MCP_USER_ROLE` to the minimum tier needed. Run separate server instances with different roles if you need both a read-only analyst interface and a responder interface.

### API key authentication

Set `WAZUH_MCP_API_KEY` to require a bearer token on all HTTP requests. Share this with `mcp-remote` via `--header "Authorization: Bearer KEY"` or with Open WebUI via the **API Key** field.

### Rate limiting

The sliding-window rate limiter (`WAZUH_MCP_RATE_LIMIT_RPM=60`) prevents runaway tool loops from overwhelming the Wazuh API.

### Audit trail

Every tool call is logged to `WAZUH_AUDIT_LOG` (default `logs/audit.jsonl`) as a JSONL record containing timestamp, tool name, caller identity, scrubbed parameters, result code, and duration. Credential values are never written.

The log is **automatically rotated** at 50 MB (7 backups, ~350 MB total). Override with `WAZUH_AUDIT_MAX_BYTES` and `WAZUH_AUDIT_BACKUP_COUNT`.

### Response sanitization

Tool responses are sanitized before reaching the LLM client — prompt injection tokens (`<system>`, `[INST]`, `###System:`) and plaintext secrets are stripped from all string values in returned data.

### Secrets backends

Store credentials in HashiCorp Vault or AWS Secrets Manager instead of `.env` files by setting `WAZUH_SECRET_BACKEND=vault` or `WAZUH_SECRET_BACKEND=aws`.

### TLS for the MCP endpoint

Set `WAZUH_MCP_TLS_CERT` and `WAZUH_MCP_TLS_KEY` to enable HTTPS on port 8000. Add `WAZUH_MCP_CLIENT_CA` for mutual TLS.

### Network binding

For Docker on a private network, `0.0.0.0` with a firewall rule on port 8000 is acceptable. Never expose port 8000 directly to the internet. Use an nginx/Caddy TLS reverse proxy in production (removes `--allow-http` requirement).

---

## Optional Integrations

All integrations are opt-in. Tools degrade gracefully if credentials are absent.

### Threat Intelligence

- **VirusTotal** — `VIRUSTOTAL_API_KEY` — free tier: 500 lookups/day
- **AbuseIPDB** — `ABUSEIPDB_API_KEY` — free tier: 1000/day
- **ipinfo.io** — `IPINFO_TOKEN` — free tier: 50,000/month (extended GeoIP/ASN)

### Threat Feeds (no API key required)

- **Feodo Tracker** — Botnet C2 IPs (abuse.ch)
- **URLhaus** — Active malicious domains (abuse.ch)
- **Tor Project** — Bulk exit node list

### Ticketing

- **Jira** — `JIRA_URL`, `JIRA_USER`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`
- **TheHive** — `THEHIVE_URL`, `THEHIVE_API_KEY`

### Notifications

- **Slack webhook** — `SLACK_WEBHOOK_URL` (simpler, single channel)
- **Slack bot token** — `SLACK_BOT_TOKEN` + `SLACK_DEFAULT_CHANNEL` (multi-channel)
- **Microsoft Teams** — `TEAMS_WEBHOOK_URL` — Teams channel → **…** → Connectors → Incoming Webhook → Create → copy URL
- **Email (SMTP)** — `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `REPORT_EMAIL_FROM`, `REPORT_EMAIL_TO`

---

## Development & CI

### Running tests locally

```bash
pip install -e ".[dev]"
pytest -q                          # run all tests
pytest --cov --cov-report=html     # with HTML coverage report in htmlcov/
```

### Lint & security scan

```bash
pip install ruff mypy bandit pip-audit
ruff check wazuh_mcp               # linting
mypy wazuh_mcp --ignore-missing-imports  # type checking
bandit -r wazuh_mcp -c pyproject.toml    # SAST scan
pip-audit --requirement requirements.txt # dependency CVE check
```

### CI pipeline

Every push and pull request runs four GitHub Actions jobs automatically:

| Job | What it checks |
|---|---|
| **lint** | `ruff check` + `mypy` on Python 3.11 |
| **security** | `bandit` SAST + `pip-audit` dependency CVE scan |
| **test** | `pytest --cov-fail-under=70` across Python 3.10, 3.11, 3.12 |
| **docker** | Full `docker build` with layer cache |

---

## Common Issues

### `HTTP 421 Invalid Host header` from mcp-remote

DNS-rebinding protection is **enabled** (`TransportSecuritySettings(enable_dns_rebinding_protection=True)` in `server.py`) and only accepts `Host` headers matching the bind host plus localhost. If you reach the server via a hostname, reverse proxy, or non-loopback IP, add that value to `WAZUH_MCP_ALLOWED_HOSTS` (comma-separated), e.g. `WAZUH_MCP_ALLOWED_HOSTS=wazuh-mcp.internal,wazuh-mcp.internal:8000`. Then restart the server.

### `ECONNREFUSED` on port 8000

```bash
docker compose ps           # check container is Up
docker compose logs wazuh-mcp | tail -30
```

The default bind is `127.0.0.1` (localhost only). To accept connections from
other hosts, set `WAZUH_MCP_HOST=0.0.0.0` **and** `WAZUH_MCP_API_KEY` in `.env`
(the server always refuses a non-loopback bind without an API key — there is no
insecure override).

### Empty results from alert/vulnerability tools

```bash
curl -sk -u USER:PASS https://INDEXER:9200/_cat/indices?h=index | grep wazuh
```

Update `WAZUH_ALERTS_INDEX` and `WAZUH_VULN_INDEX` in `.env` to match your actual index names.

### `401 Unauthorized` from Wazuh Manager API

```bash
curl -k -X POST -u "wazuh-mcp:password" https://MANAGER:55000/security/user/authenticate
```

If this returns a token, credentials are correct but RBAC permissions are missing. Add read permissions for agents, rules, sca, syscollector, syscheck.

### Fleet inventory tools return errors (Wazuh < 4.10)

The `fleet_find_*` tools require the `wazuh-states-inventory-*` indices added in Wazuh 4.10. Per-agent tools (`get_agent_packages`, `get_agent_processes`, `get_agent_open_ports`) work on all supported versions via the Manager API.

### Archive tools return no results

Archive logging must be enabled in `ossec.conf`:

```xml
<ossec_config>
  <global>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>
</ossec_config>
```

Restart the Wazuh manager after changing this setting.

### Claude Desktop shows no tools

1. Fully quit Claude Desktop (not just close the window).
2. Verify `mcp-remote` connects: `mcp-remote http://SERVER:8000/sse --allow-http` (should hang silently).
3. Check the config file uses `command`/`args` format, not the `url` shorthand.
4. Relaunch Claude Desktop and look for the tools icon in the chat input bar.

### Tool call rejected: "Insufficient role"

Increase `WAZUH_MCP_USER_ROLE` to the required tier (see [Role-Based Access Control](#role-based-access-control)). Write tools also require `WAZUH_ALLOW_WRITES=true`.

---

## Sources

- [Wazuh REST API Documentation](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh Indexer Documentation](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/docs)
- [FastMCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [mcp-remote](https://github.com/geelen/mcp-remote)
- [Open WebUI MCP Integration](https://docs.openwebui.com)
