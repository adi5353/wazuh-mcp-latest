# Wazuh MCP — AI-Powered Security Operations

> **Connect Wazuh to Claude AI via the Model Context Protocol (MCP), enabling natural-language security operations directly inside Claude Desktop.**

**87 tools** across 21 domain modules — alerts, vulnerabilities, FIM, compliance, MITRE ATT&CK, threat hunting, active response, fleet inventory, SCA, CDB lists, rules, threat intel, incidents, reporting, notifications, onboarding, cluster health, archive search, and alert suppression.

---

## Table of Contents

- [Quick Start — Docker](#quick-start--docker)
- [Quick Start — Local (systemd)](#quick-start--local-systemd)
- [Connect Claude Desktop](#connect-claude-desktop)
- [Environment Variables](#environment-variables)
- [Tool Reference](#tool-reference)
- [MCP Prompts](#mcp-prompts)
- [Architecture](#architecture)
- [Optional Integrations](#optional-integrations)
- [Security Considerations](#security-considerations)
- [Common Issues](#common-issues)

---

## Quick Start — Docker

This is the recommended deployment method. The container bundles all dependencies and exposes the MCP server on port 8000.

### 1. Clone the repository

```bash
git clone https://github.com/adi5353/wazuh-mcp.git
cd wazuh-mcp
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

WAZUH_VERIFY_SSL=false
WAZUH_MCP_TRANSPORT=http
WAZUH_MCP_HOST=0.0.0.0
WAZUH_MCP_PORT=8000
```

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

View logs:

```bash
docker compose logs -f wazuh-mcp
```

Stop and restart:

```bash
docker compose down
docker compose up -d
```

---

## Quick Start — Local (systemd)

Use this if you want to run directly on the Wazuh server without Docker.

### 1. Clone and install

```bash
git clone https://github.com/adi5353/wazuh-mcp.git
cd wazuh-mcp
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
User=vagrant
WorkingDirectory=/home/vagrant/wazuh-mcp
EnvironmentFile=/home/vagrant/wazuh-mcp/.env
ExecStart=/home/vagrant/wazuh-mcp/.venv/bin/python -m wazuh_mcp
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
ss -tlnp | grep 8000   # must show 0.0.0.0:8000
curl -si http://localhost:8000/sse | head -3
```

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

If Claude Desktop and the MCP server run on the same machine, use stdio transport:

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

---

## Environment Variables

### Required

| Variable | Description |
|---|---|
| `WAZUH_HOST` | Wazuh Manager API URL, e.g. `https://192.168.1.10:55000` |
| `WAZUH_USER` | Wazuh Manager API username |
| `WAZUH_PASS` | Wazuh Manager API password |
| `WAZUH_INDEXER_HOST` | Wazuh Indexer (OpenSearch) URL, e.g. `https://192.168.1.10:9200` |
| `WAZUH_INDEXER_USER` | Indexer username |
| `WAZUH_INDEXER_PASS` | Indexer password |

### Transport

| Variable | Default | Description |
|---|---|---|
| `WAZUH_MCP_TRANSPORT` | `http` | `http` for Docker/remote, `stdio` for local Claude Desktop |
| `WAZUH_MCP_HOST` | `0.0.0.0` | Bind address for HTTP mode |
| `WAZUH_MCP_PORT` | `8000` | Port for HTTP mode |

### Security

| Variable | Default | Description |
|---|---|---|
| `WAZUH_VERIFY_SSL` | `false` | Set `true` in production with valid CA chain |
| `WAZUH_ALLOW_WRITES` | `false` | Enable write tools (restart agents, active response, CDB edits) |
| `WAZUH_REQUEST_TIMEOUT` | `30` | API request timeout in seconds |

### Index Patterns

| Variable | Default | Description |
|---|---|---|
| `WAZUH_ALERTS_INDEX` | `wazuh-alerts-4.x-*` | Alert index pattern |
| `WAZUH_VULN_INDEX` | `wazuh-states-vulnerabilities-4.x-*` | Vulnerability state index |
| `WAZUH_ARCHIVES_INDEX` | `wazuh-archives-*` | Archive index (all ingested logs) |

### Optional Integrations

| Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal enrichment (500 lookups/day free) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB enrichment (1000/day free) |
| `JIRA_URL` | Jira base URL for ticket creation |
| `JIRA_USER` | Jira username (email) |
| `JIRA_TOKEN` | Jira API token |
| `JIRA_PROJECT_KEY` | Jira project key, e.g. `SOC` |
| `THEHIVE_URL` | TheHive base URL |
| `THEHIVE_API_KEY` | TheHive API key |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for notifications |
| `SLACK_BOT_TOKEN` | Slack bot token (alternative to webhook) |
| `SLACK_DEFAULT_CHANNEL` | Default Slack channel, e.g. `#soc-alerts` |
| `SMTP_HOST` | SMTP server for email reports |
| `SMTP_PORT` | SMTP port (default `587`) |
| `SMTP_USER` | SMTP username |
| `SMTP_PASS` | SMTP password |
| `SMTP_FROM` | Sender email address |

---

## Tool Reference

### Agents (6 tools)

| Tool | Description |
|---|---|
| `list_agents` | List agents by status (active, disconnected, pending) |
| `get_agent` | Detailed info for one agent by ID |
| `restart_agent` | Restart an agent *(requires `WAZUH_ALLOW_WRITES=true`)* |
| `list_groups` | All groups with member counts |
| `get_group_agents` | Agents belonging to a group |
| `add_agent_to_group` | Assign an agent to a group *(write)* |

### Alerts (9 tools)

| Tool | Description |
|---|---|
| `alert_summary` | Aggregated overview — top rules, agents, MITRE, groups |
| `search_alerts` | Filtered alert search with trimmed payloads |
| `search_by_mitre` | Alerts mapped to a specific ATT&CK technique |
| `search_by_source_ip` | All alerts from a given IP — IoC pivoting |
| `search_authentication_failures` | Brute-force candidate sources |
| `alert_timeline` | Date histogram — spot spikes and quiet periods |
| `get_alert_by_id` | Full alert detail by document ID |
| `compare_alert_volume` | This period vs last period — volume deltas |
| `detect_rule_anomalies` | NEW, SPIKE, DROP, GONE rules vs baseline |

### Vulnerabilities (4 tools)

| Tool | Description |
|---|---|
| `vulnerability_summary` | Fleet-wide unpatched CVE overview |
| `get_agent_vulnerabilities_detailed` | Per-agent CVE list, worst CVSS first |
| `search_cve` | Every agent affected by a specific CVE |
| `prioritize_patches` | Patch queue ranked by agents × CVSS |

### Active Response (3 tools)

| Tool | Description |
|---|---|
| `get_active_responses` | Recent AR actions with triggering alert context |
| `correlate_alert_with_response` | Did Wazuh act on this attack? |
| `active_response_effectiveness` | Did automated blocks stop traffic? |
| `run_active_response` | Trigger an AR command on an agent *(write)* |

### File Integrity Monitoring (4 tools)

| Tool | Description |
|---|---|
| `get_recent_fim_changes` | Recent FIM events for an agent (Manager API) |
| `search_fim_alerts` | Indexer-side FIM alerts with optional path filter |
| `fim_summary` | Aggregated FIM activity by agent, event type, path |
| `critical_file_changes` | FIM events on sensitive paths only |

### Compliance (4 tools)

| Tool | Description |
|---|---|
| `compliance_summary` | Alerts by control for PCI-DSS, HIPAA, GDPR, NIST 800-53, TSC |
| `compliance_control_details` | Drill into alerts for one specific control |
| `generate_compliance_report` | Full compliance report for a framework |
| `email_compliance_report` | Email the compliance report *(requires SMTP config)* |

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
| `add_to_cdb_list` | Add an IP, domain, or hash *(write)* |
| `remove_from_cdb_list` | Remove an entry *(write)* |
| `bulk_suppress_rule` | Tag multiple alerts for a rule as false_positive *(write)* |

### Rules & Decoders (6 tools)

| Tool | Description |
|---|---|
| `search_rules` | Search rules by description, group, level, or MITRE |
| `list_rule_files` | All rule files — built-in and custom |
| `get_custom_rules` | Rules from custom files only |
| `list_decoders` | All loaded decoders |
| `get_rule_details` | Full metadata for a rule ID |
| `test_log_against_rules` | Test a raw log line against the rule engine |
| `test_rule_coverage` | Test up to 20 log samples, report detection % |

### Threat Intelligence (3 tools)

| Tool | Description |
|---|---|
| `enrich_ip` | VirusTotal + AbuseIPDB verdict for an IP |
| `enrich_file_hash` | VirusTotal lookup for MD5/SHA1/SHA256 |
| `enrich_ip_geo` | GeoIP lookup (ASN, country, city) |

### Threat Hunting (4 tools)

| Tool | Description |
|---|---|
| `hunt_lateral_movement` | Detect internal pivoting between agents |
| `hunt_persistence_mechanisms` | Detect persistence (cron, registry, startup) |
| `hunt_data_exfiltration` | Detect large outbound transfers and DNS exfil |
| `get_agent_login_history` | Login audit log for a specific agent |

### MITRE ATT&CK (2 tools)

| Tool | Description |
|---|---|
| `mitre_coverage_analysis` | Technique coverage across the ruleset |
| `get_mitre_gaps` | Techniques firing with only 1 rule (gap detection) |
| `search_by_mitre` | Live alerts for a specific technique *(in Alerts)* |

### Incidents (5 tools)

| Tool | Description |
|---|---|
| `incident_timeline` | Chronological kill-chain reconstruction |
| `blast_radius_analysis` | Everything a compromised IP/agent touched |
| `create_incident_report` | Generate a structured incident report |
| `tag_alert` | Tag an alert with analyst verdict and notes *(write)* |
| `get_alert_by_id` | Full alert detail *(in Alerts)* |

### Reporting (3 tools)

| Tool | Description |
|---|---|
| `generate_shift_handover` | Structured SOC shift handover report |
| `generate_weekly_summary` | Weekly executive summary |
| `create_incident_report` | Incident report with MITRE mapping |

### Integrations (3 tools)

| Tool | Description |
|---|---|
| `create_jira_ticket` | Create a Jira issue from an alert |
| `create_thehive_case` | Create a TheHive case |
| `update_ticket_status` | Update Jira ticket status |

### Notifications (3 tools)

| Tool | Description |
|---|---|
| `send_alert_to_slack` | Send a formatted alert to Slack |
| `send_shift_handover_to_slack` | Post shift handover report to Slack |
| `send_weekly_summary_to_slack` | Post weekly summary to Slack |
| `send_critical_alert_notify` | Immediate critical alert notification |

### Agent Onboarding (3 tools)

| Tool | Description |
|---|---|
| `generate_enrollment_command` | Generate install command for Ubuntu/Debian/CentOS/RHEL/Windows/macOS |
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

### Alert Suppression (3 tools)

| Tool | Description |
|---|---|
| `list_suppressed_rules` | Rules tagged as false_positive with FP rate and tuning advice |
| `expire_suppression` | Remove false_positive tags older than N hours |
| `noise_score_rule` | 0-100 noise score with CRITICAL/HIGH/MEDIUM/LOW tier |

---

## MCP Prompts

Available as `/` commands in Claude Code and prompt-aware clients.

| Prompt | What it does |
|---|---|
| `investigate_brute_force` | 5-step guided brute force investigation |
| `weekly_soc_briefing` | Executive briefing — trends, CVEs, patches, SCA, MITRE |
| `triage_alert` | True/false positive triage for any alert ID |
| `cve_emergency_response` | CVE impact assessment — scope, evidence, patch priority |
| `threat_hunt_session` | Guided lateral movement and persistence hunt |
| `compliance_audit` | Full compliance posture for a framework |
| `incident_response` | Structured IR workflow for a compromised host |
| `shift_handover` | End-of-shift summary and hand-off |

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
wazuh-mcp/
├── wazuh_mcp/
│   ├── __main__.py          # entry point — transport selection
│   ├── server.py            # FastMCP app, shared helpers, MCP prompts
│   ├── config.py            # Config dataclass, env loading
│   ├── helpers.py           # trim_alert, time_window utilities
│   └── tools/               # 21 domain modules
│       ├── agents.py        # agent + group management
│       ├── alerts.py        # alert search + anomaly detection
│       ├── vulnerabilities.py
│       ├── active_response.py
│       ├── fim.py
│       ├── compliance.py
│       ├── fleet.py         # per-agent + fleet-wide inventory
│       ├── sca.py
│       ├── cdb.py
│       ├── rules.py
│       ├── threat_intel.py
│       ├── threat_hunting.py
│       ├── mitre.py
│       ├── incidents.py
│       ├── reporting.py
│       ├── integrations.py  # Jira, TheHive
│       ├── notifications.py # Slack, email
│       ├── onboarding.py
│       ├── cluster.py
│       ├── archive.py
│       └── suppression.py
├── compose.yaml
├── Dockerfile
├── env.example
├── pyproject.toml
└── requirements.txt
```

---

## Optional Integrations

All integrations are opt-in. Tools degrade gracefully if credentials are absent.

### Threat Intelligence

- **VirusTotal** — `VIRUSTOTAL_API_KEY` — free tier: 500 lookups/day at virustotal.com
- **AbuseIPDB** — `ABUSEIPDB_API_KEY` — free tier: 1000/day at abuseipdb.com

### Ticketing

- **Jira** — `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN`, `JIRA_PROJECT_KEY`
- **TheHive** — `THEHIVE_URL`, `THEHIVE_API_KEY`

### Notifications

- **Slack webhook** — `SLACK_WEBHOOK_URL` (simpler, single channel)
- **Slack bot token** — `SLACK_BOT_TOKEN` + `SLACK_DEFAULT_CHANNEL` (multi-channel)
- **Email (SMTP)** — `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`

---

## Security Considerations

**Dedicated read-only accounts.** Create separate Wazuh Manager API and Indexer users with minimum permissions. Never use `admin`.

**Write guard.** `WAZUH_ALLOW_WRITES=false` (default) disables `restart_agent`, `run_active_response`, `add_to_cdb_list`, `remove_from_cdb_list`, `tag_alert`, `expire_suppression`, and `bulk_suppress_rule`. Enable only when explicitly delegating remediation.

**Bind to trusted interfaces.** For Docker on a private network, `0.0.0.0` with a firewall rule on port 8000 is acceptable. Never expose port 8000 to the internet.

**TLS for production.** `WAZUH_VERIFY_SSL=false` is lab-only. In production: valid CA chain, `WAZUH_VERIFY_SSL=true`, and an nginx/Caddy TLS reverse proxy in front of port 8000 (removes `--allow-http` requirement).

**API keys stay in `.env`.** The `.env` file is in `.gitignore`. Never commit `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, Jira/TheHive tokens, or SMTP credentials.

---

## Common Issues

### `HTTP 421 Invalid Host header` from mcp-remote

The MCP SDK's DNS-rebinding protection blocks non-localhost `Host` headers. This is already disabled in `server.py` via `TransportSecuritySettings(enable_dns_rebinding_protection=False)`. If you see this, ensure you are running the latest code.

### `ECONNREFUSED` on port 8000

```bash
docker compose ps           # check container is Up
docker compose logs wazuh-mcp | tail -30
```

Ensure `WAZUH_MCP_HOST=0.0.0.0` is set in `.env`, not `127.0.0.1`.

### Empty results from alert/vulnerability tools

```bash
curl -sk -u USER:PASS https://INDEXER:9200/_cat/indices?h=index | grep wazuh
```

Update `WAZUH_ALERTS_INDEX` and `WAZUH_VULN_INDEX` in `.env` to match your actual index names.

### `401 Unauthorized` from Wazuh Manager API

```bash
curl -k -X POST -u "wazuh-mcp:password" https://MANAGER:55000/security/user/authenticate
```

If this returns a token, credentials are correct but RBAC is missing. Add read permissions for agents, rules, sca, syscollector, syscheck.

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

Restart Wazuh manager after changing this.

### Claude Desktop shows no tools

1. Fully quit Claude Desktop (not just close the window).
2. Verify `mcp-remote` connects: `mcp-remote http://SERVER:8000/sse --allow-http` (should hang silently).
3. Check the config file uses `command`/`args` format, not the `url` shorthand.
4. Relaunch Claude Desktop and look for the tools icon in the chat input bar.

---

## Sources

- [Wazuh REST API Documentation](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh Indexer Documentation](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/docs)
- [FastMCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [mcp-remote](https://github.com/geelen/mcp-remote)
