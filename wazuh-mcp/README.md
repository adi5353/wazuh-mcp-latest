# Claude AI (MCP) — Wazuh Integration

> **Connect Wazuh to Claude AI via the Model Context Protocol (MCP), enabling natural-language security operations directly inside Claude Desktop.**

---

## Table of Contents

- [Introduction](#introduction)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation and Configuration](#installation-and-configuration)
  - [Step 1 — Clone the Repository](#step-1--clone-the-repository)
  - [Step 2 — Create a Python Virtual Environment](#step-2--create-a-python-virtual-environment)
  - [Step 3 — Install Dependencies](#step-3--install-dependencies)
  - [Step 4 — Create Wazuh API Accounts](#step-4--create-wazuh-api-accounts)
  - [Step 5 — Configure the Environment File](#step-5--configure-the-environment-file)
  - [Step 6 — Run the Server as a Systemd Service](#step-6--run-the-server-as-a-systemd-service)
  - [Step 7 — Connect Claude Desktop](#step-7--connect-claude-desktop)
- [Available Tools](#available-tools)
- [Integration Testing](#integration-testing)
- [Common Mistakes and Fixes](#common-mistakes-and-fixes)
- [Security Considerations](#security-considerations)
- [Sources](#sources)

---

## Introduction

This integration exposes the Wazuh security platform to Claude AI through the **Model Context Protocol (MCP)** — an open standard that allows AI assistants to call external tools and data sources. Once connected, Claude Desktop can query your Wazuh deployment using plain English.

Instead of navigating dashboards or writing manual API calls, you can ask questions like:

- *"Give me an alert summary for the last 24 hours."*
- *"Which agents are affected by CVE-2024-3094?"*
- *"What should I patch first this week?"*
- *"Are we being brute-forced right now?"*
- *"How effective have our automated blocks been this week?"*

The integration connects Claude to both the **Wazuh Manager REST API** (port 55000) and the **Wazuh Indexer / OpenSearch** (port 9200), giving it access to live agent state, alerts, vulnerability data, FIM events, compliance findings, and active response history.

**61 tools** are registered across 9 functional areas covering the full daily workflow of a SOC team.

---

## Architecture

```
┌─────────────────────────────┐        ┌──────────────────────────────────────┐
│      Windows Workstation    │        │           Wazuh Server (Linux)       │
│                             │        │                                      │
│  ┌───────────────────────┐  │  HTTP  │  ┌────────────────────────────────┐  │
│  │    Claude Desktop     │◄─┼────────┼─►│    wazuh-mcp (Python, SSE)    │  │
│  │                       │  │  /sse  │  │    systemd service, port 8000  │  │
│  │  mcp-remote (Node.js) │  │        │  └────────────┬───────────────────┘  │
│  └───────────────────────┘  │        │               │                      │
└─────────────────────────────┘        │     ┌─────────┴──────────┐          │
                                       │     │                    │          │
                                       │  :55000             :9200           │
                                       │  Wazuh Manager    Wazuh Indexer     │
                                       │  REST API         (OpenSearch)      │
                                       └────────────────────────────────────┘
```

Claude Desktop launches `mcp-remote` locally on Windows. `mcp-remote` connects over HTTP to the MCP server running as a persistent `systemd` service on the Wazuh host. The MCP server bridges Claude's requests to both the Wazuh Manager API and the Wazuh Indexer.

---

## Prerequisites

| Component | Requirement |
|---|---|
| Wazuh | 4.8 or later (4.10+ required for fleet inventory tools) |
| Python | 3.10 or later on the Wazuh server |
| Node.js | 18 or later on the machine running Claude Desktop |
| Claude Desktop | Latest version (Windows, macOS, or Linux) |
| Network | Claude Desktop machine must reach the Wazuh server on port 8000 |
| Wazuh API user | Read-only user on the Manager API (port 55000) |
| Indexer user | Read-only user on the Wazuh Indexer (port 9200) |

---

## Installation and Configuration

### Step 1 — Clone the Repository

On the **Wazuh server**:

```bash
cd /home/vagrant   # or any directory you prefer
git clone https://github.com/your-org/wazuh-mcp.git
cd wazuh-mcp
```

If you are not using git, extract the downloaded tarball:

```bash
tar -xzf wazuh-mcp.tar.gz
cd wazuh-mcp
```

### Step 2 — Create a Python Virtual Environment

Always install into a virtual environment — never into the system Python on a Wazuh server.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Verify the venv is active:

```bash
which python   # should show /path/to/wazuh-mcp/.venv/bin/python
```

### Step 3 — Install Dependencies

```bash
pip install -e .
```

This installs `mcp`, `httpx`, and `python-dotenv` as declared in `pyproject.toml`. Verify:

```bash
pip list | grep -E "mcp|httpx|dotenv"
```

Expected output:

```
httpx          0.28.x
mcp            1.x.x
python-dotenv  1.x.x
```

### Step 4 — Create Wazuh API Accounts

Two dedicated accounts are required. Never use the `admin` account.

#### Wazuh Manager API user

1. Log into the Wazuh Dashboard.
2. Navigate to **Server Management → API → Users**.
3. Create a user (e.g., `wazuh-mcp`) with a strong password.
4. Assign a role with read permissions on agents, rules, SCA, and syscollector.
5. If you want to enable write operations (restart agents, trigger active response), also grant `active-response` write permissions — but keep `WAZUH_ALLOW_WRITES=false` by default.

#### Wazuh Indexer (OpenSearch) user

1. In the Wazuh Dashboard, navigate to **Security → Internal users → Create internal user**.
2. Create a user (e.g., `wazuh-readonly`) with a strong password.
3. Create a role with these minimum permissions:

```
Cluster permissions : cluster:monitor/*
Index permissions   : indices:data/read/* on wazuh-alerts-* and wazuh-states-*
```

4. Map the user to the role.

### Step 5 — Configure the Environment File

```bash
cp .env.example .env
nano .env
```

Minimum required values:

```dotenv
# ── Wazuh Manager API ─────────────────────────────────────────────────────────
WAZUH_HOST=https://Wazuh_Manager_IP/DNS:55000
WAZUH_USER=wazuh-mcp
WAZUH_PASS=YourStrongPassword

# ── Wazuh Indexer (OpenSearch) ────────────────────────────────────────────────
WAZUH_INDEXER_HOST=https://Wazuh_Indexer_IP/DNS:9200
WAZUH_INDEXER_USER=wazuh-readonly
WAZUH_INDEXER_PASS=YourStrongPassword

# ── MCP Server Transport ──────────────────────────────────────────────────────
WAZUH_MCP_TRANSPORT=http
WAZUH_MCP_HOST=0.0.0.0
WAZUH_MCP_PORT=8000

# ── Optional ──────────────────────────────────────────────────────────────────
WAZUH_VERIFY_SSL=false         # set true in production with a valid CA chain
WAZUH_ALLOW_WRITES=false       # set true only to enable restart/AR tools
WAZUH_REQUEST_TIMEOUT=30

# ── Archives (search_archive_logs tool) ───────────────────────────────────────
WAZUH_ARCHIVES_INDEX=wazuh-archives-*

# ── Threat Intelligence enrichment (enrich_ip, enrich_file_hash tools) ────────
# Free at virustotal.com (500 lookups/day) and abuseipdb.com (1000/day)
# Both are optional — tools return a clear message if keys are absent
VIRUSTOTAL_API_KEY=<YOUR_VIRUSTOTAL_KEY>
ABUSEIPDB_API_KEY=<YOUR_ABUSEIPDB_KEY>
```

Verify the config loads cleanly:

```bash
source .venv/bin/activate
source .env
python -c "from wazuh_mcp.config import Config; print(Config.from_env())"
```

You should see a `Config(...)` object with all your values. If you see `Missing required env var: WAZUH_HOST`, the `.env` file was not sourced — re-run `source .env` first.

### Step 6 — Run the Server as a Systemd Service

Running the server as a `systemd` service ensures it starts on boot, auto-restarts on crash, and is always available for Claude Desktop to connect to.

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
sudo systemctl enable wazuh-mcp
sudo systemctl start wazuh-mcp
sudo systemctl status wazuh-mcp
```

Expected status output:

```
● wazuh-mcp.service - Wazuh MCP Server
   Active: active (running) since ...
```

Verify the server is listening on the correct interface:

```bash
ss -tlnp | grep 8000
# Expected: LISTEN 0.0.0.0:8000
```

Check live logs at any time:

```bash
sudo journalctl -u wazuh-mcp -f
```

### Step 7 — Connect Claude Desktop

#### Install mcp-remote on the machine running Claude Desktop

`mcp-remote` is a small Node.js bridge that runs locally and proxies Claude Desktop's STDIO connection to the remote HTTP/SSE server.

```bash
npm install -g mcp-remote
```

Test the connection before configuring Claude Desktop:

```bash
mcp-remote http://WAZUH_SERVER_IP:8000/sse --allow-http
```

The command should hang silently — this means it connected successfully. Press `Ctrl+C` to stop.

#### Edit `claude_desktop_config.json`

| OS | Config file location |
|---|---|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Add the `mcpServers` block. If the file already has content (preferences, etc.), add `mcpServers` as a sibling key — do not replace existing content.

```json
 {
  "mcpServers": {
    "wazuh": {
      "command": "mcp-remote",
      "args": [
        "http://WAZUH_Server_IP:8000/sse",
        "--allow-http"
      ]
    }
  }
```

Fully quit Claude Desktop (tray icon → **Quit**, not just close the window), then relaunch. Open a new chat — you should see a tools icon at the bottom of the input box. Clicking it shows `wazuh` with all 61 tools listed.

---

## Available Tools

### Agent Operations (Manager API)

| Tool | Description |
|---|---|
| `list_agents` | List agents by status (active, disconnected, pending) |
| `get_agent` | Detailed info for one agent by ID |
| `get_rule_details` | Full metadata for a rule ID — description, level, MITRE, compliance mappings |
| `restart_agent` | Restart an agent *(write — requires `WAZUH_ALLOW_WRITES=true`)* |
| `run_active_response` | Trigger an AR command on an agent *(write)* |

### Group Management

| Tool | Description |
|---|---|
| `list_groups` | All groups with member counts |
| `get_group_agents` | Agents belonging to a group |
| `add_agent_to_group` | Assign agent to a group *(write)* |

### Alert Intelligence (Indexer)

| Tool | Description |
|---|---|
| `alert_summary` | Aggregated overview — use this first for broad questions |
| `search_alerts` | Filtered alert search with trimmed payloads |
| `search_by_mitre` | Alerts mapped to a specific ATT&CK technique |
| `search_by_source_ip` | All alerts from a given IP — IoC pivoting |
| `search_authentication_failures` | Brute-force candidate sources |
| `alert_timeline` | Date histogram — spot spikes and quiet periods |
| `get_alert_by_id` | Full alert detail by document ID |

### File Integrity Monitoring

| Tool | Description |
|---|---|
| `get_recent_fim_changes` | Recent FIM events on a single agent (Manager API) |
| `search_fim_alerts` | Indexer-side FIM alerts with optional path filter |
| `fim_summary` | Aggregated FIM activity by agent, event type, and path |
| `critical_file_changes` | FIM events on sensitive paths only (passwd, sudoers, ssh keys, system binaries) |

### Compliance

| Tool | Description |
|---|---|
| `compliance_summary` | Alerts by control for PCI-DSS, HIPAA, GDPR, NIST 800-53, TSC |
| `compliance_control_details` | Drill into alerts for one specific control |

### Vulnerability Detection

| Tool | Description |
|---|---|
| `vulnerability_summary` | Fleet-wide unpatched CVE overview |
| `get_agent_vulnerabilities_detailed` | Per-agent CVE list, worst CVSS first |
| `search_cve` | Every agent affected by a specific CVE |
| `prioritize_patches` | Patch queue ranked by `agents × CVSS` |

### Active Response Correlation

| Tool | Description |
|---|---|
| `get_active_responses` | Recent AR actions with triggering alert context |
| `correlate_alert_with_response` | Did Wazuh act on this attack? |
| `active_response_effectiveness` | Audit: did blocks actually stop traffic? |

### Anomaly Comparison

| Tool | Description |
|---|---|
| `compare_alert_volume` | This period vs last period — total and per-level deltas |
| `detect_rule_anomalies` | NEW, SPIKE, DROP, GONE rules vs baseline |

### Inventory — Per-Agent (Manager API, all 4.x)

| Tool | Description |
|---|---|
| `get_agent_packages` | Installed packages with substring search |
| `get_agent_processes` | Currently-tracked processes |
| `get_agent_open_ports` | Listening ports and bound processes |
| `get_agent_hardware_os` | Hardware + OS info in one call |

### Inventory — Fleet-Wide (Indexer, requires Wazuh 4.10+)

| Tool | Description |
|---|---|
| `fleet_find_package` | Every agent with a given package — the CVE-response query |
| `fleet_find_process` | Every agent running a given process |
| `fleet_find_listening_port` | Every agent with a given port open |

### Security Configuration Assessment

| Tool | Description |
|---|---|
| `get_agent_sca_policies` | CIS benchmark policies and scores per agent |
| `get_sca_failed_checks` | Failing checks with rationale and remediation |
| `sca_alerts_summary` | Fleet-wide SCA aggregation from Indexer |
| `fleet_sca_weakest_agents` | Agents ranked by failing check count |

### CDB List Management

| Tool | Description |
|---|---|
| `list_cdb_lists` | All configured CDB lists (IP blocklists, domain lists, hash lists) |
| `get_cdb_list_contents` | Raw key:value contents of a specific list |
| `add_to_cdb_list` | Add an IP, domain, or hash — takes effect immediately *(write)* |
| `remove_from_cdb_list` | Remove an entry (unblock) *(write)* |

### Detection Engineering (Logtest)

| Tool | Description |
|---|---|
| `test_log_against_rules` | Test a raw log line against Wazuh's decoder + rule engine |
| `test_rule_coverage` | Test up to 20 log samples and report detection coverage % |

### MITRE ATT&CK Analysis

| Tool | Description |
|---|---|
| `mitre_coverage_analysis` | Technique coverage across the ruleset — tactic breakdown + weak spots |
| `get_mitre_gaps` | Techniques firing in live alerts but covered by only 1 rule |

### Incident Response

| Tool | Description |
|---|---|
| `incident_timeline` | Chronological event timeline for a given window — kill-chain reconstruction |
| `blast_radius_analysis` | Everything a compromised IP or agent touched — lateral movement detection |

### Threat Intelligence Enrichment

Requires `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY` in `.env`. Tools degrade gracefully if keys are absent.

| Tool | Description |
|---|---|
| `enrich_ip` | VirusTotal + AbuseIPDB verdict for any source IP |
| `enrich_file_hash` | VirusTotal lookup for MD5/SHA1/SHA256 — use after FIM alerts |

### Archive Log Search

| Tool | Description |
|---|---|
| `search_archive_logs` | Search all ingested logs (not just alerts) — forensic reconstruction |

### Cluster Health

| Tool | Description |
|---|---|
| `get_cluster_health` | Wazuh cluster node status + Indexer cluster health |
| `check_event_queue_health` | Detect silent event loss due to queue pressure |

### Rule & Decoder Management

| Tool | Description |
|---|---|
| `search_rules` | Search enabled rules by description, group, level, or MITRE technique |
| `list_rule_files` | All rule files — built-in and custom |
| `get_custom_rules` | Rules from custom files only (local_rules.xml etc.) |
| `list_decoders` | All loaded decoders with source files |

### Shift Handover

| Tool | Description |
|---|---|
| `generate_shift_handover` | Parallel 6-tool pull synthesised into a structured handover report |

### MCP Prompts (one-click workflows)

Available as `/` commands in Claude Code and prompt-aware clients.

| Prompt | What it does |
|---|---|
| `investigate_brute_force` | 5-step guided brute force investigation — auth failures → IP enrichment → blast radius |
| `weekly_soc_briefing` | 7-tool executive briefing — volume trends, CVEs, patches, SCA, MITRE coverage |
| `triage_alert` | Structured true/false positive triage for any alert document ID |
| `cve_emergency_response` | Immediate CVE impact assessment — scope, exploitation evidence, patch priority |

---

## Integration Testing

After completing the setup, run these test prompts in a new Claude Desktop chat to confirm each layer is working. The validated output examples below are from a live deployment.

---

### Test 1 — Alert Summary (Last 24 Hours)

**Prompt:**
```
Give me an alert summary for the last 24 hours.
```

Claude calls `alert_summary` and returns aggregated counts by level, top rules, top agents, MITRE techniques, and rule groups — without fetching a single raw alert document. The Wazuh Indexer view below confirms the same dataset Claude queried: **1,303 alerts** over a 24-hour window with a spike around 12:00.

**Alert timeline — Wazuh Indexer (1,303 hits, last 24 hours):**

<img width="953" height="547" alt="image" src="https://github.com/user-attachments/assets/41729741-7e5c-48bc-97af-46cd06a8b304" />


**Top agents returned by Claude:**

<img width="969" height="481" alt="image" src="https://github.com/user-attachments/assets/ae920e80-3408-4732-80e5-5f9c03810b1e" />


Claude correctly identified **Server1** as the noisiest agent (751 alerts, 57.7%) and **windows-test** as second (551 alerts, 42.3%), matching the Wazuh dashboard exactly. This output came from a single `alert_summary` aggregation call — no raw alerts were fetched, keeping the response compact enough for follow-up questions in the same conversation.

---

### Test 2 — CVE List for a Specific Agent

**Prompt:**
```
Pull the CVE list for windows-test.
```

Claude calls `get_agent_vulnerabilities_detailed` and returns all unpatched CVEs for the agent, sorted worst CVSS first. It then enriches the output by cross-referencing against the CISA Known Exploited Vulnerabilities (KEV) catalog to flag actively exploited findings.

**Claude's output — 26 findings across 6 packages, with CISA KEV triage:**

<img width="959" height="504" alt="image" src="https://github.com/user-attachments/assets/5bf3914a-8677-4e3f-9949-3d9f858d828d" />


Claude surfaced three **CISA KEV** findings that require immediate attention before treating any other CVE:

| CVE | Package | CVSS | Status |
|---|---|---|---|
| CVE-2025-8088 | WinRAR 6.23 | 8.8 | CISA KEV — Zero-day, exploited by RomCom APT |
| CVE-2025-6218 | WinRAR 6.23 | 7.8 | CISA KEV — Directory traversal, exploited by APT-C-08 |
| CVE-2025-15556 | Notepad++ 8.7.8 | 7.5 | CISA KEV — Updater integrity bypass, supply-chain risk |

**Wazuh dashboard cross-check — same 3 CVEs confirmed on windows-test:**

<img width="938" height="369" alt="image" src="https://github.com/user-attachments/assets/25c104e7-89f8-46f6-8b6f-70c59cc61618" />


The Wazuh Vulnerability Dashboard filtered to these three CVEs confirms the findings: **3 High severity** vulnerabilities on `windows-test` (agent 001), affecting `WinRAR 6.23 (64-bit)` and `Notepad++ (64-bit x64)` on Windows 11 Home 10.0.26200.8457. Claude's output matches the dashboard data exactly.

---

### Verify the server from the command line

On the Wazuh host:

```bash
curl -si -H "Accept: text/event-stream" http://127.0.0.1:8000/sse | head -3
# Expected: HTTP/1.1 200 OK
```

From the Claude Desktop machine:

```bash
supergateway --sse http://Wazuh_SERVER_IP:8000/sse
# Expected: hangs silently (connected). Ctrl+C to exit.
```


---

## Common Mistakes and Fixes

### 1. `RuntimeError: Missing required env var: WAZUH_HOST`

**Cause:** Python launched without `.env` values in `os.environ`. Python does not automatically load `.env` files.

**Quick fix:**
```bash
set -a && source .env && set +a
python -c "from wazuh_mcp.config import Config; print(Config.from_env())"
```

**Permanent fix:** Install the full package so `python-dotenv` is available:
```bash
pip install -e .
```

---

### 2. `ModuleNotFoundError: No module named 'mcp'`

**Cause:** The server was launched using the system Python instead of the virtual environment. The `mcp` package is only inside `.venv`.

**Fix:** Always use the full venv path:
```bash
# Wrong
python3 -m wazuh_mcp

# Correct
/home/vagrant/wazuh-mcp/.venv/bin/python -m wazuh_mcp
```

In the `systemd` service file, `ExecStart` must point to the venv Python:
```ini
ExecStart=/home/vagrant/wazuh-mcp/.venv/bin/python -m wazuh_mcp
```

---

### 3. `WARNING: UNPROTECTED PRIVATE KEY FILE!` (Windows SSH)

**Cause:** The Vagrant SSH private key has overly permissive Windows ACLs. OpenSSH refuses to use it and falls back to password auth.

**Fix:** Run in PowerShell (not as Administrator):
```powershell
$keyPath = "C:\HashiCorp\.vagrant\machines\Server1\virtualbox\private_key"
icacls $keyPath /inheritance:r
icacls $keyPath /grant:r "$($env:USERNAME):(R)"
```

---

### 4. Claude Desktop disconnects in ~50ms (SSH STDIO approach)

**Cause:** Python takes 300–500ms to start. Claude Desktop's STDIO handshake timeout is ~100ms. The process exits before Claude Desktop completes the handshake.

**Fix:** Run the server as a persistent HTTP service so no startup delay is incurred per connection.

```dotenv
# .env
WAZUH_MCP_TRANSPORT=http
WAZUH_MCP_HOST=0.0.0.0
WAZUH_MCP_PORT=8000
```

```bash
sudo systemctl enable --now wazuh-mcp
```

Update `claude_desktop_config.json` to use `mcp-remote` over HTTP instead of SSH:
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "mcp-remote",
      "args": ["http://SERVER_IP:8000/sse", "--allow-http"]
    }
  }
}
```

---

### 5. `ECONNREFUSED` on port 8000

**Cause:** The MCP server is not running, bound to `127.0.0.1` instead of `0.0.0.0`, or port 8000 is blocked by a firewall.

**Diagnose:**
```bash
sudo systemctl status wazuh-mcp
ss -tlnp | grep 8000     # must show 0.0.0.0:8000
sudo ufw status
```

**Fix — service not running:**
```bash
sudo systemctl start wazuh-mcp
```

**Fix — bound to 127.0.0.1:**
Confirm `WAZUH_MCP_HOST=0.0.0.0` is in `.env`, then:
```bash
sudo systemctl restart wazuh-mcp
```

**Fix — firewall blocking:**
```bash
sudo ufw allow 8000/tcp && sudo ufw reload
```

---

### 6. `RequestContentLengthMismatch` in mcp-remote

**Cause:** `mcp-remote` used the `streamable-http` protocol (`/mcp` path). A bug in some versions of `mcp-remote`'s HTTP client causes a content-length mismatch on streaming responses.

**Fix:** Use the `/sse` path instead of `/mcp`:
```bash
# Wrong
mcp-remote http://SERVER_IP:8000/mcp --allow-http

# Correct
mcp-remote http://SERVER_IP:8000/sse --allow-http
```

In `claude_desktop_config.json`, ensure the URL ends with `/sse`.

---

### 7. `Some MCP servers could not be loaded: wazuh` popup in Claude Desktop

**Cause:** The config used the `"url": "http://..."` shorthand format, which is not supported by all Claude Desktop versions.

**Fix:** Use `command` + `args` format with `mcp-remote`:
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "mcp-remote",
      "args": ["http://SERVER_IP:8000/sse", "--allow-http"]
    }
  }
}
```

---

### 8. `Non-HTTPS URLs are only allowed for localhost` (mcp-remote)

**Cause:** `mcp-remote` blocks plain HTTP to non-localhost addresses by default.

**Fix:** Add the `--allow-http` flag to the args list:
```json
"args": ["http://SERVER_IP:8000/sse", "--allow-http"]
```

---

### 9. `401 Unauthorized` from the Wazuh Manager API

**Cause:** Wrong credentials or the API user lacks RBAC permissions.

**Diagnose:**
```bash
curl -k -X POST -u "wazuh-mcp:YourPassword" \
  https://SERVER_IP:55000/security/user/authenticate
```

If this returns `{"token": "..."}` then credentials are correct and the issue is RBAC. If it returns 401, the password is wrong.

**Fix:** In the Wazuh Dashboard verify the API user exists and its role grants read permissions for `agents`, `rules`, `syscheck`, `sca`, and `syscollector`.

---

### 10. Empty results from `search_alerts` or `vulnerability_summary`

**Cause:** The configured index patterns do not match the actual index names in the deployment.

**Diagnose:**
```bash
curl -sk -u wazuh-readonly:PASSWORD \
  https://SERVER_IP:9200/_cat/indices?h=index | grep wazuh
```

**Fix:** Update `.env` to match your actual index names:
```dotenv
WAZUH_ALERTS_INDEX=wazuh-alerts-4.x-*
WAZUH_VULN_INDEX=wazuh-states-vulnerabilities-4.x-*
```

Then restart the service:
```bash
sudo systemctl restart wazuh-mcp
```

---

### 11. `Permission denied` on SCP to the VM

**Cause:** The target file on the VM is owned by `root` (from an earlier `sudo` edit), blocking the `vagrant` user SSH session from overwriting it.

**Fix:** On the VM, restore ownership before running SCP:
```bash
sudo chown vagrant:vagrant /home/vagrant/wazuh-mcp/wazuh_mcp/server.py
```

---

### 12. `TypeError: FastMCP.run() got an unexpected keyword argument 'host'`

**Cause:** The installed `mcp` package version does not support `host`/`port` arguments in `FastMCP.run()`.

**Fix:** Ensure you are running the latest `server.py` from this repository. The correct implementation bypasses `run()` entirely and calls `mcp.sse_app()` with `uvicorn.run()` directly:

```bash
tail -10 /home/vagrant/wazuh-mcp/wazuh_mcp/server.py
# Should show:
#   asgi_app = mcp.sse_app()
#   uvicorn.run(asgi_app, host=host, port=port, ...)
```

If it shows `mcp.run(transport="stdio")` the old file is still in place — replace it with the latest version.

---

### 13. Server binds to `127.0.0.1` instead of `0.0.0.0`

**Cause:** FastMCP's internal async runners (`run_sse_async`, `run_streamable_http_async`) read the host from `self.settings.host`, which defaults to `127.0.0.1` and ignores environment variables in some package versions.

**Fix:** The correct `server.py` uses `mcp.sse_app() + uvicorn.run(host=host, ...)` directly, which always respects the `host` argument. After replacing `server.py`:

```bash
sudo systemctl restart wazuh-mcp
ss -tlnp | grep 8000   # must show 0.0.0.0:8000
```

---


### 14. HTTP 421 `Invalid Host header` — remote clients rejected

**Cause:** The MCP Python SDK (`mcp` package ≥ 1.x) ships with a `TransportSecuritySettings` class that enables DNS-rebinding protection by default. When `sse_app()` is called it passes these settings to `SseServerTransport`, which validates every incoming `Host` header against an allowlist of `["127.0.0.1:*", "localhost:*", "[::1]:*"]`. Any request arriving with a non-localhost `Host` — such as a VirtualBox host-only IP (`HOST_IP`), a LAN IP, or a hostname — receives:

```
HTTP/1.1 421 Misdirected Request
Invalid Host header
```

This affects `mcp-remote`, `curl`, and any other client that is not running on the same machine as the server.

**Symptoms:**
- `curl -v http://<SERVER_IP>:8000/sse` → `421 Misdirected Request`
- `mcp-remote` logs `SSE error: Non-200 status code (421)` then exits
- `journalctl -u wazuh-mcp` shows `WARNING mcp.server.transport_security: Invalid Host header: <your-ip>`

**Diagnose:**
```bash
# Confirm the log message
sudo journalctl -u wazuh-mcp -n 50 --no-pager | grep "Invalid Host"

# Confirm the SDK has the restrictive default
grep -r "allowed_hosts" \
  .venv/lib/*/site-packages/mcp/server/fastmcp/server.py
```

**Fix:** Before calling `mcp.sse_app()`, override `transport_security` to disable the host check:

```python
import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
mcp.settings.transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=False
)
asgi_app = mcp.sse_app()
uvicorn.run(asgi_app, host=host, port=port, log_level="warning")
```

This is already applied in the current `server.py`. If you are upgrading from an older version of this repo, pull the latest `server.py` and restart the service:

```bash
sudo systemctl restart wazuh-mcp
curl -si http://<SERVER_IP>:8000/sse | head -3
# Expected: HTTP/1.1 200 OK
```

**Security note:** `enable_dns_rebinding_protection=False` is safe for servers running on a trusted private or host-only network. For internet-facing deployments, place the server behind a TLS reverse proxy (nginx/Caddy) and restrict access at the network/firewall level rather than relying on Host-header validation.

---

## Security Considerations

**Use dedicated read-only accounts.** Create a separate Wazuh Manager API user and Indexer user with minimum required permissions. Never use `admin`.

**Keep `WAZUH_ALLOW_WRITES=false` in production.** `restart_agent`, `run_active_response`, `add_to_cdb_list`, and `remove_from_cdb_list` are disabled by default. Enable only when explicitly delegating remediation to the AI.

**Threat intelligence API keys are optional but sensitive.** `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` grant access to external services. Store them only in `.env` (which is in `.gitignore`) — never commit them to the repository.

**Bind to trusted interfaces only.** If Claude Desktop and the Wazuh server are on the same host, set `WAZUH_MCP_HOST=127.0.0.1`. For separate hosts on a trusted internal network, `0.0.0.0` is acceptable. Never expose port 8000 to the internet.

**Enable TLS for production.** `WAZUH_VERIFY_SSL=false` is for lab environments only. In production, configure a valid CA chain, set `WAZUH_VERIFY_SSL=true`, and put the MCP HTTP endpoint behind an nginx reverse proxy with a valid TLS certificate — removing the need for `--allow-http` in `mcp-remote`.

**Alert content reaches the AI.** Trimmed payloads still include hostnames, usernames, source IPs, and log snippets. Confirm your AI client's data handling policy is compatible with your data classification requirements before connecting to a production Wazuh deployment.

---

## Sources

- [Wazuh REST API Documentation](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh Indexer Documentation](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/docs)
- [FastMCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [mcp-remote](https://github.com/geelen/mcp-remote)
- [Wazuh Integrations Repository](https://github.com/wazuh/integrations)
- [Wazuh Integration Contributing Guide](https://github.com/wazuh/integrations/blob/main/CONTRIBUTING.md)
