# Wazuh MCP Server

A Model Context Protocol (MCP) server that exposes a Wazuh deployment to LLM clients
like Claude Desktop, Claude Code, or any other MCP-compatible host.

It bridges two Wazuh data planes:

- **Wazuh Manager API** (`:55000`) — agent management, restarts, active-response triggers.
- **Wazuh Indexer** (`:9200`) — alerts, vulnerability state, MITRE ATT&CK mappings.

Built around the principle of **aggregations-first**: broad questions resolve through
indexer aggregations (tiny payloads) before any tool returns raw alert documents, so a
single conversation can cover a whole shift without blowing context.

---

## What's in the box

41 MCP tools, organized by purpose:

### Agent + manager operations
- `list_agents`, `get_agent`
- `get_rule_details` — full metadata for a rule ID (description, level, MITRE, compliance)
- `restart_agent`, `run_active_response` *(write tools — disabled by default)*

### Agent group management
- `list_groups`, `get_group_agents`
- `add_agent_to_group` *(write tool — disabled by default)*

### Alert intelligence (indexer)
- `alert_summary` — aggregated overview by level, rule, agent, MITRE, groups
- `search_alerts` — filtered alert search with trimmed payloads
- `search_by_mitre` — alerts mapped to an ATT&CK technique
- `search_by_source_ip` — IoC pivoting
- `search_authentication_failures` — brute-force candidates
- `alert_timeline` — date histogram for spike detection
- `get_alert_by_id` — full alert detail (escape hatch)

### File integrity monitoring
- `get_recent_fim_changes` — per-agent file changes from the Manager API
- `search_fim_alerts` — indexer-side FIM alerts with optional path filter
- `fim_summary` — aggregated FIM activity by agent, event type, and path
- `critical_file_changes` — FIM events on sensitive paths (passwd, sudoers, ssh keys, system binaries)

### Compliance frameworks
- `compliance_summary` — aggregate alerts by control for PCI-DSS, HIPAA, GDPR, NIST 800-53, TSC
- `compliance_control_details` — drill into alerts mapped to one specific control

### Vulnerability detection
- `vulnerability_summary` — fleet-wide unpatched CVE overview
- `get_agent_vulnerabilities_detailed` — per-agent CVE list, CVSS-sorted
- `search_cve` — every agent affected by a specific CVE
- `prioritize_patches` — patch queue ranked by `agents × CVSS`, not raw count

### Active response correlation
- `get_active_responses` — recent AR actions with triggering context
- `correlate_alert_with_response` — did Wazuh act on this attack?
- `active_response_effectiveness` — audit whether blocks actually worked

### Anomaly comparison (current vs baseline)
- `compare_alert_volume` — total + per-level deltas between this period and last
- `detect_rule_anomalies` — surface NEW rules, SPIKES, DROPS, and GONE rules vs baseline

### Inventory — per-agent (Manager API, all 4.x)
- `get_agent_packages` — installed packages, with substring search
- `get_agent_processes` — currently-tracked processes
- `get_agent_open_ports` — listening ports + bound process
- `get_agent_hardware_os` — consolidated hardware + OS info

### Inventory — fleet-wide (Indexer, requires Wazuh 4.10+)
- `fleet_find_package` — every agent with a given package (the CVE-response query)
- `fleet_find_process` — every agent currently running a process
- `fleet_find_listening_port` — every agent with a port open

### Security Configuration Assessment (CIS benchmarks)
- `get_agent_sca_policies` — list policies + pass/fail scores on an agent
- `get_sca_failed_checks` — failing checks with rationale and remediation
- `sca_alerts_summary` — fleet-wide SCA aggregation from indexer
- `fleet_sca_weakest_agents` — rank agents by configuration weakness

---

## Quick start

### 1. Prepare Wazuh-side accounts

Create **two read-only accounts** in your Wazuh deployment:

**Manager API user**
- In the Wazuh Dashboard → Server Management → API → Users
- Assign a role with read permissions on agents and active response
- Give it write permissions only if you plan to enable `WAZUH_ALLOW_WRITES`

**Indexer user**
- In Wazuh Dashboard → Security → Internal users → Create `wazuh-readonly`
- Create a role with `cluster:monitor/*` and `indices:data/read/*` on
  `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`
- Map the user to that role

Never use the `admin` indexer account for this — the MCP can be invoked by an LLM, so
least-privilege is non-optional.

### 2. Run locally with Python

```bash
git clone <your-repo>/wazuh-mcp.git
cd wazuh-mcp
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e .

cp .env.example .env
$EDITOR .env                 # fill in the four required passwords

# Smoke test — should print a Config object
python -c "from wazuh_mcp.config import Config; print(Config.from_env())"

# Run it
python -m wazuh_mcp
```

The server speaks STDIO JSON-RPC and waits for a client to attach.

### 3. Run via Docker

```bash
cp .env.example .env
$EDITOR .env
docker compose build

# Verify config loads
docker compose run --rm wazuh-mcp python -c \
  "from wazuh_mcp.config import Config; print(Config.from_env())"
```

The container won't sit idle — Claude Desktop launches it on demand and tears it down
when the session ends.

### 4. Wire it into Claude Desktop

Edit `claude_desktop_config.json`:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

See `claude_desktop_config.example.json` for both the local-Python and Docker variants.
Restart Claude Desktop after editing — the `wazuh` server should appear in the tools list.

---

## Things that will go wrong (and how to spot them)

| Symptom | Likely cause | Fix |
|---|---|---|
| `Missing required env var` on startup | `.env` not loaded by Claude Desktop | Use absolute paths and embed env vars directly in `claude_desktop_config.json` |
| `401 Unauthorized` from manager | Wrong creds, or API user lacks RBAC | Test with `curl -k -u user:pass https://manager:55000/security/user/authenticate -X POST` |
| Empty results from `search_alerts` | Index pattern mismatch | Check `WAZUH_ALERTS_INDEX` against `GET _cat/indices` on the indexer |
| Timeouts on aggregation tools | Indexer slow / huge time range | Lower `time_range`, or raise `WAZUH_REQUEST_TIMEOUT` |
| SSL handshake fails | Self-signed certs not trusted | Either set `WAZUH_VERIFY_SSL=false` (lab) or mount your CA bundle |
| Claude can't see tools | Server crashed on launch | Check Claude Desktop's MCP log file — server stderr goes there |
| `data.srcip` queries return nothing | Older Wazuh schema | Try `srcip` instead, or check one alert with `get_alert_by_id` to confirm field names |

**STDIO logging gotcha:** never `print()` to stdout from inside a tool. It corrupts the
JSON-RPC stream and breaks the session. Use `logging` (already wired to stderr in
`server.py`).

---

## Security notes

This server is a **privileged read interface** to your SIEM. Treat it like any other
SIEM integration:

1. **Run on the Wazuh manager host or an adjacent admin network.** Don't expose it to
   user networks.
2. **Use dedicated, narrowly-scoped accounts.** The provided `.env.example` assumes
   read-only by default.
3. **Keep `WAZUH_ALLOW_WRITES=false` in production.** Flip it only for short windows
   when you're explicitly delegating remediation to the LLM, and audit every call.
4. **Pin TLS verification on.** `WAZUH_VERIFY_SSL=false` is for the lab. In production,
   mount your internal CA bundle into the container and set `WAZUH_VERIFY_SSL=true`.
5. **The LLM sees alert content.** Trimmed payloads still contain hostnames, usernames,
   source IPs, and log snippets. Make sure your AI client's data handling matches your
   data classification policy.

---

## Example prompts to try

Once connected:

**Operational overview**
- "Give me an alert summary for the last 24 hours."
- "Are we being brute-forced right now? Anything failing auth more than 20 times?"
- "Show critical alerts from web-03 in the last 4 hours."
- "What MITRE techniques have been most active this week?"
- "What does rule 31151 actually mean?"

**Anomaly detection**
- "Compare this week's alert volume to last week's — anything off?"
- "Which rules are firing way more than baseline? Anything that went silent?"

**File integrity monitoring**
- "Has anything changed under /etc on the database servers today?"
- "Show me sensitive-file changes this week across the fleet."
- "What FIM events have fired on agent 007 in the last hour?"

**Compliance**
- "Summarize PCI-DSS findings for the last 30 days."
- "Show me all alerts mapped to HIPAA control 164.312(b)."

**Vulnerability management**
- "How exposed are we to high-severity vulnerabilities?"
- "What should I patch first this week?"
- "Are any of our agents affected by CVE-2024-3094?"

**Active response audit**
- "What has Wazuh blocked in the last hour?"
- "How effective have our automated blocks been this week?"

**Asset inventory**
- "Which agents have openssl 3.0.x installed?"
- "Find every host currently running curl."
- "Who has port 3389 open in our environment?"
- "What's installed on agent 012?"

**Configuration hardening (SCA)**
- "Which agents have the worst CIS benchmark scores?"
- "What's failing on the CIS Ubuntu benchmark on web-03?"
- "Summarize SCA failures across the fleet this week."

**Agent management**
- "Which agents are in the 'web-servers' group?"
- "Move agent 015 to the 'pci-scope' group." *(needs writes enabled)*

---

## Extending

The server is intentionally one flat `server.py` so you can read it end-to-end. To add a
new tool:

1. Write an `async def` function in `server.py`.
2. Decorate it with `@mcp.tool()`.
3. Write a docstring — the LLM uses this to decide when to call it. Be specific about
   *when* to use the tool, not just what it does.
4. Restart your MCP client.

Likely next additions, in order of impact:

- **Custom rule / CDB list management** — read and push detection content via the manager
- **Cross-period IoC tracking** — was this IP/hash seen before, when, and how often
- **Saved-query resources** — curated MCP *resources* (alongside tools) so frequent
  investigations are one click in the client
- **HTTP transport + OAuth** — to support remote (non-STDIO) MCP clients like
  Claude Code in containerized agent setups
- **Per-agent log streaming** — exposing the manager's log archives as on-demand fetch

---

## License

MIT — adapt freely for your environment.
