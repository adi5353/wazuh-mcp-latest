"""Wazuh MCP Server — exposes Wazuh manager + indexer capabilities as MCP tools.

Logging note: in STDIO mode, never print() to stdout — it corrupts the JSON-RPC stream.
The logging module below is configured to write to stderr.

Enhanced edition — adds:
  • Incident management tools (create_incident_report, tag_alert, bulk_suppress_rule)
  • Threat hunting tools (hunt_lateral_movement, hunt_persistence_mechanisms, hunt_data_exfiltration)
  • CDB write helpers with dry-run safety (add_ip_to_blocklist, remove_ip_from_blocklist, preview_cdb_list_impact)
  • Archive tools (search_archive_logs_by_agent, get_agent_login_history)
  • Reporting tools (generate_weekly_summary, generate_compliance_report)
  • GeoIP enrichment (enrich_ip_geo)
  • Alert trend enrichment inline in alert_summary
  • 4 new MCP prompts (morning_briefing, incident_triage, shift_handover, threat_hunt_session)
  • /health HTTP endpoint
  • Optional API-key bearer-token middleware (WAZUH_MCP_API_KEY)
  • Structured JSON logging via structlog (falls back gracefully if not installed)
  • WAZUH_MAX_RESULTS_GLOBAL hard cap across all list tools
  • dry_run=True guard on restart_agent and run_active_response
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time

import httpx
from mcp.server.fastmcp import FastMCP

from .audit import audit_logger, sanitize_response, cap_response_size, _sanitize_string
from .input_sanitizer import sanitize_input_value
from .config import Config
from .identity import resolve_role_for_key, set_session_role, record_injection_attempt
from .rbac import _current_role, _ROLE_NAMES, ROLE, _NAME_TO_ROLE
from .rate_limit import RateLimitMiddleware
from .helpers import trim_alert, trim_vuln, severities_at_or_above, time_window
from .wazuh_client import WazuhClient
from .wazuh_indexer import WazuhIndexer
from .mitre_data import enrich_mitre_ids as _enrich_mitre_ids, _MITRE_MAP
from .geo import geoip_lookup as _geoip_lookup
from .triage import incident_recommendations as _incident_recommendations
from .middleware import ToolMiddleware

# ── Structured logging (structlog optional, stdlib fallback) ──────────────────
try:
    import structlog
    from .logging_config import _redact_sensitive

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.PositionalArgumentsFormatter(),
            _redact_sensitive,                      # ← strip secrets before rendering
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    log = structlog.get_logger("wazuh-mcp")
    _structlog_available = True
except ImportError:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    log = logging.getLogger("wazuh-mcp")  # type: ignore[assignment]
    _structlog_available = False

# ── Global config ─────────────────────────────────────────────────────────────
cfg = Config.from_env()
wz = WazuhClient(cfg)
idx = WazuhIndexer(cfg)

MAX_RESULTS_GLOBAL = int(os.getenv("WAZUH_MAX_RESULTS_GLOBAL", "500"))
SERVER_START_TIME = time.time()

mcp = FastMCP("wazuh")

# ── Tool registry for playbook engine ────────────────────────────────────────
# Maps tool_name → async callable so run_playbook can invoke tools directly.
_TOOL_REGISTRY: dict[str, Any] = {}

# ── Single middleware: sanitization + registry capture (replaces two monkey-patches) ──
_tool_mw = ToolMiddleware(mcp, _TOOL_REGISTRY)
_tool_mw.install()

# ── Domain tool modules ────────────────────────────────────────────────────────
from .tools import agents as _agents_module  # noqa: E402
from .tools import alerts as _alerts_module  # noqa: E402
from .tools import vulnerabilities as _vulns_module  # noqa: E402
from .tools import active_response as _ar_module  # noqa: E402
from .tools import fim as _fim_module  # noqa: E402
from .tools import compliance as _compliance_module  # noqa: E402
from .tools import fleet as _fleet_module  # noqa: E402
from .tools import sca as _sca_module  # noqa: E402
from .tools import cdb as _cdb_module  # noqa: E402
from .tools import rules as _rules_module  # noqa: E402
from .tools import threat_intel as _ti_module  # noqa: E402
from .tools import threat_hunting as _hunting_module  # noqa: E402
from .tools import mitre as _mitre_module  # noqa: E402
from .tools import incidents as _incidents_module  # noqa: E402
from .tools import reporting as _reporting_module  # noqa: E402
from .tools import integrations as _integrations_module  # noqa: E402
from .tools import notifications as _notifications_module  # noqa: E402
from .tools import onboarding as _onboarding_module  # noqa: E402
from .tools import cluster as _cluster_module  # noqa: E402
from .tools import archive as _archive_module  # noqa: E402
from .tools import suppression as _suppression_module  # noqa: E402
from .tools import agent_health as _agent_health_module  # noqa: E402
from .tools import credential_mgmt as _cred_module  # noqa: E402
from .tools import cve_watchlist as _cve_watchlist_module  # noqa: E402
from .tools import rule_wizard as _rule_wizard_module  # noqa: E402
from .tools import workspaces as _workspaces_module  # noqa: E402
from .tools import geo_intel as _geo_intel_module  # noqa: E402
from .tools import threat_feeds as _threat_feeds_module  # noqa: E402
from .tools import playbooks as _playbooks_module  # noqa: E402
from .tools import network_topology as _net_topology_module  # noqa: E402
from .tools import autonomous_soc as _autonomous_soc_module  # noqa: E402
from .tools import baseline as _baseline_module  # noqa: E402
from .tools import ueba as _ueba_module  # noqa: E402
from .tools import scheduler as _scheduler_module  # noqa: E402
from .tools import agent_upgrades as _agent_upgrades_module  # noqa: E402
from .tools import audit_mgmt as _audit_mgmt_module  # noqa: E402
from .tools import azure_devops as _azure_devops_module  # noqa: E402
from .tools import export as _export_module  # noqa: E402
from .tools import index_mgmt as _index_mgmt_module  # noqa: E402
from .tools import manager_audit as _manager_audit_module  # noqa: E402
from .tools import manager_config as _manager_config_module  # noqa: E402
from .tools import pagerduty as _pagerduty_module  # noqa: E402
from .tools import rootcheck as _rootcheck_module  # noqa: E402
from .tools import servicenow as _servicenow_module  # noqa: E402
from .tools import syslog_config as _syslog_config_module  # noqa: E402
from .tools import health_check as _health_check_module  # noqa: E402
from .tools import prompt_advisor as _prompt_advisor_module  # noqa: E402
from .tools import explain_alert as _explain_alert_module  # noqa: E402
from .tools import roi as _roi_module  # noqa: E402
from .tools import quick_wins as _quick_wins_module  # noqa: E402
from .tools import metrics as _metrics_module  # noqa: E402


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _require_writes() -> dict | None:
    """Return an error dict if writes are disabled, else None."""
    if not cfg.allow_writes:
        return {
            "error": "Write operations are disabled. "
                     "Set WAZUH_ALLOW_WRITES=true to enable destructive tools."
        }
    return None


def _cap(n: int) -> int:
    """Clamp a requested limit to MAX_RESULTS_GLOBAL."""
    return min(n, MAX_RESULTS_GLOBAL)


def _truncate(s: str | None, n: int = 300) -> str | None:
    """Cap long strings so process command lines don't blow up payloads."""
    if s is None:
        return None
    return s if len(s) <= n else s[:n] + "…"


# _MITRE_MAP, _enrich_mitre_ids → wazuh_mcp/mitre_data.py
# _geoip_lookup              → wazuh_mcp/geo.py
# _incident_recommendations  → wazuh_mcp/triage.py


# ── Register domain modules ────────────────────────────────────────────────────
_agents_module.register(mcp, wz, idx, cfg, _cap, _require_writes)
_alerts_module.register(mcp, wz, idx, cfg, _cap, _enrich_mitre_ids)
_vulns_module.register(mcp, wz, idx, cfg, _cap)
_ar_module.register(mcp, wz, idx, cfg, _cap)
_fim_module.register(mcp, wz, idx, cfg, _cap)
_compliance_fns = _compliance_module.register(mcp, wz, idx, cfg, _cap)
_fleet_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_sca_module.register(mcp, wz, idx, cfg, _cap)
_cdb_module.register(mcp, wz, idx, cfg, _require_writes)
_rules_module.register(mcp, wz, idx, cfg, _cap)
_ti_module.register(mcp, wz, idx, cfg, _geoip_lookup)
_hunting_module.register(mcp, wz, idx, cfg)
_mitre_module.register(mcp, wz, idx, cfg)
_incidents_module.register(mcp, wz, idx, cfg, _cap, _require_writes, _enrich_mitre_ids, _incident_recommendations)
_reporting_fns = _reporting_module.register(mcp, wz, idx, cfg, _cap, _enrich_mitre_ids)
_integrations_module.register(mcp, wz, idx, cfg)
_notifications_module.register(
    mcp, wz, idx, cfg,
    generate_shift_handover=_reporting_fns["generate_shift_handover"],
    generate_weekly_summary=_reporting_fns["generate_weekly_summary"],
    generate_compliance_report=_compliance_fns["generate_compliance_report"],
)
_onboarding_module.register(mcp, wz, idx, cfg, _cap)
_cluster_module.register(mcp, wz, idx, cfg)
_archive_module.register(mcp, wz, idx, cfg, _cap)
_suppression_module.register(mcp, wz, idx, cfg, _require_writes)
_agent_health_module.register(mcp, wz, idx, cfg, _cap)
_cred_module.register(mcp, wz, cfg, _require_writes)
_cve_watchlist_module.register(mcp, wz, idx, cfg)
_rule_wizard_module.register(mcp, wz, cfg)
_workspaces_module.register(mcp, cfg)
_geo_intel_module.register(mcp, wz, idx, cfg)
_threat_feeds_module.register(mcp, wz, idx, cfg, _require_writes)
_playbooks_module.register(mcp, wz, idx, cfg, tool_registry=_TOOL_REGISTRY)
_net_topology_module.register(mcp, wz, idx, cfg, _cap)
_autonomous_soc_module.register(mcp, wz, idx, cfg, tool_registry=_TOOL_REGISTRY)
_baseline_module.register(mcp, wz, idx, cfg, _cap)
_ueba_module.register(mcp, wz, idx, cfg, _cap)
_scheduler_module.register(mcp, wz, idx, cfg)
_agent_upgrades_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_audit_mgmt_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_azure_devops_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_export_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_index_mgmt_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_manager_audit_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_manager_config_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_pagerduty_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_rootcheck_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_servicenow_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_syslog_config_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_health_check_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_prompt_advisor_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_explain_alert_module.register(mcp, wz, idx, cfg, _cap, _geoip_lookup)
_roi_module.register(mcp, wz, idx, cfg, _cap, _truncate)
_quick_wins_module.register(mcp, wz, idx, cfg, _cap)
_metrics_module.register(mcp, wz, idx, cfg, _cap, _truncate)


# ── Session identity tool (Gap 1) ─────────────────────────────────────────────

@mcp.tool()
async def set_session_role_tool(api_key: str) -> dict:
    """Authenticate this session with an API key and bind its role.

    Configure API keys via WAZUH_MCP_KEY_MAP env var:
        WAZUH_MCP_KEY_MAP=viewer:key_abc,analyst:key_def,admin:key_xyz

    If WAZUH_MCP_KEY_MAP is not set, this tool has no effect and the server
    falls back to WAZUH_MCP_USER_ROLE (single-user mode).
    """
    role = resolve_role_for_key(api_key)
    if role is None:
        return {
            "error": "Unknown API key. Configure WAZUH_MCP_KEY_MAP or check your key.",
            "hint": "Format: WAZUH_MCP_KEY_MAP=viewer:key1,analyst:key2,admin:key3",
        }
    set_session_role(role)
    role_name = {ROLE.VIEWER: "viewer", ROLE.ANALYST: "analyst",
                 ROLE.RESPONDER: "responder", ROLE.ADMIN: "admin"}.get(role, "analyst")
    return {
        "status": "ok",
        "role": role_name,
        "message": f"Session authenticated as '{role_name}'.",
    }


# ============================================================================
# MSSP multi-tenant instance switching
# ============================================================================

# Active tenant state (None = use default single-instance config)
_active_tenant: dict | None = None


@mcp.tool()
async def list_tenants() -> dict:
    """List all configured Wazuh tenants (MSSP mode).

    Returns tenant names and manager hosts from WAZUH_INSTANCES config.
    Only available when WAZUH_INSTANCES is configured.
    """
    if not cfg.tenants:
        return {
            "mssp_mode": False,
            "message": "Single-instance mode. Set WAZUH_INSTANCES env var to enable MSSP multi-tenant mode.",
        }
    return {
        "mssp_mode": True,
        "active_tenant": _active_tenant["name"] if _active_tenant else "(default)",
        "tenants": [
            {"name": t.name, "manager_host": t.manager_host}
            for t in cfg.tenants
        ],
    }


@mcp.tool()
async def switch_tenant(tenant_name: str) -> dict:
    """Switch the active Wazuh tenant for this session (MSSP mode).

    After switching, all subsequent tool calls query the selected tenant's
    Wazuh Manager and Indexer. Requires WAZUH_INSTANCES to be configured.

    Args:
        tenant_name: The name of the tenant as defined in WAZUH_INSTANCES.
    """
    global _active_tenant, wz, idx

    if not cfg.tenants:
        return {
            "error": "MSSP multi-tenant mode is not configured. "
                     "Set WAZUH_INSTANCES JSON env var to enable.",
        }

    tenant = next((t for t in cfg.tenants if t.name == tenant_name), None)
    if not tenant:
        names = [t.name for t in cfg.tenants]
        return {
            "error": f"Tenant '{tenant_name}' not found.",
            "available": names,
        }

    # Swap out the shared WazuhClient + WazuhIndexer to point at the new tenant
    from .config import Config as _Config
    from .wazuh_client import WazuhClient as _WC
    from .wazuh_indexer import WazuhIndexer as _WI
    import dataclasses

    tenant_cfg = dataclasses.replace(
        cfg,
        manager_host=tenant.manager_host,
        manager_user=tenant.manager_user,
        manager_pass=tenant.manager_pass,
        indexer_host=tenant.indexer_host,
        indexer_user=tenant.indexer_user,
        indexer_pass=tenant.indexer_pass,
    )
    wz = _WC(tenant_cfg)
    idx = _WI(tenant_cfg)
    _active_tenant = {"name": tenant.name, "manager_host": tenant.manager_host}

    log.info("MSSP tenant switched to '%s' (%s)", tenant.name, tenant.manager_host)
    return {
        "status": "ok",
        "active_tenant": tenant.name,
        "manager_host": tenant.manager_host,
        "message": f"All subsequent tool calls now target tenant '{tenant.name}'.",
    }


# ============================================================================
# Anomaly comparison + reporting — see tools/reporting.py
# ============================================================================


# ============================================================================
# Incident response — see tools/incidents.py
# ============================================================================


# ============================================================================
# Archive log search — see tools/archive.py
# ============================================================================


# ============================================================================
# Cluster health — see tools/cluster.py
# ============================================================================




# ============================================================================
# Incident management — see tools/incidents.py
# ============================================================================


# ============================================================================
# Reporting — see tools/reporting.py
# ============================================================================

# ============================================================================
# Alert suppression lifecycle — see tools/suppression.py
# ============================================================================

# Suppression — see tools/suppression.py

# Notifications — see tools/notifications.py
# Onboarding — see tools/onboarding.py

# Push report delivery — see tools/notifications.py


# ============================================================================
# MCP Prompts — one-click investigation workflows
# ============================================================================

@mcp.prompt()
def investigate_brute_force(time_range: str = "1h") -> str:
    """One-click brute force investigation."""
    return f"""Perform a complete brute force investigation for the last {time_range}:

1. search_authentication_failures(time_range="{time_range}", threshold=5) — find candidate IPs
2. For the top 3 IPs: search_by_source_ip to get full alert context
3. enrich_ip for each top IP — VirusTotal + AbuseIPDB reputation
4. enrich_ip_geo for each top IP — geolocation context
5. correlate_alert_with_response for the highest-volume IP — did Wazuh block it?
6. If NOT blocked: blast_radius_analysis to assess lateral spread

Conclude with:
- What happened and which accounts/services were targeted
- Whether the attack is ongoing or was blocked
- Recommended action (add_to_cdb_list if ALLOW_WRITES=true, or escalate)"""


@mcp.prompt()
def weekly_soc_briefing() -> str:
    """Generate a complete weekly SOC executive briefing."""
    return """Generate the weekly SOC executive briefing by calling these tools in order:

1. compare_alert_volume(current_range="7d", baseline_offset="7d") — volume trend
2. detect_rule_anomalies(current_range="7d") — new/spiking/silent rules
3. generate_weekly_summary() — aggregated top rules, agents, MITRE
4. vulnerability_summary(min_severity="Critical") — fleet CVE posture
5. prioritize_patches(top_n=5) — top patches by exposure × CVSS
6. active_response_effectiveness(time_range="7d") — block effectiveness rate
7. fleet_sca_weakest_agents(limit=5) — most misconfigured agents
8. mitre_coverage_analysis() — ATT&CK technique coverage stats

Format as an executive briefing with:
- Executive Summary (3 sentences)
- Key Metrics table
- Top 3 Risks this week
- Recommended Actions (owner + priority)"""


@mcp.prompt()
def triage_alert(alert_id: str) -> str:
    """Full structured triage for a single alert document ID."""
    return f"""Perform full triage on alert ID: {alert_id}

1. get_alert_by_id("{alert_id}") — full alert detail
2. get_rule_details(rule_id from alert) — what does this rule detect?
3. If alert has src_ip: search_by_source_ip(src_ip, time_range="24h")
4. enrich_ip(src_ip) — VirusTotal + AbuseIPDB verdict
5. enrich_ip_geo([src_ip]) — geolocation
6. correlate_alert_with_response(src_ip=src_ip) — automated response triggered?
7. blast_radius_analysis(src_ip=src_ip, time_range="2h") — scope of compromise
8. If alert involves file change: enrich_file_hash(sha256 from alert)

Produce a triage report:
- Classification: True Positive / False Positive / Needs Investigation
- Severity: Critical / High / Medium / Low
- Evidence summary (3 bullets)
- Recommended response
- Escalate: Yes/No — and to whom"""


@mcp.prompt()
def cve_emergency_response(cve_id: str) -> str:
    """Immediate CVE emergency response workflow."""
    return f"""Emergency response for {cve_id}:

1. search_cve("{cve_id}") — find every affected agent immediately
2. For top 5 affected agents: get_agent_vulnerabilities_detailed
3. prioritize_patches() — where does {cve_id} rank overall?
4. search_alerts(time_range="7d", rule_groups=["exploit","web_attack"]) — exploitation attempts?
5. fleet_find_package(package_name) — confirm package spread across fleet

Emergency response brief:
- Impact: agent count, environments affected
- Exploitation evidence: confirmed / suspected / not observed
- Immediate mitigations available
- Patch priority: P0 (now) / P1 (this week) / P2 (next cycle)
- Monitoring to add until patched"""


@mcp.prompt()
def morning_briefing() -> str:
    """Morning SOC shift briefing — run at the start of each shift."""
    return """Run a morning SOC briefing. Please:
1. alert_summary(time_range="24h") — overnight alert overview with trend
2. compare_alert_volume(current_range="24h", baseline_offset="24h") — vs yesterday
3. search_authentication_failures(time_range="24h", threshold=5) — overnight brute force
4. active_response_effectiveness(time_range="24h") — did overnight blocks work?
5. check_event_queue_health() — confirm the pipeline is healthy

Summarize findings as a shift handover with:
- Risk rating: LOW / MEDIUM / HIGH / CRITICAL
- 3 recommended actions for this shift
- Anything that needs immediate attention"""


@mcp.prompt()
def incident_triage_full(agent_name: str = "", src_ip: str = "") -> str:
    """Full incident triage for a specific agent or source IP."""
    target = f"agent '{agent_name}'" if agent_name else f"source IP '{src_ip}'"
    return f"""Run a full incident triage for {target}:
1. search_alerts(time_range="48h") filtered to the target
2. search_fim_alerts(time_range="48h") for the agent if known
3. get_agent_login_history(agent_name="{agent_name}") if agent known
4. correlate_alert_with_response(src_ip="{src_ip}") if IP known
5. enrich_ip_geo(["{src_ip}"]) if IP known — geolocation
6. blast_radius_analysis — assess lateral spread
7. create_incident_report from the top alert IDs found

End with:
- Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
- Recommended containment steps
- Whether to tag alerts as investigated or escalate"""


@mcp.prompt()
def threat_hunt_session() -> str:
    """Structured threat hunt across lateral movement, persistence, and exfiltration."""
    return """Run a full threat hunt session across the last 48 hours:
1. hunt_lateral_movement(time_range="48h") — auth patterns + multi-agent spread
2. hunt_persistence_mechanisms(time_range="48h") — startup/registry/cron changes
3. hunt_data_exfiltration(time_range="48h") — unusual outbound event volumes
4. For any agent flagged in 2+ hunts: get_agent_login_history and search_fim_alerts
5. Correlate findings — identify composite-risk agents (appear in multiple hunts)

Rate each finding LOW/MEDIUM/HIGH/CRITICAL.
Finish with a prioritised list of agents to investigate further."""


@mcp.prompt()
def end_of_shift_handover() -> str:
    """End-of-shift handover report."""
    return """Generate an end-of-shift handover report for the last 12 hours:
1. generate_shift_handover(shift_duration="12h")
2. generate_weekly_summary() for broader context
3. prioritize_patches(top_n=3) — top CVEs to patch
4. fleet_sca_weakest_agents(limit=5) — config posture
5. hunt_lateral_movement(time_range="12h") — any active threats?

Format as a handover document:
SUMMARY | OPEN INCIDENTS | PATCH QUEUE | CONFIG ISSUES | WATCH LIST"""


# ── Role-optimized prompts ────────────────────────────────────────────────────

@mcp.prompt()
def tier1_analyst_guide(alert_id: str = "") -> str:
    """Step-by-step alert walkthrough for Tier 1 SOC analysts.

    Designed for analysts who are new to Wazuh or to a particular alert type.
    Explains every step before executing it so the analyst builds understanding.
    """
    target = f'alert ID {alert_id}' if alert_id else 'the most recent high-severity alert'
    return f"""You are helping a Tier 1 SOC analyst investigate {target}.
Explain WHAT each tool does and WHY before calling it. Use simple language — assume the analyst
is learning on the job and may not know Wazuh terminology.

Step 1 — Get the alert details:
  Call: {'get_alert_by_id("' + alert_id + '")' if alert_id else 'explain_recent_alerts(time_range="1h", min_level=10, audience="tier1")'}
  Explain what each field means (rule.level, rule.description, agent.name, data.srcip).

Step 2 — Get a plain-English explanation:
  Call: explain_alert("{alert_id or '<id from step 1>'}", audience="tier1")
  Read the narrative aloud and confirm you understand the WHAT HAPPENED section.

Step 3 — Is the source IP suspicious?
  If there is a src_ip, call: enrich_ip("<src_ip>")
  Explain: VirusTotal score >5 = likely malicious. AbuseIPDB confidence >50 = block it.

Step 4 — Did Wazuh already respond?
  Call: correlate_alert_with_response(src_ip="<src_ip>")
  If active response fired = the IP was blocked. If not = we may need to act.

Step 5 — Decide and document:
  - False positive? → tag_alert(alert_id, tag="false_positive", note="your reason")
  - True positive, handled? → tag_alert(alert_id, tag="investigated")
  - Not sure? → Escalate to Tier 2 and describe what you found in Steps 1-4.

Remember: it is always OK to escalate. Document your findings before doing so."""


@mcp.prompt()
def tier2_analyst_deep_dive(agent_name: str = "", src_ip: str = "", time_range: str = "24h") -> str:
    """Deep-dive investigation workflow for experienced Tier 2 / IR analysts.

    Assumes familiarity with Wazuh, MITRE ATT&CK, and incident response procedures.
    Focuses on breadth-first evidence gathering followed by hypothesis testing.
    """
    target = f"agent '{agent_name}'" if agent_name else f"source IP '{src_ip}'" if src_ip else "the active incident"
    return f"""Tier 2 deep-dive investigation for {target} over the last {time_range}.

Phase 1 — Evidence collection (run in parallel where possible):
  search_alerts(time_range="{time_range}") filtered to target
  search_fim_alerts(time_range="{time_range}") — file integrity events
  {'get_agent_login_history(agent_name="' + agent_name + '")' if agent_name else 'search_authentication_failures(time_range="' + time_range + '", threshold=3)'}
  {'enrich_ip("' + src_ip + '")' if src_ip else 'get_agent_processes(agent_name="' + agent_name + '")'}
  {'enrich_ip_extended("' + src_ip + '")' if src_ip else ''}

Phase 2 — Lateral movement check:
  hunt_lateral_movement(time_range="{time_range}")
  get_agent_neighbors({'agent_name="' + agent_name + '"' if agent_name else ''})
  blast_radius_analysis({'src_ip="' + src_ip + '"' if src_ip else 'agent_name="' + agent_name + '"'}, time_range="{time_range}")

Phase 3 — Persistence check:
  hunt_persistence_mechanisms(time_range="{time_range}")
  critical_file_changes({'agent_name="' + agent_name + '"' if agent_name else ''}, time_range="{time_range}")

Phase 4 — MITRE mapping:
  search_by_mitre() on all technique IDs found in alerts above
  mitre_coverage_analysis() — confirm detection coverage for observed techniques

Phase 5 — Containment decision:
  Score findings: CONFIRMED / SUSPECTED / BENIGN
  If CONFIRMED HIGH/CRITICAL:
    run_active_response(agent_id, command="firewall-drop", src_ip="{src_ip or '?'}")  [requires ALLOW_WRITES]
    create_incident_report(alert_ids=[...], title="...", severity="HIGH")
    create_jira_ticket(summary="...", description="...", priority="High")
  Document all findings in create_workspace() for handover."""


@mcp.prompt()
def ciso_security_briefing(period: str = "7d") -> str:
    """Executive security briefing formatted for CISO / leadership consumption.

    No technical jargon. Business risk framing. Action items with owners.
    """
    return f"""Generate an executive security briefing for the last {period}.

Data collection (run these first):
  alert_summary(time_range="{period}", min_level=7)
  vulnerability_summary(min_severity="High")
  prioritize_patches(top_n=5)
  compliance_summary(framework="PCI-DSS")
  fleet_sca_weakest_agents(limit=3)
  active_response_effectiveness(time_range="{period}")

Format the output as:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY BRIEFING — {period.upper()} SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OVERALL RISK POSTURE:  [GREEN / YELLOW / RED]

KEY METRICS
  Total alerts:         [n]   vs prior period [n] ([+/-x%])
  Critical/High:        [n]   requiring immediate attention
  Systems monitored:    [n]   agents
  Unpatched CVEs (High+): [n]

TOP 3 RISKS THIS PERIOD
  1. [Risk name] — [1-sentence business impact] — Owner: [team]
  2. [Risk name] — [1-sentence business impact] — Owner: [team]
  3. [Risk name] — [1-sentence business impact] — Owner: [team]

COMPLIANCE STATUS
  [Framework]: [PASS/PARTIAL/FAIL] — [key finding]

ACTIONS REQUIRED
  • [Action] — Priority: [P0/P1/P2] — Due: [timeframe] — Owner: [team]

No further escalation required at this time. / Recommend emergency review."""


@mcp.prompt()
def compliance_officer_review(framework: str = "PCI-DSS", period: str = "30d") -> str:
    """Compliance review workflow for compliance officers and auditors.

    Maps security events to specific control requirements and produces
    audit-ready evidence summaries.
    """
    return f"""Run a {framework} compliance review for the last {period}.

Step 1 — Framework compliance status:
  compliance_summary(framework="{framework}", time_range="{period}")
  compliance_control_details(framework="{framework}")

Step 2 — Evidence collection:
  export_compliance_csv(framework="{framework}", time_range="{period}")
  generate_compliance_report(framework="{framework}")

Step 3 — Security controls verification:
  fleet_sca_weakest_agents(limit=10) — configuration compliance posture
  get_agent_sca_policies(agent_id=<worst agent>) — specific policy failures
  critical_file_changes(time_range="{period}") — file integrity evidence

Step 4 — Access control review:
  search_authentication_failures(time_range="{period}") — failed access attempts
  list_privileged_escalations(time_range="{period}") — privilege escalation events
  get_credential_age() — credential rotation compliance

Step 5 — Audit trail verification:
  verify_audit_log_integrity() — confirm logs are tamper-evident
  get_audit_log_stats() — coverage and completeness

Format output as audit-ready evidence with:
  Control ID | Requirement | Status | Evidence | Risk | Remediation

Flag any control failures with FAIL status and link to specific alert IDs as evidence.
Export final report with: email_compliance_report(framework="{framework}", recipient="compliance@yourorg.com")"""


# ============================================================================
# Entry point — HTTP (SSE) or STDIO
# ============================================================================

def main() -> None:
    import signal

    transport = os.getenv("WAZUH_MCP_TRANSPORT", "stdio")
    host = os.getenv("WAZUH_MCP_HOST", "0.0.0.0")
    port = int(os.getenv("WAZUH_MCP_PORT", "8000"))
    api_key = os.getenv("WAZUH_MCP_API_KEY", "")

    log.info(
        "Starting Wazuh MCP server — transport=%s host=%s port=%s writes=%s manager=%s indexer=%s",
        transport, host, port, cfg.allow_writes, cfg.manager_host, cfg.indexer_host,
    )

    # ── Auto-resume autonomous monitor if it was running before restart (Gap 2) ──
    from .state_store import load_monitor_state
    _saved_monitor = load_monitor_state()
    if _saved_monitor and _saved_monitor.get("running"):
        log.info(
            "Autonomous SOC monitor was active before restart — auto-resuming "
            "(interval=%ds threshold=%d)",
            _saved_monitor.get("interval_seconds", 60),
            _saved_monitor.get("severity_threshold", 10),
        )
        import asyncio as _asyncio
        from .tools.autonomous_soc import _monitor_state, _monitor_loop
        _monitor_state.update({
            "running": True,
            "interval_seconds": _saved_monitor.get("interval_seconds", 60),
            "severity_threshold": _saved_monitor.get("severity_threshold", 10),
            "started_at": _saved_monitor.get("started_at"),
            "alerts_processed": _saved_monitor.get("alerts_processed", 0),
            "actions_taken": _saved_monitor.get("actions_taken", 0),
            "seen_alert_ids": _saved_monitor.get("seen_alert_ids", []),
            "recent_actions": [],
        })
        try:
            loop = _asyncio.get_event_loop()
            task = loop.create_task(
                _monitor_loop(
                    wz, idx, cfg,
                    _saved_monitor.get("interval_seconds", 60),
                    _saved_monitor.get("severity_threshold", 10),
                    tool_registry=_TOOL_REGISTRY,
                )
            )
            _monitor_state["task"] = task
        except RuntimeError:
            log.warning("Could not auto-resume monitor — no running event loop at startup")

    if transport == "http":
        import uvicorn
        from starlette.applications import Starlette
        from .tls_config import build_uvicorn_tls_kwargs, tls_enabled
        from .body_limit import MaxBodySizeMiddleware
        from .security_headers import SecurityHeadersMiddleware
        from .ip_filter import IPFilterMiddleware
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse, Response
        from starlette.routing import Mount, Route
        from mcp.server.transport_security import TransportSecuritySettings

        # ── Gap 11: Prometheus metrics ─────────────────────────────────────
        try:
            from prometheus_client import (
                Counter, Histogram, Gauge,
                generate_latest, CONTENT_TYPE_LATEST,
            )
            _metrics_enabled = True
            _req_total   = Counter(
                "wazuh_mcp_requests_total",
                "Total MCP tool invocations",
                ["tool", "status"],
            )
            _req_duration = Histogram(
                "wazuh_mcp_request_duration_seconds",
                "MCP tool call duration in seconds",
                ["tool"],
                buckets=[.05, .1, .25, .5, 1, 2.5, 5, 10, 30],
            )
            _rate_limit_hits = Counter(
                "wazuh_mcp_rate_limit_hits_total",
                "Requests rejected by rate limiter",
            )
            _active_conns = Gauge(
                "wazuh_mcp_active_connections",
                "Current open HTTP connections",
            )
        except ImportError:
            _metrics_enabled = False
            log.info("prometheus_client not installed — /metrics disabled. "
                     "Add prometheus-client to requirements.txt to enable.")

        async def metrics_endpoint(request):  # type: ignore[no-untyped-def]
            if not _metrics_enabled:
                return Response(
                    "# prometheus_client not installed\n",
                    media_type="text/plain",
                    status_code=501,
                )
            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

        # ── OpenAPI spec endpoint ──────────────────────────────────────────
        async def openapi_endpoint(request):  # type: ignore[no-untyped-def]
            """Auto-generated OpenAPI 3.1 spec from registered MCP tool schemas."""
            tools_list = []
            for tool in mcp._tools.values():  # type: ignore[attr-defined]
                schema = getattr(tool, "parameters", {}) or {}
                tools_list.append({
                    "name": tool.name,
                    "description": (tool.description or "")[:300],
                    "inputSchema": schema,
                })
            spec = {
                "openapi": "3.1.0",
                "info": {
                    "title": "Wazuh MCP Server",
                    "version": "1.0.0",
                    "description": "Model Context Protocol bridge for Wazuh SIEM",
                },
                "paths": {
                    f"/tools/{t['name']}": {
                        "post": {
                            "summary": t["description"],
                            "operationId": t["name"],
                            "requestBody": {
                                "content": {
                                    "application/json": {"schema": t["inputSchema"]}
                                }
                            },
                            "responses": {"200": {"description": "Tool result"}},
                        }
                    }
                    for t in tools_list
                },
                "components": {},
            }
            return JSONResponse(spec)

        # ── Gap 10: Graceful SIGTERM shutdown ──────────────────────────────
        _uvicorn_server: list = []  # populated after server starts

        def _sigterm_handler(signum, frame):  # type: ignore[no-untyped-def]
            log.info(
                "SIGTERM received — initiating graceful shutdown "
                "(compose stop_grace_period gives 35s before SIGKILL)"
            )
            # Tell uvicorn to stop accepting new connections and drain
            if _uvicorn_server:
                _uvicorn_server[0].should_exit = True
            # Release HTTP connection pools
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(wz.aclose())
                loop.create_task(idx.aclose())

        signal.signal(signal.SIGTERM, _sigterm_handler)

        # ── /health endpoint (deep component health) ───────────────────────
        async def health_check(request):  # type: ignore[no-untyped-def]
            checks: dict = {}
            latencies: dict = {}

            # Manager API ping + version
            try:
                t0 = time.time()
                info = await wz.request("GET", "/")
                latencies["manager_api_ms"] = round((time.time() - t0) * 1000)
                checks["manager_api"] = "ok"
                mgr_version = (
                    (info.get("data") or {}).get("api_version") or
                    (info.get("data") or {}).get("version", "unknown")
                )
            except Exception as e:
                checks["manager_api"] = f"error: {str(e)[:80]}"
                mgr_version = "unknown"

            # Indexer cluster health + latency
            try:
                t0 = time.time()
                async with httpx.AsyncClient(
                    verify=cfg.verify_ssl,
                    auth=(cfg.indexer_user, cfg.indexer_pass),
                    timeout=5,
                ) as c:
                    r = await c.get(f"{cfg.indexer_host}/_cluster/health")
                    latencies["indexer_ms"] = round((time.time() - t0) * 1000)
                    if r.status_code == 200:
                        body = r.json()
                        checks["indexer"] = body.get("status", "unknown")
                        checks["indexer_nodes"] = body.get("number_of_nodes", 0)
                    else:
                        checks["indexer"] = "unreachable"
            except Exception as e:
                checks["indexer"] = f"error: {str(e)[:80]}"

            # Audit log writability
            try:
                from .audit import _AUDIT_LOG_PATH
                _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
                audit_size = _AUDIT_LOG_PATH.stat().st_size if _AUDIT_LOG_PATH.exists() else 0
                checks["audit_log"] = "writable"
                checks["audit_log_bytes"] = audit_size
            except Exception as e:
                checks["audit_log"] = f"error: {str(e)[:60]}"

            # Cache stats
            from .cache import cache_stats
            checks["cache"] = cache_stats()

            all_ok = all(
                v in ("ok", "green", "yellow") or "ok" in str(v)
                for k, v in checks.items()
                if k in ("manager_api", "indexer", "audit_log")
            )
            return JSONResponse(
                {
                    "status": "healthy" if all_ok else "degraded",
                    "uptime_seconds": round(time.time() - SERVER_START_TIME, 1),
                    "manager_version": mgr_version,
                    "checks": checks,
                    "latency_ms": latencies,
                    # Operational intelligence omitted from public /health to prevent
                    # unauthenticated reconnaissance (Gap 8 fix).
                },
                status_code=200 if all_ok else 503,
            )

        # ── Audit middleware — pure ASGI (no BaseHTTPMiddleware) ─────────────
        # BaseHTTPMiddleware consumes the request body stream, preventing the
        # MCP SDK from reading it. A raw ASGI middleware reads the body once,
        # then creates a replay receive() so downstream can still read it.
        _AUDIT_SKIP_PATHS = {"/health", "/sse", "/"}

        class AuditMiddleware:
            def __init__(self, app):
                self._app = app

            async def __call__(self, scope, receive, send):
                # Only intercept HTTP POST requests to MCP tool endpoints
                if scope["type"] != "http":
                    await self._app(scope, receive, send)
                    return

                path    = scope.get("path", "")
                method  = scope.get("method", "GET")

                if path in _AUDIT_SKIP_PATHS or method != "POST":
                    await self._app(scope, receive, send)
                    return

                # ── Read body once, then create a replay receive ──────────
                body_chunks: list[bytes] = []
                more_body = True
                while more_body:
                    msg = await receive()
                    body_chunks.append(msg.get("body", b""))
                    more_body = msg.get("more_body", False)
                body_bytes = b"".join(body_chunks)

                replayed = False
                async def replay_receive():
                    nonlocal replayed
                    if not replayed:
                        replayed = True
                        return {"type": "http.request", "body": body_bytes, "more_body": False}
                    # After replaying body, forward real disconnect events
                    return await receive()

                # ── Parse MCP JSON-RPC envelope ───────────────────────────
                try:
                    payload = json.loads(body_bytes) if body_bytes else {}
                except Exception:
                    payload = {}

                rpc_method = payload.get("method", "")
                if rpc_method == "tools/call":
                    p = payload.get("params", {})
                    tool_name = p.get("name", "unknown_tool")
                    tool_args = p.get("arguments", {})
                elif rpc_method:
                    tool_name = rpc_method
                    tool_args = payload.get("params", {})
                else:
                    tool_name = path
                    tool_args = {}

                # ── Identity from Authorization header ────────────────────
                import hashlib
                headers_raw = dict(scope.get("headers", []))
                auth_raw = headers_raw.get(b"authorization", b"").decode("utf-8", errors="replace")
                identity = (
                    hashlib.sha256(auth_raw.encode()).hexdigest()[:12]
                    if auth_raw else "anonymous"
                )

                # ── Capture response status via wrapped send ───────────────
                status_code: list[int] = [200]

                async def capture_send(message):
                    if message.get("type") == "http.response.start":
                        status_code[0] = message.get("status", 200)
                    await send(message)

                # ── Run app, write audit record, record Prometheus metrics ──
                exc_caught = None
                t0 = time.time()
                try:
                    await self._app(scope, replay_receive, capture_send)
                except Exception as exc:
                    exc_caught = exc
                finally:
                    result_label = "error" if exc_caught else str(status_code[0])
                    with audit_logger.record(tool_name, tool_args, identity=identity) as ctx:
                        ctx.set_result_code(result_label)
                    # Prometheus metrics (no-op if prometheus_client not installed)
                    if _metrics_enabled and rpc_method == "tools/call":
                        elapsed = time.time() - t0
                        _req_total.labels(tool=tool_name, status=result_label).inc()
                        _req_duration.labels(tool=tool_name).observe(elapsed)

                if exc_caught:
                    raise exc_caught

        # ── Optional Bearer-token middleware ───────────────────────────────
        import hmac as _hmac

        class APIKeyMiddleware(BaseHTTPMiddleware):
            def __init__(self, app, key: str) -> None:
                super().__init__(app)
                self._key = key

            async def dispatch(self, request, call_next):  # type: ignore[override]
                if self._key and request.url.path != "/health":
                    auth = request.headers.get("Authorization", "")
                    token = auth.removeprefix("Bearer ").strip()
                    # Constant-time comparison prevents timing-attack brute force
                    if not _hmac.compare_digest(token, self._key):
                        return Response("Unauthorized", status_code=401)
                return await call_next(request)

        # ── Origin validation middleware (CSRF protection) ─────────────────
        # Rejects requests whose Origin header is not in the allowlist.
        # Set WAZUH_MCP_ALLOWED_ORIGINS as a comma-separated list of trusted
        # origins (e.g. "https://claude.ai,https://your-dashboard.example.com").
        # When unset, same-host requests and requests without an Origin header
        # (non-browser clients, curl, MCP SDKs) pass through unrestricted.
        _raw_origins = os.getenv("WAZUH_MCP_ALLOWED_ORIGINS", "").strip()
        _allowed_origins: set[str] = (
            {o.strip().rstrip("/") for o in _raw_origins.split(",") if o.strip()}
            if _raw_origins else set()
        )

        class OriginValidationMiddleware:
            def __init__(self, app) -> None:
                self._app = app

            async def __call__(self, scope, receive, send) -> None:
                if scope["type"] != "http":
                    await self._app(scope, receive, send)
                    return

                headers = dict(scope.get("headers", []))
                origin = headers.get(b"origin", b"").decode("utf-8", errors="replace").rstrip("/")

                # Non-browser clients (SDKs, curl) send no Origin — allow through
                if not origin:
                    await self._app(scope, receive, send)
                    return

                path = scope.get("path", "")
                if path == "/health":
                    await self._app(scope, receive, send)
                    return

                # If an allowlist is configured, enforce it
                if _allowed_origins and origin not in _allowed_origins:
                    response = Response(
                        f"Origin '{origin}' not allowed. "
                        f"Set WAZUH_MCP_ALLOWED_ORIGINS to permit it.",
                        status_code=403,
                    )
                    await response(scope, receive, send)
                    return

                await self._app(scope, receive, send)

        # ── Assemble ASGI app ──────────────────────────────────────────────
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )
        mcp_asgi = mcp.sse_app()

        app = Starlette(
            routes=[
                Route("/health",      health_check),
                Route("/metrics",     metrics_endpoint),
                Route("/openapi.json", openapi_endpoint),
                Mount("/",            app=mcp_asgi),
            ]
        )

        # Middleware stack ordering (outermost runs FIRST on request, LAST on response):
        # 1. APIKeyMiddleware       — reject unauthenticated requests
        # 2. OriginValidationMiddleware — CSRF: block disallowed browser origins
        # 3. RateLimitMiddleware    — throttle authenticated requests
        # 4. AuditMiddleware        — log only authenticated, rate-allowed requests

        app = AuditMiddleware(app)  # type: ignore[assignment]
        log.info("Audit logging enabled → %s", os.getenv("WAZUH_AUDIT_LOG", "logs/audit.jsonl"))

        app = RateLimitMiddleware(app)  # type: ignore[assignment]
        log.info(
            "Rate limiting enabled — %s RPM per identity (burst +%s)",
            os.getenv("WAZUH_MCP_RATE_LIMIT_RPM", "60"),
            os.getenv("WAZUH_MCP_RATE_LIMIT_BURST", "10"),
        )

        app = OriginValidationMiddleware(app)  # type: ignore[assignment]
        if _allowed_origins:
            log.info("Origin validation enabled — allowed: %s", ", ".join(sorted(_allowed_origins)))
        else:
            log.info("Origin validation: passthrough (set WAZUH_MCP_ALLOWED_ORIGINS to restrict)")

        if api_key:
            app = APIKeyMiddleware(app, key=api_key)  # type: ignore[assignment]
            log.info("API key authentication enabled (outermost middleware — runs first)")
        else:
            log.info("API key authentication disabled — set WAZUH_MCP_API_KEY to enable")

        # IPFilterMiddleware — network allowlist/blocklist
        allowed_ips = os.getenv("WAZUH_MCP_ALLOWED_IPS", "")
        blocked_ips = os.getenv("WAZUH_MCP_BLOCKED_IPS", "")
        if allowed_ips or blocked_ips:
            app = IPFilterMiddleware(app)  # type: ignore[assignment]
            log.info(
                "IP filter enabled — allowed=%s blocked=%s",
                allowed_ips or "(all)",
                blocked_ips or "(none)",
            )

        # SecurityHeadersMiddleware — injects HSTS, CSP, X-Frame-Options etc.
        _tls_on = bool(os.getenv("WAZUH_MCP_TLS_CERT"))
        app = SecurityHeadersMiddleware(app, tls_enabled=_tls_on)  # type: ignore[assignment]
        log.info("Security headers middleware enabled (HSTS=%s)", _tls_on)

        # MaxBodySizeMiddleware — absolute outermost, guards everything below
        app = MaxBodySizeMiddleware(app)  # type: ignore[assignment]
        log.info(
            "Body size limit: %s KB (override with WAZUH_MCP_MAX_BODY_KB)",
            os.getenv("WAZUH_MCP_MAX_BODY_KB", "512"),
        )

        log.info("SSE routes: /sse (GET), /messages (POST), /health (GET), /metrics (GET)")
        tls_kwargs = build_uvicorn_tls_kwargs()
        if tls_kwargs:
            log.info(
                "TLS enabled — cert=%s%s",
                tls_kwargs.get("ssl_certfile"),
                f", mTLS CA={tls_kwargs['ssl_ca_certs']}" if "ssl_ca_certs" in tls_kwargs else "",
            )

        # Use uvicorn.Server directly so _sigterm_handler can set should_exit
        # for a clean 30-second graceful drain (Gap 10).
        uv_config = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="warning",
            timeout_graceful_shutdown=30,
            **tls_kwargs,
        )
        uv_server = uvicorn.Server(uv_config)
        _uvicorn_server.append(uv_server)  # expose to SIGTERM handler
        uv_server.run()
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
