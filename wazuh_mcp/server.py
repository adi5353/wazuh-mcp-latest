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
import datetime
import ipaddress
import json
import logging
import os
import sys
import time

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx
from mcp.server.fastmcp import FastMCP

from .audit import audit_logger, sanitize_response, cap_response_size, _sanitize_string
from .input_sanitizer import sanitize_input_value
from .config import Config
from .rbac import _current_role, _ROLE_NAMES
from .rate_limit import RateLimitMiddleware
from .helpers import trim_alert, trim_vuln, severities_at_or_above, time_window
from .wazuh_client import WazuhClient
from .wazuh_indexer import WazuhIndexer

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

# ── Response sanitization wrapper (Gap 7 + Gap 9) ────────────────────────────
# Intercept every @mcp.tool() registration so tool return values are sanitized
# before reaching the LLM. Strips prompt injection tokens and plaintext secrets.
_original_mcp_tool = mcp.tool


def _sanitizing_tool_decorator(*args, **kwargs):
    """Wrap mcp.tool() to enforce input sanitization and output sanitization on every tool.

    Input pass:  screens all string/list/dict kwargs for injection patterns,
                 length limits, and dangerous characters before the tool runs.
    Output pass: strips prompt injection tokens, executable code, plaintext
                 secrets, and PII from the result; caps oversized responses.
    Covers dict, str, and list return types (previously only dict was handled).
    """
    import functools

    decorator = _original_mcp_tool(*args, **kwargs)

    def wrapping_decorator(fn):
        @functools.wraps(fn)
        async def sanitized_fn(*fn_args, **fn_kwargs):
            # ── INPUT sanitization ────────────────────────────────────────────
            clean_kwargs: dict = {}
            for field, value in fn_kwargs.items():
                try:
                    clean_kwargs[field] = sanitize_input_value(value, field)
                except ValueError as exc:
                    return {"error": f"Input rejected: {exc}"}

            # ── Tool execution ────────────────────────────────────────────────
            result = await fn(*fn_args, **clean_kwargs)

            # ── OUTPUT sanitization ───────────────────────────────────────────
            if isinstance(result, dict):
                result = sanitize_response(result)
            elif isinstance(result, str):
                result = _sanitize_string(result)
            elif isinstance(result, list):
                result = [
                    sanitize_response(item) if isinstance(item, dict)
                    else (_sanitize_string(item) if isinstance(item, str) else item)
                    for item in result
                ]

            result = cap_response_size(result)
            return result

        return decorator(sanitized_fn)

    return wrapping_decorator


mcp.tool = _sanitizing_tool_decorator  # type: ignore[method-assign]

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


# ── Inline MITRE technique ID → name/tactic table (no network call needed) ───
_MITRE_MAP: dict[str, dict] = {
    "T1003": {"name": "OS Credential Dumping",              "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services",                    "tactic": "Lateral Movement"},
    "T1027": {"name": "Obfuscated Files or Information",    "tactic": "Defense Evasion"},
    "T1053": {"name": "Scheduled Task/Job",                 "tactic": "Persistence"},
    "T1055": {"name": "Process Injection",                  "tactic": "Defense Evasion"},
    "T1059": {"name": "Command and Scripting Interpreter",  "tactic": "Execution"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1071": {"name": "Application Layer Protocol",         "tactic": "Command and Control"},
    "T1078": {"name": "Valid Accounts",                     "tactic": "Persistence"},
    "T1082": {"name": "System Information Discovery",       "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery",       "tactic": "Discovery"},
    "T1098": {"name": "Account Manipulation",               "tactic": "Persistence"},
    "T1105": {"name": "Ingress Tool Transfer",              "tactic": "Command and Control"},
    "T1110": {"name": "Brute Force",                        "tactic": "Credential Access"},
    "T1112": {"name": "Modify Registry",                    "tactic": "Defense Evasion"},
    "T1190": {"name": "Exploit Public-Facing Application",  "tactic": "Initial Access"},
    "T1219": {"name": "Remote Access Software",             "tactic": "Command and Control"},
    "T1543": {"name": "Create or Modify System Process",    "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism",  "tactic": "Privilege Escalation"},
    "T1562": {"name": "Impair Defenses",                    "tactic": "Defense Evasion"},
    "T1569": {"name": "System Services",                    "tactic": "Execution"},
}


def _enrich_mitre_ids(technique_ids: list) -> list:
    enriched = []
    for tid in technique_ids:
        base_id = tid.split(".")[0]
        info = _MITRE_MAP.get(base_id, {})
        enriched.append({
            "id": tid,
            "name": info.get("name", "Unknown Technique"),
            "tactic": info.get("tactic", "Unknown"),
        })
    return enriched


def _incident_recommendations(techniques: list, severity: str, src_ips: list) -> list:
    recs: list[str] = []
    t = [x.lower() for x in techniques]
    if severity in ("CRITICAL", "HIGH"):
        recs.append("Isolate affected agents immediately and capture memory dumps if possible.")
    if any(k in x for x in t for k in ("brute", "credential", "password")):
        recs.append("Reset credentials for all accounts active on affected agents.")
        recs.append("Enable MFA if not already enforced.")
    if any(k in x for x in t for k in ("lateral", "remote")):
        recs.append("Review SMB/RDP/WinRM connections from affected agents to peer systems.")
    if any(k in x for x in t for k in ("persist", "scheduled", "registry")):
        recs.append("Audit startup items, scheduled tasks, and registry run keys on affected agents.")
    if src_ips:
        recs.append(f"Block source IPs via CDB list or firewall: {', '.join(src_ips[:5])}")
    if not recs:
        recs.append("Review alerts manually and escalate if activity continues.")
    return recs


async def _geoip_lookup(ip: str) -> dict:
    """Free GeoIP via ip-api.com — no key required, 45 req/min."""
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback:
            return {"ip": ip, "geo": "private/local"}
    except ValueError:
        return {"ip": ip, "geo": "invalid_ip"}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,city,isp,as"},
            )
            data = r.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "asn": data.get("as", ""),
                }
    except Exception:
        pass
    return {"ip": ip, "geo": "lookup_failed"}


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
_playbooks_module.register(mcp, wz, idx, cfg)
_net_topology_module.register(mcp, wz, idx, cfg, _cap)
_autonomous_soc_module.register(mcp, wz, idx, cfg)
_baseline_module.register(mcp, wz, idx, cfg, _cap)
_ueba_module.register(mcp, wz, idx, cfg, _cap)
_scheduler_module.register(mcp, wz, idx, cfg)

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

    if transport == "http":
        import uvicorn
        from starlette.applications import Starlette
        from .tls_config import build_uvicorn_tls_kwargs, tls_enabled
        from .body_limit import MaxBodySizeMiddleware
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

        signal.signal(signal.SIGTERM, _sigterm_handler)

        # ── /health endpoint ───────────────────────────────────────────────
        async def health_check(request):  # type: ignore[no-untyped-def]
            checks: dict = {}
            # Manager API ping
            try:
                await wz.request("GET", "/")
                checks["manager_api"] = "ok"
            except Exception as e:
                checks["manager_api"] = f"error: {str(e)[:80]}"
            # Indexer cluster health
            try:
                async with httpx.AsyncClient(
                    verify=cfg.verify_ssl,
                    auth=(cfg.indexer_user, cfg.indexer_pass),
                    timeout=5,
                ) as c:
                    r = await c.get(f"{cfg.indexer_host}/_cluster/health")
                    status = r.json().get("status", "unknown") if r.status_code == 200 else "unreachable"
                    checks["indexer"] = status
            except Exception as e:
                checks["indexer"] = f"error: {str(e)[:80]}"

            all_ok = all(
                v in ("ok", "green", "yellow") or "ok" in str(v)
                for v in checks.values()
            )
            return JSONResponse(
                {
                    "status": "healthy" if all_ok else "degraded",
                    "uptime_seconds": round(time.time() - SERVER_START_TIME, 1),
                    "checks": checks,
                    # Operational intelligence omitted from public /health to prevent
                    # unauthenticated reconnaissance (Gap 8 fix — use /status for details).
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

        # ── Assemble ASGI app ──────────────────────────────────────────────
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )
        mcp_asgi = mcp.sse_app()

        app = Starlette(
            routes=[
                Route("/health", health_check),
                Route("/metrics", metrics_endpoint),
                Mount("/", app=mcp_asgi),
            ]
        )

        # Middleware stack ordering (outermost runs FIRST on request, LAST on response):
        # 1. APIKeyMiddleware  — reject unauthenticated requests before anything else
        # 2. RateLimitMiddleware — throttle authenticated requests
        # 3. AuditMiddleware  — log only authenticated, rate-allowed requests
        # This prevents unauthenticated probe patterns from appearing in audit logs.

        app = AuditMiddleware(app)  # type: ignore[assignment]
        log.info("Audit logging enabled → %s", os.getenv("WAZUH_AUDIT_LOG", "logs/audit.jsonl"))

        app = RateLimitMiddleware(app)  # type: ignore[assignment]
        log.info(
            "Rate limiting enabled — %s RPM per identity (burst +%s)",
            os.getenv("WAZUH_MCP_RATE_LIMIT_RPM", "60"),
            os.getenv("WAZUH_MCP_RATE_LIMIT_BURST", "10"),
        )

        if api_key:
            app = APIKeyMiddleware(app, key=api_key)  # type: ignore[assignment]
            log.info("API key authentication enabled (outermost middleware — runs first)")
        else:
            log.info("API key authentication disabled — set WAZUH_MCP_API_KEY to enable")

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
