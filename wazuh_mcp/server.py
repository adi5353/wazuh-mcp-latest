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
import contextvars
import json
import logging
import os
import sys
import time
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from .audit import audit_logger, sanitize_response, cap_response_size, sanitize_string
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

# ── H1: /health auth check — pure function, module-level for testability ──────

import hmac as _hmac_module  # noqa: E402 — placed here to keep close to usage


async def _health_caller_is_authenticated_fn(request: Any, api_key: str) -> bool:
    """Return True when *request* carries the valid API-key bearer token.

    Pure function (no globals) so tests can call it directly.
    Returns False if *api_key* is empty — no key configured means no
    authenticated health callers (prevents timing-oracle on an empty secret).
    """
    if not api_key:
        return False
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        return False
    return _hmac_module.compare_digest(token.encode(), api_key.encode())


# ── Global config ─────────────────────────────────────────────────────────────
cfg = Config.from_env()
wz = WazuhClient(cfg)
idx = WazuhIndexer(cfg)

# Per-session context variables — each asyncio task (i.e. each MCP request) gets
# its own tenant client without affecting other concurrent sessions.
_ctx_wz: contextvars.ContextVar[WazuhClient] = contextvars.ContextVar("_ctx_wz")
_ctx_idx: contextvars.ContextVar[WazuhIndexer] = contextvars.ContextVar("_ctx_idx")
_ctx_active_tenant: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "_ctx_active_tenant", default={}
)


class _ClientProxy:
    """Session-scoped proxy for WazuhClient/WazuhIndexer.

    All tool-module closures capture this proxy by reference.  Attribute access
    resolves the underlying client from a per-task ContextVar, so switch_tenant()
    only affects the calling session — other concurrent sessions are untouched.
    """

    def __init__(self, default_client, ctx_var: contextvars.ContextVar):
        self._default = default_client
        self._ctx_var = ctx_var

    def replace(self, new_client) -> contextvars.Token:
        """Bind *new_client* to the current asyncio task only."""
        return self._ctx_var.set(new_client)

    def reset(self, token: contextvars.Token) -> None:
        """Restore the previous client binding for the current task."""
        self._ctx_var.reset(token)

    def __getattr__(self, name: str):
        client = self._ctx_var.get(self._default)
        return getattr(client, name)


_wz_proxy = _ClientProxy(wz, _ctx_wz)
_idx_proxy = _ClientProxy(idx, _ctx_idx)

MAX_RESULTS_GLOBAL = int(os.getenv("WAZUH_MAX_RESULTS_GLOBAL", "500"))
SERVER_START_TIME = time.time()

mcp = FastMCP("wazuh")

# ── Tool registry for playbook engine ────────────────────────────────────────
# Maps tool_name → async callable so run_playbook can invoke tools directly.
_TOOL_REGISTRY: dict[str, Any] = {}

# ── Single middleware: sanitization + registry capture (replaces two monkey-patches) ──
_tool_mw = ToolMiddleware(mcp, _TOOL_REGISTRY)
_tool_mw.install()

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


# ── Build a single ToolContext shared by all modules ──────────────────────────
# _enrich_mitre_ids → wazuh_mcp/mitre_data.py
# _geoip_lookup     → wazuh_mcp/geo.py
# _incident_recommendations → wazuh_mcp/triage.py

from .tool_context import ToolContext  # noqa: E402

_ctx = ToolContext(
    mcp=mcp,
    wz=_wz_proxy,
    idx=_idx_proxy,
    cfg=cfg,
    cap=_cap,
    require_writes=_require_writes,
    truncate=_truncate,
    enrich_mitre_ids=_enrich_mitre_ids,
    geoip_lookup=_geoip_lookup,
    incident_recommendations=_incident_recommendations,
    tool_registry=_TOOL_REGISTRY,
)

# ── Auto-discover and register all tool modules ───────────────────────────────
# Each module in wazuh_mcp/tools/ exposes register(ctx: ToolContext).
# Modules are registered in alphabetical order except that `notifications`
# is deferred to the end so compliance and reporting can write their callables
# into ctx.shared first.
import importlib  # noqa: E402
import pkgutil    # noqa: E402
from . import tools as _tools_pkg  # noqa: E402

_DEFERRED = {"notifications"}   # registered after all others; reads ctx.shared

_TOOL_MODULE_ALLOWLIST = frozenset({
    "active_response", "agent_health", "agent_upgrades", "agents", "alerts",
    "archive", "audit_mgmt", "autonomous_soc", "azure_devops", "baseline",
    "cdb", "cluster", "compliance", "correlation", "credential_mgmt",
    "cve_watchlist", "explain_alert", "export", "fim", "fleet", "geo_intel",
    "health_check", "incidents", "index_mgmt", "integrations", "manager_audit",
    "manager_config", "metrics", "mitre", "network_topology", "notifications",
    "onboarding", "pagerduty", "playbooks", "prompt_advisor", "quick_wins",
    "reporting", "roi", "rootcheck", "rule_wizard", "rules", "sca",
    "scheduler", "servicenow", "suppression", "syslog_config", "threat_feeds",
    "threat_hunting", "threat_intel", "ueba", "vulnerabilities", "workspaces",
    "rule_wizard_generate", "rule_wizard_validate", "rule_wizard_deploy",
})

for _importer, _modname, _ispkg in pkgutil.iter_modules(_tools_pkg.__path__):
    if _modname == "__init__" or _modname in _DEFERRED:
        continue
    if _modname not in _TOOL_MODULE_ALLOWLIST:
        log.warning("Skipping unrecognised tool module %r — not in allowlist", _modname)
        continue
    _mod = importlib.import_module(f".tools.{_modname}", package="wazuh_mcp")
    if hasattr(_mod, "register"):
        # Dynamic role-based tool registration: skip modules the session role
        # cannot access. This keeps LLM context lean — a VIEWER session sees
        # ~60 tools instead of 130+, reducing hallucinated tool selection.
        _required = getattr(_mod, "REQUIRED_ROLE", ROLE.VIEWER)
        if _current_role() < _required:
            log.info(
                "Skipping tool module '%s' (requires %s, current session role is lower)",
                _modname, _ROLE_NAMES.get(_required, str(_required)),
            )
            continue
        try:
            _mod.register(_ctx)
        except Exception as _e:
            log.error("Failed to register tool module %s: %s", _modname, _e)

# Register deferred modules (those that depend on ctx.shared populated above)
for _modname in _DEFERRED:
    _mod = importlib.import_module(f".tools.{_modname}", package="wazuh_mcp")
    if hasattr(_mod, "register"):
        try:
            _mod.register(_ctx)
        except Exception as _e:
            log.error("Failed to register deferred tool module %s: %s", _modname, _e)

# ── MCP Resources ─────────────────────────────────────────────────────────────
from . import resources as _resources_module  # noqa: E402
_resources_module.register(mcp, _wz_proxy, _idx_proxy, cfg)

# ── Enrichment pipeline tools (P3) ────────────────────────────────────────────

@mcp.tool()
async def enrich_alert_full(alert_id: str) -> dict:
    """Fully enrich a single alert with GeoIP, MITRE details, agent context,
    reputation (VirusTotal/AbuseIPDB), and historical rule frequency.

    Runs all enrichers concurrently for minimal latency.

    Args:
        alert_id: Wazuh alert document ID (from get_alert_by_id or search_alerts).
    """
    from .rbac import require_role, ROLE
    err = require_role(ROLE.ANALYST)
    if err:
        return err

    try:
        resp = await idx.search(
            {"query": {"ids": {"values": [alert_id]}}, "size": 1}
        )
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return {"error": f"Alert '{alert_id}' not found"}
        alert = hits[0].get("_source", {})
        alert["_id"] = alert_id
    except Exception as exc:
        return {"error": f"Failed to fetch alert: {exc}"}

    from .enrichment.pipeline import enrich_alert
    enriched = await enrich_alert(alert, wz=wz, idx=idx, cfg=cfg)
    return {"alert_id": alert_id, "enriched": enriched}


@mcp.tool()
async def enrich_alerts_batch(alert_ids: list, max_concurrent: int = 5) -> dict:
    """Enrich a batch of alerts concurrently with the full enrichment pipeline.

    Args:
        alert_ids:      List of alert document IDs (up to 20).
        max_concurrent: Maximum parallel enrichment workers. Default 5.
    """
    from .rbac import require_role, ROLE
    err = require_role(ROLE.ANALYST)
    if err:
        return err

    alert_ids = alert_ids[:20]
    try:
        resp = await idx.search(
            {"query": {"ids": {"values": alert_ids}}, "size": len(alert_ids)}
        )
        hits = resp.get("hits", {}).get("hits", [])
    except Exception as exc:
        return {"error": f"Failed to fetch alerts: {exc}"}

    alerts = [{"_id": h["_id"], **h.get("_source", {})} for h in hits]
    from .enrichment.pipeline import enrich_alerts_batch as _batch
    enriched = await _batch(alerts, wz=wz, idx=idx, cfg=cfg, max_concurrent=max_concurrent)
    return {"enriched_count": len(enriched), "alerts": enriched}


# ── Session identity tool (Gap 1) ─────────────────────────────────────────────

@mcp.tool()
async def set_session_role_tool(api_key: str) -> dict:
    """Authenticate this session with an API key and bind its role.

    Configure API keys via WAZUH_MCP_KEY_MAP env var:
        WAZUH_MCP_KEY_MAP=viewer:key_abc,analyst:key_def,admin:key_xyz

    If WAZUH_MCP_KEY_MAP is not set, this tool has no effect and the server
    falls back to WAZUH_MCP_USER_ROLE (single-user mode).

    HTTP transport: this tool is DISABLED. A request's role is derived from the
    authenticated bearer token in the request middleware, never from a tool
    argument — otherwise any caller could self-elevate. Use stdio for the
    single-local-user set-role workflow.
    """
    if not os.getenv("WAZUH_MCP_KEY_MAP", "").strip():
        return {
            "error": (
                "set_session_role requires WAZUH_MCP_KEY_MAP to be configured. "
                "Without a key map, role is fixed to WAZUH_MCP_USER_ROLE env var "
                "and cannot be changed via tool call."
            )
        }
    if os.getenv("WAZUH_MCP_TRANSPORT", "stdio") == "http":
        return {
            "error": (
                "set_session_role is only available in stdio transport. In HTTP "
                "mode the session role is derived from your authenticated API key "
                "(WAZUH_MCP_KEY_MAP); it cannot be set via a tool argument."
            )
        }
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
    active = _ctx_active_tenant.get({})
    return {
        "mssp_mode": True,
        "active_tenant": active.get("name", "(default)"),
        "tenants": [
            {"name": t.name, "manager_host": t.manager_host}
            for t in cfg.tenants
        ],
    }


@mcp.tool()
async def switch_tenant(tenant_name: str) -> dict:
    """Switch the active Wazuh tenant for this session (MSSP mode).

    After switching, all subsequent tool calls in this session query the
    selected tenant's Wazuh Manager and Indexer.  Other concurrent sessions
    are not affected.  Requires WAZUH_INSTANCES to be configured.

    Args:
        tenant_name: The name of the tenant as defined in WAZUH_INSTANCES.
    """
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

    new_wz = _WC(tenant_cfg)
    new_idx = _WI(tenant_cfg)

    # Bind the new clients to this session's asyncio task context only.
    # Other sessions continue using their own (possibly different) clients.
    _wz_proxy.replace(new_wz)
    _idx_proxy.replace(new_idx)
    _ctx_active_tenant.set({"name": tenant.name, "manager_host": tenant.manager_host})

    log.info("MSSP tenant switched to '%s' (%s)", tenant.name, tenant.manager_host)
    return {
        "status": "ok",
        "active_tenant": tenant.name,
        "manager_host": tenant.manager_host,
        "message": f"All subsequent tool calls in this session now target tenant '{tenant.name}'.",
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
# Prompt builders live in wazuh_mcp/prompts.py. Import them here so they remain
# accessible as ``server.<name>`` (backwards compat) and register them with the
# MCP instance.
from .prompts import (  # noqa: E402
    register_prompts,
    investigate_brute_force,
    weekly_soc_briefing,
    triage_alert,
    cve_emergency_response,
    morning_briefing,
    incident_triage_full,
    threat_hunt_session,
    end_of_shift_handover,
    tier1_analyst_guide,
    tier2_analyst_deep_dive,
    ciso_security_briefing,
    compliance_officer_review,
    executive_summary,
    compliance_audit_prep,
    post_incident_review,
    new_analyst_onboarding,
)

register_prompts(mcp)

# ============================================================================
# Entry point — HTTP (SSE) or STDIO
# ============================================================================

def _is_loopback_host(host: str) -> bool:
    """True if *host* binds only to the local machine (no remote exposure)."""
    h = (host or "").strip().lower()
    if h in ("localhost", "::1", ""):
        return True
    try:
        import ipaddress as _ipaddress
        return _ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _check_bind_security(transport: str, host: str, api_key: str) -> None:
    """Secure-by-default bind guard (Issue 1).

    Refuse to expose the server on a non-loopback address without authentication
    unless WAZUH_MCP_ALLOW_INSECURE_BIND=true is explicitly set (logs a warning).
    Raises SystemExit(2) when refusing.
    """
    if transport != "http" or _is_loopback_host(host) or api_key:
        return
    allow_insecure = os.getenv("WAZUH_MCP_ALLOW_INSECURE_BIND", "false").strip().lower() == "true"
    if not allow_insecure:
        log.error(
            "Refusing to start: WAZUH_MCP_HOST=%s is non-loopback but no "
            "WAZUH_MCP_API_KEY is set. Either set WAZUH_MCP_API_KEY, bind to "
            "127.0.0.1, or (NOT recommended) set WAZUH_MCP_ALLOW_INSECURE_BIND=true.",
            host,
        )
        raise SystemExit(2)
    log.warning(
        "INSECURE BIND: serving on non-loopback host %s with NO API key "
        "because WAZUH_MCP_ALLOW_INSECURE_BIND=true. Anyone who can reach "
        "this port has full access. Set WAZUH_MCP_API_KEY immediately.",
        host,
    )


def _origin_request_allowed(
    origin: str,
    *,
    is_loopback: bool,
    has_auth: bool,
    allowed_origins: set,
) -> bool:
    """CSRF/origin decision (Issue 5). Pure function — easy to unit-test.

    * No Origin header (SDK/curl): allowed, except on a non-loopback bind with no
      API-key auth.
    * Origin present + allowlist configured: enforce it.
    * Origin present, no allowlist, non-loopback: deny browser origins by default.
    * Origin present, no allowlist, loopback: passthrough (dev-friendly).
    """
    if not origin:
        return is_loopback or has_auth
    if allowed_origins:
        return origin in allowed_origins
    if not is_loopback:
        return False
    return True


def main() -> None:
    import signal

    transport = os.getenv("WAZUH_MCP_TRANSPORT", "stdio")
    host = os.getenv("WAZUH_MCP_HOST", "127.0.0.1")
    port = int(os.getenv("WAZUH_MCP_PORT", "8000"))
    api_key = os.getenv("WAZUH_MCP_API_KEY", "")

    _check_bind_security(transport, host, api_key)

    log.info(
        "Starting Wazuh MCP server — transport=%s host=%s port=%s writes=%s manager=%s indexer=%s",
        transport, host, port, cfg.allow_writes, cfg.manager_host, cfg.indexer_host,
    )

    # ── Auto-resume autonomous monitor if it was running before restart (Gap 2) ──
    # Gated behind WAZUH_MCP_AUTO_RESUME_MONITOR (default false): a background
    # loop that acts on alerts must not silently restart on every reboot.
    _auto_resume = os.getenv("WAZUH_MCP_AUTO_RESUME_MONITOR", "false").strip().lower() == "true"
    from .state_store import load_monitor_state
    _saved_monitor = load_monitor_state()
    if _saved_monitor and _saved_monitor.get("running") and not _auto_resume:
        log.warning(
            "Autonomous SOC monitor was active before restart but auto-resume is "
            "disabled (set WAZUH_MCP_AUTO_RESUME_MONITOR=true to re-enable). "
            "Call start_autonomous_monitor to resume manually."
        )
    if _saved_monitor and _saved_monitor.get("running") and _auto_resume:
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
            _metrics_api_key = os.getenv("WAZUH_MCP_API_KEY", "").strip()
            if not await _health_caller_is_authenticated_fn(request, _metrics_api_key):
                return Response(
                    '{"error": "Authentication required"}',
                    media_type="application/json",
                    status_code=401,
                )
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
            # L3: mcp._tools is a private SDK attribute that may change between
            # releases.  Use it when available; fall back to the public tool-list
            # API or the locally-maintained _TOOL_REGISTRY as a last resort.
            tools_list = []
            try:
                # Preferred: public API (MCP SDK >= 1.2)
                tool_iter = mcp.get_tools() if callable(getattr(mcp, "get_tools", None)) else None
                if tool_iter is None:
                    # Fall back to private attr (MCP SDK < 1.2) under try/except
                    _raw = mcp._tools  # type: ignore[attr-defined]
                    tool_iter = _raw.values()
                for tool in tool_iter:
                    schema = getattr(tool, "parameters", None) or getattr(tool, "inputSchema", {}) or {}
                    tools_list.append({
                        "name": getattr(tool, "name", str(tool)),
                        "description": (getattr(tool, "description", None) or "")[:300],
                        "inputSchema": schema,
                    })
            except AttributeError:
                # Private SDK attribute unavailable — use local registry as fallback.
                for tool_name in _TOOL_REGISTRY:
                    tools_list.append({
                        "name": tool_name,
                        "description": "",
                        "inputSchema": {},
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
            from .tools.threat_intel import close_shared_ti_clients
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_wz_proxy._client.aclose())
                loop.create_task(_idx_proxy._client.aclose())
                loop.create_task(close_shared_ti_clients())

        signal.signal(signal.SIGTERM, _sigterm_handler)

        # ── /health endpoint (deep component health) ───────────────────────
        # H1: unauthenticated callers receive ONLY {status, uptime_seconds}.
        # Authenticated callers (valid WAZUH_MCP_API_KEY bearer) get full detail.
        _health_api_key = os.getenv("WAZUH_MCP_API_KEY", "").strip()

        async def _health_caller_is_authenticated(request) -> bool:  # type: ignore[no-untyped-def]
            """Delegate to module-level pure function (testable)."""
            return await _health_caller_is_authenticated_fn(request, _health_api_key)

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

            # Fix 9: secret backend connectivity check
            try:
                from .secrets_backend import _backend, _loaded, _cache as _sb_cache
                checks["secrets_backend"] = {
                    "backend": _backend or "env",
                    "loaded": _loaded,
                    "cached_secrets": len(_sb_cache),
                    "status": "ok" if _loaded else "not_loaded",
                }
            except Exception as _sb_err:
                checks["secrets_backend"] = {"status": f"error: {_sb_err}"}
            checks["cache"] = cache_stats()

            all_ok = all(
                v in ("ok", "green", "yellow") or "ok" in str(v)
                for k, v in checks.items()
                if k in ("manager_api", "indexer", "audit_log")
            )
            # H1: restrict detailed health intel to authenticated callers only.
            status_str = "healthy" if all_ok else "degraded"
            public_body = {
                "status": status_str,
                "uptime_seconds": round(time.time() - SERVER_START_TIME, 1),
            }
            if await _health_caller_is_authenticated(request):
                full_body = {
                    **public_body,
                    "manager_version": mgr_version,
                    "checks": checks,
                    "latency_ms": latencies,
                }
                return JSONResponse(full_body, status_code=200 if all_ok else 503)
            return JSONResponse(public_body, status_code=200 if all_ok else 503)

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

                # ── Bind session role from the AUTHENTICATED bearer token (Issue 3) ──
                # Role is derived from the verified key here, before tool dispatch,
                # so it can never be set by a tool argument. Runs in the same task
                # context as the downstream app, so the ContextVar propagates.
                if auth_raw:
                    _bearer = auth_raw.removeprefix("Bearer ").strip()
                    _resolved_role = resolve_role_for_key(_bearer)
                    if _resolved_role is not None:
                        set_session_role(_resolved_role)

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
                    # M2: bind token as identity key so cross-request injection
                    # counter accumulates per authenticated caller across requests.
                    from .identity import set_identity_key as _set_id_key
                    _set_id_key(token)
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
            def __init__(self, app, *, is_loopback: bool, has_auth: bool) -> None:
                self._app = app
                self._is_loopback = is_loopback
                self._has_auth = has_auth

            async def __call__(self, scope, receive, send) -> None:
                if scope["type"] != "http":
                    await self._app(scope, receive, send)
                    return

                path = scope.get("path", "")
                if path == "/health":
                    await self._app(scope, receive, send)
                    return

                headers = dict(scope.get("headers", []))
                origin = headers.get(b"origin", b"").decode("utf-8", errors="replace").rstrip("/")

                async def _deny(message: str) -> None:
                    await Response(message, status_code=403)(scope, receive, send)

                # Delegate to the module-level pure function (testable without HTTP).
                if not _origin_request_allowed(
                    origin,
                    is_loopback=self._is_loopback,
                    has_auth=self._has_auth,
                    allowed_origins=_allowed_origins,
                ):
                    msg = (
                        f"Origin '{origin}' not allowed. Set WAZUH_MCP_ALLOWED_ORIGINS "
                        f"to permit it."
                        if origin else
                        "Origin-less requests require API-key authentication when "
                        "bound to a non-loopback address. Set WAZUH_MCP_API_KEY."
                    )
                    await Response(msg, status_code=403)(scope, receive, send)
                    return

                await self._app(scope, receive, send)

        # ── Assemble ASGI app ──────────────────────────────────────────────
        # ── DNS-rebinding protection (Issue 2) ─────────────────────────────
        # Enabled by default. Host header must match the server's bind host or
        # an entry in WAZUH_MCP_ALLOWED_HOSTS. mcp-remote users behind a proxy
        # or DNS name MUST add that name to WAZUH_MCP_ALLOWED_HOSTS.
        _allowed_hosts_env = os.getenv("WAZUH_MCP_ALLOWED_HOSTS", "").strip()
        _allowed_hosts: set[str] = {
            host, f"{host}:{port}",
            "localhost", f"localhost:{port}",
            "127.0.0.1", f"127.0.0.1:{port}",
        }
        _allowed_hosts |= {h.strip() for h in _allowed_hosts_env.split(",") if h.strip()}
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=sorted(_allowed_hosts),
            allowed_origins=sorted(_allowed_origins),
        )
        log.info(
            "DNS-rebinding protection enabled — allowed_hosts=%s (add your "
            "server host to WAZUH_MCP_ALLOWED_HOSTS if mcp-remote gets HTTP 421)",
            ", ".join(sorted(_allowed_hosts)),
        )
        mcp_asgi = mcp.sse_app()

        # ── Lifespan: start/stop background AlertPrecomputer ──────────────
        from contextlib import asynccontextmanager as _asynccontextmanager
        from .background import init_precomputer as _init_precomputer

        async def _approval_cleanup_loop() -> None:
            """Periodically evict stale approval tokens (runs every 5 minutes)."""
            from .approval import approval_store as _approval_store
            while True:
                try:
                    await asyncio.sleep(300)
                    removed = _approval_store.expire_stale()
                    if removed:
                        log.info("Approval cleanup: removed %d stale token(s)", removed)
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    log.error("Approval cleanup error: %s", exc)

        @_asynccontextmanager
        async def _lifespan(app):
            _pc = _init_precomputer(_idx_proxy, cfg)
            _pc.start()
            log.info("Background AlertPrecomputer started")
            _cleanup_task = asyncio.create_task(
                _approval_cleanup_loop(), name="approval-cleanup"
            )
            log.info("Background approval token cleanup started (every 300s)")
            yield
            _pc.stop()
            _cleanup_task.cancel()
            log.info("Background AlertPrecomputer and approval cleanup stopped")

        from .ws_alerts import ws_alerts_handler
        from starlette.routing import WebSocketRoute
        from starlette.websockets import WebSocket as _WS

        async def _ws_alerts_endpoint(ws: _WS) -> None:
            await ws_alerts_handler(ws, idx=idx, cfg=cfg)

        app = Starlette(
            routes=[
                Route("/health",           health_check),
                Route("/metrics",          metrics_endpoint),
                Route("/openapi.json",     openapi_endpoint),
                WebSocketRoute("/ws/alerts", endpoint=_ws_alerts_endpoint),
                Mount("/",                 app=mcp_asgi),
            ],
            lifespan=_lifespan,
        )

        # Middleware stack — each app = Foo(app) wraps an extra OUTER layer.
        # The LAST assignment is the outermost layer and therefore runs FIRST on
        # each incoming request.  Wrapping order (innermost → outermost):
        #
        #   innermost (runs last)
        #   4. AuditMiddleware          — log after auth + rate-limit checks pass
        #   3. RateLimitMiddleware      — throttle authenticated requests
        #   2. OriginValidationMiddleware — CSRF / origin check
        #   1. APIKeyMiddleware         — reject unauthenticated requests        ← outermost (runs first)
        #   0. IPFilterMiddleware       — block banned IPs (if configured)       ← outermost when enabled
        #  -1. SecurityHeadersMiddleware — inject HSTS / CSP response headers    ← very outermost
        #
        # L4 fix: comment now reflects actual ASGI wrap/execution order above.

        app = AuditMiddleware(app)  # type: ignore[assignment]
        log.info("Audit logging enabled → %s", os.getenv("WAZUH_AUDIT_LOG", "logs/audit.jsonl"))

        app = RateLimitMiddleware(app)  # type: ignore[assignment]
        log.info(
            "Rate limiting enabled — %s RPM per identity (burst +%s)",
            os.getenv("WAZUH_MCP_RATE_LIMIT_RPM", "60"),
            os.getenv("WAZUH_MCP_RATE_LIMIT_BURST", "10"),
        )

        app = OriginValidationMiddleware(  # type: ignore[assignment]
            app, is_loopback=_is_loopback_host(host), has_auth=bool(api_key)
        )
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
            os.getenv("WAZUH_MCP_MAX_BODY_KB", "4096"),
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
