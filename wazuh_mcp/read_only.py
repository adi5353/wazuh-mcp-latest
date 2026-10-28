"""Server-wide read-only mode (WAZUH_MCP_READ_ONLY, default ON).

Defence in depth, three layers:

1. **Transport guard** — httpx request hooks on the Manager and Indexer clients
   refuse every request that is not a known read. This is the choke point: it
   holds even if a tool forgets its own ``require_writes`` check.
2. **Tool hiding** — tools that write to Wazuh, to local state, or to external
   services (Slack/Jira/PagerDuty/...) are not registered at all.
3. ``_require_writes()`` in server.py always refuses.

Set ``WAZUH_MCP_READ_ONLY=false`` to restore the previous per-tool behaviour.
"""
from __future__ import annotations

import os
import re
from urllib.parse import unquote, urlsplit

import httpx


class ReadOnlyViolation(RuntimeError):
    """Raised when a request would modify state while read-only mode is on."""


def is_read_only() -> bool:
    return os.getenv("WAZUH_MCP_READ_ONLY", "true").strip().lower() not in ("0", "false", "no", "off")


# ── Tools hidden in read-only mode ───────────────────────────────────────────
WRITE_TOOLS: frozenset[str] = frozenset({
    # Wazuh Manager writes
    "restart_agent", "run_active_response", "add_agent_to_group",
    "trigger_agent_upgrade", "rollback_agent_upgrade",
    "add_to_cdb_list", "remove_from_cdb_list", "import_cdb_backup",
    "rotate_wazuh_api_password", "clear_rootcheck_results",
    "push_custom_rule", "push_custom_decoder", "sigma_bulk_import",
    "rollback_custom_rule", "sync_threat_feed",
    "add_cve_to_watchlist", "mark_patched",
    "propose_active_response", "approve_response", "deny_response",
    # Indexer writes
    "tag_alert", "bulk_suppress_rule", "expire_suppression",
    "approve_suppression", "reject_suppression",
    # Outbound notifications / ticketing
    "send_alert_to_slack", "send_shift_handover_to_slack",
    "send_weekly_summary_to_slack", "send_critical_alert_notify",
    "email_compliance_report", "send_alert_to_teams",
    "send_critical_alert_to_teams", "send_weekly_summary_to_teams",
    "create_jira_ticket", "create_thehive_case", "update_ticket_status",
    "trigger_pagerduty_alert", "resolve_pagerduty_alert", "acknowledge_pagerduty_alert",
    "create_servicenow_incident", "update_servicenow_incident",
    "create_azure_devops_work_item", "update_azure_devops_work_item",
    # Background automation / scheduling / playbooks
    "start_autonomous_monitor", "stop_autonomous_monitor",
    "configure_auto_ticketing", "configure_scheduled_reports",
    "create_report_schedule", "delete_report_schedule",
    "run_playbook", "resume_playbook",
    # Local state
    "create_workspace", "add_to_workspace",
})


def tool_hidden(name: str) -> bool:
    return is_read_only() and name in WRITE_TOOLS


# ── Manager API ──────────────────────────────────────────────────────────────
_MGR_DENIED_READS = (
    re.compile(r"^/agents/[^/]+/key/?$"),          # returns the agent enrolment key
)
_MGR_ALLOWED = {
    ("POST", re.compile(r"^/security/user/authenticate/?$")),   # JWT login
    ("PUT", re.compile(r"^/logtest/?$")),                       # dry-run rule test
    ("DELETE", re.compile(r"^/logtest/sessions/[^/]+/?$")),     # end a logtest session
}


def _path(url: httpx.URL) -> str:
    p = unquote(unquote(urlsplit(str(url)).path)).replace("\\", "/")
    # Manager may sit behind a prefix; match on the API route suffix only.
    return re.sub(r"/{2,}", "/", p)


def check_manager_request(method: str, url: httpx.URL) -> None:
    if not is_read_only():
        return
    method = method.upper()
    path = _path(url)
    if method in ("GET", "HEAD", "OPTIONS"):
        if any(rx.match(path) for rx in _MGR_DENIED_READS):
            raise ReadOnlyViolation(f"read-only mode: GET {path} is blocked (returns secrets)")
        return
    if any(m == method and rx.match(path) for m, rx in _MGR_ALLOWED):
        return
    raise ReadOnlyViolation(f"read-only mode: {method} {path} blocked on Wazuh Manager API")


async def manager_request_hook(request: httpx.Request) -> None:
    check_manager_request(request.method, request.url)


# ── Indexer (OpenSearch) ─────────────────────────────────────────────────────
_IDX_POST_OK = re.compile(r"/(_search|_count|_msearch|_mget|_validate/query)/?$")


def check_indexer_request(method: str, url: httpx.URL) -> None:
    if not is_read_only():
        return
    method = method.upper()
    path = _path(url)
    if method in ("GET", "HEAD", "OPTIONS"):
        return
    if method == "POST" and _IDX_POST_OK.search(path):
        return
    raise ReadOnlyViolation(f"read-only mode: {method} {path} blocked on Wazuh Indexer")


async def indexer_request_hook(request: httpx.Request) -> None:
    check_indexer_request(request.method, request.url)
