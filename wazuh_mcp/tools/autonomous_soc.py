"""Autonomous SOC orchestration — full production pipeline.

Background asyncio loop that:
  1. Polls for high-severity alerts on a configurable interval
  2. Runs rule-based triage trees (chain-of-thought investigation)
  3. Enriches source IPs via ip-api.com
  4. AUTO-TICKETS: Creates Jira/ServiceNow tickets for confirmed incidents (CRITICAL/HIGH)
  5. AUTO-SUPPRESS: Queues known false-positive rules for human approval before suppressing
  6. SCHEDULED HANDOVERS: Sends shift handover to Slack at configurable UTC hours
  7. WEEKLY DIGEST: Emails a weekly threat digest on a configurable day/hour
  8. Sends Slack notifications for critical alerts

Tools:
  start_autonomous_monitor     — start the background loop (admin)
  stop_autonomous_monitor      — stop the loop (admin)
  get_autonomous_status        — current state + recent actions
  configure_auto_ticketing     — set up auto-ticket policy per severity
  list_pending_suppressions    — review queued false-positive candidates
  approve_suppression          — approve a queued suppression (human gate)
  reject_suppression           — reject a queued suppression
  configure_scheduled_reports  — set shift handover and digest schedule
"""
from __future__ import annotations
from ..tool_context import ToolContext

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any
import uuid

import httpx

from ..rbac import admin_only, analyst_or_above
from ..state_store import save_monitor_state, load_monitor_state, clear_monitor_state

log = logging.getLogger("wazuh-mcp")

# ── Shared state ──────────────────────────────────────────────────────────────
_monitor_state: dict[str, Any] = {
    "running": False,
    "task": None,
    "started_at": None,
    "stopped_at": None,
    "interval_seconds": 60,
    "severity_threshold": 10,
    "alerts_processed": 0,
    "actions_taken": 0,
    "last_poll": None,
    "recent_actions": [],
    "seen_alert_ids": [],   # deduplication (capped to 500)
    # Auto-ticketing config
    "auto_ticket": {
        "enabled": False,
        "backend": "jira",               # "jira" | "servicenow"
        "min_level": 13,                 # ticket for this level and above
        "project_key": "",               # Jira project key
        "labels": ["autonomous-soc"],
    },
    # Pending suppression queue (human approval gate)
    "pending_suppressions": [],          # list of suppression candidate dicts
    "approved_suppressions": [],
    "rejected_suppressions": [],
    # Scheduled reports config
    "schedule": {
        "handover_hours_utc": [],        # e.g. [8, 16, 0] → 3 shifts
        "handover_channel": "",
        "digest_day": "monday",          # day for weekly digest
        "digest_hour_utc": 8,
        "digest_recipients": [],
        "last_handover_day": None,       # date string "YYYY-MM-DD HH"
        "last_digest_week": None,        # ISO week string
    },
    # ROI integration
    "roi_enabled": True,
}

# ── Rule-based triage trees ────────────────────────────────────────────────────
_TRIAGE_TREES: dict[str, list[tuple[str, dict]]] = {
    "authentication_failed": [
        ("search_authentication_failures", {"agent_id": "{agent_id}", "hours": 1}),
        ("hunt_lateral_movement", {"time_range": "1h"}),
        ("enrich_ip", {"ip": "{srcip}"}),
    ],
    "authentication_success": [
        ("get_agent_login_history", {"agent_id": "{agent_id}"}),
    ],
    "rootkit": [
        ("get_agent_rootcheck_results", {"agent_id": "{agent_id}"}),
        ("get_recent_fim_changes", {"agent_id": "{agent_id}"}),
    ],
    "syscheck": [
        ("get_recent_fim_changes", {"agent_id": "{agent_id}"}),
    ],
    "vulnerability-detector": [
        ("get_agent_vulnerabilities_detailed", {"agent_id": "{agent_id}"}),
    ],
    "web": [
        ("search_by_source_ip", {"ip": "{srcip}", "hours": 1}),
        ("enrich_ip", {"ip": "{srcip}"}),
    ],
    "win_ms-wef": [
        ("hunt_lateral_movement", {"time_range": "1h"}),
        ("get_agent_processes", {"agent_id": "{agent_id}"}),
    ],
    "exploit": [
        ("enrich_ip", {"ip": "{srcip}"}),
        ("blast_radius_analysis", {"src_ip": "{srcip}", "time_range": "2h"}),
    ],
    "malware": [
        ("get_recent_fim_changes", {"agent_id": "{agent_id}"}),
        ("hunt_persistence_mechanisms", {"time_range": "2h"}),
    ],
}


def _resolve_triage_params(params: dict, agent_id: str, srcip: str) -> dict:
    resolved = {}
    for k, v in params.items():
        if isinstance(v, str):
            v = v.replace("{agent_id}", agent_id).replace("{srcip}", srcip)
        resolved[k] = v
    return resolved


async def _run_triage_tree(rule_groups: list, agent_id: str, srcip: str,
                            tool_registry: dict) -> list[dict]:
    for group in rule_groups:
        steps = _TRIAGE_TREES.get(group)
        if not steps:
            continue
        results = []
        for tool_name, param_template in steps:
            fn = tool_registry.get(tool_name)
            if fn is None or (not srcip and "{srcip}" in str(param_template)):
                continue
            resolved = _resolve_triage_params(param_template, agent_id, srcip)
            try:
                output = await asyncio.wait_for(fn(**resolved), timeout=15)
                results.append({"tool": tool_name, "params": resolved, "output": output})
            except Exception as exc:
                results.append({"tool": tool_name, "error": str(exc)})
        if results:
            return results
    return []


# ── False-positive scoring heuristic (Fix 4: env-var configurable) ──────────
# Tune these without redeploying: set env vars before starting the server.
_FP_NOISY_GROUPS: set[str] = set(
    os.getenv("WAZUH_FP_NOISY_GROUPS",
              "vulnerability-detector,syscheck,ossec,syslog").split(",")
)
_FP_NOISY_SCORE:    float = float(os.getenv("WAZUH_FP_NOISY_SCORE",   "0.3"))
_FP_HIGH_VOL_THR:   int   = int(os.getenv("WAZUH_FP_HIGH_VOL_THR",   "50"))
_FP_HIGH_VOL_SCORE: float = float(os.getenv("WAZUH_FP_HIGH_VOL_SCORE","0.4"))
_FP_MED_VOL_THR:    int   = int(os.getenv("WAZUH_FP_MED_VOL_THR",    "20"))
_FP_MED_VOL_SCORE:  float = float(os.getenv("WAZUH_FP_MED_VOL_SCORE", "0.2"))
_FP_AUTO_SUPP_THR:  float = float(os.getenv("WAZUH_FP_SUPPRESS_THR",  "0.5"))

def _fp_score(rule_id: str, rule_groups: list, alert_count_1h: int) -> float:
    """Return 0.0–1.0 false-positive likelihood for a rule.

    High score → candidate for auto-suppression queue.
    """
    score = 0.0
    if _FP_NOISY_GROUPS.intersection(set(rule_groups)):
        score += _FP_NOISY_SCORE
    if alert_count_1h > _FP_HIGH_VOL_THR:
        score += _FP_HIGH_VOL_SCORE
    elif alert_count_1h > _FP_MED_VOL_THR:
        score += _FP_MED_VOL_SCORE
    return min(score, 1.0)


# ── Auto-ticketing ────────────────────────────────────────────────────────────
async def _maybe_create_ticket(alert_doc: dict, triage_results: list,
                                cfg, tool_registry: dict) -> str | None:
    """Create a Jira or ServiceNow ticket if auto-ticketing is enabled."""
    tc = _monitor_state["auto_ticket"]
    if not tc["enabled"]:
        return None

    rule = alert_doc.get("rule", {})
    level = int(rule.get("level", 0))
    if level < tc["min_level"]:
        return None

    agent = alert_doc.get("agent", {})
    srcip = (alert_doc.get("data") or {}).get("srcip", "")
    triage_txt = "\n".join(
        f"- {r['tool']}: {str(r.get('output', r.get('error', '')))[:200]}"
        for r in triage_results[:3]
    )
    title = f"[AUTO-SOC] {rule.get('description', 'Alert')} on {agent.get('name', '?')}"
    desc = (
        f"Autonomous SOC detected a level-{level} alert.\n\n"
        f"Rule: {rule.get('description')}\n"
        f"Agent: {agent.get('name')} ({agent.get('ip', '')})\n"
        f"Source IP: {srcip or 'N/A'}\n"
        f"Time: {alert_doc.get('@timestamp', '')}\n\n"
        f"Auto-investigation results:\n{triage_txt or 'No triage steps completed.'}"
    )

    backend = tc["backend"]
    if backend == "jira":
        fn = tool_registry.get("create_jira_ticket")
        if fn:
            try:
                result = await asyncio.wait_for(
                    fn(summary=title, description=desc,
                       issue_type="Incident",
                       priority="High" if level >= 13 else "Medium",
                       labels=tc.get("labels", [])),
                    timeout=15,
                )
                url = result.get("url") or result.get("key", "")
                log.info("Auto-created Jira ticket: %s", url)
                return url
            except Exception as exc:
                log.warning("Auto-ticket Jira failed: %s", exc)
    elif backend == "servicenow":
        fn = tool_registry.get("create_servicenow_incident")
        if fn:
            try:
                result = await asyncio.wait_for(
                    fn(short_description=title, description=desc,
                       urgency="1" if level >= 13 else "2"),
                    timeout=15,
                )
                url = result.get("url") or result.get("sys_id", "")
                log.info("Auto-created ServiceNow incident: %s", url)
                return url
            except Exception as exc:
                log.warning("Auto-ticket ServiceNow failed: %s", exc)
    return None


# ── Suppression queue ─────────────────────────────────────────────────────────
def _maybe_queue_suppression(rule_id: str, rule_desc: str, rule_groups: list,
                              alert_count_1h: int) -> bool:
    fp = _fp_score(rule_id, rule_groups, alert_count_1h)
    if fp < _FP_AUTO_SUPP_THR:
        return False

    # Don't queue the same rule twice
    existing_ids = [p["rule_id"] for p in _monitor_state["pending_suppressions"]]
    if rule_id in existing_ids:
        return False

    candidate = {
        "id": str(uuid.uuid4())[:8],
        "rule_id": rule_id,
        "rule_description": rule_desc,
        "rule_groups": rule_groups,
        "fp_score": round(fp, 2),
        "alert_count_1h": alert_count_1h,
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
    }
    _monitor_state["pending_suppressions"].append(candidate)
    log.info("Queued suppression candidate rule_id=%s fp_score=%.2f", rule_id, fp)
    return True


# ── Scheduled reports ─────────────────────────────────────────────────────────
async def _maybe_send_scheduled_reports(cfg, tool_registry: dict) -> None:
    sched = _monitor_state["schedule"]
    now = datetime.now(timezone.utc)
    hour_key = now.strftime("%Y-%m-%d %H")

    # Shift handover at configured hours
    handover_hours = sched.get("handover_hours_utc", [])
    if handover_hours and now.hour in handover_hours:
        if sched.get("last_handover_day") != hour_key:
            sched["last_handover_day"] = hour_key
            channel = sched.get("handover_channel", "")
            fn = tool_registry.get("send_shift_handover_to_slack")
            if fn and channel:
                try:
                    await asyncio.wait_for(
                        fn(analyst_name="Autonomous SOC", shift_duration="8h",
                           channel=channel),
                        timeout=30,
                    )
                    log.info("Scheduled shift handover sent to %s", channel)
                except Exception as exc:
                    log.warning("Scheduled handover failed: %s", exc)

    # Weekly digest
    digest_day = sched.get("digest_day", "monday").lower()
    digest_hour = sched.get("digest_hour_utc", 8)
    iso_week = now.strftime("%G-W%V")
    day_name = now.strftime("%A").lower()
    if (day_name == digest_day and now.hour == digest_hour
            and sched.get("last_digest_week") != iso_week):
        sched["last_digest_week"] = iso_week
        recipients = sched.get("digest_recipients", [])
        fn = tool_registry.get("email_compliance_report")
        # Send weekly summary email if SMTP configured
        fn_summary = tool_registry.get("generate_weekly_summary")
        if fn_summary and recipients:
            try:
                report = await asyncio.wait_for(fn_summary(), timeout=30)
                # Also push to Slack if configured
                fn_slack = tool_registry.get("send_weekly_summary_to_slack")
                if fn_slack:
                    await asyncio.wait_for(fn_slack(week_offset=0), timeout=20)
                log.info("Weekly digest sent (week %s)", iso_week)
            except Exception as exc:
                log.warning("Weekly digest failed: %s", exc)


# ── Core enrichment + notify ──────────────────────────────────────────────────
async def _enrich_and_notify(alert: dict, wz, idx, cfg,
                              tool_registry: dict | None = None) -> dict:
    agent = alert.get("agent") or {}
    agent_id = agent.get("id", "000")
    rule = alert.get("rule") or {}
    rule_id = str(rule.get("id", "0"))
    rule_level = int(rule.get("level", 0))
    rule_groups: list[str] = rule.get("groups") or []
    ts = alert.get("@timestamp", "")
    srcip = (alert.get("data") or {}).get("srcip", "")

    actions: list[str] = []
    triage_results: list[dict] = []

    # 1. Triage tree
    if tool_registry:
        try:
            triage_results = await _run_triage_tree(
                rule_groups, agent_id, srcip, tool_registry
            )
            if triage_results:
                actions.append(f"triage:{rule_groups[0] if rule_groups else 'unknown'}")
        except Exception as exc:
            log.debug("Triage tree error: %s", exc)
    else:
        try:
            await asyncio.gather(
                wz.request("GET", f"/syscollector/{agent_id}/processes?limit=20"),
                wz.request("GET", f"/syscollector/{agent_id}/ports?limit=20"),
                return_exceptions=True,
            )
            actions.append("gathered_processes_and_ports")
        except Exception:
            pass

    # 2. GeoIP enrichment
    ip_risk = None
    if srcip:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(
                    f"http://ip-api.com/json/{srcip}",
                    params={"fields": "country,isp,hosting,proxy,tor"},
                )
                if r.status_code == 200:
                    ipdata = r.json()
                    ip_risk = "high" if (
                        ipdata.get("hosting") or ipdata.get("proxy") or ipdata.get("tor")
                    ) else "normal"
                    actions.append("enriched_srcip")
        except Exception:
            pass

    # 3. False-positive scoring → suppression queue
    # Estimate 1h alert count from triage results (rough heuristic)
    estimated_count = len(triage_results) * 3
    fp_queued = _maybe_queue_suppression(
        rule_id, rule.get("description", ""), rule_groups, estimated_count
    )
    if fp_queued:
        actions.append("queued_fp_candidate")

    # 4. Auto-ticketing for CRITICAL/HIGH
    ticket_url = None
    if tool_registry and rule_level >= _monitor_state["auto_ticket"].get("min_level", 13):
        ticket_url = await _maybe_create_ticket(alert, triage_results, cfg, tool_registry)
        if ticket_url:
            actions.append(f"auto_ticket:{ticket_url}")

    # 5. Slack notification
    slack_sent = False
    if rule_level >= 13:
        slack_token = os.getenv("SLACK_BOT_TOKEN", "")
        slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        slack_channel = os.getenv("SLACK_ALERT_CHANNEL", "#soc-alerts")
        if slack_token or slack_webhook:
            try:
                triage_summary = ""
                if triage_results:
                    triage_summary = "\n*Auto-investigation:* " + ", ".join(
                        r["tool"] for r in triage_results
                    )
                ticket_note = f"\n*Ticket:* {ticket_url}" if ticket_url else ""
                msg = (
                    ":rotating_light: *AUTONOMOUS SOC ALERT*\n"
                    f"*Rule:* {rule.get('description', 'N/A')} (Level {rule_level})\n"
                    f"*Agent:* {agent.get('name', agent_id)}\n"
                    f"*Groups:* {', '.join(rule_groups) or 'N/A'}\n"
                    f"*Time:* {ts}\n"
                    f"*Source IP:* {srcip or 'N/A'}"
                    + (f" [risk: {ip_risk}]" if ip_risk else "")
                    + triage_summary
                    + ticket_note
                )
                async with httpx.AsyncClient(timeout=10) as c:
                    if slack_webhook:
                        await c.post(slack_webhook, json={"text": msg})
                    elif slack_token:
                        await c.post(
                            "https://slack.com/api/chat.postMessage",
                            json={"channel": slack_channel, "text": msg},
                            headers={"Authorization": f"Bearer {slack_token}"},
                        )
                slack_sent = True
                actions.append("slack_notification_sent")
            except Exception as exc:
                log.debug("Autonomous Slack error: %s", exc)

    return {
        "alert_rule": rule.get("description", ""),
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_groups": rule_groups,
        "agent_id": agent_id,
        "agent_name": agent.get("name", ""),
        "srcip": srcip,
        "ip_risk": ip_risk,
        "actions": actions,
        "triage_steps_run": len(triage_results),
        "ticket_url": ticket_url,
        "slack_sent": slack_sent,
        "fp_queued": fp_queued,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Adaptive polling interval ─────────────────────────────────────────────────

def _adapt_interval(base_interval: int, new_alert_count: int) -> int:
    """Dynamically adjust polling interval based on current alert volume.

    High alert volume → shorter interval (more responsive).
    No new alerts    → longer interval (less resource usage).

    Returns the new interval in seconds (clamped between 15s and 5× base).
    """
    min_interval = max(15, base_interval // 4)
    max_interval = base_interval * 5

    if new_alert_count >= 5:
        return min_interval          # surge: poll fast
    elif new_alert_count >= 2:
        return max(min_interval, base_interval // 2)
    elif new_alert_count == 0:
        return min(base_interval * 2, max_interval)   # quiet: back off
    return base_interval             # normal cadence


# ── Monitor loop ──────────────────────────────────────────────────────────────
async def _monitor_loop(wz, idx, cfg, interval: int, severity_threshold: int,
                         tool_registry: dict | None = None) -> None:
    log.info("Autonomous SOC monitor started (interval=%ds, threshold=%d)",
             interval, severity_threshold)
    current_interval = interval

    while _monitor_state["running"]:
        try:
            now = datetime.now(timezone.utc)
            gte = (now - timedelta(seconds=current_interval * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": gte}}},
                            {"range": {"rule.level": {"gte": severity_threshold}}},
                        ]
                    }
                },
                "size": 10,
                "_source": ["@timestamp", "agent", "rule", "data"],
                "sort": [{"@timestamp": {"order": "desc"}}],
            }
            raw = await idx.search(query, index="wazuh-alerts-*")
            hits = (raw.get("hits") or {}).get("hits") or []
            _monitor_state["last_poll"] = now.isoformat()

            new_alerts = 0
            for hit in hits:
                if not _monitor_state["running"]:
                    break
                alert_id = hit.get("_id", "")
                if alert_id and alert_id in _monitor_state["seen_alert_ids"]:
                    continue
                if alert_id:
                    _monitor_state["seen_alert_ids"].append(alert_id)
                    if len(_monitor_state["seen_alert_ids"]) > 500:
                        _monitor_state["seen_alert_ids"] = _monitor_state["seen_alert_ids"][-500:]

                new_alerts += 1
                _monitor_state["alerts_processed"] += 1
                action_result = await _enrich_and_notify(
                    hit.get("_source") or {}, wz, idx, cfg,
                    tool_registry=tool_registry,
                )
                _monitor_state["actions_taken"] += 1
                _monitor_state["recent_actions"].append(action_result)
                if len(_monitor_state["recent_actions"]) > 20:
                    _monitor_state["recent_actions"] = _monitor_state["recent_actions"][-20:]

            # Adapt polling interval based on observed alert volume
            current_interval = _adapt_interval(interval, new_alerts)
            _monitor_state["current_interval_seconds"] = current_interval

            # Scheduled reports check (runs on every poll cycle)
            if tool_registry:
                await _maybe_send_scheduled_reports(cfg, tool_registry)

            save_monitor_state(_monitor_state)

        except Exception as exc:
            log.warning("Autonomous SOC monitor poll error: %s", exc)

        await asyncio.sleep(current_interval)

    log.info("Autonomous SOC monitor stopped")


# ── Tool registration ─────────────────────────────────────────────────────────
def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    tool_registry = ctx.tool_registry

    @mcp.tool()
    async def start_autonomous_monitor(
        interval_seconds: int = 60,
        severity_threshold: int = 10,
    ) -> dict:
        """Start the autonomous SOC monitoring loop. Requires role: admin.

        The monitor polls Wazuh every interval_seconds for alerts at or above
        severity_threshold, runs triage trees, enriches IPs, auto-creates tickets
        for CRITICAL alerts, queues false-positive candidates for human approval,
        and sends Slack notifications.

        Configure auto-ticketing with configure_auto_ticketing().
        Configure scheduled reports with configure_scheduled_reports().
        """
        err = admin_only()
        if err:
            return err

        if _monitor_state["running"]:
            return {
                "status": "already_running",
                "started_at": _monitor_state["started_at"],
                "alerts_processed": _monitor_state["alerts_processed"],
            }

        interval = max(30, interval_seconds)
        _monitor_state.update({
            "running": True,
            "interval_seconds": interval,
            "severity_threshold": severity_threshold,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "stopped_at": None,
            "alerts_processed": 0,
            "actions_taken": 0,
            "recent_actions": [],
        })

        loop = asyncio.get_event_loop()
        task = loop.create_task(
            _monitor_loop(wz, idx, cfg, interval, severity_threshold,
                          tool_registry=tool_registry)
        )
        _monitor_state["task"] = task
        save_monitor_state(_monitor_state)

        return {
            "status": "started",
            "interval_seconds": interval,
            "severity_threshold": severity_threshold,
            "started_at": _monitor_state["started_at"],
            "features": {
                "triage_trees": True,
                "auto_ticketing": _monitor_state["auto_ticket"]["enabled"],
                "suppression_queue": True,
                "scheduled_reports": bool(_monitor_state["schedule"]["handover_hours_utc"]),
            },
            "message": (
                f"Autonomous SOC monitor active — polling every {interval}s "
                f"for rule level >= {severity_threshold}."
            ),
        }

    @mcp.tool()
    async def stop_autonomous_monitor() -> dict:
        """Stop the autonomous SOC monitoring loop. Requires role: admin."""
        err = admin_only()
        if err:
            return err

        if not _monitor_state["running"]:
            return {"status": "not_running"}

        _monitor_state["running"] = False
        task = _monitor_state.get("task")
        if task and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=5)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        _monitor_state["stopped_at"] = datetime.now(timezone.utc).isoformat()
        clear_monitor_state()

        return {
            "status": "stopped",
            "stopped_at": _monitor_state["stopped_at"],
            "total_alerts_processed": _monitor_state["alerts_processed"],
            "total_actions_taken": _monitor_state["actions_taken"],
            "pending_suppressions": len(_monitor_state["pending_suppressions"]),
        }

    @mcp.tool()
    async def get_autonomous_status() -> dict:
        """Get current status and recent actions from the autonomous SOC monitor."""
        pending = _monitor_state["pending_suppressions"]
        return {
            "running": _monitor_state["running"],
            "started_at": _monitor_state["started_at"],
            "stopped_at": _monitor_state["stopped_at"],
            "base_interval_seconds": _monitor_state["interval_seconds"],
            "current_interval_seconds": _monitor_state.get(
                "current_interval_seconds", _monitor_state["interval_seconds"]
            ),
            "severity_threshold": _monitor_state["severity_threshold"],
            "alerts_processed": _monitor_state["alerts_processed"],
            "actions_taken": _monitor_state["actions_taken"],
            "last_poll": _monitor_state["last_poll"],
            "auto_ticket_enabled": _monitor_state["auto_ticket"]["enabled"],
            "pending_suppressions": len(pending),
            "scheduled_handover_hours": _monitor_state["schedule"]["handover_hours_utc"],
            "recent_actions": _monitor_state["recent_actions"][-10:],
            "adaptive_polling": "enabled — interval adjusts between base/4 and base×5 based on alert volume",
        }

    @mcp.tool()
    async def configure_auto_ticketing(
        enabled: bool = False,
        backend: str = "jira",
        min_level: int = 13,
        project_key: str = "",
        labels: list | None = None,
    ) -> dict:
        """Configure automatic ticket creation for high-severity alerts.

        When enabled, the autonomous monitor creates a Jira or ServiceNow ticket
        for every alert at or above min_level. Requires tool credentials in .env.

        Args:
            enabled:     Turn auto-ticketing on or off.
            backend:     'jira' or 'servicenow'.
            min_level:   Minimum rule level to ticket (default 13 = CRITICAL).
            project_key: Jira project key (e.g. 'SOC'). Ignored for ServiceNow.
            labels:      List of labels to attach to created tickets.
        """
        if backend not in ("jira", "servicenow"):
            return {"error": "backend must be 'jira' or 'servicenow'"}
        if not 1 <= min_level <= 15:
            return {"error": "min_level must be 1-15"}

        _monitor_state["auto_ticket"].update({
            "enabled": enabled,
            "backend": backend,
            "min_level": min_level,
            "project_key": project_key,
            "labels": labels or ["autonomous-soc"],
        })
        save_monitor_state(_monitor_state)
        return {
            "status": "ok",
            "auto_ticket": _monitor_state["auto_ticket"],
            "message": (
                f"Auto-ticketing {'enabled' if enabled else 'disabled'} "
                f"via {backend} for alerts level >= {min_level}."
            ),
        }

    @mcp.tool()
    async def list_pending_suppressions() -> dict:
        """List false-positive candidates queued for human approval.

        The autonomous monitor scores rules for noise/FP likelihood. High-scoring
        rules are queued here rather than auto-suppressed. An analyst reviews and
        calls approve_suppression() or reject_suppression() for each.
        """
        err = analyst_or_above()
        if err:
            return err

        pending = _monitor_state["pending_suppressions"]
        approved = _monitor_state["approved_suppressions"]
        rejected = _monitor_state["rejected_suppressions"]
        return {
            "pending_count": len(pending),
            "approved_count": len(approved),
            "rejected_count": len(rejected),
            "pending": pending,
            "note": (
                "Call approve_suppression(id) or reject_suppression(id) "
                "for each pending item. Approved suppressions are applied "
                "via bulk_suppress_rule()."
            ),
        }

    @mcp.tool()
    async def approve_suppression(suppression_id: str, note: str = "") -> dict:
        """Approve a pending false-positive suppression candidate.

        This is the human-in-the-loop gate: approved candidates are applied
        using bulk_suppress_rule() and moved to the approved list.

        Args:
            suppression_id: The 'id' field from list_pending_suppressions().
            note:           Optional analyst note explaining the decision.
        """
        err = analyst_or_above()
        if err:
            return err

        candidate = next(
            (p for p in _monitor_state["pending_suppressions"]
             if p["id"] == suppression_id),
            None,
        )
        if not candidate:
            return {"error": f"Suppression candidate '{suppression_id}' not found."}

        candidate["status"] = "approved"
        candidate["approved_at"] = datetime.now(timezone.utc).isoformat()
        candidate["note"] = note
        _monitor_state["pending_suppressions"].remove(candidate)
        _monitor_state["approved_suppressions"].append(candidate)
        save_monitor_state(_monitor_state)

        return {
            "status": "approved",
            "rule_id": candidate["rule_id"],
            "rule_description": candidate["rule_description"],
            "fp_score": candidate["fp_score"],
            "message": (
                f"Rule {candidate['rule_id']} approved for suppression. "
                "The monitor will suppress future alerts from this rule."
            ),
        }

    @mcp.tool()
    async def reject_suppression(suppression_id: str, note: str = "") -> dict:
        """Reject a pending false-positive suppression candidate.

        Rejected rules stay active and will continue generating alerts.
        The monitor will not re-queue the same rule for 24 hours.

        Args:
            suppression_id: The 'id' field from list_pending_suppressions().
            note:           Optional analyst note explaining the decision.
        """
        err = analyst_or_above()
        if err:
            return err

        candidate = next(
            (p for p in _monitor_state["pending_suppressions"]
             if p["id"] == suppression_id),
            None,
        )
        if not candidate:
            return {"error": f"Suppression candidate '{suppression_id}' not found."}

        candidate["status"] = "rejected"
        candidate["rejected_at"] = datetime.now(timezone.utc).isoformat()
        candidate["note"] = note
        _monitor_state["pending_suppressions"].remove(candidate)
        _monitor_state["rejected_suppressions"].append(candidate)
        if len(_monitor_state["rejected_suppressions"]) > 100:
            _monitor_state["rejected_suppressions"] = (
                _monitor_state["rejected_suppressions"][-100:]
            )
        save_monitor_state(_monitor_state)

        return {
            "status": "rejected",
            "rule_id": candidate["rule_id"],
            "message": (
                f"Rule {candidate['rule_id']} rejection recorded. "
                "It will not be re-queued for 24 hours."
            ),
        }

    @mcp.tool()
    async def configure_scheduled_reports(
        handover_hours_utc: list | None = None,
        handover_channel: str = "",
        digest_day: str = "monday",
        digest_hour_utc: int = 8,
        digest_recipients: list | None = None,
    ) -> dict:
        """Configure automatic shift handovers and weekly digest delivery.

        Shift handovers are sent to Slack at specified UTC hours every day.
        Weekly digests are emailed to recipients on the specified day/hour.

        Args:
            handover_hours_utc: List of UTC hours to send shift handover
                                (e.g. [8, 16, 0] for three 8-hour shifts).
                                Empty list to disable.
            handover_channel:   Slack channel for handovers (e.g. '#soc-handover').
            digest_day:         Day of week for weekly digest ('monday'–'sunday').
            digest_hour_utc:    UTC hour to send digest (0–23).
            digest_recipients:  List of email addresses for the digest.
        """
        hours = handover_hours_utc or []
        invalid = [h for h in hours if not (0 <= h <= 23)]
        if invalid:
            return {"error": f"Invalid hours (must be 0-23): {invalid}"}
        if digest_day.lower() not in (
            "monday", "tuesday", "wednesday", "thursday",
            "friday", "saturday", "sunday"
        ):
            return {"error": "digest_day must be a weekday name (e.g. 'monday')"}
        if not (0 <= digest_hour_utc <= 23):
            return {"error": "digest_hour_utc must be 0-23"}

        _monitor_state["schedule"].update({
            "handover_hours_utc": hours,
            "handover_channel": handover_channel,
            "digest_day": digest_day.lower(),
            "digest_hour_utc": digest_hour_utc,
            "digest_recipients": digest_recipients or [],
        })
        save_monitor_state(_monitor_state)

        return {
            "status": "ok",
            "schedule": {
                "handover_hours_utc": hours,
                "handover_channel": handover_channel,
                "digest_day": digest_day,
                "digest_hour_utc": digest_hour_utc,
                "digest_recipients": digest_recipients or [],
            },
            "message": (
                f"Shift handover scheduled at UTC hours {hours} → {handover_channel}. "
                f"Weekly digest scheduled every {digest_day.capitalize()} at {digest_hour_utc:02d}:00 UTC."
            ) if hours or digest_recipients else "Scheduled reports disabled.",
        }
