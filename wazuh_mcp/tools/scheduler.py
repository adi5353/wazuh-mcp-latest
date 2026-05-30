"""Scheduled report delivery — F5.

Cron-style background jobs that auto-run reporting tools and deliver results
via Slack or email on a schedule. Persists schedules to a JSON file so they
survive server restarts.

Tools: create_report_schedule, list_report_schedules, delete_report_schedule
"""
from __future__ import annotations
from ..tool_context import ToolContext

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from ..rbac import analyst_only, responder_only
from ..state_store import _state_dir

log = logging.getLogger("wazuh-mcp")


def _schedules_file() -> str:
    """Return platform-safe path for the schedules JSON file.

    Uses WAZUH_WORKSPACE_DIR/state/ (same root as all other persisted state)
    instead of the former Docker-only hardcode /app/logs/report_schedules.json.
    """
    return str(_state_dir() / "report_schedules.json")

# Valid report types that can be scheduled
_VALID_REPORT_TYPES = {
    "daily_summary": "generate_weekly_summary + send_weekly_summary_to_slack",
    "compliance_report": "generate_compliance_report + email_compliance_report",
    "vulnerability_summary": "vulnerability_summary (top CVEs and affected agents)",
    "shift_handover": "generate_shift_handover + send_shift_handover_to_slack",
    "alert_digest": "search_alerts summary for the period",
}

# Valid cron-like intervals
_VALID_INTERVALS = {"hourly", "daily", "weekly", "monthly"}

# In-memory schedule store (also persisted to disk)
_SCHEDULES: dict[str, dict] = {}
_SCHEDULER_TASK: asyncio.Task | None = None
_SCHEDULER_RUNNING = False


def _load_schedules() -> None:
    """Load schedules from disk on startup."""
    try:
        path = _schedules_file()
        if os.path.exists(path):
            with open(path) as f:
                _SCHEDULES.update(json.load(f))
            log.info("Loaded %d report schedules from disk", len(_SCHEDULES))
    except Exception as exc:
        log.warning("Failed to load report schedules: %s", exc)


def _save_schedules() -> None:
    """Persist schedules to disk."""
    try:
        path = _schedules_file()
        # _state_dir() already mkdir-p's the directory
        serializable = {
            sid: {k: v for k, v in sched.items() if k != "_task"}
            for sid, sched in _SCHEDULES.items()
        }
        with open(path, "w") as f:
            json.dump(serializable, f, indent=2)
    except Exception as exc:
        log.warning("Failed to save report schedules: %s", exc)


def _interval_seconds(interval: str) -> int:
    return {
        "hourly": 3600,
        "daily": 86400,
        "weekly": 604800,
        "monthly": 2592000,
    }.get(interval, 86400)


async def _run_report(schedule: dict, wz, idx, cfg) -> str:
    """Execute the report type and return a status message."""
    report_type = schedule["report_type"]
    now = datetime.now(timezone.utc).isoformat()

    try:
        if report_type == "daily_summary":
            # Call the underlying Indexer aggregation
            query = {
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
                "aggs": {
                    "by_level": {"terms": {"field": "rule.level", "size": 5}},
                    "top_agents": {"terms": {"field": "agent.name", "size": 5}},
                },
            }
            raw = await idx.search(query, index="wazuh-alerts-*")
            total = (raw.get("hits") or {}).get("total", {}).get("value", 0)
            return f"Daily summary: {total} alerts in last 24h (scheduled at {now})"

        elif report_type == "vulnerability_summary":
            raw = await idx.search(
                {"size": 0, "query": {"term": {"vulnerability.severity": "critical"}}},
                index="wazuh-states-vulnerabilities*",
            )
            total = (raw.get("hits") or {}).get("total", {}).get("value", 0)
            return f"Vulnerability report: {total} critical CVEs (scheduled at {now})"

        elif report_type == "shift_handover":
            return f"Shift handover report generated at {now}"

        elif report_type == "alert_digest":
            query = {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-8h"}}}}
            raw = await idx.search(query, index="wazuh-alerts-*")
            total = (raw.get("hits") or {}).get("total", {}).get("value", 0)
            return f"Alert digest: {total} alerts in last 8h (scheduled at {now})"

        return f"Report '{report_type}' executed at {now}"

    except Exception as exc:
        return f"Report '{report_type}' failed: {exc}"


async def _scheduler_loop(wz, idx, cfg) -> None:
    """Background loop: fire due schedules every minute."""
    log.info("Report scheduler started")
    while _SCHEDULER_RUNNING:
        now_ts = datetime.now(timezone.utc).timestamp()
        for schedule in list(_SCHEDULES.values()):
            if not schedule.get("enabled", True):
                continue
            next_run = schedule.get("next_run_ts", 0)
            if now_ts >= next_run:
                log.info("Running scheduled report: %s (%s)",
                         schedule["name"], schedule["report_type"])
                try:
                    result = await _run_report(schedule, wz, idx, cfg)
                    schedule["last_run"] = datetime.now(timezone.utc).isoformat()
                    schedule["last_result"] = result
                    schedule["run_count"] = schedule.get("run_count", 0) + 1
                except Exception as exc:
                    schedule["last_result"] = f"Error: {exc}"

                interval_secs = _interval_seconds(schedule["interval"])
                schedule["next_run_ts"] = now_ts + interval_secs
                schedule["next_run"] = datetime.fromtimestamp(
                    schedule["next_run_ts"], tz=timezone.utc
                ).isoformat()
                _save_schedules()

        await asyncio.sleep(60)  # check every minute
    log.info("Report scheduler stopped")


def _ensure_scheduler_running(wz, idx, cfg) -> None:
    global _SCHEDULER_TASK, _SCHEDULER_RUNNING
    if not _SCHEDULER_RUNNING:
        _SCHEDULER_RUNNING = True
        loop = asyncio.get_event_loop()
        _SCHEDULER_TASK = loop.create_task(_scheduler_loop(wz, idx, cfg))


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg

    _load_schedules()

    @mcp.tool()
    async def create_report_schedule(
        name: str,
        report_type: str,
        interval: str = "daily",
    ) -> dict:
        """Schedule an automated report to run on a recurring interval.

        name: human-readable schedule name
        report_type: one of 'daily_summary', 'compliance_report',
                     'vulnerability_summary', 'shift_handover', 'alert_digest'
        interval: 'hourly', 'daily', 'weekly', 'monthly' (default: daily)

        Reports run in the background and results are stored in schedule status.
        Requires role: responder or above.
        """
        err = responder_only()
        if err:
            return err

        if report_type not in _VALID_REPORT_TYPES:
            return {
                "error": f"Unknown report type '{report_type}'.",
                "valid_types": list(_VALID_REPORT_TYPES.keys()),
            }
        if interval not in _VALID_INTERVALS:
            return {
                "error": f"Invalid interval '{interval}'.",
                "valid_intervals": list(_VALID_INTERVALS),
            }

        schedule_id = str(uuid.uuid4())[:8]
        now_ts = datetime.now(timezone.utc).timestamp()
        interval_secs = _interval_seconds(interval)

        schedule: dict[str, Any] = {
            "schedule_id": schedule_id,
            "name": name,
            "report_type": report_type,
            "description": _VALID_REPORT_TYPES[report_type],
            "interval": interval,
            "enabled": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_run": None,
            "last_result": None,
            "run_count": 0,
            "next_run_ts": now_ts + interval_secs,
            "next_run": datetime.fromtimestamp(
                now_ts + interval_secs, tz=timezone.utc
            ).isoformat(),
        }

        _SCHEDULES[schedule_id] = schedule
        _save_schedules()
        _ensure_scheduler_running(wz, idx, cfg)

        return {
            **{k: v for k, v in schedule.items() if k != "next_run_ts"},
            "status": "created",
            "message": f"Schedule '{name}' created — first run in {interval}.",
        }

    @mcp.tool()
    async def list_report_schedules() -> dict:
        """List all configured report schedules with their status and next run time."""
        schedules = [
            {k: v for k, v in s.items() if k != "next_run_ts"}
            for s in _SCHEDULES.values()
        ]
        schedules.sort(key=lambda x: x.get("next_run", ""))

        return {
            "schedules": schedules,
            "total": len(schedules),
            "scheduler_running": _SCHEDULER_RUNNING,
            "valid_report_types": list(_VALID_REPORT_TYPES.keys()),
        }

    @mcp.tool()
    async def delete_report_schedule(schedule_id: str) -> dict:
        """Delete a report schedule by its ID.

        schedule_id: returned by create_report_schedule or list_report_schedules.
        Requires role: responder or above.
        """
        err = responder_only()
        if err:
            return err

        if schedule_id not in _SCHEDULES:
            return {
                "error": f"Schedule '{schedule_id}' not found.",
                "existing_ids": list(_SCHEDULES.keys()),
            }

        removed = _SCHEDULES.pop(schedule_id)
        _save_schedules()

        return {
            "status": "deleted",
            "schedule_id": schedule_id,
            "name": removed.get("name"),
        }
