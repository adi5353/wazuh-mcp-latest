"""Autonomous SOC orchestration — F9-doc.

Background asyncio loop that polls for high-severity alerts and automatically
chains investigative tool calls then sends Slack notifications.

Tools: start_autonomous_monitor, stop_autonomous_monitor, get_autonomous_status
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..rbac import admin_only

log = logging.getLogger("wazuh-mcp")

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
}


async def _enrich_and_notify(alert: dict, wz, idx, cfg) -> dict:
    agent = alert.get("agent") or {}
    agent_id = agent.get("id", "000")
    rule = alert.get("rule") or {}
    rule_level = rule.get("level", 0)
    ts = alert.get("@timestamp", "")
    srcip = (alert.get("data") or {}).get("srcip", "")

    actions = []
    try:
        await asyncio.gather(
            wz.request("GET", f"/syscollector/{agent_id}/processes?limit=20"),
            wz.request("GET", f"/syscollector/{agent_id}/ports?limit=20"),
            return_exceptions=True,
        )
        actions.append("gathered_processes_and_ports")
    except Exception as exc:
        log.debug("Autonomous gather error: %s", exc)

    ip_risk = None
    if srcip:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(
                    f"http://ip-api.com/json/{srcip}",
                    params={"fields": "country,isp,hosting,proxy"},
                )
                if r.status_code == 200:
                    ipdata = r.json()
                    ip_risk = "high" if (ipdata.get("hosting") or ipdata.get("proxy")) else "normal"
                    actions.append("enriched_srcip")
        except Exception:
            pass

    slack_sent = False
    if rule_level >= 13:
        slack_token = getattr(cfg, "slack_bot_token", "") or os.getenv("SLACK_BOT_TOKEN", "")
        slack_channel = os.getenv("SLACK_ALERT_CHANNEL", "#soc-alerts")
        if slack_token:
            try:
                msg = (
                    ":rotating_light: *AUTONOMOUS SOC ALERT*\n"
                    f"*Rule:* {rule.get('description', 'N/A')} (Level {rule_level})\n"
                    f"*Agent:* {agent.get('name', agent_id)}\n"
                    f"*Time:* {ts}\n"
                    f"*Source IP:* {srcip or 'N/A'}"
                    + (f" [risk: {ip_risk}]" if ip_risk else "")
                )
                async with httpx.AsyncClient(timeout=10) as c:
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
        "rule_level": rule_level,
        "agent_id": agent_id,
        "agent_name": agent.get("name", ""),
        "srcip": srcip,
        "ip_risk": ip_risk,
        "actions": actions,
        "slack_sent": slack_sent,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def _monitor_loop(wz, idx, cfg, interval: int, severity_threshold: int) -> None:
    log.info("Autonomous SOC monitor started (interval=%ds, threshold=%d)",
             interval, severity_threshold)
    while _monitor_state["running"]:
        try:
            now = datetime.now(timezone.utc)
            gte = (now - timedelta(seconds=interval * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
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
            raw = await idx.search("wazuh-alerts-*", query)
            hits = (raw.get("hits") or {}).get("hits") or []
            _monitor_state["last_poll"] = now.isoformat()
            _monitor_state["alerts_processed"] += len(hits)

            for hit in hits:
                if not _monitor_state["running"]:
                    break
                action_result = await _enrich_and_notify(hit.get("_source") or {}, wz, idx, cfg)
                _monitor_state["actions_taken"] += 1
                _monitor_state["recent_actions"].append(action_result)
                if len(_monitor_state["recent_actions"]) > 20:
                    _monitor_state["recent_actions"] = _monitor_state["recent_actions"][-20:]

        except Exception as exc:
            log.warning("Autonomous SOC monitor poll error: %s", exc)

        await asyncio.sleep(interval)

    log.info("Autonomous SOC monitor stopped")


def register(mcp, wz, idx, cfg):

    @mcp.tool()
    async def start_autonomous_monitor(
        interval_seconds: int = 60,
        severity_threshold: int = 10,
    ) -> dict:
        """Start the autonomous SOC monitoring loop. Requires role: admin.

        Polls Wazuh Indexer every interval_seconds for alerts at or above
        severity_threshold (Wazuh rule level 1-15). For each match:
          1. Collects processes and open ports from the affected agent
          2. Enriches the source IP via ip-api.com
          3. Sends Slack notification for critical alerts (level >= 13)

        interval_seconds: poll frequency (default 60, min 30)
        severity_threshold: minimum rule level to act on (default 10)
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
        task = loop.create_task(_monitor_loop(wz, idx, cfg, interval, severity_threshold))
        _monitor_state["task"] = task

        return {
            "status": "started",
            "interval_seconds": interval,
            "severity_threshold": severity_threshold,
            "started_at": _monitor_state["started_at"],
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

        return {
            "status": "stopped",
            "stopped_at": _monitor_state["stopped_at"],
            "total_alerts_processed": _monitor_state["alerts_processed"],
            "total_actions_taken": _monitor_state["actions_taken"],
        }

    @mcp.tool()
    async def get_autonomous_status() -> dict:
        """Get current status and recent actions from the autonomous SOC monitor."""
        return {
            "running": _monitor_state["running"],
            "started_at": _monitor_state["started_at"],
            "stopped_at": _monitor_state["stopped_at"],
            "interval_seconds": _monitor_state["interval_seconds"],
            "severity_threshold": _monitor_state["severity_threshold"],
            "alerts_processed": _monitor_state["alerts_processed"],
            "actions_taken": _monitor_state["actions_taken"],
            "last_poll": _monitor_state["last_poll"],
            "recent_actions": _monitor_state["recent_actions"][-10:],
        }
