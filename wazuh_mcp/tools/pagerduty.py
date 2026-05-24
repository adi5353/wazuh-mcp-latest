"""PagerDuty integration tools.

Trigger and resolve PagerDuty incidents from Wazuh alerts.

Configuration:
    PAGERDUTY_ROUTING_KEY  — PagerDuty Events API v2 routing (integration) key
"""
from __future__ import annotations

import os

_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
_SEVERITY_MAP = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def trigger_pagerduty_alert(
        summary: str,
        severity: str = "high",
        source: str = "wazuh-mcp",
        dedup_key: str | None = None,
        alert_details: dict | None = None,
    ) -> dict:
        """Trigger a PagerDuty alert from a Wazuh security event.

        Args:
            summary: One-line alert description.
            severity: 'critical', 'high', 'medium', or 'low'.
            source: Component/service that detected the issue.
            dedup_key: Optional deduplication key (reuses existing incident if same key).
            alert_details: Optional dict with additional context fields.
        """
        import httpx
        routing_key = os.getenv("PAGERDUTY_ROUTING_KEY", "")
        if not routing_key:
            return {"error": "PAGERDUTY_ROUTING_KEY not configured."}

        payload: dict = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary[:1024],
                "severity": _SEVERITY_MAP.get(severity.lower(), "error"),
                "source": source,
                "custom_details": alert_details or {},
            },
        }
        if dedup_key:
            payload["dedup_key"] = dedup_key

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(_EVENTS_URL, json=payload)
                r.raise_for_status()
                data = r.json()
                return {
                    "triggered": True,
                    "status": data.get("status"),
                    "dedup_key": data.get("dedup_key"),
                    "message": data.get("message"),
                }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def resolve_pagerduty_alert(dedup_key: str) -> dict:
        """Resolve a PagerDuty incident by its deduplication key.

        Args:
            dedup_key: The dedup_key returned when the alert was triggered.
        """
        import httpx
        routing_key = os.getenv("PAGERDUTY_ROUTING_KEY", "")
        if not routing_key:
            return {"error": "PAGERDUTY_ROUTING_KEY not configured."}

        payload = {
            "routing_key": routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(_EVENTS_URL, json=payload)
                r.raise_for_status()
                data = r.json()
                return {
                    "resolved": True,
                    "status": data.get("status"),
                    "dedup_key": data.get("dedup_key"),
                }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def acknowledge_pagerduty_alert(dedup_key: str) -> dict:
        """Acknowledge a PagerDuty incident (suppresses further notifications).

        Args:
            dedup_key: The dedup_key of the incident to acknowledge.
        """
        import httpx
        routing_key = os.getenv("PAGERDUTY_ROUTING_KEY", "")
        if not routing_key:
            return {"error": "PAGERDUTY_ROUTING_KEY not configured."}

        payload = {
            "routing_key": routing_key,
            "event_action": "acknowledge",
            "dedup_key": dedup_key,
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(_EVENTS_URL, json=payload)
                r.raise_for_status()
                data = r.json()
                return {
                    "acknowledged": True,
                    "status": data.get("status"),
                    "dedup_key": data.get("dedup_key"),
                }
        except Exception as e:
            return {"error": str(e)}
