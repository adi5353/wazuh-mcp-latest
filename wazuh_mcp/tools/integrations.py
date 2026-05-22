"""SOAR integration tools — Jira and TheHive ticketing."""
from __future__ import annotations

import datetime
import logging
import os

import httpx

log = logging.getLogger("wazuh-mcp")

_SOAR_TIMEOUT = 15


def register(mcp, wz, idx, cfg):

    _JIRA_URL     = os.getenv("JIRA_URL", "")
    _JIRA_USER    = os.getenv("JIRA_USER", "")
    _JIRA_TOKEN   = os.getenv("JIRA_API_TOKEN", "")
    _JIRA_PROJECT = os.getenv("JIRA_PROJECT_KEY", "SOC")
    _THEHIVE_URL  = os.getenv("THEHIVE_URL", "")
    _THEHIVE_KEY  = os.getenv("THEHIVE_API_KEY", "")

    @mcp.tool()
    async def create_jira_ticket(
        title: str,
        description: str,
        severity: str = "High",
        affected_agents: list | None = None,
        mitre_techniques: list | None = None,
        alert_ids: list | None = None,
        assignee: str | None = None,
        labels: list | None = None,
    ) -> dict:
        """Create a Jira issue in the SOC project from a Wazuh incident.

        Typically called right after create_incident_report — pass the report
        title and description directly.
        severity: Critical | High | Medium | Low
        assignee: Jira accountId (not email) — find in Jira user profile URL.
        Requires JIRA_URL, JIRA_USER, JIRA_API_TOKEN in .env.
        """
        if not _JIRA_URL or not _JIRA_TOKEN:
            return {
                "error": "Jira not configured. Add JIRA_URL, JIRA_USER, JIRA_API_TOKEN to .env."
            }

        priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}
        jira_priority = priority_map.get(severity.lower(), "High")

        body_lines = [description, ""]
        if affected_agents:
            body_lines.append("*Affected agents:* " + ", ".join(str(a) for a in affected_agents))
        if mitre_techniques:
            body_lines.append("*MITRE techniques:* " + ", ".join(mitre_techniques))
        if alert_ids:
            body_lines.append("*Wazuh alert IDs:* " + ", ".join(str(i) for i in alert_ids[:10]))
        body_lines.append(
            f"\n_Created by Wazuh MCP at "
            f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_"
        )

        all_labels = ["wazuh-mcp", f"severity-{severity.lower()}"] + (labels or [])

        payload: dict = {
            "fields": {
                "project":     {"key": _JIRA_PROJECT},
                "summary":     title,
                "description": "\n".join(body_lines),
                "issuetype":   {"name": "Bug"},
                "priority":    {"name": jira_priority},
                "labels":      all_labels,
            }
        }
        if assignee:
            payload["fields"]["assignee"] = {"accountId": assignee}

        try:
            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                r = await client.post(
                    f"{_JIRA_URL.rstrip('/')}/rest/api/2/issue",
                    json=payload,
                    auth=(_JIRA_USER, _JIRA_TOKEN),
                    headers={"Content-Type": "application/json"},
                )
            r.raise_for_status()
            data      = r.json()
            issue_key = data.get("key", "")
            issue_url = f"{_JIRA_URL.rstrip('/')}/browse/{issue_key}"
            log.info("Created Jira issue %s for: %s", issue_key, title)
            return {
                "status":    "ok",
                "issue_key": issue_key,
                "issue_url": issue_url,
                "priority":  jira_priority,
                "message":   f"Jira issue {issue_key} created: {issue_url}",
            }
        except httpx.HTTPStatusError as e:
            return {"error": f"Jira API {e.response.status_code}: {e.response.text[:300]}"}
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def create_thehive_case(
        title: str,
        description: str,
        severity: str = "High",
        affected_agents: list | None = None,
        mitre_techniques: list | None = None,
        alert_ids: list | None = None,
        tags: list | None = None,
        tlp: int = 2,
        pap: int = 2,
    ) -> dict:
        """Open a TheHive 5 case from a Wazuh incident report.

        severity: Low | Medium | High | Critical
        tlp: 0=WHITE 1=GREEN 2=AMBER 3=RED (default AMBER)
        pap: 0=WHITE 1=GREEN 2=AMBER 3=RED (default AMBER)
        Requires THEHIVE_URL and THEHIVE_API_KEY in .env.
        """
        if not _THEHIVE_URL or not _THEHIVE_KEY:
            return {
                "error": "TheHive not configured. Add THEHIVE_URL, THEHIVE_API_KEY to .env."
            }

        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        hive_severity = severity_map.get(severity.lower(), 3)

        extra = []
        if affected_agents:
            extra.append(f"**Affected agents:** {', '.join(str(a) for a in affected_agents)}")
        if mitre_techniques:
            extra.append(f"**MITRE techniques:** {', '.join(mitre_techniques)}")
        if alert_ids:
            extra.append(f"**Wazuh alert IDs:** {', '.join(str(i) for i in alert_ids[:10])}")

        full_desc = description
        if extra:
            full_desc += "\n\n---\n" + "\n\n".join(extra)
        full_desc += (
            f"\n\n_Source: Wazuh MCP — "
            f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_"
        )

        all_tags = ["wazuh", "wazuh-mcp", f"severity:{severity.lower()}"]
        if mitre_techniques:
            all_tags += [f"mitre:{t}" for t in mitre_techniques]
        if tags:
            all_tags += tags

        payload = {
            "title":       title,
            "description": full_desc,
            "severity":    hive_severity,
            "tlp":         tlp,
            "pap":         pap,
            "tags":        all_tags,
            "flag":        False,
            "status":      "New",
        }
        try:
            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                r = await client.post(
                    f"{_THEHIVE_URL.rstrip('/')}/api/v1/case",
                    json=payload,
                    headers={
                        "Authorization":  f"Bearer {_THEHIVE_KEY}",
                        "Content-Type":   "application/json",
                    },
                )
            r.raise_for_status()
            data     = r.json()
            case_id  = data.get("_id", "")
            case_num = data.get("caseId", "")
            case_url = f"{_THEHIVE_URL.rstrip('/')}/cases/{case_id}"
            log.info("Created TheHive case #%s (%s) for: %s", case_num, case_id, title)
            return {
                "status":   "ok",
                "case_id":  case_id,
                "case_num": case_num,
                "case_url": case_url,
                "severity": hive_severity,
                "message":  f"TheHive case #{case_num} created: {case_url}",
            }
        except httpx.HTTPStatusError as e:
            return {"error": f"TheHive API {e.response.status_code}: {e.response.text[:300]}"}
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def update_ticket_status(
        issue_key: str,
        new_status: str,
        comment: str | None = None,
        resolution: str | None = None,
    ) -> dict:
        """Transition a Jira issue to a new workflow status.

        Common values for new_status: 'In Progress', 'Done', 'Resolved', 'Closed'.
        resolution: e.g. 'Fixed', 'Won\\'t Fix', 'Duplicate' (used when closing).
        Requires JIRA_URL, JIRA_USER, JIRA_API_TOKEN in .env.
        """
        if not _JIRA_URL or not _JIRA_TOKEN:
            return {
                "error": "Jira not configured. Add JIRA_URL, JIRA_USER, JIRA_API_TOKEN to .env."
            }
        try:
            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                tr_r = await client.get(
                    f"{_JIRA_URL.rstrip('/')}/rest/api/2/issue/{issue_key}/transitions",
                    auth=(_JIRA_USER, _JIRA_TOKEN),
                )
                tr_r.raise_for_status()
                transitions = tr_r.json().get("transitions", [])

            match = next(
                (t for t in transitions if t["to"]["name"].lower() == new_status.lower()),
                None,
            )
            if not match:
                available = [t["to"]["name"] for t in transitions]
                return {
                    "error": (
                        f"Transition '{new_status}' not found for {issue_key}. "
                        f"Available: {available}"
                    )
                }

            tr_payload: dict = {"transition": {"id": match["id"]}}
            if resolution:
                tr_payload["fields"] = {"resolution": {"name": resolution}}
            if comment:
                tr_payload["update"] = {"comment": [{"add": {"body": comment}}]}

            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                do_r = await client.post(
                    f"{_JIRA_URL.rstrip('/')}/rest/api/2/issue/{issue_key}/transitions",
                    json=tr_payload,
                    auth=(_JIRA_USER, _JIRA_TOKEN),
                    headers={"Content-Type": "application/json"},
                )
            do_r.raise_for_status()
            log.info("Transitioned Jira %s → %s", issue_key, new_status)
            return {
                "status":     "ok",
                "issue_key":  issue_key,
                "new_status": new_status,
                "issue_url":  f"{_JIRA_URL.rstrip('/')}/browse/{issue_key}",
                "message":    f"{issue_key} transitioned to '{new_status}'.",
            }
        except httpx.HTTPStatusError as e:
            return {"error": f"Jira API {e.response.status_code}: {e.response.text[:300]}"}
        except Exception as e:
            return {"error": str(e)}
