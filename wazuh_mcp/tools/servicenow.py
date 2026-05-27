"""ServiceNow ITSM integration tools.

Create, update, and query ServiceNow incidents from Wazuh alerts.

Configuration (env vars):
    SERVICENOW_INSTANCE  — your instance name (e.g. 'mycompany' for mycompany.service-now.com)
    SERVICENOW_USER      — API username
    SERVICENOW_PASS      — API password
"""
from __future__ import annotations
from ..tool_context import ToolContext

import os


def _client():
    import httpx
    instance = os.getenv("SERVICENOW_INSTANCE", "")
    user = os.getenv("SERVICENOW_USER", "")
    password = os.getenv("SERVICENOW_PASS", "")
    if not all([instance, user, password]):
        return None, "ServiceNow not configured. Set SERVICENOW_INSTANCE, SERVICENOW_USER, SERVICENOW_PASS."
    base_url = f"https://{instance}.service-now.com/api/now"
    return httpx.AsyncClient(
        base_url=base_url,
        auth=(user, password),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    ), None


_PRIORITY_MAP = {"critical": "1", "high": "2", "medium": "3", "low": "4"}


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _truncate = ctx.truncate

    @mcp.tool()
    async def create_servicenow_incident(
        short_description: str,
        description: str,
        priority: str = "high",
        assignment_group: str | None = None,
        caller_id: str | None = None,
    ) -> dict:
        """Create a ServiceNow incident from a Wazuh alert or investigation.

        Args:
            short_description: One-line incident title.
            description: Full incident detail.
            priority: 'critical', 'high', 'medium', or 'low'.
            assignment_group: ServiceNow assignment group name.
            caller_id: ServiceNow user sys_id for the caller.
        """
        client, err = _client()
        if err:
            return {"error": err}

        payload: dict = {
            "short_description": short_description[:160],
            "description": description[:4000],
            "priority": _PRIORITY_MAP.get(priority.lower(), "2"),
            "category": "Security",
            "subcategory": "SIEM",
        }
        if assignment_group:
            payload["assignment_group"] = assignment_group
        if caller_id:
            payload["caller_id"] = caller_id

        try:
            async with client:
                r = await client.post("/table/incident", json=payload)
                r.raise_for_status()
                data = r.json().get("result", {})
                return {
                    "created": True,
                    "sys_id": data.get("sys_id"),
                    "number": data.get("number"),
                    "state": data.get("state"),
                    "url": f"https://{os.getenv('SERVICENOW_INSTANCE')}.service-now.com/nav_to.do?uri=incident.do?sys_id={data.get('sys_id')}",
                }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_servicenow_incident(sys_id: str) -> dict:
        """Retrieve a ServiceNow incident by its sys_id."""
        client, err = _client()
        if err:
            return {"error": err}

        try:
            async with client:
                r = await client.get(
                    f"/table/incident/{sys_id}",
                    params={"sysparm_fields": "sys_id,number,short_description,state,priority,assigned_to,assignment_group,opened_at,resolved_at"},
                )
                r.raise_for_status()
                data = r.json().get("result", {})
                return {
                    "sys_id": data.get("sys_id"),
                    "number": data.get("number"),
                    "short_description": data.get("short_description"),
                    "state": data.get("state"),
                    "priority": data.get("priority"),
                    "assigned_to": (data.get("assigned_to") or {}).get("display_value"),
                    "assignment_group": (data.get("assignment_group") or {}).get("display_value"),
                    "opened_at": data.get("opened_at"),
                    "resolved_at": data.get("resolved_at"),
                }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def update_servicenow_incident(
        sys_id: str,
        state: str | None = None,
        comment: str | None = None,
        work_notes: str | None = None,
    ) -> dict:
        """Update a ServiceNow incident (add comment, change state).

        Args:
            sys_id: Incident sys_id.
            state: New state code ('1'=New, '2'=In Progress, '6'=Resolved, '7'=Closed).
            comment: Customer-visible comment to append.
            work_notes: Internal work note to append.
        """
        client, err = _client()
        if err:
            return {"error": err}

        payload: dict = {}
        if state:
            payload["state"] = state
        if comment:
            payload["comments"] = comment
        if work_notes:
            payload["work_notes"] = work_notes

        if not payload:
            return {"error": "No update fields provided."}

        try:
            async with client:
                r = await client.patch(f"/table/incident/{sys_id}", json=payload)
                r.raise_for_status()
                data = r.json().get("result", {})
                return {
                    "updated": True,
                    "sys_id": data.get("sys_id"),
                    "number": data.get("number"),
                    "state": data.get("state"),
                }
        except Exception as e:
            return {"error": str(e)}
