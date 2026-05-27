"""Rootcheck / rootkit detection results browser.

These tools expose Wazuh's rootkit hunter scan results per agent.
"""
from __future__ import annotations
from ..tool_context import ToolContext


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _truncate = ctx.truncate

    @mcp.tool()
    async def get_agent_rootcheck_results(
        agent_id: str,
        status: str = "outstanding",
        limit: int = 50,
    ) -> dict:
        """Retrieve rootcheck scan findings for an agent.

        Args:
            agent_id: Wazuh agent ID.
            status: Filter by status — 'outstanding', 'solved', or 'all'.
            limit: Maximum results to return.
        """
        from ..validators import validate_agent_id
        try:
            agent_id = validate_agent_id(agent_id)
        except ValueError as e:
            return {"error": str(e)}

        path = f"/rootcheck/{agent_id}?limit={_cap(limit)}"
        if status != "all":
            path += f"&status={status}"
        try:
            result = await wz.request("GET", path)
            items = (result.get("data") or {}).get("affected_items", [])
            return {
                "agent_id": agent_id,
                "status_filter": status,
                "total": (result.get("data") or {}).get("total_affected_items", len(items)),
                "findings": [
                    {
                        "event": item.get("event"),
                        "file": item.get("file"),
                        "status": item.get("status"),
                        "date_first": item.get("date"),
                        "date_last": item.get("date_last"),
                        "cis": item.get("cis"),
                    }
                    for item in items
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_rootcheck_last_scan(agent_id: str) -> dict:
        """Get the timestamp and summary of the last rootcheck scan for an agent."""
        from ..validators import validate_agent_id
        try:
            agent_id = validate_agent_id(agent_id)
        except ValueError as e:
            return {"error": str(e)}

        try:
            result = await wz.request("GET", f"/rootcheck/{agent_id}/last_scan")
            return {
                "agent_id": agent_id,
                "last_scan": result,
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def clear_rootcheck_results(agent_id: str, dry_run: bool = True) -> dict:
        """Clear rootcheck results for an agent.

        Requires ADMIN role and WAZUH_ALLOW_WRITES=true. dry_run=True by default.
        """
        from ..rbac import admin_only
        err = admin_only()
        if err:
            return err

        from ..server import _require_writes
        err = _require_writes()
        if err:
            return err

        from ..validators import validate_agent_id
        try:
            agent_id = validate_agent_id(agent_id)
        except ValueError as e:
            return {"error": str(e)}

        if dry_run:
            return {
                "dry_run": True,
                "agent_id": agent_id,
                "message": "Set dry_run=False to clear rootcheck results.",
            }
        try:
            result = await wz.request("DELETE", f"/rootcheck/{agent_id}")
            return {"cleared": True, "agent_id": agent_id, "result": result}
        except Exception as e:
            return {"error": str(e)}
