"""Agent management tools — list, inspect, restart, group assignment."""
from __future__ import annotations
from ..tool_context import ToolContext

from ..rbac import responder_only, admin_only


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _require_writes = ctx.require_writes

    @mcp.tool()
    async def list_agents(status: str = "active", limit: int = 50, group_filter: str = "") -> dict:
        """List Wazuh agents filtered by status.

        status: active | disconnected | pending | never_connected
        group_filter: optional agent group for multi-tenant scoping (e.g. "linux-servers")
        """
        url = f"/agents?status={status}&limit={_cap(limit)}"
        if group_filter:
            # Strip characters that could break the query string
            safe_group = "".join(c for c in group_filter if c.isalnum() or c in ("-", "_"))
            url += f"&group={safe_group}"
        return await wz.request("GET", url)

    @mcp.tool()
    async def get_agent(agent_id: str) -> dict:
        """Get detailed info for a single agent by its ID (e.g. '001')."""
        return await wz.request("GET", f"/agents?agents_list={agent_id}")

    @mcp.tool()
    async def restart_agent(agent_id: str, dry_run: bool = True) -> dict:
        """Restart a Wazuh agent.

        dry_run=True (default) — shows what would happen without executing.
        Set dry_run=False to actually restart. Requires WAZUH_ALLOW_WRITES=true.
        Requires role: responder or above.
        """
        err = responder_only()
        if err:
            return err
        if dry_run:
            return {
                "dry_run": True,
                "agent_id": agent_id,
                "message": "Set dry_run=False to restart the agent. Requires WAZUH_ALLOW_WRITES=true.",
            }
        blocked = _require_writes()
        if blocked:
            return blocked
        return await wz.request("PUT", f"/agents/{agent_id}/restart")

    @mcp.tool()
    async def run_active_response(
        agent_id: str,
        command: str,
        arguments: list | None = None,
        dry_run: bool = True,
    ) -> dict:
        """Trigger an active response command on an agent (e.g. firewall-drop).

        dry_run=True (default) — shows what would be sent without executing.
        Set dry_run=False to actually trigger. Requires WAZUH_ALLOW_WRITES=true.
        Requires role: responder or above.
        """
        err = responder_only()
        if err:
            return err
        if dry_run:
            return {
                "dry_run": True,
                "agent_id": agent_id,
                "command": command,
                "arguments": arguments or [],
                "message": "Set dry_run=False to execute. Requires WAZUH_ALLOW_WRITES=true.",
            }
        blocked = _require_writes()
        if blocked:
            return blocked
        body = {"command": command, "arguments": arguments or [], "alert": {}}
        return await wz.request(
            "PUT", f"/active-response?agents_list={agent_id}", json=body
        )

    @mcp.tool()
    async def list_groups(limit: int = 100) -> dict:
        """List Wazuh agent groups with their member counts and config status."""
        return await wz.request("GET", f"/groups?limit={_cap(limit)}")

    @mcp.tool()
    async def get_group_agents(group_id: str, limit: int = 200) -> dict:
        """List agents that belong to a given group."""
        return await wz.request(
            "GET", f"/groups/{group_id}/agents?limit={_cap(limit)}"
        )

    @mcp.tool()
    async def add_agent_to_group(agent_id: str, group_id: str) -> dict:
        """Assign an agent to a group. Destructive — requires WAZUH_ALLOW_WRITES=true.
        Requires role: admin.
        """
        err = admin_only()
        if err:
            return err
        blocked = _require_writes()
        if blocked:
            return blocked
        return await wz.request("PUT", f"/agents/{agent_id}/group/{group_id}")
