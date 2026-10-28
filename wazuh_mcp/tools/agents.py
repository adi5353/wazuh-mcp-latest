"""Agent management tools — list, inspect, restart, group assignment."""
from __future__ import annotations
from ..tool_context import ToolContext

from ..rbac import require_responder_or_above, require_admin_or_above, ROLE
REQUIRED_ROLE = ROLE.VIEWER
from ..abac import filter_manager_agents, check_group_access
from ..validators import (
    validate_active_response_target,
    validate_ar_command,
    validate_agent_id,
    safe_validate,
)


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
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
        # ABAC: the Manager API isn't group-scoped, so filter enumeration to the
        # session's allowed groups (no-op unless WAZUH_MCP_ALLOWED_GROUPS is set).
        return filter_manager_agents(await wz.request("GET", url))

    @mcp.tool()
    async def get_agent(agent_id: str) -> dict:
        """Get detailed info for a single agent by its ID (e.g. '001')."""
        agent_id, err = safe_validate(validate_agent_id, agent_id)
        if err:
            return err
        # ABAC: filtered to empty if the agent is outside the session's groups.
        return filter_manager_agents(
            await wz.request("GET", f"/agents?agents_list={agent_id}")
        )

    @mcp.tool()
    async def restart_agent(agent_id: str, dry_run: bool = True) -> dict:
        """Restart a Wazuh agent.

        dry_run=True (default) — shows what would happen without executing.
        Set dry_run=False to actually restart. Requires WAZUH_ALLOW_WRITES=true.
        Requires role: responder or above.
        """
        err = require_responder_or_above()
        if err:
            return err
        # Reject fan-out targets ('all'/'*') and malformed IDs before they reach
        # the Manager — a single-agent restart must never become fleet-wide.
        agent_id, verr = safe_validate(validate_agent_id, agent_id)
        if verr:
            return verr
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
        err = require_responder_or_above()
        if err:
            return err

        # Reject fan-out targets ('all'/'*') and malformed IDs — an active-response
        # on a single agent must never be turned into a fleet-wide firewall-drop.
        agent_id, verr = safe_validate(validate_agent_id, agent_id)
        if verr:
            return verr

        # Restrict to the active-response command allowlist (Issue 10)
        cmd_err = validate_ar_command(command)
        if cmd_err:
            return {"error": cmd_err, "blocked": True}

        # Protect critical infrastructure — block requests targeting private/reserved IPs
        src_ip_arg = (arguments or [None])[0] if arguments else None
        ip_err = validate_active_response_target(src_ip_arg)
        if ip_err:
            return {"error": ip_err, "blocked": True}

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
        # ABAC: deny enumeration of a group outside the session's allowed set.
        denied = check_group_access(group_id)
        if denied:
            return denied
        return filter_manager_agents(
            await wz.request("GET", f"/groups/{group_id}/agents?limit={_cap(limit)}")
        )

    @mcp.tool()
    async def add_agent_to_group(agent_id: str, group_id: str) -> dict:
        """Assign an agent to a group. Destructive — requires WAZUH_ALLOW_WRITES=true.
        Requires role: admin.
        """
        err = require_admin_or_above()
        if err:
            return err
        # ABAC: can't move an agent into a group outside the session's scope.
        denied = check_group_access(group_id)
        if denied:
            return denied
        blocked = _require_writes()
        if blocked:
            return blocked
        return await wz.request("PUT", f"/agents/{agent_id}/group/{group_id}")
