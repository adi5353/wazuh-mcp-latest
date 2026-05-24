"""Agent upgrade management tools — trigger, track, and roll back agent upgrades."""
from __future__ import annotations


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def list_agent_upgrades(limit: int = 50) -> dict:
        """List agents that have an upgrade available, with current and latest versions."""
        try:
            result = await wz.request("GET", f"/agents?limit={_cap(limit)}&select=id,name,version,status")
            agents = (result.get("data") or {}).get("affected_items", [])
            upgradeable = [
                {
                    "agent_id": a.get("id"),
                    "agent_name": a.get("name"),
                    "current_version": a.get("version"),
                    "status": a.get("status"),
                }
                for a in agents
                if a.get("status") == "active"
            ]
            return {
                "total_active": len(upgradeable),
                "agents": upgradeable,
                "note": "Use trigger_agent_upgrade() to upgrade specific agents.",
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def trigger_agent_upgrade(
        agent_ids: list[str],
        version: str | None = None,
        dry_run: bool = True,
    ) -> dict:
        """Trigger a Wazuh agent version upgrade for one or more agents.

        Requires RESPONDER role and WAZUH_ALLOW_WRITES=true.
        Always dry_run=True by default — set dry_run=False to execute.
        """
        from ..rbac import responder_only
        err = responder_only()
        if err:
            return err

        from ..server import _require_writes
        err = _require_writes()
        if err:
            return err

        if not agent_ids:
            return {"error": "agent_ids list must not be empty."}

        if dry_run:
            return {
                "dry_run": True,
                "would_upgrade": agent_ids,
                "version": version or "latest",
                "message": "Set dry_run=False to execute the upgrade.",
            }

        payload: dict = {"agents_list": agent_ids}
        if version:
            payload["version"] = version

        try:
            result = await wz.request("PUT", "/agents/upgrade", json=payload)
            return {
                "upgrade_triggered": True,
                "agents": agent_ids,
                "version": version or "latest",
                "result": result,
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_agent_upgrade_status(agent_ids: list[str]) -> dict:
        """Poll the upgrade task status for a list of agents."""
        if not agent_ids:
            return {"error": "agent_ids must not be empty."}
        try:
            ids_param = ",".join(agent_ids)
            result = await wz.request(
                "GET", f"/agents/upgrade_result?agents_list={ids_param}"
            )
            return result
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def rollback_agent_upgrade(agent_id: str, dry_run: bool = True) -> dict:
        """Roll back a single agent to its previous version.

        Requires ADMIN role and WAZUH_ALLOW_WRITES=true.
        """
        from ..rbac import admin_only
        err = admin_only()
        if err:
            return err

        from ..server import _require_writes
        err = _require_writes()
        if err:
            return err

        if dry_run:
            return {
                "dry_run": True,
                "agent_id": agent_id,
                "message": "Set dry_run=False to execute the rollback.",
            }
        try:
            result = await wz.request(
                "PUT", "/agents/upgrade", json={"agents_list": [agent_id], "force": True}
            )
            return {"rollback_triggered": True, "agent_id": agent_id, "result": result}
        except Exception as e:
            return {"error": str(e)}
