"""Wazuh Manager security audit log tools.

Query the Manager's built-in security audit trail — who logged in,
what API actions were performed, and by which user.
Requires ADMIN role.
"""
from __future__ import annotations


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def search_manager_audit_log(
        limit: int = 50,
        action_type: str | None = None,
        user: str | None = None,
    ) -> dict:
        """Search the Wazuh Manager security audit log (API actions).

        Returns who performed what operations via the Manager REST API.
        Requires ADMIN role.

        Args:
            limit: Maximum entries to return.
            action_type: Optional filter (e.g. 'security:login', 'agents:delete').
            user: Optional filter by username.
        """
        from ..rbac import admin_only
        err = admin_only()
        if err:
            return err

        path = f"/security/actions?limit={_cap(limit)}"
        if action_type:
            path += f"&action={action_type}"
        if user:
            path += f"&user={user}"
        try:
            result = await wz.request("GET", path)
            items = (result.get("data") or {}).get("affected_items", [])
            return {
                "total": (result.get("data") or {}).get("total_affected_items", len(items)),
                "filter_action": action_type,
                "filter_user": user,
                "entries": [
                    {
                        "timestamp": item.get("timestamp"),
                        "user": item.get("user"),
                        "action": item.get("action"),
                        "resource": item.get("resource"),
                        "result": item.get("result"),
                        "ip": item.get("ip"),
                    }
                    for item in items
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_manager_login_history(limit: int = 50) -> dict:
        """List recent logins to the Wazuh Manager API.

        Shows successful and failed authentication attempts.
        Requires ADMIN role.
        """
        from ..rbac import admin_only
        err = admin_only()
        if err:
            return err

        try:
            result = await wz.request(
                "GET",
                f"/security/actions?limit={_cap(limit)}&action=security:login",
            )
            items = (result.get("data") or {}).get("affected_items", [])
            return {
                "total": (result.get("data") or {}).get("total_affected_items", len(items)),
                "logins": [
                    {
                        "timestamp": item.get("timestamp"),
                        "user": item.get("user"),
                        "result": item.get("result"),
                        "ip": item.get("ip"),
                    }
                    for item in items
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def list_manager_api_users() -> dict:
        """List all configured Wazuh Manager API users and their roles.

        Requires ADMIN role.
        """
        from ..rbac import admin_only
        err = admin_only()
        if err:
            return err

        try:
            result = await wz.request("GET", "/security/users?limit=500")
            items = (result.get("data") or {}).get("affected_items", [])
            return {
                "total": len(items),
                "users": [
                    {
                        "id": u.get("id"),
                        "username": u.get("username"),
                        "allow_run_as": u.get("allow_run_as"),
                        "roles": [r.get("name") for r in (u.get("roles") or [])],
                    }
                    for u in items
                ],
            }
        except Exception as e:
            return {"error": str(e)}
