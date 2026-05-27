"""Credential management tools — rotation support and age reporting.

H8: Allows admins to check how old the current API credentials are and
rotate the Wazuh Manager API user password without restarting the server.

Requires:
  - WAZUH_ALLOW_WRITES=true
  - WAZUH_MCP_USER_ROLE=admin
  - WAZUH_CRED_CREATED_AT=<unix-timestamp>  (optional, for age reporting)
"""
from __future__ import annotations

import os
import time

from ..rbac import admin_only
from ..validators import safe_validate, validate_free_text


def register(mcp, wz, cfg, _require_writes):

    @mcp.tool()
    async def get_credential_age() -> dict:
        """Report how old the current Wazuh API credentials are.

        Set WAZUH_CRED_CREATED_AT=<unix-timestamp> in .env to enable age tracking.
        Returns age in days and a recommendation if rotation is overdue (>90 days).
        """
        created_at_raw = os.getenv("WAZUH_CRED_CREATED_AT")
        if not created_at_raw:
            return {
                "status": "unknown",
                "message": (
                    "Set WAZUH_CRED_CREATED_AT=<unix-timestamp> in .env to track credential age. "
                    "Get the current timestamp with: python3 -c \"import time; print(int(time.time()))\""
                ),
            }
        try:
            created_at = float(created_at_raw)
        except ValueError:
            return {"error": "WAZUH_CRED_CREATED_AT must be a Unix timestamp (integer seconds)."}

        age_seconds = time.time() - created_at
        age_days = round(age_seconds / 86400, 1)

        if age_days > 90:
            recommendation = "OVERDUE — rotate credentials immediately (>90 days old)."
            status = "critical"
        elif age_days > 60:
            recommendation = "WARNING — credentials are aging (>60 days). Plan rotation soon."
            status = "warning"
        else:
            recommendation = "OK — credentials are within acceptable age."
            status = "ok"

        return {
            "status": status,
            "age_days": age_days,
            "created_at_unix": created_at,
            "recommendation": recommendation,
            "wazuh_user": cfg.manager_user,
        }

    @mcp.tool()
    async def rotate_wazuh_api_password(
        new_password: str,
        dry_run: bool = True,
    ) -> dict:
        """Rotate the Wazuh Manager API user password.

        Calls PUT /security/users/{id} to update the password, then forces
        a JWT re-login so the server continues working without restart.

        new_password: the new password to set (min 8 chars, must include uppercase,
                      lowercase, digit, and special char per Wazuh policy).
        dry_run=True (default): validate inputs without making changes.
        Requires role: admin. Requires WAZUH_ALLOW_WRITES=true.
        """
        err = admin_only()
        if err:
            return err

        blocked = _require_writes()
        if blocked:
            return blocked

        _, err = safe_validate(validate_free_text, new_password, "new_password", max_len=128)
        if err:
            return err

        if len(new_password) < 8:
            return {"error": "new_password must be at least 8 characters."}

        if dry_run:
            return {
                "dry_run": True,
                "user": cfg.manager_user,
                "message": (
                    "DRY RUN: Would update password for Wazuh API user "
                    f"'{cfg.manager_user}' and force a JWT re-login. "
                    "Set dry_run=False to apply."
                ),
            }

        # 1. Find the user's numeric ID
        try:
            users_resp = await wz.request("GET", "/security/users")
            users = (users_resp.get("data") or {}).get("affected_items", [])
            user_id = next(
                (u["id"] for u in users if u.get("username") == cfg.manager_user),
                None,
            )
            if not user_id:
                return {"error": f"User '{cfg.manager_user}' not found in Wazuh Manager."}
        except Exception as exc:
            return {"error": f"Failed to look up user ID: {exc}"}

        # 2. Update the password
        try:
            result = await wz.request(
                "PUT",
                f"/security/users/{user_id}",
                json={"password": new_password},
            )
        except Exception as exc:
            return {"error": f"Password update failed: {exc}"}

        # 3. Force JWT re-login (clear cached token)
        wz._token = None
        wz._token_expires = 0.0
        try:
            await wz._login()
            login_status = "re-authenticated successfully"
        except Exception as exc:
            login_status = f"WARNING: re-login failed ({exc}) — restart the server manually"

        # 4. Post-rotation connectivity verification
        connectivity_ok = False
        connectivity_error = None
        try:
            probe = await wz.request("GET", "/manager/info")
            if probe and (probe.get("data") or probe.get("error") is None):
                connectivity_ok = True
        except Exception as exc:
            connectivity_error = str(exc)

        if not connectivity_ok:
            return {
                "success": False,
                "user": cfg.manager_user,
                "user_id": user_id,
                "login_status": login_status,
                "connectivity_verified": False,
                "connectivity_error": connectivity_error,
                "warning": (
                    "Password was updated but post-rotation connectivity check failed. "
                    "Update WAZUH_PASS in your .env file and restart the server."
                ),
                "api_result": result,
            }

        return {
            "success": True,
            "user": cfg.manager_user,
            "user_id": user_id,
            "login_status": login_status,
            "connectivity_verified": True,
            "next_step": (
                f"Update WAZUH_PASS in your .env file to the new password "
                "and set WAZUH_CRED_CREATED_AT to the current timestamp."
            ),
            "api_result": result,
        }
