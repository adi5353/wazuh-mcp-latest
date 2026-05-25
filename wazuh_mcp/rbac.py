"""Role-Based Access Control for Wazuh MCP tools.

Defines four role tiers with escalating privileges:

  viewer     — read-only: summaries, searches, listings
  analyst    — viewer + enrichment, hunt, compliance, rules, incidents
  responder  — analyst + active response, CDB writes, suppression
  admin      — responder + cluster management, agent restart, rule push

Set the server-wide role via WAZUH_MCP_USER_ROLE env var (default: analyst).
Tools annotated with a role requirement will reject calls from lower-tier roles.

Usage in a tool module::

    from ..rbac import require_role, ROLE

    @mcp.tool()
    async def run_active_response(...) -> dict:
        err = require_role(ROLE.RESPONDER)
        if err:
            return err
        ...
"""
from __future__ import annotations

import os
from enum import IntEnum


class ROLE(IntEnum):
    """Numeric tiers — higher value = more privileged."""
    VIEWER    = 10
    ANALYST   = 20
    RESPONDER = 30
    ADMIN     = 40


# Human-readable names → tier mapping (case-insensitive)
_NAME_TO_ROLE: dict[str, ROLE] = {
    "viewer":    ROLE.VIEWER,
    "analyst":   ROLE.ANALYST,
    "responder": ROLE.RESPONDER,
    "admin":     ROLE.ADMIN,
}

# Role → friendly name for error messages
_ROLE_NAMES: dict[ROLE, str] = {v: k for k, v in _NAME_TO_ROLE.items()}


def _current_role() -> ROLE:
    """Return the effective role: task-local identity first, env var fallback."""
    try:
        from .identity import effective_role
        return effective_role()
    except ImportError:
        pass
    raw = os.getenv("WAZUH_MCP_USER_ROLE", "analyst").strip().lower()
    return _NAME_TO_ROLE.get(raw, ROLE.ANALYST)


def require_role(minimum: ROLE) -> dict | None:
    """Return an error dict when the current role is below *minimum*, else None.

    Drop-in guard for tool functions::

        err = require_role(ROLE.RESPONDER)
        if err:
            return err
    """
    current = _current_role()
    if current < minimum:
        return {
            "error": (
                f"Insufficient role. This tool requires '{_ROLE_NAMES[minimum]}' or above. "
                f"Current role: '{_ROLE_NAMES.get(current, current)}'. "
                f"Set WAZUH_MCP_USER_ROLE to a higher tier to enable this tool."
            ),
            "required_role": _ROLE_NAMES[minimum],
            "current_role":  _ROLE_NAMES.get(current, str(current)),
        }
    return None


# ── Convenience aliases ───────────────────────────────────────────────────────

def viewer_only()    -> dict | None: return require_role(ROLE.VIEWER)
def analyst_only()   -> dict | None: return require_role(ROLE.ANALYST)
def responder_only() -> dict | None: return require_role(ROLE.RESPONDER)
def admin_only()     -> dict | None: return require_role(ROLE.ADMIN)
