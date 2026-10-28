"""Role-Based Access Control for Wazuh MCP tools.

Defines four role tiers with escalating privileges:

  viewer     — read-only: summaries, searches, listings
  analyst    — viewer + enrichment, hunt, compliance, rules, incidents
  responder  — analyst + active response, CDB writes, suppression
  admin      — responder + cluster management, agent restart, rule push

Set the server-wide role via WAZUH_MCP_USER_ROLE env var (default: viewer — fail closed).
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

import functools
import os
from enum import IntEnum
from typing import Callable


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
    """Return the effective role: task-local identity first, env var fallback.

    Fails closed: an unknown/misspelled role name resolves to VIEWER
    (least privilege) rather than ANALYST.
    """
    try:
        from .identity import effective_role
        return effective_role()
    except ImportError:
        pass
    raw = os.getenv("WAZUH_MCP_USER_ROLE", "viewer").strip().lower()
    return _NAME_TO_ROLE.get(raw, ROLE.VIEWER)


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


# ── Decorator form (preferred for new tools) ──────────────────────────────────

def require(minimum: ROLE) -> Callable:
    """Decorator that enforces a minimum role before the tool body runs.

    Use this on new tools so RBAC can never be forgotten::

        @mcp.tool()
        @rbac.require(ROLE.RESPONDER)
        async def run_active_response(...) -> dict:
            ...

    Returns the same error dict shape as require_role() on rejection,
    so the LLM receives a structured error rather than an exception.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            err = require_role(minimum)
            if err:
                return err
            return await fn(*args, **kwargs)
        return wrapper
    return decorator


# ── Convenience helpers ───────────────────────────────────────────────────────
# Each enforces a MINIMUM tier: "<role>_or_above" passes for that role and every
# higher one. The old "<role>_only" names were misleading — they read as "only
# this exact role" but always meant "this role or above" — so they are kept only
# as deprecated aliases below.

def require_viewer_or_above()    -> dict | None: return require_role(ROLE.VIEWER)
def require_analyst_or_above()   -> dict | None: return require_role(ROLE.ANALYST)
def require_responder_or_above() -> dict | None: return require_role(ROLE.RESPONDER)
def require_admin_or_above()     -> dict | None: return require_role(ROLE.ADMIN)


# ── Deprecated aliases (misleading "_only" naming) ────────────────────────────
# Retained for backward compatibility with any external importers. Prefer the
# "_or_above" names above; these may be removed in a future major release.
viewer_only      = require_viewer_or_above
analyst_only     = require_analyst_or_above
analyst_or_above = require_analyst_or_above
responder_only   = require_responder_or_above
admin_only       = require_admin_or_above
