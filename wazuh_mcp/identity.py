"""Per-session identity and RBAC key-mapping (Gap 1).

Provides task-local context variables so multiple concurrent sessions can each
carry their own role without sharing global env-var state.

Multi-user setup
----------------
Set WAZUH_MCP_KEY_MAP as a comma-separated list of ``role:apikey`` pairs::

    WAZUH_MCP_KEY_MAP=viewer:key_abc123,analyst:key_def456,admin:key_xyz789

Then callers pass their key via the ``set_session_role`` MCP tool (STDIO mode)
or the ``X-MCP-Api-Key`` HTTP header (SSE/HTTP mode).

Single-user setup
-----------------
Leave WAZUH_MCP_KEY_MAP unset.  The server falls back to
``WAZUH_MCP_USER_ROLE`` (default: analyst) — existing behaviour unchanged.

Injection lockout
-----------------
After 3 injection attempts in a session the role is downgraded to VIEWER and
the event is logged. Counter resets on each new session (ContextVar default).
"""
from __future__ import annotations

import contextvars
import logging
import os
from typing import Optional

from .rbac import ROLE, _NAME_TO_ROLE

log = logging.getLogger("wazuh-mcp")

# ── Per-task context variables ────────────────────────────────────────────────

_ctx_role: contextvars.ContextVar[Optional[ROLE]] = contextvars.ContextVar(
    "_ctx_role", default=None
)
_ctx_injection_count: contextvars.ContextVar[int] = contextvars.ContextVar(
    "_ctx_injection_count", default=0
)

INJECTION_LOCKOUT_THRESHOLD = 3


# ── Key map (parsed once at import) ──────────────────────────────────────────

def _parse_key_map() -> dict[str, ROLE]:
    """Parse WAZUH_MCP_KEY_MAP into {apikey: ROLE}."""
    raw = os.getenv("WAZUH_MCP_KEY_MAP", "").strip()
    result: dict[str, ROLE] = {}
    if not raw:
        return result
    for entry in raw.split(","):
        entry = entry.strip()
        if ":" not in entry:
            continue
        role_name, _, key = entry.partition(":")
        role = _NAME_TO_ROLE.get(role_name.strip().lower())
        if role and key.strip():
            result[key.strip()] = role
    return result


_KEY_MAP: dict[str, ROLE] = _parse_key_map()


# ── Public API ────────────────────────────────────────────────────────────────

def resolve_role_for_key(api_key: str) -> Optional[ROLE]:
    """Return the role for a given API key, or None if unknown."""
    return _KEY_MAP.get(api_key)


def set_session_role(role: ROLE) -> None:
    """Bind *role* to the current asyncio task context."""
    _ctx_role.set(role)


def get_session_role() -> Optional[ROLE]:
    """Return the role bound to this task, or None if not set."""
    return _ctx_role.get()


def record_injection_attempt() -> bool:
    """Increment injection counter. Returns True if lockout threshold is reached."""
    count = _ctx_injection_count.get() + 1
    _ctx_injection_count.set(count)
    if count >= INJECTION_LOCKOUT_THRESHOLD:
        _ctx_role.set(ROLE.VIEWER)
        log.warning(
            "Session locked to VIEWER after %d injection attempts", count
        )
        return True
    return False


def effective_role() -> ROLE:
    """Return the effective ROLE for the current session.

    Priority order:
      1. Task-local role (set via set_session_role or set_session_role tool)
      2. WAZUH_MCP_USER_ROLE env var
      3. Default: ANALYST
    """
    task_role = _ctx_role.get()
    if task_role is not None:
        return task_role
    raw = os.getenv("WAZUH_MCP_USER_ROLE", "viewer").strip().lower()
    return _NAME_TO_ROLE.get(raw, ROLE.ANALYST)
