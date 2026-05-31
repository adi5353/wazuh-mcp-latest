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
``WAZUH_MCP_USER_ROLE`` (default: viewer — fail closed).

Injection lockout
-----------------
After 3 injection attempts in a session the role is downgraded to VIEWER and
the event is logged. Counter resets on each new session (ContextVar default).
"""
from __future__ import annotations

import contextvars
import logging
import os
import threading
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
# ContextVar holding the identity key (API key hash or session ID) so that the
# persistent cross-request counter can be keyed per identity.
_ctx_identity_key: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "_ctx_identity_key", default=None
)

INJECTION_LOCKOUT_THRESHOLD = 3

# M2: Persistent injection counter across requests — keyed by identity.
# Uses a process-wide dict protected by a lock so concurrent asyncio tasks can
# each increment atomically without interfering with each other.
_persistent_injection_counts: dict[str, int] = {}
_persistent_injection_lock = threading.Lock()


def set_identity_key(key: str) -> None:
    """Bind an identity key (e.g. hashed API key) to the current task context."""
    import hashlib
    # Store only a hash, never the raw key.
    _ctx_identity_key.set(hashlib.sha256(key.encode()).hexdigest()[:16])


def get_identity_key() -> str:
    """Return the current task's identity key (hashed API key), or 'anonymous'.

    Used to key per-caller state such as the tool-failure circuit breaker so one
    caller's retry loop cannot trip another caller's tools.
    """
    return _ctx_identity_key.get() or "anonymous"


def get_persistent_injection_count(identity: str) -> int:
    """Return the cross-request injection count for *identity*."""
    with _persistent_injection_lock:
        return _persistent_injection_counts.get(identity, 0)


def _increment_persistent(identity: str) -> int:
    """Atomically increment and return the new count for *identity*."""
    with _persistent_injection_lock:
        new = _persistent_injection_counts.get(identity, 0) + 1
        _persistent_injection_counts[identity] = new
        return new


def reset_persistent_injection_count(identity: str) -> None:
    """Reset the persistent counter (e.g. after an admin override)."""
    with _persistent_injection_lock:
        _persistent_injection_counts.pop(identity, None)


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
    """Increment injection counters (per-task and cross-request).

    M2: In addition to the per-task ContextVar counter (resets each new MCP
    request), also increments a persistent cross-request counter keyed by the
    identity key so that repeated attempts across separate requests accumulate.

    Returns True if the lockout threshold is reached on either counter.
    """
    # Per-task counter (original behaviour)
    task_count = _ctx_injection_count.get() + 1
    _ctx_injection_count.set(task_count)

    # M2: Cross-request persistent counter
    identity = _ctx_identity_key.get()
    persistent_count = _increment_persistent(identity) if identity else task_count

    # Lockout on either counter reaching the threshold
    reached = task_count >= INJECTION_LOCKOUT_THRESHOLD or (
        identity and persistent_count >= INJECTION_LOCKOUT_THRESHOLD
    )
    if reached:
        _ctx_role.set(ROLE.VIEWER)
        log.warning(
            "Session locked to VIEWER after %d injection attempts "
            "(task_count=%d, persistent_count=%d, identity=%s)",
            max(task_count, persistent_count), task_count, persistent_count,
            identity or "anonymous",
        )
        return True
    return False


def effective_role() -> ROLE:
    """Return the effective ROLE for the current session.

    Priority order:
      1. Task-local role (set via set_session_role or set_session_role tool)
      2. WAZUH_MCP_USER_ROLE env var
      3. Default: VIEWER

    Fails closed: an unknown/misspelled role name resolves to VIEWER
    (least privilege) rather than ANALYST.
    """
    task_role = _ctx_role.get()
    if task_role is not None:
        return task_role
    raw = os.getenv("WAZUH_MCP_USER_ROLE", "viewer").strip().lower()
    return _NAME_TO_ROLE.get(raw, ROLE.VIEWER)
