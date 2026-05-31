"""Operational-context gating — shrink the *effective* tool surface per session.

Even after role-based registration filtering (``server.py``), an ADMIN session
exposes a large number of tools. This module adds a second, orthogonal dimension:
**operational contexts** (Threat Hunting, Active Response, Compliance, System
Health). When gating is enabled, the heavy, specialised tool groups are *inert*
until the caller explicitly enters their context via a routing tool — which keeps
the model focused and reduces mis-selection.

Why gating (not dynamic add/remove)? FastMCP's tool registry is process-global,
so ``add_tool``/``remove_tool`` would change the tool list for *every* concurrent
HTTP client. Gating instead keys the active context to the **caller identity**,
so two tenants sharing one server never affect each other.

Disabled by default — set ``WAZUH_MCP_CONTEXT_GATING=true`` to enable. When
disabled, ``is_tool_allowed`` always returns True and behaviour is unchanged.

Configuration (env vars):
    WAZUH_MCP_CONTEXT_GATING — "true"/"1" to enable gating (default off)

Flow:
    1. A tool module declares ``CONTEXT = "threat_hunting"`` (optional). Modules
       without a CONTEXT are "core" and always available.
    2. At registration, ``server.py`` calls ``set_registering_module(name)`` so
       the tool middleware can ``tag_tool(tool_name)`` — auto-building the
       tool→context map without per-tool annotations.
    3. At call time, the middleware calls ``is_tool_allowed(tool, identity)``.
       Out-of-context tools return ``gate_message(tool)`` instructing the model
       to call ``enter_operational_context(<ctx>)`` first.
"""
from __future__ import annotations

import os
import threading

CORE = "core"  # always-on: never gated

# Canonical operational contexts and the tool *modules* that belong to each.
# Modules not listed here are treated as CORE (always available). Keeping this
# central (rather than a per-module attribute) makes the grouping reviewable in
# one place and easy to extend.
CONTEXT_MODULES: dict[str, set[str]] = {
    "threat_hunting": {
        "threat_hunting", "threat_intel", "threat_feeds", "correlation", "ueba",
    },
    "active_response": {
        "active_response", "cdb", "suppression", "rule_wizard_deploy",
    },
    "compliance": {
        "compliance", "reporting", "scheduler",
    },
    "system_health": {
        "agent_upgrades", "fim", "rootcheck", "sca", "fleet",
    },
}

# Reverse map: module name → context name (built once at import).
_MODULE_TO_CONTEXT: dict[str, str] = {
    mod: ctx for ctx, mods in CONTEXT_MODULES.items() for mod in mods
}


def gating_enabled() -> bool:
    return os.getenv("WAZUH_MCP_CONTEXT_GATING", "").strip().lower() in ("1", "true", "yes")


# ── Tool → context map, built during registration ────────────────────────────
_registering_module: str | None = None
_tool_to_context: dict[str, str] = {}


def set_registering_module(modname: str | None) -> None:
    """Called by server.py around each ``mod.register(ctx)`` so newly registered
    tools can be tagged with the module's context."""
    global _registering_module
    _registering_module = modname


def tag_tool(tool_name: str) -> None:
    """Record the context of a tool based on the module currently registering.

    Tools registered outside any module (e.g. defined inline in server.py) have
    ``_registering_module is None`` and are treated as CORE.
    """
    ctx = _MODULE_TO_CONTEXT.get(_registering_module or "", CORE)
    _tool_to_context[tool_name] = ctx


def context_of(tool_name: str) -> str:
    return _tool_to_context.get(tool_name, CORE)


# ── Per-identity active contexts (persists across HTTP requests) ──────────────
# Keyed by the caller identity hash (see identity.get_identity_key). A ContextVar
# would reset every HTTP request; a process-wide dict lets a caller's chosen
# context survive across the multiple requests of one MCP session.
_active: dict[str, set[str]] = {}
_lock = threading.Lock()


def active_contexts(identity: str) -> set[str]:
    with _lock:
        return set(_active.get(identity, set()))


def enter_context(identity: str, context: str) -> set[str]:
    """Activate *context* for *identity*. Returns the new active set."""
    with _lock:
        cur = _active.setdefault(identity, set())
        cur.add(context)
        return set(cur)


def exit_context(identity: str, context: str) -> set[str]:
    with _lock:
        cur = _active.setdefault(identity, set())
        cur.discard(context)
        return set(cur)


def reset_contexts(identity: str) -> None:
    with _lock:
        _active.pop(identity, None)


def is_tool_allowed(tool_name: str, identity: str) -> bool:
    """True if *tool_name* may run for *identity* under the current gating policy."""
    if not gating_enabled():
        return True
    ctx = context_of(tool_name)
    if ctx == CORE:
        return True
    return ctx in active_contexts(identity)


def gate_message(tool_name: str) -> dict:
    ctx = context_of(tool_name)
    return {
        "error": (
            f"Tool '{tool_name}' belongs to the '{ctx}' operational context, "
            f"which is not active for this session. Call "
            f"enter_operational_context('{ctx}') first to enable this group of "
            f"tools, then retry."
        ),
        "gated": True,
        "required_context": ctx,
    }
