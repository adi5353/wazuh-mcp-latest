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

from .bounded_state import BoundedTTLStore

CORE = "core"  # always-on: never gated

# Canonical operational contexts and the tool *modules* that belong to each.
# Modules not listed here are treated as CORE (always available). Keeping this
# central (rather than a per-module attribute) makes the grouping reviewable in
# one place and easy to extend.
#
# CORE (intentionally NOT listed below) is the lean everyday-triage surface that
# stays available without entering any context: alerts, agents, agent_health,
# health_check, cluster, metrics, routing, prompt_advisor, explain_alert,
# quick_wins, onboarding, workspaces. Every other module is routed into one of
# the contexts below so that, when gating is enabled, a session only advertises
# the specialised groups it has explicitly entered. Gating is OFF by default
# (see ``gating_enabled``), so expanding this map does not change default
# behaviour — it only makes opt-in gating shrink the surface more effectively.
CONTEXT_MODULES: dict[str, set[str]] = {
    # Investigation / hunting / enrichment
    "threat_hunting": {
        "threat_hunting", "threat_intel", "threat_feeds", "correlation", "ueba",
        "mitre", "geo_intel", "network_topology", "baseline", "archive",
    },
    # Containment, remediation, and detection-rule authoring
    "active_response": {
        "active_response", "cdb", "suppression",
        "rule_wizard", "rule_wizard_deploy", "rule_wizard_generate",
        "rule_wizard_validate", "rules",
        "decoder_wizard", "decoder_wizard_generate", "decoder_wizard_validate",
        "detection_drafter",
    },
    # Compliance posture, reporting, audit trails, evidence export
    "compliance": {
        "compliance", "reporting", "scheduler", "audit_mgmt", "manager_audit",
        "export",
    },
    # Fleet posture: upgrades, FIM, rootcheck, SCA, vulnerabilities
    "system_health": {
        "agent_upgrades", "fim", "rootcheck", "sca", "fleet",
        "vulnerabilities", "cve_watchlist",
    },
    # Case management, automation playbooks, and ticketing/notification sinks
    "incident_response": {
        "incidents", "playbooks", "autonomous_soc", "pagerduty", "servicenow",
        "azure_devops", "integrations", "notifications",
    },
    # Manager/index/credential/syslog configuration + ROI bookkeeping
    "administration": {
        "index_mgmt", "manager_config", "credential_mgmt", "syslog_config", "roi",
    },
}

# Reverse map: module name → context name (built once at import).
_MODULE_TO_CONTEXT: dict[str, str] = {
    mod: ctx for ctx, mods in CONTEXT_MODULES.items() for mod in mods
}


# ── Static, deployment-level module scoping (registration-time) ────────────────
# Orthogonal to both role-based registration filtering and per-session context
# gating: lets an operator pin the *advertised* tool surface for the whole
# process via env vars. This is the non-breaking answer to "242 tools is a lot of
# context" — no tool is renamed; a deployment simply chooses which domain modules
# to load. Default (both unset) = every module registers, identical to before.
#
#   WAZUH_MCP_ENABLED_MODULES  — allowlist. If set, ONLY these register.
#   WAZUH_MCP_DISABLED_MODULES — denylist. Always removed, even if also enabled.
#
# Both accept comma-separated entries that are either a tool module name
# (e.g. "alerts", "vulnerabilities") or a context-group name from
# CONTEXT_MODULES (e.g. "threat_hunting" expands to all its modules).

def _parse_module_set(env_value: str) -> set[str]:
    """Expand a comma-separated env value into a concrete set of module names.

    Group names (keys of CONTEXT_MODULES) expand to their member modules;
    everything else is treated as a literal module name. Blank/whitespace
    entries are ignored.
    """
    out: set[str] = set()
    for raw in env_value.split(","):
        name = raw.strip()
        if not name:
            continue
        if name in CONTEXT_MODULES:
            out.update(CONTEXT_MODULES[name])
        else:
            out.add(name)
    return out


def module_registration_allowed(modname: str) -> bool:
    """Return True if *modname* should be registered under the env scoping.

    Precedence: a module must be in the allowlist (when one is set) AND must not
    be in the denylist. With neither env var set, every module is allowed.
    """
    enabled = _parse_module_set(os.getenv("WAZUH_MCP_ENABLED_MODULES", ""))
    disabled = _parse_module_set(os.getenv("WAZUH_MCP_DISABLED_MODULES", ""))
    if enabled and modname not in enabled:
        return False
    if modname in disabled:
        return False
    return True


def unknown_scoping_names(valid_modules: set[str]) -> set[str]:
    """Return env-listed names that match neither a module nor a group.

    Lets the server warn on typos (e.g. WAZUH_MCP_DISABLED_MODULES=alert) instead
    of silently scoping nothing — *valid_modules* is the set of discovered tool
    module names. Group names are always considered valid.
    """
    listed: set[str] = set()
    for var in ("WAZUH_MCP_ENABLED_MODULES", "WAZUH_MCP_DISABLED_MODULES"):
        for raw in os.getenv(var, "").split(","):
            name = raw.strip()
            if name:
                listed.add(name)
    return {n for n in listed if n not in valid_modules and n not in CONTEXT_MODULES}


def gating_enabled() -> bool:
    return os.getenv("WAZUH_MCP_CONTEXT_GATING", "").strip().lower() in ("1", "true", "yes")


def legacy_aliases_enabled() -> bool:
    """Whether legacy duplicate-tool aliases are advertised (default True).

    Some tool families were consolidated behind a single parameterized tool
    (e.g. the per-framework ``*_compliance_summary`` tools behind
    ``compliance_framework_summary(framework=...)``). The original tool names
    are kept as thin wrappers so existing clients keep working. Set
    ``WAZUH_MCP_LEGACY_ALIASES=false`` to advertise only the consolidated tools
    and shrink the advertised surface. Default keeps every legacy name.
    """
    return os.getenv("WAZUH_MCP_LEGACY_ALIASES", "true").strip().lower() not in (
        "0", "false", "no",
    )


def alias_tool(mcp):
    """Return an ``@mcp.tool``-style decorator for backward-compatible aliases.

    The returned decorator registers a function as an MCP tool only when legacy
    aliases are enabled (the default). When ``WAZUH_MCP_LEGACY_ALIASES=false`` it
    leaves the function defined-but-unregistered, so it disappears from the
    advertised surface while remaining callable from the consolidated tool that
    replaced it. Used by modules that collapse duplicate tool families (see
    ``compliance``/``threat_intel``/``notifications``). The local name a module
    binds this to (``_alias_tool``) is recognised by
    ``scripts/generate_tool_table.py`` so the inventory count stays accurate.
    """
    def deco(*a, **k):
        if legacy_aliases_enabled():
            return mcp.tool(*a, **k)
        return lambda fn: fn
    return deco


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
# would reset every HTTP request; a process-wide store lets a caller's chosen
# context survive across the multiple requests of one MCP session. Bounded by
# size + idle-TTL so a long-lived server can't leak memory across many callers.
_MAX_TRACKED_IDENTITIES = int(os.getenv("WAZUH_MCP_MAX_TRACKED_IDENTITIES", "10000"))
_IDENTITY_TTL_SECONDS = float(os.getenv("WAZUH_MCP_IDENTITY_TTL_SECONDS", "86400"))

_active: BoundedTTLStore[set] = BoundedTTLStore(
    max_entries=_MAX_TRACKED_IDENTITIES,
    ttl_seconds=_IDENTITY_TTL_SECONDS,
    default_factory=set,
)


def active_contexts(identity: str) -> set[str]:
    return set(_active.get(identity) or set())


def enter_context(identity: str, context: str) -> set[str]:
    """Activate *context* for *identity*. Returns the new active set."""
    cur = _active.get_or_create(identity)
    cur.add(context)
    return set(cur)


def exit_context(identity: str, context: str) -> set[str]:
    cur = _active.get(identity)
    if cur is None:
        return set()
    cur.discard(context)
    return set(cur)


def reset_contexts(identity: str) -> None:
    _active.pop(identity)


def tracked_identity_count() -> int:
    """Number of identities with active operational contexts (for metrics)."""
    return len(_active)


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
