"""Routing tools — let an operator/agent enter operational contexts.

These tools are always available (CORE). When context gating is enabled
(``WAZUH_MCP_CONTEXT_GATING=true``), specialised tool groups are inert until the
caller activates their context here. See ``wazuh_mcp/tool_contexts.py``.

When gating is disabled these tools still work and simply report that all
contexts are already available.
"""
from __future__ import annotations

from ..tool_context import ToolContext
from .. import tool_contexts as tc
from ..identity import get_identity_key


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp

    @mcp.tool()
    async def list_operational_contexts() -> dict:
        """List operational contexts (Threat Hunting, Active Response, etc.),
        which are active for this session, and the tool modules each unlocks.

        Use this to discover what to pass to enter_operational_context().
        """
        identity = get_identity_key()
        active = tc.active_contexts(identity)
        return {
            "gating_enabled": tc.gating_enabled(),
            "active_contexts": sorted(active),
            "available_contexts": {
                name: sorted(mods) for name, mods in tc.CONTEXT_MODULES.items()
            },
            "note": (
                "Gating is enabled — call enter_operational_context(<name>) to "
                "activate a context before using its tools."
                if tc.gating_enabled()
                else "Gating is disabled — all tools are available regardless of context."
            ),
        }

    @mcp.tool()
    async def enter_operational_context(context: str) -> dict:
        """Activate an operational context for this session, unlocking its tools.

        context — one of: threat_hunting, active_response, compliance, system_health.
        """
        if context not in tc.CONTEXT_MODULES:
            return {
                "error": f"Unknown context '{context}'.",
                "available_contexts": sorted(tc.CONTEXT_MODULES),
            }
        identity = get_identity_key()
        active = tc.enter_context(identity, context)
        return {
            "entered": context,
            "active_contexts": sorted(active),
            "unlocked_modules": sorted(tc.CONTEXT_MODULES[context]),
        }

    @mcp.tool()
    async def exit_operational_context(context: str) -> dict:
        """Deactivate an operational context for this session."""
        identity = get_identity_key()
        active = tc.exit_context(identity, context)
        return {"exited": context, "active_contexts": sorted(active)}
