"""Tests for operational-context gating (wazuh_mcp/tool_contexts.py).

Gating is opt-in via WAZUH_MCP_CONTEXT_GATING and keyed per caller identity so
concurrent HTTP clients never affect each other.
"""
import os

import pytest
from unittest.mock import patch

import wazuh_mcp.tool_contexts as tc


@pytest.fixture(autouse=True)
def _clean_state():
    # Reset per-identity active contexts and the tool→context map around each test.
    tc._active.clear()
    yield
    tc._active.clear()


class TestGatingDisabled:
    def test_disabled_allows_everything(self):
        # No env var set → gating off → every tool allowed.
        tc._tool_to_context["hunt_lateral_movement"] = "threat_hunting"
        assert tc.is_tool_allowed("hunt_lateral_movement", "id1") is True

    def test_enabled_flag_parsing(self):
        with patch.dict(os.environ, {"WAZUH_MCP_CONTEXT_GATING": "true"}):
            assert tc.gating_enabled() is True
        with patch.dict(os.environ, {"WAZUH_MCP_CONTEXT_GATING": "0"}):
            assert tc.gating_enabled() is False


class TestGatingEnabled:
    def _enabled(self):
        return patch.dict(os.environ, {"WAZUH_MCP_CONTEXT_GATING": "true"})

    def test_core_tool_always_allowed(self):
        tc._tool_to_context["get_cluster_health"] = tc.CORE
        with self._enabled():
            assert tc.is_tool_allowed("get_cluster_health", "id1") is True

    def test_specialised_tool_gated_until_entered(self):
        tc._tool_to_context["hunt_lateral_movement"] = "threat_hunting"
        with self._enabled():
            assert tc.is_tool_allowed("hunt_lateral_movement", "id1") is False
            tc.enter_context("id1", "threat_hunting")
            assert tc.is_tool_allowed("hunt_lateral_movement", "id1") is True

    def test_per_identity_isolation(self):
        tc._tool_to_context["hunt_lateral_movement"] = "threat_hunting"
        with self._enabled():
            tc.enter_context("id1", "threat_hunting")
            # id2 never entered the context → still gated
            assert tc.is_tool_allowed("hunt_lateral_movement", "id1") is True
            assert tc.is_tool_allowed("hunt_lateral_movement", "id2") is False

    def test_exit_regates(self):
        tc._tool_to_context["hunt_lateral_movement"] = "threat_hunting"
        with self._enabled():
            tc.enter_context("id1", "threat_hunting")
            tc.exit_context("id1", "threat_hunting")
            assert tc.is_tool_allowed("hunt_lateral_movement", "id1") is False

    def test_gate_message_shape(self):
        tc._tool_to_context["hunt_lateral_movement"] = "threat_hunting"
        msg = tc.gate_message("hunt_lateral_movement")
        assert msg["gated"] is True
        assert msg["required_context"] == "threat_hunting"
        assert "enter_operational_context" in msg["error"]


class TestTagging:
    def test_tag_tool_uses_registering_module(self):
        tc.set_registering_module("threat_hunting")
        tc.tag_tool("some_hunt_tool")
        tc.set_registering_module(None)
        assert tc.context_of("some_hunt_tool") == "threat_hunting"

    def test_tag_tool_outside_module_is_core(self):
        tc.set_registering_module(None)
        tc.tag_tool("inline_server_tool")
        assert tc.context_of("inline_server_tool") == tc.CORE

    def test_unmapped_module_is_core(self):
        tc.set_registering_module("alerts")  # not in CONTEXT_MODULES
        tc.tag_tool("search_alerts")
        tc.set_registering_module(None)
        assert tc.context_of("search_alerts") == tc.CORE


@pytest.mark.asyncio
async def test_middleware_gates_specialised_tool():
    """End-to-end: when gating is on, a specialised tool is inert until the
    caller enters its context; a core tool always runs."""
    from wazuh_mcp.middleware.tool_middleware import ToolMiddleware

    class _FakeMcp:
        def tool(self, *a, **k):
            return lambda fn: fn

    registry: dict = {}
    mw = ToolMiddleware(_FakeMcp(), registry)

    # Register a threat_hunting tool and a core tool.
    tc.set_registering_module("threat_hunting")

    @mw.tool()
    async def fake_hunt() -> dict:
        return {"ran": True}

    tc.set_registering_module(None)

    @mw.tool()
    async def fake_core() -> dict:
        return {"ran": True}

    with patch.dict(os.environ, {"WAZUH_MCP_CONTEXT_GATING": "true"}):
        # Core tool runs regardless of context.
        out = await registry["fake_core"]()
        assert out == {"ran": True}

        # Specialised tool is gated for the anonymous identity.
        out = await registry["fake_hunt"]()
        assert out["gated"] is True
        assert out["required_context"] == "threat_hunting"

        # After entering the context, it runs.
        tc.enter_context("anonymous", "threat_hunting")
        out = await registry["fake_hunt"]()
        assert out == {"ran": True}

    tc._active.clear()
