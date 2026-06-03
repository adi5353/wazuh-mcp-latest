"""H3 follow-on: consolidation of enrichment + notification tool families.

Verifies the unified dispatchers (enrich_indicator, send_alert,
send_weekly_summary) and that the legacy per-type/per-platform tools register
by default but are suppressed under WAZUH_MCP_LEGACY_ALIASES=false — while
non-aliased siblings (enrich_ip_geo, send_shift_handover_to_slack) are kept.
"""
from __future__ import annotations

import asyncio
import importlib
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wazuh_mcp.tool_context import ToolContext


def _run(coro):
    return asyncio.run(coro)


def _capture_ctx(shared=None):
    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    ctx = ToolContext(
        mcp=mcp, wz=AsyncMock(), idx=AsyncMock(), cfg=MagicMock(),
        cap=lambda n: n, require_writes=lambda: None,
        truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [{"id": i} for i in (ids or [])],
        geoip_lookup=AsyncMock(return_value={"ip": "x", "geo": "private/local"}),
        incident_recommendations=lambda *a, **k: [],
        tool_registry={},
        shared=shared or {},
    )
    return tools, ctx


def _register(module_name, shared=None):
    tools, ctx = _capture_ctx(shared)
    importlib.import_module(module_name).register(ctx)
    return tools


# ── Enrichment: enrich_indicator ─────────────────────────────────────────────

class TestEnrichIndicator:
    def test_legacy_enrichers_present_by_default(self):
        tools = _register("wazuh_mcp.tools.threat_intel")
        for name in ["enrich_ip", "enrich_file_hash", "enrich_domain",
                     "enrich_url", "enrich_email"]:
            assert name in tools
        assert "enrich_indicator" in tools

    def test_dispatch_routes_to_ip_enricher(self):
        import wazuh_mcp.tools.threat_intel as ti
        tools = _register("wazuh_mcp.tools.threat_intel")
        # No TI keys configured → enrich_ip still returns a structured verdict dict.
        with patch.object(ti, "_vt_get", AsyncMock(return_value=None)), \
             patch.object(ti, "_abuse_get", AsyncMock(return_value=None)):
            out = _run(tools["enrich_indicator"](indicator_type="ip", value="8.8.8.8"))
        assert out["ip"] == "8.8.8.8"
        assert "verdict" in out

    def test_dispatch_unknown_type(self):
        tools = _register("wazuh_mcp.tools.threat_intel")
        out = _run(tools["enrich_indicator"](indicator_type="bogus", value="x"))
        assert "error" in out and "ip" in out["supported"]

    def test_aliases_suppressed_but_dispatcher_works(self):
        import wazuh_mcp.tools.threat_intel as ti
        with patch.dict(os.environ, {"WAZUH_MCP_LEGACY_ALIASES": "false"}):
            tools = _register("wazuh_mcp.tools.threat_intel")
            assert "enrich_ip" not in tools          # legacy alias hidden
            assert "enrich_indicator" in tools         # consolidated tool stays
            assert "enrich_ip_geo" in tools            # non-aliased sibling kept
            with patch.object(ti, "_vt_get", AsyncMock(return_value=None)), \
                 patch.object(ti, "_abuse_get", AsyncMock(return_value=None)):
                out = _run(tools["enrich_indicator"](indicator_type="ip", value="8.8.8.8"))
            assert out["ip"] == "8.8.8.8"


# ── Notifications: send_alert / send_weekly_summary ──────────────────────────

class TestUnifiedSenders:
    def test_legacy_senders_present_by_default(self):
        tools = _register("wazuh_mcp.tools.notifications")
        for name in ["send_alert_to_slack", "send_alert_to_teams",
                     "send_weekly_summary_to_slack", "send_weekly_summary_to_teams"]:
            assert name in tools
        assert "send_alert" in tools and "send_weekly_summary" in tools

    def test_send_alert_routes_to_platform(self):
        # No webhooks configured → each platform branch returns its own
        # "not configured" error, proving the dispatch reached that sender.
        env = {k: v for k, v in os.environ.items()
               if k not in ("SLACK_WEBHOOK_URL", "SLACK_BOT_TOKEN", "TEAMS_WEBHOOK_URL")}
        with patch.dict(os.environ, env, clear=True):
            tools = _register("wazuh_mcp.tools.notifications")
            slack = _run(tools["send_alert"](platform="slack", message="hi"))
            teams = _run(tools["send_alert"](platform="teams", message="hi"))
        assert "Slack not configured" in slack["error"]
        assert "Teams not configured" in teams["error"]

    def test_send_alert_unknown_platform(self):
        tools = _register("wazuh_mcp.tools.notifications")
        out = _run(tools["send_alert"](platform="discord", message="hi"))
        assert "error" in out and out["supported"] == ["slack", "teams"]

    def test_aliases_suppressed_but_dispatcher_works(self):
        with patch.dict(os.environ, {"WAZUH_MCP_LEGACY_ALIASES": "false"}):
            tools = _register("wazuh_mcp.tools.notifications")
            assert "send_alert_to_slack" not in tools       # legacy alias hidden
            assert "send_alert" in tools                      # consolidated stays
            # non-aliased sibling kept
            assert "send_shift_handover_to_slack" in tools
            out = _run(tools["send_alert"](platform="nope", message="x"))
            assert "error" in out
