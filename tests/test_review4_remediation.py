"""Regression tests for the fourth-review remediation.

  H1 — ABAC now scopes agent/group enumeration (tools + resource)
  M1 — rule-wizard XML escapes attribute names and element content
  M2 — timestamps remain ISO-8601 with a trailing Z after the utcnow swap
"""
from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wazuh_mcp.tool_context import ToolContext


def _run(coro):
    return asyncio.run(coro)


def _tools(module_name, wz=None, idx=None):
    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    ctx = ToolContext(
        mcp=mcp, wz=wz or AsyncMock(), idx=idx or AsyncMock(), cfg=MagicMock(),
        cap=lambda n: n, require_writes=lambda: None, truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda *a, **k: [], tool_registry={}, shared={},
    )
    __import__(module_name, fromlist=["register"]).register(ctx)
    return tools


_AGENTS_RESP = {
    "data": {
        "affected_items": [
            {"id": "001", "name": "a1", "group": ["dept-a"]},
            {"id": "002", "name": "b1", "group": ["dept-b"]},
        ],
        "total_affected_items": 2,
    }
}


# ── H1: ABAC agent/group enumeration ──────────────────────────────────────────

class TestAbacAgentEnumeration:
    def test_filter_manager_agents_noop_without_abac(self):
        from wazuh_mcp.abac import filter_manager_agents
        with patch.dict(os.environ, {}, clear=False):
            for v in ("WAZUH_MCP_ALLOWED_GROUPS", "WAZUH_MCP_DENIED_GROUPS", "WAZUH_MCP_ALLOWED_AGENTS"):
                os.environ.pop(v, None)
            assert filter_manager_agents(_AGENTS_RESP) is _AGENTS_RESP

    def test_list_agents_scoped_to_allowed_group(self):
        wz = AsyncMock(); wz.request = AsyncMock(return_value=_AGENTS_RESP)
        tools = _tools("wazuh_mcp.tools.agents", wz=wz)
        with patch.dict(os.environ, {"WAZUH_MCP_ALLOWED_GROUPS": "dept-a"}):
            out = _run(tools["list_agents"]())
        ids = [a["id"] for a in out["data"]["affected_items"]]
        assert ids == ["001"]
        assert out["data"]["total_affected_items"] == 1
        assert out["abac_filtered"] is True

    def test_list_agents_unfiltered_without_abac(self):
        wz = AsyncMock(); wz.request = AsyncMock(return_value=_AGENTS_RESP)
        tools = _tools("wazuh_mcp.tools.agents", wz=wz)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WAZUH_MCP_ALLOWED_GROUPS", None)
            out = _run(tools["list_agents"]())
        assert len(out["data"]["affected_items"]) == 2  # unchanged

    def test_get_group_agents_denies_out_of_scope_group(self):
        wz = AsyncMock(); wz.request = AsyncMock(return_value=_AGENTS_RESP)
        tools = _tools("wazuh_mcp.tools.agents", wz=wz)
        with patch.dict(os.environ, {"WAZUH_MCP_ALLOWED_GROUPS": "dept-a"}):
            denied = _run(tools["get_group_agents"]("dept-b"))
            assert "error" in denied
            wz.request.assert_not_awaited()  # never queried the Manager
            ok = _run(tools["get_group_agents"]("dept-a"))
            assert "error" not in ok

    def test_agents_resource_scoped(self):
        wz = AsyncMock(); wz.request = AsyncMock(return_value=_AGENTS_RESP)
        captured: dict = {}
        mcp = MagicMock()
        mcp.resource = lambda *a, **k: (lambda fn: captured.__setitem__(fn.__name__, fn) or fn)
        from wazuh_mcp import resources
        resources.register(mcp, wz, AsyncMock(), MagicMock())
        with patch.dict(os.environ, {"WAZUH_MCP_ALLOWED_GROUPS": "dept-a"}):
            out = json.loads(_run(captured["agents_resource"]()))
        assert out["total"] == 1
        assert out["agents"][0]["id"] == "001"


# ── M1: rule-wizard XML escaping ──────────────────────────────────────────────

class TestRuleWizardXmlEscaping:
    def test_attr_and_content_escaper(self):
        from wazuh_mcp.tools.rule_wizard_generate import _xml_attr, _xml_text
        assert _xml_attr('x" bad="1') == "x&quot; bad=&quot;1"
        assert _xml_text("a<b>&c") == "a&lt;b&gt;&amp;c"

    def test_generate_rule_xml_escapes_injection(self):
        import defusedxml.ElementTree as ET
        from wazuh_mcp.tools import rule_wizard_generate as rwg
        tools: dict = {}
        mcp = MagicMock()
        mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
        ctx = ToolContext(
            mcp=mcp, wz=AsyncMock(), idx=AsyncMock(), cfg=MagicMock(), cap=lambda n: n,
            require_writes=lambda: None, truncate=lambda s, n=300: s,
            enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value={}),
            incident_recommendations=lambda *a, **k: [], tool_registry={}, shared={},
        )
        rwg.register_generate(ctx)
        out = _run(tools["generate_rule_xml"](
            description="test rule",
            field_name='srcip" injected="evil',
            field_pattern="1.2.3.4",
            mitre_id="T1110</id></mitre><command>x",
        ))
        xml = out["xml"]
        # The injection must be escaped, not present as live markup.
        assert 'injected="evil"' not in xml
        assert "&quot;" in xml
        assert "<command>" not in xml
        # And the result must still be well-formed XML.
        ET.fromstring(xml)


# ── M2: timestamp format preserved ────────────────────────────────────────────

class TestTimestampFormat:
    def test_compliance_report_timestamp_ends_with_z(self):
        idx = AsyncMock()
        idx.search.return_value = {
            "hits": {"total": {"value": 0}},
            "aggregations": {"by_control": {"buckets": [], "sum_other_doc_count": 0}},
        }
        tools = _tools("wazuh_mcp.tools.compliance", idx=idx)
        out = _run(tools["generate_compliance_report"](framework="pci_dss"))
        assert out["generated_at"].endswith("Z")
        assert "+00:00" not in out["generated_at"]
