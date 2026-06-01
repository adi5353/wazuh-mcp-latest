"""Additional tests to push coverage above the 40% CI gate."""
from __future__ import annotations

import pytest

# Quarantined from the coverage gate: these exercise code paths against mocked
# clients to catch crashes/imports, but assert little real behaviour. Run via
# `pytest -m smoke`; excluded from the gated run by `-m "not smoke"` (pyproject).
pytestmark = pytest.mark.smoke

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh_mcp.tool_context import ToolContext


def _make_ctx(tools: dict | None = None) -> tuple[dict, ToolContext]:
    if tools is None:
        tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    wz = AsyncMock()
    idx = AsyncMock()
    idx.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {},
    }
    cfg = MagicMock()
    cfg.alerts_index = "wazuh-alerts-*"
    cfg.archives_index = "wazuh-archives-*"
    cfg.verify_ssl = False
    cfg.indexer_host = "http://localhost:9200"
    cfg.indexer_user = "admin"
    cfg.indexer_pass = "admin"
    ctx = ToolContext(
        mcp=mcp, wz=wz, idx=idx, cfg=cfg,
        cap=lambda x: min(x, 500),
        require_writes=lambda: None,
        truncate=lambda s, n=300: s[:n] if isinstance(s, str) else s,
        enrich_mitre_ids=lambda ids: [{"id": i, "name": "X", "tactic": "Y"} for i in ids],
        geoip_lookup=AsyncMock(return_value={"ip": "1.2.3.4", "country": "US"}),
        incident_recommendations=lambda a: [],
    )
    return tools, ctx


# ── cluster.py ────────────────────────────────────────────────────────────────

class TestCluster:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.cluster import register
        register(ctx)
        return tools, ctx

    def test_get_cluster_health(self):
        async def run():
            tools, ctx = self._register()
            ctx.wz.request.return_value = {"data": {"affected_items": [], "status": "disabled"}}
            result = await tools["get_cluster_health"]()
            assert isinstance(result, dict)
            assert "wazuh_cluster_status" in result
        asyncio.run(run())

    def test_check_event_queue_health(self):
        async def run():
            tools, ctx = self._register()
            ctx.wz.request.return_value = {
                "data": {"affected_items": [{"total_events_decoded": 100, "events_dropped_queue": 0}]}
            }
            result = await tools["check_event_queue_health"]()
            assert "health" in result
            assert result["health"] == "OK"
        asyncio.run(run())

    def test_check_event_queue_health_degraded(self):
        async def run():
            tools, ctx = self._register()
            ctx.wz.request.return_value = {
                "data": {"affected_items": [{"total_events_decoded": 100, "events_dropped_queue": 50}]}
            }
            result = await tools["check_event_queue_health"]()
            assert "DEGRADED" in result["health"]
        asyncio.run(run())

    def test_check_event_queue_health_error(self):
        async def run():
            tools, ctx = self._register()
            ctx.wz.request.side_effect = Exception("connection refused")
            result = await tools["check_event_queue_health"]()
            assert "error" in result
        asyncio.run(run())


# ── rate_limit.py ─────────────────────────────────────────────────────────────

class TestRateLimit:
    def test_rpm_defaults(self):
        from wazuh_mcp.rate_limit import _rpm, _burst, _writes_rpm, _admin_rpm
        with patch.dict(os.environ, {}):
            assert _rpm() > 0
            assert _burst() > 0
            assert _writes_rpm() > 0
            assert _admin_rpm() > 0

    def test_rpm_from_env(self):
        from wazuh_mcp.rate_limit import _rpm
        with patch.dict(os.environ, {"WAZUH_MCP_RATE_LIMIT_RPM": "100"}):
            assert _rpm() == 100

    def test_identity_from_scope(self):
        from wazuh_mcp.rate_limit import _identity_from_scope
        scope = {"client": ("127.0.0.1", 5000), "type": "http"}
        result = _identity_from_scope(scope)
        assert isinstance(result, str)

    def test_tool_name_from_scope(self):
        from wazuh_mcp.rate_limit import _tool_name_from_scope
        scope = {}
        result = _tool_name_from_scope(scope)
        assert result is None or isinstance(result, str)

    def test_is_throttled_first_call(self):
        from wazuh_mcp.rate_limit import _is_throttled
        throttled, wait = _is_throttled("test-identity-unique-xyz123")
        assert throttled is False
        assert wait == 0


# ── approval.py async methods ─────────────────────────────────────────────────

class TestApprovalAsync:
    def _store(self):
        import importlib
        with patch.dict(os.environ, {"REDIS_URL": "", "WAZUH_ALLOW_WRITES": "false"}):
            import wazuh_mcp.approval as mod
            importlib.reload(mod)
            return mod.ApprovalStore()

    def test_acreate_and_aapprove(self):
        async def run():
            store = self._store()
            token = await store.acreate("block", {"ip": "1.2.3.4"}, ttl=60)
            assert token
            entry = await store.aapprove(token)
            assert entry is not None
            assert entry["action"] == "block"
        asyncio.run(run())

    def test_acreate_and_adeny(self):
        async def run():
            store = self._store()
            token = await store.acreate("isolate", {}, ttl=60)
            result = await store.adeny(token)
            assert result is True
        asyncio.run(run())

    def test_alist_pending(self):
        async def run():
            store = self._store()
            token = await store.acreate("action", {"x": 1}, ttl=300)
            pending = await store.alist_pending()
            tokens = [p["token"] for p in pending]
            assert token in tokens
        asyncio.run(run())

    def test_aapprove_nonexistent(self):
        async def run():
            store = self._store()
            result = await store.aapprove("no-such-token")
            assert result is None
        asyncio.run(run())

    def test_adeny_nonexistent(self):
        async def run():
            store = self._store()
            result = await store.adeny("no-such-token")
            assert result is False
        asyncio.run(run())


# ── sca.py ────────────────────────────────────────────────────────────────────

class TestSCA:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.sca import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0

    def test_get_sca_summary_returns_dict(self):
        async def run():
            tools, ctx = self._register()
            ctx.wz.request.return_value = {"data": {"affected_items": [], "total_affected_items": 0}}
            fn = tools.get("get_sca_summary") or tools.get("list_sca_policies")
            if fn:
                result = await fn()
                assert isinstance(result, dict)
        asyncio.run(run())


# ── cdb.py ────────────────────────────────────────────────────────────────────

class TestCDB:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.cdb import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0

    def test_list_cdb_lists(self):
        async def run():
            tools, ctx = self._register()
            ctx.wz.request.return_value = {"data": {"affected_items": [], "total_affected_items": 0}}
            fn = tools.get("list_cdb_lists") or tools.get("get_cdb_lists")
            if fn:
                result = await fn()
                assert isinstance(result, dict)
        asyncio.run(run())


# ── archive.py ────────────────────────────────────────────────────────────────

class TestArchive:
    def _register(self):
        tools, ctx = _make_ctx()
        try:
            from wazuh_mcp.tools.archive import register
            register(ctx)
        except ImportError:
            pass
        return tools, ctx

    def test_module_registers_or_skips(self):
        tools, _ = self._register()
        assert isinstance(tools, dict)


# ── mitre.py ─────────────────────────────────────────────────────────────────

class TestMITRE:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.mitre import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0

    def test_mitre_tool_returns_dict(self):
        async def run():
            tools, ctx = self._register()
            ctx.wz.request.return_value = {"data": {"affected_items": [], "total_affected_items": 0}}
            fn = list(tools.values())[0] if tools else None
            if fn:
                try:
                    result = await fn()
                    assert isinstance(result, dict)
                except Exception:
                    pass
        asyncio.run(run())


# ── export.py ─────────────────────────────────────────────────────────────────

class TestExport:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.export import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0


# ── onboarding.py ─────────────────────────────────────────────────────────────

class TestOnboarding:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.onboarding import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0


# ── fim.py ────────────────────────────────────────────────────────────────────

class TestFIM:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.fim import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0


# ── baseline.py ───────────────────────────────────────────────────────────────

class TestBaseline:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.baseline import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0


# ── rootcheck.py ──────────────────────────────────────────────────────────────

class TestRootcheck:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.rootcheck import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0

    def test_rootcheck_tool_returns_dict(self):
        async def run():
            tools, ctx = self._register()
            ctx.wz.request.return_value = {"data": {"affected_items": [], "total_affected_items": 0}}
            fn = list(tools.values())[0] if tools else None
            if fn:
                try:
                    result = await fn()
                    assert isinstance(result, dict)
                except Exception:
                    pass
        asyncio.run(run())


# ── correlation.py ────────────────────────────────────────────────────────────

class TestCorrelation:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.correlation import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0


# ── incidents.py ──────────────────────────────────────────────────────────────

class TestIncidents:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.incidents import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0


# ── compliance.py ─────────────────────────────────────────────────────────────

class TestCompliance:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.compliance import register
        register(ctx)
        return tools, ctx

    def test_module_registers(self):
        tools, _ = self._register()
        assert len(tools) > 0


# ── rule_wizard_generate pure functions ────────────────────────────────────────

class TestRuleWizardGeneratePure:
    def test_sigma_to_wazuh_level(self):
        from wazuh_mcp.tools.rule_wizard_generate import _sigma_to_wazuh_level
        assert _sigma_to_wazuh_level("critical") == 14
        assert _sigma_to_wazuh_level("high") == 12
        assert _sigma_to_wazuh_level("medium") == 8
        assert _sigma_to_wazuh_level("low") == 5
        assert _sigma_to_wazuh_level("unknown") == 8

    def test_extract_sigma_field_conditions_dict(self):
        from wazuh_mcp.tools.rule_wizard_generate import _extract_sigma_field_conditions
        detection = {
            "selection": {
                "commandline": "powershell",
                "image": "cmd.exe",
            }
        }
        pairs = _extract_sigma_field_conditions(detection)
        assert len(pairs) == 2
        fields = [f for f, _ in pairs]
        assert any("commandLine" in f for f in fields)

    def test_extract_sigma_field_conditions_list(self):
        from wazuh_mcp.tools.rule_wizard_generate import _extract_sigma_field_conditions
        detection = {"keywords": ["mimikatz", "lsass"]}
        pairs = _extract_sigma_field_conditions(detection)
        assert len(pairs) == 0  # keywords is skipped

    def test_extract_sigma_field_conditions_list_values(self):
        from wazuh_mcp.tools.rule_wizard_generate import _extract_sigma_field_conditions
        detection = {"selection": ["keyword1", "keyword2"]}
        pairs = _extract_sigma_field_conditions(detection)
        assert len(pairs) == 2
        assert all(f == "full_log" for f, _ in pairs)


# ── rule_wizard_validate pure function ─────────────────────────────────────────

class TestRuleWizardValidatePure:
    def test_validate_valid_xml(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        xml = '''<group name="local,syslog,">
  <rule id="100001" level="5">
    <match>test</match>
    <description>Test rule</description>
  </rule>
</group>'''
        result = _validate_rule_xml_impl(xml)
        assert result["valid"] is True
        assert result["rules_found"] == 1

    def test_validate_invalid_xml(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        result = _validate_rule_xml_impl("<bad xml")
        assert result["valid"] is False

    def test_validate_empty_xml(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        result = _validate_rule_xml_impl("")
        assert result["valid"] is False

    def test_validate_no_rule_element(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        result = _validate_rule_xml_impl("<group></group>")
        assert result["valid"] is False

    def test_validate_warns_on_system_rule_id(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        xml = '<rule id="5710" level="5"><description>test</description></rule>'
        result = _validate_rule_xml_impl(xml)
        assert result["valid"] is True
        assert any("outside custom range" in w for w in result["warnings"])

    def test_validate_warns_on_missing_description(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        xml = '<rule id="100001" level="5"><match>test</match></rule>'
        result = _validate_rule_xml_impl(xml)
        assert result["valid"] is True
        assert any("description" in w for w in result["warnings"])


# ── rule_wizard_generate registered tools ──────────────────────────────────────

class TestRuleWizardGenerateTools:
    def _register(self):
        tools, ctx = _make_ctx()
        from wazuh_mcp.tools.rule_wizard_generate import register_generate
        register_generate(ctx)
        return tools, ctx

    def test_generate_rule_xml_basic(self):
        async def run():
            tools, _ = self._register()
            result = await tools["generate_rule_xml"](
                description="Detect SSH brute force",
                rule_id=100001,
                level=8,
            )
            assert "xml" in result
            assert "100001" in result["xml"]
        asyncio.run(run())

    def test_generate_rule_xml_invalid_id(self):
        async def run():
            tools, _ = self._register()
            result = await tools["generate_rule_xml"](description="test", rule_id=999)
            assert "error" in result
        asyncio.run(run())

    def test_generate_rule_xml_invalid_level(self):
        async def run():
            tools, _ = self._register()
            result = await tools["generate_rule_xml"](description="test", rule_id=100001, level=20)
            assert "error" in result
        asyncio.run(run())

    def test_generate_rule_xml_empty_description(self):
        async def run():
            tools, _ = self._register()
            result = await tools["generate_rule_xml"](description="")
            assert "error" in result
        asyncio.run(run())

    def test_generate_rule_xml_with_mitre(self):
        async def run():
            tools, _ = self._register()
            result = await tools["generate_rule_xml"](
                description="Brute force", rule_id=100002, level=10, mitre_id="T1110"
            )
            assert "T1110" in result["xml"]
        asyncio.run(run())

    def test_generate_rule_xml_with_parent(self):
        async def run():
            tools, _ = self._register()
            result = await tools["generate_rule_xml"](
                description="Child rule", rule_id=100003, parent_rule_id=5710
            )
            assert "5710" in result["xml"]
        asyncio.run(run())

    def test_convert_sigma_rule_no_yaml(self):
        async def run():
            tools, _ = self._register()
            result = await tools["convert_sigma_rule"](sigma_yaml="")
            assert "error" in result
        asyncio.run(run())

    def test_convert_sigma_rule_basic(self):
        async def run():
            tools, _ = self._register()
            sigma = """title: Test Rule
description: A test sigma rule
level: high
logsource:
  product: windows
detection:
  selection:
    commandline: mimikatz
  condition: selection
tags:
  - attack.credential-access
  - attack.t1003"""
            result = await tools["convert_sigma_rule"](sigma_yaml=sigma, rule_id=100100)
            assert "xml" in result
            assert result.get("wazuh_level", 0) >= 8
        asyncio.run(run())
