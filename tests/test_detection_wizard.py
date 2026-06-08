"""Tests for the Log-to-Detection Wizard (decoder + rule generation/validation
and the non-mutating test pipeline).

Covers official-format enforcement, <order>/capture parity, regex simulation,
the orchestrator report shape, RBAC, and — critically — the non-mutating
guarantee (no tool ever writes to or restarts the Manager).
"""
import asyncio
from unittest.mock import MagicMock, AsyncMock

import pytest

import wazuh_mcp.identity as identity
from wazuh_mcp.rbac import ROLE
from wazuh_mcp.tool_context import ToolContext
from wazuh_mcp.tools.decoder_wizard_validate import _validate_decoder_xml_impl
from wazuh_mcp.tools.detection_drafter import _validate_rule_official_impl


def _run(coro):
    return asyncio.run(coro)


def _make_env(role=ROLE.ANALYST):
    identity.set_session_role(role)
    tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    wz = MagicMock()
    wz.request = AsyncMock(return_value={"data": {"output": {}}})
    wz.upload_xml_file = AsyncMock()  # must NEVER be called by these tools
    ctx = ToolContext(
        mcp=mcp, wz=wz, idx=MagicMock(), cfg=MagicMock(), cap=lambda x: x,
        require_writes=lambda: None, truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda a: [],
    )
    from wazuh_mcp.tools.decoder_wizard import register as reg_dec
    from wazuh_mcp.tools.detection_drafter import register as reg_draft
    reg_dec(ctx)
    reg_draft(ctx)
    return tools, wz


def teardown_function():
    identity._ctx_role.set(None)


# ── Decoder schema validation ─────────────────────────────────────────────────

class TestDecoderValidation:
    def test_valid_child_decoder(self):
        xml = (
            '<decoder name="myapp">\n'
            '  <parent>syslog</parent>\n'
            '  <regex type="pcre2">user=(\\S+) action=(\\S+)</regex>\n'
            '  <order>user, action</order>\n'
            '</decoder>'
        )
        r = _validate_decoder_xml_impl(xml)
        assert r["valid"] is True
        assert r["blockers"] == []
        assert set(r["fields"]) == {"user", "action"}

    def test_invented_element_blocked(self):
        xml = '<decoder name="x"><frobnicate>y</frobnicate></decoder>'
        r = _validate_decoder_xml_impl(xml)
        assert r["valid"] is False
        assert any("invented element" in b for b in r["blockers"])

    def test_missing_name_blocked(self):
        r = _validate_decoder_xml_impl("<decoder><prematch>^x</prematch></decoder>")
        assert r["valid"] is False
        assert any("name" in b for b in r["blockers"])

    def test_order_capture_mismatch_blocked(self):
        xml = (
            '<decoder name="x">'
            '<regex type="pcre2">(\\S+) (\\S+) (\\S+)</regex>'
            '<order>a, b</order></decoder>'
        )
        r = _validate_decoder_xml_impl(xml)
        assert r["valid"] is False
        assert any("capture group" in b for b in r["blockers"])

    def test_bad_regex_type_blocked(self):
        xml = '<decoder name="x"><regex type="bogus">(\\S+)</regex><order>a</order></decoder>'
        r = _validate_decoder_xml_impl(xml)
        assert r["valid"] is False

    def test_bad_plugin_decoder_blocked(self):
        xml = '<decoder name="x"><plugin_decoder>Evil_Decoder</plugin_decoder></decoder>'
        r = _validate_decoder_xml_impl(xml)
        assert r["valid"] is False

    def test_grandchild_blocked(self):
        # B parents on A, but A is itself a child (declares <parent>) → grandchild.
        xml = (
            '<decoder name="A"><parent>root</parent>'
            '<regex type="pcre2">(\\S+)</regex><order>x</order></decoder>'
            '<decoder name="B"><parent>A</parent>'
            '<regex type="pcre2">(\\S+)</regex><order>y</order></decoder>'
        )
        r = _validate_decoder_xml_impl(xml)
        assert r["valid"] is False
        assert any("grandchild" in b for b in r["blockers"])

    def test_osregex_alternation_warns(self):
        xml = '<decoder name="x"><regex type="osregex">(foo|bar)</regex><order>a</order></decoder>'
        r = _validate_decoder_xml_impl(xml)
        assert any("pcre2" in w for w in r["warnings"])


# ── Rule official validation ──────────────────────────────────────────────────

class TestRuleValidation:
    def _wrap(self, inner):
        return f'<group name="local,">{inner}</group>'

    def test_clean_custom_id(self):
        xml = self._wrap('<rule id="100050" level="5"><description>x</description></rule>')
        r = _validate_rule_official_impl(xml)
        assert r["valid"] is True
        assert r["rule_ids"] == [100050]

    def test_official_range_warning(self):
        xml = self._wrap('<rule id="150000" level="5"><description>x</description></rule>')
        r = _validate_rule_official_impl(xml)
        assert r["valid"] is True  # warning, not blocker
        assert any("officially documented" in w for w in r["warnings"])

    def test_system_range_blocked(self):
        xml = self._wrap('<rule id="500" level="5"><description>x</description></rule>')
        r = _validate_rule_official_impl(xml)
        assert r["valid"] is False

    def test_bad_level_blocked(self):
        xml = self._wrap('<rule id="100050" level="17"><description>x</description></rule>')
        r = _validate_rule_official_impl(xml)
        assert r["valid"] is False

    def test_invented_rule_element_blocked(self):
        xml = self._wrap('<rule id="100050" level="5"><zap>1</zap><description>x</description></rule>')
        r = _validate_rule_official_impl(xml)
        assert r["valid"] is False
        assert any("invented element" in b for b in r["blockers"])

    def test_field_and_decoded_as_tracked(self):
        xml = self._wrap(
            '<rule id="100050" level="5"><decoded_as>sshd</decoded_as>'
            '<field name="srcuser">admin</field><description>x</description></rule>'
        )
        r = _validate_rule_official_impl(xml)
        assert r["uses_fields"] is True
        assert "srcuser" in r["field_names"]
        assert "sshd" in r["decoded_as"]

    def test_bad_mitre_id_warns(self):
        xml = self._wrap(
            '<rule id="100050" level="5"><mitre><id>NOPE</id></mitre>'
            '<description>x</description></rule>'
        )
        r = _validate_rule_official_impl(xml)
        assert any("MITRE" in w for w in r["warnings"])


# ── generate_decoder_xml ──────────────────────────────────────────────────────

class TestGenerateDecoder:
    def test_generates_valid_xml_with_parity(self):
        tools, _ = _make_env()
        r = _run(tools["generate_decoder_xml"](
            decoder_name="myapp", fields=["user", "action"],
            regex=r"user=(\S+) action=(\S+)", sample_log="user=bob action=login",
        ))
        assert "<decoder name=\"myapp\">" in r["xml"]
        assert "<order>user, action</order>" in r["xml"]
        assert r["validation"]["valid"] is True
        assert r["simulation"]["matched"] is True
        assert r["simulation"]["captures"] == ["bob", "login"]

    def test_attribute_escaping(self):
        tools, _ = _make_env()
        r = _run(tools["generate_decoder_xml"](
            decoder_name='bad"name', fields=["a"], regex=r"(\S+)",
        ))
        assert "&quot;" in r["xml"]  # quote escaped, no attribute breakout


# ── Orchestrator pipeline ─────────────────────────────────────────────────────

class TestPipeline:
    def test_report_shape_and_recipe(self):
        tools, wz = _make_env()
        wz.request = AsyncMock(return_value={"data": {"output": {}}})
        decoder = (
            '<decoder name="myapp"><parent>syslog</parent>'
            '<regex type="pcre2">user=(\\S+) action=(\\S+)</regex>'
            '<order>user, action</order></decoder>'
        )
        rule = '<group name="local,"><rule id="100050" level="5"><description>x</description></rule></group>'
        r = _run(tools["test_detection_candidate"](
            decoder_xml=decoder, rule_xml=rule,
            sample_logs=["user=bob action=login"],
        ))
        for key in ("verdict", "blockers", "warnings", "regex_simulation",
                    "baseline_logtest", "parent_check", "duplicate_id",
                    "dependency_check", "honesty_note", "manual_recipe"):
            assert key in r
        assert r["regex_simulation"]["matched_samples"] == 1
        assert r["manual_recipe"]
        assert r["verdict"] == "READY_FOR_MANUAL_STAGING_TEST"

    def test_regex_no_match_blocks(self):
        tools, wz = _make_env()
        wz.request = AsyncMock(return_value={"data": {"output": {}}})
        decoder = ('<decoder name="x"><regex type="pcre2">WILLNOTMATCH(\\d+)</regex>'
                   '<order>n</order></decoder>')
        rule = '<group name="local,"><rule id="100050" level="5"><description>x</description></rule></group>'
        r = _run(tools["test_detection_candidate"](
            decoder_xml=decoder, rule_xml=rule, sample_logs=["nothing here"],
        ))
        assert r["verdict"] == "HAS_BLOCKERS"
        assert any("matched none" in b for b in r["blockers"])

    def test_duplicate_rule_id_blocks(self):
        tools, wz = _make_env()
        # GET /rules returns an existing rule with this id → duplicate.
        wz.request = AsyncMock(return_value={"data": {"affected_items": [{"id": 100050}],
                                                       "output": {}}})
        rule = '<group name="local,"><rule id="100050" level="5"><description>x</description></rule></group>'
        r = _run(tools["test_detection_candidate"](
            decoder_xml="", rule_xml=rule, sample_logs=["anything"],
        ))
        assert r["verdict"] == "HAS_BLOCKERS"
        assert any("already exists" in b for b in r["blockers"])

    def test_missing_if_sid_parent_blocks(self):
        tools, wz = _make_env()

        async def _req(method, path, **kw):
            # logtest returns nothing; GET /rules for the parent returns empty.
            if path == "/logtest" or method == "PUT":
                return {"data": {"output": {}}}
            return {"data": {"affected_items": []}}

        wz.request = AsyncMock(side_effect=_req)
        rule = ('<group name="local,"><rule id="100050" level="5">'
                '<if_sid>999999</if_sid><description>x</description></rule></group>')
        r = _run(tools["test_detection_candidate"](
            decoder_xml="", rule_xml=rule, sample_logs=["anything"],
        ))
        assert any("if_sid" in b for b in r["blockers"])


# ── RBAC + non-mutating guarantee ─────────────────────────────────────────────

class TestSafety:
    def test_viewer_blocked(self):
        tools, _ = _make_env(role=ROLE.VIEWER)
        for name in ("validate_decoder_xml", "generate_decoder_xml",
                     "test_detection_candidate", "draft_detection_from_logs"):
            if name == "generate_decoder_xml":
                out = _run(tools[name](decoder_name="x", fields=["a"], regex=r"(\S+)"))
            elif name == "validate_decoder_xml":
                out = _run(tools[name]("<decoder name='x'/>"))
            else:
                out = _run(tools[name](sample_logs=["x"]) if name == "draft_detection_from_logs"
                           else tools[name](decoder_xml="", rule_xml="<group><rule id='100050' level='5'><description>x</description></rule></group>", sample_logs=["x"]))
            assert isinstance(out, dict) and "error" in out

    def test_never_writes_or_restarts(self):
        """The non-mutating guarantee: no tool may call upload_xml_file, and the
        only Manager calls are read-only logtest (PUT /logtest) and GET /rules."""
        tools, wz = _make_env()
        calls = []
        wz.request = AsyncMock(side_effect=lambda m, p, **k: calls.append((m, p))
                               or {"data": {"output": {}, "affected_items": []}})
        decoder = ('<decoder name="x"><regex type="pcre2">(\\S+)</regex><order>a</order></decoder>')
        rule = '<group name="local,"><rule id="100050" level="5"><description>x</description></rule></group>'
        _run(tools["test_detection_candidate"](
            decoder_xml=decoder, rule_xml=rule, sample_logs=["hello"],
        ))
        _run(tools["draft_detection_from_logs"](sample_logs=["hello"]))
        wz.upload_xml_file.assert_not_called()
        for method, path in calls:
            assert path.startswith("/logtest") or path.startswith("/rules"), (method, path)
            # No restart endpoint, ever.
            assert "restart" not in path
