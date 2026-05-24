"""Tests for F7: Custom Detection Rules Wizard."""
import pytest
from unittest.mock import MagicMock, AsyncMock


def _make_env():
    tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    wz = MagicMock()
    cfg = MagicMock()

    from wazuh_mcp.tools.rule_wizard import register
    register(mcp, wz, cfg)
    return tools, wz, cfg


class TestGenerateRuleXML:
    def test_generates_xml_with_description(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.get_event_loop().run_until_complete(
            tools["generate_rule_xml"](
                description="Alert when SSH login fails more than 5 times",
                rule_id=100001,
            )
        )
        assert "xml" in result
        assert "<rule" in result["xml"]
        assert "100001" in result["xml"]

    def test_rule_id_out_of_range_rejected(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.get_event_loop().run_until_complete(
            tools["generate_rule_xml"](
                description="Test rule",
                rule_id=999,  # below 100000
            )
        )
        assert "error" in result

    def test_empty_description_rejected(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.get_event_loop().run_until_complete(
            tools["generate_rule_xml"](
                description="",
                rule_id=100002,
            )
        )
        assert "error" in result

    def test_description_too_long_rejected(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.get_event_loop().run_until_complete(
            tools["generate_rule_xml"](
                description="x" * 1001,
                rule_id=100003,
            )
        )
        assert "error" in result


class TestValidateRuleXML:
    def test_valid_xml_passes(self):
        import asyncio
        tools, _, _ = _make_env()
        xml = """<group name="local,">
  <rule id="100001" level="5">
    <if_sid>5710</if_sid>
    <description>SSH brute force attempt</description>
  </rule>
</group>"""
        result = asyncio.get_event_loop().run_until_complete(
            tools["validate_rule_xml"](xml)
        )
        assert result.get("valid") is True

    def test_malformed_xml_fails(self):
        import asyncio
        tools, _, _ = _make_env()
        xml = "<rule id='100001' level='5'><description>Unclosed"
        result = asyncio.get_event_loop().run_until_complete(
            tools["validate_rule_xml"](xml)
        )
        assert result.get("valid") is False
        assert "error" in result

    def test_missing_required_fields_warns(self):
        import asyncio
        tools, _, _ = _make_env()
        xml = """<group name="local,">
  <rule id="100001" level="5">
  </rule>
</group>"""
        result = asyncio.get_event_loop().run_until_complete(
            tools["validate_rule_xml"](xml)
        )
        # Should at least parse (valid XML) but warn about missing description
        assert "valid" in result
        if result["valid"]:
            assert "warnings" in result

    def test_empty_xml_rejected(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.get_event_loop().run_until_complete(
            tools["validate_rule_xml"]("")
        )
        assert "error" in result


class TestPushCustomRule:
    def test_dry_run_returns_preview(self):
        import asyncio
        tools, wz, _ = _make_env()
        xml = """<group name="local,">
  <rule id="100001" level="5">
    <description>Test</description>
  </rule>
</group>"""
        result = asyncio.get_event_loop().run_until_complete(
            tools["push_custom_rule"](xml, dry_run=True)
        )
        assert result.get("dry_run") is True

    def test_invalid_xml_rejected_before_push(self):
        import asyncio
        tools, wz, _ = _make_env()
        result = asyncio.get_event_loop().run_until_complete(
            tools["push_custom_rule"]("<bad xml", dry_run=False)
        )
        assert "error" in result
        wz.request.assert_not_called()

    def test_push_calls_manager_api(self):
        import asyncio
        tools, wz, _ = _make_env()
        wz.request = AsyncMock(return_value={"data": {"affected_items": ["custom_rules.xml"]}})
        xml = """<group name="local,">
  <rule id="100001" level="5">
    <description>Test push</description>
  </rule>
</group>"""
        result = asyncio.get_event_loop().run_until_complete(
            tools["push_custom_rule"](xml, dry_run=False)
        )
        assert "error" not in result
        wz.request.assert_called_once()
