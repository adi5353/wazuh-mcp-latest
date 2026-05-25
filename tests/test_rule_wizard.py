"""Tests for F7: Custom Detection Rules Wizard."""
import pytest
from unittest.mock import MagicMock, AsyncMock


def _make_env():
    tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    wz = MagicMock()
    wz.upload_xml_file = AsyncMock()  # dedicated file-upload method
    cfg = MagicMock()

    from wazuh_mcp.tools.rule_wizard import register
    register(mcp, wz, cfg)
    return tools, wz, cfg


class TestGenerateRuleXML:
    def test_generates_xml_with_description(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.run(
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
        result = asyncio.run(
            tools["generate_rule_xml"](
                description="Test rule",
                rule_id=999,  # below 100000
            )
        )
        assert "error" in result

    def test_empty_description_rejected(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.run(
            tools["generate_rule_xml"](
                description="",
                rule_id=100002,
            )
        )
        assert "error" in result

    def test_description_too_long_rejected(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.run(
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
        result = asyncio.run(
            tools["validate_rule_xml"](xml)
        )
        assert result.get("valid") is True

    def test_malformed_xml_fails(self):
        import asyncio
        tools, _, _ = _make_env()
        xml = "<rule id='100001' level='5'><description>Unclosed"
        result = asyncio.run(
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
        result = asyncio.run(
            tools["validate_rule_xml"](xml)
        )
        # Should at least parse (valid XML) but warn about missing description
        assert "valid" in result
        if result["valid"]:
            assert "warnings" in result

    def test_empty_xml_rejected(self):
        import asyncio
        tools, _, _ = _make_env()
        result = asyncio.run(
            tools["validate_rule_xml"]("")
        )
        assert "error" in result


class TestPushCustomRule:
    def test_dry_run_returns_preview(self):
        import asyncio
        from unittest.mock import patch
        tools, wz, _ = _make_env()
        xml = """<group name="local,">
  <rule id="100001" level="5">
    <description>Test</description>
  </rule>
</group>"""
        with patch("wazuh_mcp.tools.rule_wizard.admin_only", return_value=None):
            result = asyncio.run(
                tools["push_custom_rule"](xml, dry_run=True)
            )
        assert result.get("dry_run") is True

    def test_invalid_xml_rejected_before_push(self):
        import asyncio
        tools, wz, _ = _make_env()
        result = asyncio.run(
            tools["push_custom_rule"]("<bad xml", dry_run=False)
        )
        assert "error" in result
        wz.upload_xml_file.assert_not_called()

    def test_push_calls_upload_xml_file(self):
        import asyncio
        from unittest.mock import patch
        tools, wz, _ = _make_env()
        wz.upload_xml_file = AsyncMock(return_value={"data": {"affected_items": ["custom_rules.xml"]}})
        xml = """<group name="local,">
  <rule id="100001" level="5">
    <description>Test push</description>
  </rule>
</group>"""
        with patch("wazuh_mcp.tools.rule_wizard.admin_only", return_value=None):
            result = asyncio.run(
                tools["push_custom_rule"](xml, dry_run=False)
            )
        assert "error" not in result
        assert result.get("success") is True
        wz.upload_xml_file.assert_called_once()
        # Verify it targets the rules endpoint
        call_args = wz.upload_xml_file.call_args
        assert "rules/files" in call_args[0][0]

    def test_dangerous_filename_rejected(self):
        import asyncio
        tools, wz, _ = _make_env()
        xml = """<group name="local,"><rule id="100001" level="5"><description>t</description></rule></group>"""
        result = asyncio.run(
            tools["push_custom_rule"](xml, filename="../etc/passwd", dry_run=False)
        )
        assert "error" in result


class TestPushCustomDecoder:
    def test_dry_run_decoder(self):
        import asyncio
        from unittest.mock import patch
        tools, wz, _ = _make_env()
        xml = """<decoder name="my-app">
  <prematch>^MyApp </prematch>
</decoder>"""
        with patch("wazuh_mcp.tools.rule_wizard.admin_only", return_value=None):
            result = asyncio.run(
                tools["push_custom_decoder"](xml, dry_run=True)
            )
        assert result.get("dry_run") is True
        assert result.get("decoders_found") == 1

    def test_no_decoder_elements_rejected(self):
        import asyncio
        tools, wz, _ = _make_env()
        xml = """<group name="local,"><rule id="100001" level="5"><description>t</description></rule></group>"""
        result = asyncio.run(
            tools["push_custom_decoder"](xml, dry_run=True)
        )
        assert "error" in result

    def test_push_decoder_calls_upload_xml_file(self):
        import asyncio
        from unittest.mock import patch
        tools, wz, _ = _make_env()
        wz.upload_xml_file = AsyncMock(return_value={"data": {"affected_items": ["custom_decoders.xml"]}})
        xml = """<decoder name="my-app">
  <prematch>^MyApp </prematch>
</decoder>"""
        with patch("wazuh_mcp.tools.rule_wizard.admin_only", return_value=None):
            result = asyncio.run(
                tools["push_custom_decoder"](xml, dry_run=False)
            )
        assert result.get("success") is True
        call_args = wz.upload_xml_file.call_args
        assert "decoders/files" in call_args[0][0]

    def test_malformed_decoder_xml_rejected(self):
        import asyncio
        tools, wz, _ = _make_env()
        result = asyncio.run(
            tools["push_custom_decoder"]("<decoder name='unclosed", dry_run=True)
        )
        assert "error" in result
