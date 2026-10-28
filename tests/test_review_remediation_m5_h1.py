"""Regression tests for the M5 (response secret redaction) and H1 (Slack
approval-message hardening) review-remediation fixes."""
from __future__ import annotations

import pytest

from wazuh_mcp.audit import sanitize_response
from wazuh_mcp.tools.active_response import _slack_safe


class TestResponseSecretRedaction:
    def test_redacts_structured_credential_values(self):
        out = sanitize_response({
            "integration": {"password": "hunter2", "client_secret": "xyz",
                            "api_key": "AKIA...", "authorization": "Bearer abc"},
            "status": "ok",
        })
        ig = out["integration"]
        assert ig["password"] == "[REDACTED]"
        assert ig["client_secret"] == "[REDACTED]"
        assert ig["api_key"] == "[REDACTED]"
        assert ig["authorization"] == "[REDACTED]"
        assert out["status"] == "ok"

    def test_preserves_overloaded_token_keys(self):
        # These contain 'token'/'secret' as substrings but are NOT credentials —
        # the approval workflow, pagination, and budget counters depend on them.
        out = sanitize_response({
            "token": "APPROVAL-TOKEN-123",        # AR approval workflow
            "next_page_token": "Y3Vyc29y",        # pagination cursor
            "token_budget": 4000,                 # count
            "estimated_tokens": 1234,             # count
            "cached_secrets": 3,                  # count
        })
        assert out["token"] == "APPROVAL-TOKEN-123"
        assert out["next_page_token"] == "Y3Vyc29y"
        assert out["token_budget"] == 4000
        assert out["estimated_tokens"] == 1234
        assert out["cached_secrets"] == 3

    def test_allowlisted_tool_keeps_credential(self):
        out = sanitize_response({"password": "new-rotated-pw"},
                                tool_name="rotate_wazuh_api_password")
        assert out["password"] == "new-rotated-pw"

    def test_non_allowlisted_tool_redacts(self):
        out = sanitize_response({"password": "leak"}, tool_name="search_alerts")
        assert out["password"] == "[REDACTED]"

    def test_redaction_is_recursive_through_lists(self):
        out = sanitize_response({"items": [{"secret_key": "s1"}, {"name": "ok"}]})
        assert out["items"][0]["secret_key"] == "[REDACTED]"
        assert out["items"][1]["name"] == "ok"

    def test_clean_dict_unchanged(self):
        data = {"status": "ok", "count": 42, "agent": {"id": "001"}}
        assert sanitize_response(data) == data

    def test_string_level_secret_still_redacted(self):
        # Inline 'password=...' inside a value of a non-sensitive key is still
        # caught by the string-level pattern.
        out = sanitize_response({"error": "auth failed: password=hunter2"})
        assert "hunter2" not in out["error"]


class TestSlackMessageHardening:
    def test_strips_backtick_and_newline(self):
        assert _slack_safe("firewall-drop`\ninjected") == "firewall-dropinjected"

    def test_caps_length(self):
        assert len(_slack_safe("x" * 500)) == 120

    def test_empty_passthrough(self):
        assert _slack_safe("") == ""
        assert _slack_safe(None) is None
