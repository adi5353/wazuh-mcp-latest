"""Tests for P2#6: deployment-level tool-module scoping (non-breaking).

The fix lets operators shrink the advertised tool surface via env vars without
renaming any tool. Default (both unset) must register everything, unchanged.
"""
from __future__ import annotations

import importlib

import pytest

from wazuh_mcp import tool_contexts as tc


@pytest.fixture(autouse=True)
def _clear_scoping_env(monkeypatch):
    monkeypatch.delenv("WAZUH_MCP_ENABLED_MODULES", raising=False)
    monkeypatch.delenv("WAZUH_MCP_DISABLED_MODULES", raising=False)
    yield


class TestModuleRegistrationAllowed:
    def test_default_allows_everything(self):
        # Both unset → every module registers (no behaviour change).
        for m in ("alerts", "vulnerabilities", "notifications", "servicenow"):
            assert tc.module_registration_allowed(m) is True

    def test_allowlist_restricts_to_listed(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_ENABLED_MODULES", "alerts,vulnerabilities")
        assert tc.module_registration_allowed("alerts") is True
        assert tc.module_registration_allowed("vulnerabilities") is True
        assert tc.module_registration_allowed("servicenow") is False
        assert tc.module_registration_allowed("compliance") is False

    def test_denylist_removes_listed(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_DISABLED_MODULES", "servicenow,azure_devops")
        assert tc.module_registration_allowed("alerts") is True
        assert tc.module_registration_allowed("servicenow") is False
        assert tc.module_registration_allowed("azure_devops") is False

    def test_denylist_wins_over_allowlist(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_ENABLED_MODULES", "alerts,servicenow")
        monkeypatch.setenv("WAZUH_MCP_DISABLED_MODULES", "servicenow")
        assert tc.module_registration_allowed("alerts") is True
        assert tc.module_registration_allowed("servicenow") is False

    def test_group_name_expands_to_member_modules(self, monkeypatch):
        # "threat_hunting" group → all its member modules enabled, others not.
        monkeypatch.setenv("WAZUH_MCP_ENABLED_MODULES", "threat_hunting")
        for m in tc.CONTEXT_MODULES["threat_hunting"]:
            assert tc.module_registration_allowed(m) is True
        assert tc.module_registration_allowed("alerts") is False

    def test_group_name_in_denylist_expands(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_DISABLED_MODULES", "compliance")
        # "compliance" group expands to compliance/reporting/scheduler
        for m in tc.CONTEXT_MODULES["compliance"]:
            assert tc.module_registration_allowed(m) is False
        assert tc.module_registration_allowed("alerts") is True

    def test_blank_entries_ignored(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_ENABLED_MODULES", " alerts , , ")
        assert tc.module_registration_allowed("alerts") is True
        assert tc.module_registration_allowed("fim") is False


class TestUnknownScopingNames:
    def test_unknown_name_flagged(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_DISABLED_MODULES", "alert,servicenow")  # 'alert' is a typo
        unknown = tc.unknown_scoping_names({"alerts", "servicenow", "fim"})
        assert unknown == {"alert"}

    def test_valid_module_and_group_names_not_flagged(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_ENABLED_MODULES", "alerts,threat_hunting")
        unknown = tc.unknown_scoping_names({"alerts", "fim"})
        assert unknown == set()


class TestParseModuleSet:
    def test_mixed_modules_and_groups(self):
        out = tc._parse_module_set("alerts,active_response,fim")
        assert "alerts" in out and "fim" in out
        # active_response group expands
        assert tc.CONTEXT_MODULES["active_response"].issubset(out)
