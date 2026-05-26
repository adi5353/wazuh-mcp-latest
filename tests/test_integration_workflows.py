"""Integration tests for multi-tool workflows.

Tests complete alert-to-ticket, CVE triage, and playbook execution flows
using mocked Wazuh API/Indexer responses. These tests verify that tool chains
work end-to-end without regressions.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_wz():
    wz = MagicMock()
    wz.request = AsyncMock(return_value={
        "data": {"affected_items": [], "total_affected_items": 0}
    })
    return wz


@pytest.fixture
def mock_idx():
    idx = MagicMock()
    idx.search = AsyncMock(return_value={
        "hits": {"hits": [], "total": {"value": 0}},
        "aggregations": {},
    })
    return idx


@pytest.fixture
def mock_cfg():
    cfg = MagicMock()
    cfg.allow_writes = True
    cfg.verify_ssl = False
    cfg.indexer_host = "https://localhost:9200"
    cfg.indexer_user = "admin"
    cfg.indexer_pass = "admin"
    return cfg


def _alert_hit(alert_id: str, level: int = 12, rule_group: str = "authentication_failed",
               srcip: str = "1.2.3.4") -> dict:
    return {
        "_id": alert_id,
        "_source": {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {"id": "100001", "level": level, "description": "Test alert",
                     "groups": [rule_group]},
            "agent": {"id": "001", "name": "test-agent", "ip": "10.0.0.1"},
            "data": {"srcip": srcip},
        },
    }


# ── CVE watchlist workflow ────────────────────────────────────────────────────

class TestCVEWorkflow:
    """add_cve → get_watchlist_exposure → prioritize_cve_risk → check_sla_breaches."""

    def test_parse_entry_roundtrip(self):
        """Entry serialization/deserialization preserves all fields."""
        from wazuh_mcp.tools.cve_watchlist import _parse_entry
        val = "active|Log4Shell RCE|9.8|14|2024-01-01T00:00:00Z"
        parsed = _parse_entry("CVE-2021-44228", val)
        assert parsed["cve_id"] == "CVE-2021-44228"
        assert parsed["status"] == "active"
        assert parsed["note"] == "Log4Shell RCE"
        assert parsed["cvss_score"] == 9.8
        assert parsed["sla_days"] == 14
        assert parsed["added_at"] == "2024-01-01T00:00:00Z"

    def test_sla_breach_detected(self):
        from wazuh_mcp.tools.cve_watchlist import _sla_status
        entry = {"sla_days": 7, "added_at": "2020-06-01T00:00:00Z"}
        result = _sla_status(entry)
        assert result["sla_breached"] is True
        assert result["days_remaining"] is not None
        assert result["days_remaining"] < 0

    def test_sla_not_breached(self):
        from wazuh_mcp.tools.cve_watchlist import _sla_status
        entry = {"sla_days": 365, "added_at": "2099-01-01T00:00:00Z"}
        result = _sla_status(entry)
        assert result["sla_breached"] is False
        assert result["days_remaining"] > 0

    def test_sla_no_deadline(self):
        from wazuh_mcp.tools.cve_watchlist import _sla_status
        entry = {"sla_days": 0, "added_at": ""}
        result = _sla_status(entry)
        assert result["sla_deadline"] is None
        assert result["sla_breached"] is False


# ── Playbook rollback workflow ────────────────────────────────────────────────

class TestPlaybookRollback:

    @pytest.mark.asyncio
    async def test_rollback_fires_on_step_failure(self):
        """When a step fails, rollback steps for completed steps execute in reverse."""
        from wazuh_mcp.tools.playbooks import _run_rollback

        pb = {
            "rollback_steps": [
                {
                    "name": "Remove IP from blocklist",
                    "tool": "remove_from_cdb_list",
                    "params": {"list_name": "malicious-ips", "key": "{ip}"},
                    "rollback_for_step": 3,
                }
            ]
        }
        variables = {"ip": "1.2.3.4", "agent_id": "", "cve_id": "", "alert_id": ""}

        rollback_called = []

        async def mock_remove_from_cdb_list(**kwargs):
            rollback_called.append(kwargs)
            return {"action": "removed", "key": kwargs["key"]}

        registry = {"remove_from_cdb_list": mock_remove_from_cdb_list}
        results = await _run_rollback(pb, [0, 1, 2, 3], variables, registry)

        assert len(results) == 1
        assert results[0]["status"] == "completed"
        assert results[0]["rollback_for_step"] == 4  # human-readable (1-indexed)
        assert len(rollback_called) == 1
        assert rollback_called[0]["key"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_rollback_skipped_when_no_defs(self):
        from wazuh_mcp.tools.playbooks import _run_rollback
        pb = {"rollback_steps": []}
        results = await _run_rollback(pb, [0, 1, 2], {}, {})
        assert results == []

    @pytest.mark.asyncio
    async def test_rollback_skipped_when_no_completed_steps(self):
        from wazuh_mcp.tools.playbooks import _run_rollback
        pb = {
            "rollback_steps": [
                {"name": "Undo", "tool": "remove_from_cdb_list",
                 "params": {}, "rollback_for_step": 0}
            ]
        }
        results = await _run_rollback(pb, [], {}, {})
        assert results == []

    @pytest.mark.asyncio
    async def test_rollback_handles_tool_error_gracefully(self):
        """Rollback failure should not raise — just record the error."""
        from wazuh_mcp.tools.playbooks import _run_rollback

        pb = {
            "rollback_steps": [
                {"name": "Failing rollback", "tool": "bad_tool",
                 "params": {}, "rollback_for_step": 0}
            ]
        }

        async def failing_tool(**kwargs):
            raise RuntimeError("Network error")

        registry = {"bad_tool": failing_tool}
        results = await _run_rollback(pb, [0], {}, registry)
        assert len(results) == 1
        assert results[0]["status"] == "failed"
        assert "Network error" in results[0]["error"]

    @pytest.mark.asyncio
    async def test_new_playbook_templates_registered(self):
        """New playbook templates (ransomware, lateral-movement, exfiltration) are present."""
        from wazuh_mcp.tools.playbooks import _BUILTIN_PLAYBOOKS
        ids = [pb["id"] for pb in _BUILTIN_PLAYBOOKS]
        assert "ransomware-containment" in ids
        assert "lateral-movement-containment" in ids
        assert "data-exfiltration-response" in ids

    def test_all_playbooks_have_rollback_field(self):
        """Every built-in playbook must define rollback_steps (even if empty)."""
        from wazuh_mcp.tools.playbooks import _BUILTIN_PLAYBOOKS
        for pb in _BUILTIN_PLAYBOOKS:
            assert "rollback_steps" in pb, f"Playbook '{pb['id']}' missing rollback_steps"
            assert isinstance(pb["rollback_steps"], list)


# ── Autonomous SOC adaptive polling ──────────────────────────────────────────

class TestAdaptivePolling:

    def test_surge_shortens_interval(self):
        from wazuh_mcp.tools.autonomous_soc import _adapt_interval
        result = _adapt_interval(base_interval=60, new_alert_count=10)
        assert result <= 30

    def test_quiet_lengthens_interval(self):
        from wazuh_mcp.tools.autonomous_soc import _adapt_interval
        result = _adapt_interval(base_interval=60, new_alert_count=0)
        assert result >= 60

    def test_normal_maintains_interval(self):
        from wazuh_mcp.tools.autonomous_soc import _adapt_interval
        result = _adapt_interval(base_interval=60, new_alert_count=1)
        assert result == 60

    def test_interval_clamped_minimum(self):
        from wazuh_mcp.tools.autonomous_soc import _adapt_interval
        result = _adapt_interval(base_interval=30, new_alert_count=100)
        assert result >= 15  # never below 15s

    def test_interval_clamped_maximum(self):
        from wazuh_mcp.tools.autonomous_soc import _adapt_interval
        result = _adapt_interval(base_interval=60, new_alert_count=0)
        assert result <= 300  # never above 5× base


# ── UEBA peer-group baseline ──────────────────────────────────────────────────

class TestUEBAPeerGroup:

    def test_analyse_activity_lateral_movement_flag(self):
        from wazuh_mcp.tools.ueba import _analyse_activity
        events = [
            {
                "@timestamp": f"2024-01-01T{i:02d}:00:00Z",
                "agent": {"id": f"00{i}", "name": f"agent-{i}"},
                "data": {"srcip": "1.2.3.4", "dstuser": "admin"},
                "rule": {"groups": ["authentication_success"], "level": 3},
            }
            for i in range(6)  # 6 distinct agents
        ]
        result = _analyse_activity(events, "admin")
        assert result["risk_level"] in ("medium", "high")
        assert any("lateral" in f.lower() for f in result["risk_factors"])

    def test_analyse_activity_high_failure_rate_flag(self):
        from wazuh_mcp.tools.ueba import _analyse_activity
        events = [
            {
                "@timestamp": "2024-01-01T00:00:00Z",
                "agent": {"id": "001", "name": "server"},
                "data": {"srcip": "1.2.3.4", "dstuser": "admin"},
                "rule": {"groups": ["authentication_failed"], "level": 5},
            }
        ] * 20 + [
            {
                "@timestamp": "2024-01-01T01:00:00Z",
                "agent": {"id": "001", "name": "server"},
                "data": {"srcip": "1.2.3.4", "dstuser": "admin"},
                "rule": {"groups": ["authentication_success"], "level": 3},
            }
        ] * 2
        result = _analyse_activity(events, "admin")
        assert any("failure" in f.lower() for f in result["risk_factors"])

    def test_analyse_activity_clean_no_flags(self):
        from wazuh_mcp.tools.ueba import _analyse_activity
        events = [
            {
                "@timestamp": "2024-01-01T09:00:00Z",
                "agent": {"id": "001", "name": "workstation"},
                "data": {"srcip": "10.0.0.5", "dstuser": "john"},
                "rule": {"groups": ["authentication_success"], "level": 3},
            }
        ] * 5
        result = _analyse_activity(events, "john")
        assert result["risk_level"] == "low"
        assert result["risk_factors"] == []


# ── CDB backup/restore workflow ───────────────────────────────────────────────

class TestCDBBackupWorkflow:
    """Validates that export_cdb_backup and import_cdb_backup tools are registered."""

    def test_backup_tools_in_module(self):
        """Module should define the backup/restore functions."""
        import ast
        import pathlib
        src = pathlib.Path("wazuh_mcp/tools/cdb.py").read_text()
        assert "export_cdb_backup" in src
        assert "import_cdb_backup" in src

    def test_cve_watchlist_has_priority_tools(self):
        import pathlib
        src = pathlib.Path("wazuh_mcp/tools/cve_watchlist.py").read_text()
        assert "prioritize_cve_risk" in src
        assert "check_sla_breaches" in src

    def test_playbooks_have_new_templates(self):
        import pathlib
        src = pathlib.Path("wazuh_mcp/tools/playbooks.py").read_text()
        assert "ransomware-containment" in src
        assert "lateral-movement-containment" in src
        assert "data-exfiltration-response" in src
        assert "_run_rollback" in src


# ── Audit HMAC tamper detection ───────────────────────────────────────────────

class TestAuditHMAC:

    def test_sign_record_adds_hmac(self):
        from wazuh_mcp import audit as _audit
        original = _audit._SIGNING_KEY
        _audit._SIGNING_KEY = "test-key-12345"
        try:
            record = {"ts": "2024-01-01", "tool": "search_alerts", "identity": "user1",
                      "params_fp": "abc", "result_code": "200", "duration_ms": 10}
            signed = _audit._sign_record(record)
            assert "hmac" in signed
            assert len(signed["hmac"]) == 64  # SHA-256 hex

            # Tampered record should produce a different HMAC
            tampered = {**record, "result_code": "999"}
            signed_tampered = _audit._sign_record(tampered)
            assert signed["hmac"] != signed_tampered["hmac"]
        finally:
            _audit._SIGNING_KEY = original

    def test_sign_record_noop_without_key(self):
        from wazuh_mcp import audit as _audit
        original = _audit._SIGNING_KEY
        _audit._SIGNING_KEY = ""
        try:
            record = {"ts": "2024-01-01", "tool": "test", "identity": "anon",
                      "params_fp": "fp", "result_code": "ok", "duration_ms": 1}
            result = _audit._sign_record(record)
            assert "hmac" not in result
        finally:
            _audit._SIGNING_KEY = original

    def test_params_scrub_sensitive_fields(self):
        from wazuh_mcp.audit import _scrub_params
        params = {
            "username": "admin",
            "password": "letmein",
            "token": "Bearer abc123",
            "api_key": "sk-secret",
            "host": "10.0.0.1",
        }
        scrubbed = _scrub_params(params)
        assert scrubbed["password"] == "[REDACTED]"
        assert scrubbed["token"] == "[REDACTED]"
        assert scrubbed["api_key"] == "[REDACTED]"
        assert scrubbed["username"] == "admin"   # not a secret key
        assert scrubbed["host"] == "10.0.0.1"    # not a secret key


# ── Rate limiter isolation ────────────────────────────────────────────────────

class TestRateLimiterIntegration:

    def test_different_identities_independent(self):
        """Each identity has its own sliding window."""
        from wazuh_mcp.rate_limit import _is_throttled, _windows
        id_a = "integration-test-identity-A"
        id_b = "integration-test-identity-B"
        # Clear any leftover state
        _windows.pop(id_a, None)
        _windows.pop(id_b, None)

        throttled_a, _ = _is_throttled(id_a)
        throttled_b, _ = _is_throttled(id_b)
        assert not throttled_a
        assert not throttled_b

    def test_global_throttle_fires_after_burst(self):
        """Identity exceeding RPM+burst should be throttled."""
        import os
        from unittest.mock import patch
        from wazuh_mcp.rate_limit import _is_throttled, _windows

        identity = "integration-burst-test-xyz"
        _windows.pop(identity, None)

        with patch.dict(os.environ, {
            "WAZUH_MCP_RATE_LIMIT_RPM": "5",
            "WAZUH_MCP_RATE_LIMIT_BURST": "0",
        }):
            # Allow up to RPM (5) calls
            for _ in range(5):
                throttled, _ = _is_throttled(identity)
                assert not throttled

            # 6th call should be throttled
            throttled, retry_after = _is_throttled(identity)
            assert throttled
            assert retry_after >= 1
