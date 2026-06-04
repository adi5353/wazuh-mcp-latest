"""Regression tests for the second-review remediation.

Covers:
  H1 — per-tenant isolation of the autonomous monitor + report schedules
  M1 — CDB key/value control-character (newline) injection rejection
  M2 — audit hash-chain external high-water anchor (tail-truncation detection)
  L1 — dict KEYS are sanitized, not just values
  L2 — WazuhClient.aclose() cancels the background refresh task
"""
from __future__ import annotations

import asyncio
import importlib
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _run(coro):
    return asyncio.run(coro)


# ── M1: CDB control-character injection ───────────────────────────────────────

class TestCdbFieldValidation:
    def test_newline_rejected(self):
        from wazuh_mcp.validators import validate_cdb_field
        with pytest.raises(ValueError, match="control characters"):
            validate_cdb_field("1.2.3.4\nevil.com:allow", "value")

    def test_carriage_return_and_nul_rejected(self):
        from wazuh_mcp.validators import validate_cdb_field
        with pytest.raises(ValueError):
            validate_cdb_field("a\rb", "key")
        with pytest.raises(ValueError):
            validate_cdb_field("a\x00b", "key")

    def test_ipv6_key_with_colons_allowed(self):
        # ':' must stay legal — IPv6 keys and value content use it; a single
        # colon stays on one line and cannot inject a new record.
        from wazuh_mcp.validators import validate_cdb_field
        assert validate_cdb_field("2001:db8::1", "key") == "2001:db8::1"
        assert validate_cdb_field("c2-server", "value") == "c2-server"

    def test_add_to_cdb_list_rejects_injection_before_write(self):
        from wazuh_mcp.tools import cdb
        from wazuh_mcp.tool_context import ToolContext
        from wazuh_mcp import identity
        from wazuh_mcp.rbac import ROLE

        tools: dict = {}
        mcp = MagicMock()
        mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
        wz = MagicMock(); wz.request = AsyncMock(return_value={"data": {"affected_items": [""]}})
        ctx = ToolContext(
            mcp=mcp, wz=wz, idx=MagicMock(), cfg=MagicMock(), cap=lambda n: n,
            require_writes=lambda: None, truncate=lambda s, n=300: s,
            enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value={}),
            incident_recommendations=lambda *a, **k: [], tool_registry={}, shared={},
        )
        cdb.register(ctx)
        identity.set_session_role(ROLE.RESPONDER)
        try:
            out = _run(tools["add_to_cdb_list"](
                list_name="malicious-ips", key="1.2.3.4", value="x\nevil.com:allow"))
        finally:
            identity._ctx_role.set(None)
        assert "error" in out
        # The malicious PUT must never have been issued.
        assert not any(c.args and c.args[0] == "PUT" for c in wz.request.call_args_list)


# ── L1: dict keys are sanitized ───────────────────────────────────────────────

class TestDictKeySanitization:
    def test_oversized_key_rejected(self):
        from wazuh_mcp.input_sanitizer import sanitize_input_value, MAX_STRING_LEN
        with pytest.raises(ValueError):
            sanitize_input_value({"k" * (MAX_STRING_LEN + 1): "v"}, "fields")

    def test_clean_dict_passes_through_unchanged(self):
        from wazuh_mcp.input_sanitizer import sanitize_input_value
        out = sanitize_input_value({"host": "web01", "count": 3}, "fields")
        assert out == {"host": "web01", "count": 3}


# ── L2: refresh task cancelled on aclose ──────────────────────────────────────

class TestRefreshTaskCleanup:
    def test_aclose_cancels_refresh_task(self):
        from wazuh_mcp.wazuh_client import WazuhClient

        async def run():
            cfg = SimpleNamespace(ca_bundle=None, verify_ssl=False, request_timeout=30)
            client = WazuhClient(cfg)

            async def _long():
                await asyncio.sleep(100)

            task = asyncio.get_event_loop().create_task(_long())
            client._refresh_task = task
            await asyncio.sleep(0)  # let it start
            await client.aclose()
            assert task.done()  # cancelled, not orphaned

        _run(run())


# ── H1: autonomous monitor per-tenant isolation ───────────────────────────────

class TestMonitorTenantIsolation:
    def test_state_is_isolated_per_tenant(self):
        from wazuh_mcp.tools import autonomous_soc as a
        with patch.object(a, "_active_tenant_name", return_value="tenant-A"):
            a._monitor_state["running"] = True
            a._monitor_state["alerts_processed"] = 7
        with patch.object(a, "_active_tenant_name", return_value="tenant-B"):
            # Fresh default store for B — A's run is invisible.
            assert a._monitor_state["running"] is False
            assert a._monitor_state["alerts_processed"] == 0
        with patch.object(a, "_active_tenant_name", return_value="tenant-A"):
            assert a._monitor_state["running"] is True
            assert a._monitor_state["alerts_processed"] == 7

    def test_single_tenant_default_unchanged(self):
        from wazuh_mcp.tools import autonomous_soc as a
        # With no tenant set, everything routes to the single '(default)' store.
        assert a._active_tenant_name() == "(default)"
        assert "running" in a._monitor_state
        assert a._monitor_state.get("auto_ticket") is not None


# ── H1: report schedule per-tenant isolation ──────────────────────────────────

class TestScheduleTenantIsolation:
    def _register(self):
        from wazuh_mcp.tools import scheduler
        tools: dict = {}
        mcp = MagicMock()
        mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
        from wazuh_mcp.tool_context import ToolContext
        ctx = ToolContext(
            mcp=mcp, wz=MagicMock(), idx=MagicMock(), cfg=MagicMock(), cap=lambda n: n,
            require_writes=lambda: None, truncate=lambda s, n=300: s,
            enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value={}),
            incident_recommendations=lambda *a, **k: [], tool_registry={}, shared={},
        )
        scheduler._SCHEDULES.clear()
        scheduler.register(ctx)
        return scheduler, tools

    def test_schedule_visible_only_to_owning_tenant(self):
        from wazuh_mcp import identity
        from wazuh_mcp.rbac import ROLE
        scheduler, tools = self._register()
        identity.set_session_role(ROLE.RESPONDER)
        try:
            with patch.object(scheduler, "_save_schedules", lambda: None), \
                 patch.object(scheduler, "_ensure_scheduler_running", lambda *a, **k: None):
                with patch.object(scheduler, "_active_tenant_name", return_value="tenant-A"):
                    created = _run(tools["create_report_schedule"](
                        name="A daily", report_type="daily_summary", interval="daily"))
                    assert created["status"] == "created"
                    sid = created["schedule_id"]
                    assert _run(tools["list_report_schedules"]())["total"] == 1
                # Tenant B sees none and cannot delete A's schedule.
                with patch.object(scheduler, "_active_tenant_name", return_value="tenant-B"):
                    assert _run(tools["list_report_schedules"]())["total"] == 0
                    deleted = _run(tools["delete_report_schedule"](schedule_id=sid))
                    assert "error" in deleted
                    assert sid not in deleted["existing_ids"]
                # A can still see and delete its own.
                with patch.object(scheduler, "_active_tenant_name", return_value="tenant-A"):
                    assert _run(tools["delete_report_schedule"](schedule_id=sid))["status"] == "deleted"
        finally:
            identity._ctx_role.set(None)
            scheduler._SCHEDULES.clear()


# ── M2: audit chain tail-truncation detection ─────────────────────────────────

class TestAuditChainAnchor:
    def test_truncation_below_anchor_is_detected_and_resumed(self, tmp_path):
        import wazuh_mcp.audit as audit
        log_path = tmp_path / "audit.jsonl"
        with patch.dict(os.environ, {
            "WAZUH_MCP_PROFILE": "dev",
            "WAZUH_AUDIT_LOG": str(log_path),
            "WAZUH_AUDIT_LOG_SIGNING_KEY": "test-key",
        }):
            mod = importlib.reload(audit)
            try:
                # Simulate a log whose tail record is seq=2 ...
                log_path.write_text(
                    '{"seq": 1, "hmac": "h1"}\n{"seq": 2, "hmac": "h2"}\n',
                    encoding="utf-8",
                )
                # ... but the external anchor recorded a later high-water seq=5.
                mod._save_chain_anchor(5, "h5")
                mod._chain_recovered = False
                mod._chain_seq = 0
                mod._chain_last_hmac = ""
                mod._recover_chain_state_locked()
                # Truncation detected: resume from the anchor, not the tail.
                assert mod._chain_seq == 5
                assert mod._chain_last_hmac == "h5"
            finally:
                with patch.dict(os.environ, {"WAZUH_MCP_PROFILE": "dev",
                                             "WAZUH_AUDIT_LOG_SIGNING_KEY": "test-key"}):
                    importlib.reload(audit)

    def test_no_false_positive_when_tail_at_or_above_anchor(self, tmp_path):
        import wazuh_mcp.audit as audit
        log_path = tmp_path / "audit.jsonl"
        with patch.dict(os.environ, {
            "WAZUH_MCP_PROFILE": "dev",
            "WAZUH_AUDIT_LOG": str(log_path),
            "WAZUH_AUDIT_LOG_SIGNING_KEY": "test-key",
        }):
            mod = importlib.reload(audit)
            try:
                log_path.write_text('{"seq": 9, "hmac": "h9"}\n', encoding="utf-8")
                mod._save_chain_anchor(7, "h7")  # anchor behind tail (normal)
                mod._chain_recovered = False
                mod._chain_seq = 0
                mod._chain_last_hmac = ""
                mod._recover_chain_state_locked()
                assert mod._chain_seq == 9  # uses the (newer) tail
                assert mod._chain_last_hmac == "h9"
            finally:
                with patch.dict(os.environ, {"WAZUH_MCP_PROFILE": "dev",
                                             "WAZUH_AUDIT_LOG_SIGNING_KEY": "test-key"}):
                    importlib.reload(audit)
