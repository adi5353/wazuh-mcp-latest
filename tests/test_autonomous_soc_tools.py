"""Tests for the autonomous SOC orchestration tools and FP/ticket helpers."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _restore_monitor_state():
    """These tests mutate the module-level ``_monitor_state`` (incl. the suppression
    queues). Snapshot and restore it so state never leaks into other modules such
    as test_roi_autonomous, which asserts on a clean pending-suppression queue."""
    import copy
    import wazuh_mcp.tools.autonomous_soc as soc
    snapshot = {k: copy.deepcopy(v) for k, v in soc._monitor_state.items() if k != "task"}
    yield
    for k, v in snapshot.items():
        soc._monitor_state[k] = v


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
    import wazuh_mcp.identity as identity
    from wazuh_mcp.rbac import ROLE
    identity.set_session_role(ROLE.ADMIN)

    import wazuh_mcp.tools.autonomous_soc as soc
    # Reset shared mutable state to a clean baseline.
    soc._monitor_state.update({
        "running": False, "task": None, "started_at": None, "stopped_at": None,
        "alerts_processed": 0, "actions_taken": 0, "recent_actions": [],
        "pending_suppressions": [], "approved_suppressions": [], "rejected_suppressions": [],
    })

    async def _noop_loop(*a, **k):
        return None
    monkeypatch.setattr(soc, "_monitor_loop", _noop_loop)
    monkeypatch.setattr(soc, "save_monitor_state", lambda *a, **k: None)
    monkeypatch.setattr(soc, "clear_monitor_state", lambda *a, **k: None)

    from wazuh_mcp.tool_context import ToolContext
    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    ctx = ToolContext(
        mcp=mcp, wz=AsyncMock(), idx=AsyncMock(), cfg=MagicMock(),
        cap=lambda n: n, require_writes=lambda: None, truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [{"id": i} for i in (ids or [])],
        geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda *a, **k: [], tool_registry={},
    )
    soc.register(ctx)
    yield tools, soc
    identity._ctx_role.set(None)


class TestMonitorLifecycle:
    def test_start_requires_admin(self, env, monkeypatch):
        tools, soc = env
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.VIEWER)
        out = _run(tools["start_autonomous_monitor"]())
        assert "error" in out

    def test_start_stop_cycle(self, env):
        tools, soc = env
        started = _run(tools["start_autonomous_monitor"](interval_seconds=10, severity_threshold=12))
        assert started["status"] == "started"
        assert started["interval_seconds"] == 30  # clamped to min 30

        again = _run(tools["start_autonomous_monitor"]())
        assert again["status"] == "already_running"

        stopped = _run(tools["stop_autonomous_monitor"]())
        assert stopped["status"] == "stopped"

    def test_stop_when_not_running(self, env):
        tools, soc = env
        out = _run(tools["stop_autonomous_monitor"]())
        assert out["status"] == "not_running"

    def test_get_status(self, env):
        tools, soc = env
        out = _run(tools["get_autonomous_status"]())
        assert out["running"] is False and "recent_actions" in out


class TestAutoTicketing:
    def test_configure_valid(self, env):
        tools, soc = env
        out = _run(tools["configure_auto_ticketing"](enabled=True, backend="servicenow", min_level=10))
        assert out["status"] == "ok" and out["auto_ticket"]["backend"] == "servicenow"

    def test_invalid_backend(self, env):
        tools, soc = env
        assert "error" in _run(tools["configure_auto_ticketing"](backend="pagerduty"))

    def test_invalid_level(self, env):
        tools, soc = env
        assert "error" in _run(tools["configure_auto_ticketing"](min_level=99))


class TestSuppressionQueue:
    def test_approve_and_reject(self, env):
        tools, soc = env
        soc._monitor_state["pending_suppressions"] = [
            {"id": "s1", "rule_id": "1002", "rule_description": "noisy", "fp_score": 0.7},
            {"id": "s2", "rule_id": "1003", "rule_description": "also noisy", "fp_score": 0.6},
        ]
        listed = _run(tools["list_pending_suppressions"]())
        assert listed["pending_count"] == 2

        approved = _run(tools["approve_suppression"](suppression_id="s1", note="confirmed"))
        assert approved["status"] == "approved" and approved["rule_id"] == "1002"

        rejected = _run(tools["reject_suppression"](suppression_id="s2"))
        assert rejected["status"] == "rejected"

        assert len(soc._monitor_state["pending_suppressions"]) == 0

    def test_approve_not_found(self, env):
        tools, soc = env
        soc._monitor_state["pending_suppressions"] = []
        assert "error" in _run(tools["approve_suppression"](suppression_id="ghost"))

    def test_reject_not_found(self, env):
        tools, soc = env
        soc._monitor_state["pending_suppressions"] = []
        assert "error" in _run(tools["reject_suppression"](suppression_id="ghost"))


class TestScheduledReports:
    def test_valid(self, env):
        tools, soc = env
        out = _run(tools["configure_scheduled_reports"](
            handover_hours_utc=[8, 16], handover_channel="#soc",
            digest_day="friday", digest_hour_utc=9, digest_recipients=["a@b.c"]))
        assert out.get("status") == "ok" or "error" not in out

    def test_invalid_hours(self, env):
        tools, soc = env
        assert "error" in _run(tools["configure_scheduled_reports"](handover_hours_utc=[25]))

    def test_invalid_day(self, env):
        tools, soc = env
        assert "error" in _run(tools["configure_scheduled_reports"](digest_day="someday"))

    def test_invalid_digest_hour(self, env):
        tools, soc = env
        assert "error" in _run(tools["configure_scheduled_reports"](digest_hour_utc=30))


class TestHelpers:
    def test_fp_score_and_queue(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        soc._monitor_state["pending_suppressions"] = []
        assert soc._fp_score("1002", ["syslog"], 80) >= 0.5
        assert soc._maybe_queue_suppression("1002", "noisy", ["syslog"], 80) is True
        # duplicate is not re-queued
        assert soc._maybe_queue_suppression("1002", "noisy", ["syslog"], 80) is False
        # below threshold (non-noisy group, low volume) → not queued
        assert soc._maybe_queue_suppression("9999", "quiet", ["custom"], 1) is False

    def test_autonomous_ar_gate(self, monkeypatch):
        import wazuh_mcp.tools.autonomous_soc as soc
        cfg = MagicMock()
        cfg.allow_writes = False
        assert "WAZUH_ALLOW_WRITES" in soc._autonomous_ar_allowed(cfg, "8.8.8.8")
        cfg.allow_writes = True
        monkeypatch.delenv("WAZUH_MCP_AUTONOMOUS_AR", raising=False)
        assert "AUTONOMOUS_AR" in soc._autonomous_ar_allowed(cfg, "8.8.8.8")

    def test_maybe_create_ticket_disabled(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        soc._monitor_state["auto_ticket"] = {"enabled": False, "min_level": 13}
        out = _run(soc._maybe_create_ticket({"rule": {"level": 14}}, [], MagicMock(), {}))
        assert out is None

    def test_maybe_create_ticket_jira(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        soc._monitor_state["auto_ticket"] = {
            "enabled": True, "min_level": 10, "backend": "jira", "labels": ["soc"]}
        registry = {"create_jira_ticket": AsyncMock(return_value={"url": "http://jira/SOC-1"})}
        alert = {"rule": {"level": 13, "description": "breach"}, "agent": {"name": "h1"}}
        out = _run(soc._maybe_create_ticket(alert, [], MagicMock(), registry))
        assert out == "http://jira/SOC-1"

    def test_maybe_create_ticket_servicenow(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        soc._monitor_state["auto_ticket"] = {
            "enabled": True, "min_level": 10, "backend": "servicenow", "labels": []}
        registry = {"create_servicenow_incident": AsyncMock(return_value={"sys_id": "SN-9"})}
        alert = {"rule": {"level": 14, "description": "x"}, "agent": {"name": "h"}}
        out = _run(soc._maybe_create_ticket(alert, [{"tool": "t", "output": "o"}], MagicMock(), registry))
        assert out == "SN-9"


class TestAdaptiveInterval:
    @pytest.mark.parametrize("base,count,expected_lo,expected_hi", [
        (60, 10, 15, 15),     # surge → min
        (60, 3, 15, 30),      # busy → base/2
        (60, 0, 120, 120),    # quiet → base*2
        (60, 1, 60, 60),      # normal
    ])
    def test_adapt_interval(self, base, count, expected_lo, expected_hi):
        import wazuh_mcp.tools.autonomous_soc as soc
        out = soc._adapt_interval(base, count)
        assert expected_lo <= out <= expected_hi


class TestEnrichAndNotify:
    def test_full_pipeline(self, monkeypatch):
        import wazuh_mcp.tools.autonomous_soc as soc

        class _FakeResp:
            status_code = 200

            def json(self):
                return {"hosting": True, "proxy": False, "tor": False}

        class _FakeClient:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, *a, **k):
                return _FakeResp()

            async def post(self, *a, **k):
                return _FakeResp()

        monkeypatch.setattr(soc.httpx, "AsyncClient", lambda *a, **k: _FakeClient())
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        soc._monitor_state["auto_ticket"] = {"enabled": False, "min_level": 13}

        wz = MagicMock()
        wz.request = AsyncMock(return_value={"data": {"affected_items": []}})
        idx = MagicMock()
        idx.search = AsyncMock(return_value={"hits": {"total": {"value": 1}, "hits": []}})

        alert = {
            "rule": {"id": "5710", "level": 13, "description": "C2 beacon",
                     "groups": ["authentication_failed"]},
            "agent": {"id": "001", "name": "host1"},
            "data": {"srcip": "8.8.8.8"},
            "@timestamp": "2024-01-01T00:00:00Z",
        }
        out = _run(soc._enrich_and_notify(alert, wz, idx, MagicMock(), tool_registry={}))
        assert out["rule_id"] == "5710" and out["rule_level"] == 13
        assert out["ip_risk"] == "high"  # hosting flag set
        assert out["slack_sent"] is True


class TestMonitorLoop:
    def test_single_iteration(self, monkeypatch):
        import wazuh_mcp.tools.autonomous_soc as soc

        soc._monitor_state["running"] = True
        soc._monitor_state["seen_alert_ids"] = []
        soc._monitor_state["alerts_processed"] = 0
        soc._monitor_state["actions_taken"] = 0
        soc._monitor_state["recent_actions"] = []

        # Exit the loop after the first sleep.
        async def _sleep(_secs):
            soc._monitor_state["running"] = False
        monkeypatch.setattr(soc.asyncio, "sleep", _sleep)
        monkeypatch.setattr(soc, "save_monitor_state", lambda *a, **k: None)

        async def _enrich(*a, **k):
            return {"actions": ["triaged"]}
        monkeypatch.setattr(soc, "_enrich_and_notify", _enrich)

        idx = MagicMock()
        idx.search = AsyncMock(return_value={"hits": {"hits": [
            {"_id": "alert-1", "_source": {"rule": {"id": "5710", "level": 13},
             "agent": {"id": "001"}, "data": {}}}]}})

        _run(soc._monitor_loop(MagicMock(), idx, MagicMock(), 60, 10, tool_registry=None))
        assert soc._monitor_state["alerts_processed"] == 1
        assert soc._monitor_state["actions_taken"] == 1
        assert "alert-1" in soc._monitor_state["seen_alert_ids"]


class TestScheduledReports:
    def test_sends_handover_and_digest(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        soc._monitor_state["schedule"] = {
            "handover_hours_utc": [now.hour],
            "handover_channel": "#soc",
            "digest_day": now.strftime("%A").lower(),
            "digest_hour_utc": now.hour,
            "digest_recipients": ["ciso@example.com"],
            "last_handover_day": None,
            "last_digest_week": None,
        }
        registry = {
            "send_shift_handover_to_slack": AsyncMock(return_value={"status": "ok"}),
            "generate_weekly_summary": AsyncMock(return_value={"summary": "ok"}),
            "send_weekly_summary_to_slack": AsyncMock(return_value={"status": "ok"}),
            "email_compliance_report": AsyncMock(return_value={"status": "ok"}),
        }
        _run(soc._maybe_send_scheduled_reports(MagicMock(), registry))
        registry["send_shift_handover_to_slack"].assert_awaited()
        registry["generate_weekly_summary"].assert_awaited()
        # de-dup: a second call in the same hour/week does nothing new
        registry["send_shift_handover_to_slack"].reset_mock()
        _run(soc._maybe_send_scheduled_reports(MagicMock(), registry))
        registry["send_shift_handover_to_slack"].assert_not_awaited()


class TestTriageTree:
    def test_resolve_triage_params(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        out = soc._resolve_triage_params(
            {"agent_id": "{agent_id}", "ip": "{srcip}", "n": 1}, "001", "8.8.8.8")
        assert out["agent_id"] == "001" and out["ip"] == "8.8.8.8"

    def test_run_triage_tree_malware(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        registry = {
            "get_recent_fim_changes": AsyncMock(return_value={"changes": []}),
            "hunt_persistence_mechanisms": AsyncMock(return_value={"hits": []}),
        }
        out = _run(soc._run_triage_tree(["malware"], "001", "8.8.8.8", registry))
        assert isinstance(out, list) and len(out) == 2

    def test_run_triage_tree_skips_srcip_steps_without_ip(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        registry = {"enrich_ip": AsyncMock(return_value={}),
                    "blast_radius_analysis": AsyncMock(return_value={})}
        # exploit tree's steps all need {srcip}; with no srcip they're skipped → []
        out = _run(soc._run_triage_tree(["exploit"], "001", "", registry))
        assert out == []

    def test_run_triage_tree_unknown_group(self):
        import wazuh_mcp.tools.autonomous_soc as soc
        out = _run(soc._run_triage_tree(["no-such-group"], "001", "8.8.8.8", {}))
        assert out == []
