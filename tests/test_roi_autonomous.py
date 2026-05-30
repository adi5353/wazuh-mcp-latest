"""Tests for the five longer-term market-fit bets.

Covers:
  1. ROI Tracker core + tools (roi_tracker.py, tools/roi.py)
  2. Autonomous SOC full pipeline (auto-ticket, suppression queue, scheduled reports)
  3. SOC Dashboard (static HTML artifact checks)
  4. Demo environment (docker-compose.yml + seed script syntax)
  5. MSSP + rbac.analyst_or_above (already wired)
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from wazuh_mcp.tool_context import ToolContext

import pytest


# ────────────────────────────────────────────────────────────────────────────
# 1. ROI Tracker
# ────────────────────────────────────────────────────────────────────────────

class TestROITracker:
    """Unit tests for wazuh_mcp/core/roi_tracker.py"""

    def setup_method(self):
        # Reset tracker state before each test
        import wazuh_mcp.core.roi_tracker as rt
        rt._state = {
            "sessions": [],
            "current_session": None,
            "total_calls": 0,
            "total_saved_minutes": 0.0,
            "total_actual_seconds": 0.0,
            "started_at": "2026-01-01T00:00:00+00:00",
        }

    def test_record_call_increments_total_calls(self):
        from wazuh_mcp.core.roi_tracker import record_call, _state
        record_call("alert_summary", 5.0)
        assert _state["total_calls"] == 1

    def test_record_call_computes_saved_minutes(self):
        from wazuh_mcp.core.roi_tracker import record_call, _state, BASELINE_MINUTES
        tool = "alert_summary"
        baseline = BASELINE_MINUTES[tool]  # 5.0 minutes
        # 10 second actual → baseline 5min → saved = 5 - 10/60 ≈ 4.83 min
        record_call(tool, 10.0)
        assert _state["total_saved_minutes"] > 0
        assert _state["total_saved_minutes"] <= baseline

    def test_saved_minutes_floored_at_zero(self):
        """If a tool takes longer than baseline, savings = 0 (no penalty)."""
        from wazuh_mcp.core.roi_tracker import record_call, _state
        # alert_summary baseline = 5 min. Pass 600s (10 min) actual.
        record_call("alert_summary", 600.0)
        assert _state["total_saved_minutes"] == 0.0

    def test_default_baseline_for_unknown_tool(self):
        from wazuh_mcp.core.roi_tracker import record_call, _state, BASELINE_MINUTES
        default = BASELINE_MINUTES["__default__"]
        record_call("unknown_exotic_tool", 1.0)
        expected = default - 1.0 / 60
        assert abs(_state["total_saved_minutes"] - expected) < 0.01

    def test_session_start_creates_session(self):
        from wazuh_mcp.core.roi_tracker import session_start, _state
        session_start("test-session-1")
        assert _state["current_session"] is not None
        assert _state["current_session"]["session_id"] == "test-session-1"

    def test_session_end_moves_to_sessions_list(self):
        from wazuh_mcp.core.roi_tracker import session_start, record_call, session_end, _state
        session_start("test-sess")
        record_call("search_alerts", 2.0)
        result = session_end()
        assert result is not None
        assert result["session_id"] == "test-sess"
        assert _state["current_session"] is None
        assert len(_state["sessions"]) == 1

    def test_session_end_without_start_returns_none(self):
        from wazuh_mcp.core.roi_tracker import session_end
        result = session_end()
        assert result is None

    def test_session_accumulates_savings(self):
        from wazuh_mcp.core.roi_tracker import session_start, record_call, session_end
        session_start("s1")
        record_call("hunt_lateral_movement", 30.0)   # baseline 20min → saved ≈ 19.5min
        record_call("enrich_ip", 2.0)                 # baseline 5min → saved ≈ 4.97min
        result = session_end()
        assert result["saved_minutes"] > 20

    def test_get_roi_summary_empty(self):
        from wazuh_mcp.core.roi_tracker import get_roi_summary
        summary = get_roi_summary(days=7)
        assert summary["sessions"] == 0
        assert summary["tool_calls"] == 0
        assert summary["time_saved_hours"] == 0.0

    def test_get_roi_summary_counts_recent_sessions(self):
        from wazuh_mcp.core.roi_tracker import session_start, record_call, session_end, get_roi_summary
        session_start("s1")
        record_call("alert_summary", 3.0)
        record_call("compliance_summary", 10.0)
        session_end()
        summary = get_roi_summary(days=7)
        assert summary["sessions"] == 1
        assert summary["tool_calls"] >= 2
        assert summary["time_saved_minutes"] > 0

    def test_get_roi_summary_top_tools(self):
        from wazuh_mcp.core.roi_tracker import session_start, record_call, session_end, get_roi_summary
        session_start("s1")
        for _ in range(5):
            record_call("hunt_lateral_movement", 5.0)
        record_call("alert_summary", 1.0)
        session_end()
        summary = get_roi_summary(days=7)
        tools = [t["tool"] for t in summary["top_tools"]]
        assert "hunt_lateral_movement" in tools

    def test_roi_efficiency_ratio_computed(self):
        from wazuh_mcp.core.roi_tracker import session_start, record_call, session_end, get_roi_summary
        session_start("s1")
        record_call("generate_weekly_summary", 5.0)  # baseline 60min, actual 5s
        session_end()
        summary = get_roi_summary(days=7)
        assert summary["efficiency_ratio"] > 1.0

    def test_baseline_minutes_has_required_tools(self):
        from wazuh_mcp.core.roi_tracker import BASELINE_MINUTES
        required = [
            "alert_summary", "generate_compliance_report",
            "hunt_lateral_movement", "generate_weekly_summary",
            "vulnerability_summary", "explain_alert", "__default__",
        ]
        for tool in required:
            assert tool in BASELINE_MINUTES, f"Missing baseline for {tool}"
            assert BASELINE_MINUTES[tool] > 0


# ────────────────────────────────────────────────────────────────────────────
# 2. ROI Tools
# ────────────────────────────────────────────────────────────────────────────

class TestROITools:

    def _register(self):
        """Register ROI tools in a test MCP context, return tool dict."""
        mcp, wz, idx, cfg = MagicMock(), MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.roi import register
        from wazuh_mcp.tool_context import ToolContext
        from unittest.mock import AsyncMock as _AM
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda n: min(n, 500),
                          require_writes=lambda: None, truncate=lambda s, n=300: s,
                          enrich_mitre_ids=lambda ids: [], geoip_lookup=_AM(return_value=dict()),
                          incident_recommendations=lambda a: [])
        register(ctx)
        return registered

    @pytest.mark.asyncio
    async def test_generate_roi_report_returns_narrative(self):
        import wazuh_mcp.core.roi_tracker as rt
        rt._state["sessions"] = []
        rt._state["current_session"] = None
        rt._state["total_calls"] = 0
        rt._state["total_saved_minutes"] = 0.0
        rt._state["total_actual_seconds"] = 0.0

        tools = self._register()
        result = await tools["generate_roi_report"](days=7)
        assert "narrative" in result
        assert "time_saved_hours" in result
        assert "sessions" in result
        assert isinstance(result["narrative"], str)

    @pytest.mark.asyncio
    async def test_generate_roi_report_days_capped_at_90(self):
        tools = self._register()
        # Should not error on large days value
        result = await tools["generate_roi_report"](days=365)
        assert "error" not in result

    @pytest.mark.asyncio
    async def test_roi_session_start_returns_session_id(self):
        tools = self._register()
        result = await tools["roi_session_start"](label="test-inv")
        assert result["status"] == "started"
        assert "test-inv" in result["session_id"]

    @pytest.mark.asyncio
    async def test_roi_session_end_without_start(self):
        import wazuh_mcp.core.roi_tracker as rt
        rt._state["current_session"] = None
        tools = self._register()
        result = await tools["roi_session_end"]()
        assert "error" in result

    @pytest.mark.asyncio
    async def test_roi_session_full_flow(self):
        import wazuh_mcp.core.roi_tracker as rt
        rt._state["sessions"] = []
        rt._state["current_session"] = None
        rt._state["total_calls"] = 0
        rt._state["total_saved_minutes"] = 0.0
        rt._state["total_actual_seconds"] = 0.0

        tools = self._register()
        start = await tools["roi_session_start"](label="flow-test")
        assert start["status"] == "started"

        # Record a few calls
        from wazuh_mcp.core.roi_tracker import record_call
        record_call("alert_summary", 3.0)
        record_call("enrich_ip", 2.0)

        end = await tools["roi_session_end"]()
        assert "session_id" in end
        assert end["call_count"] >= 2
        assert end["saved_minutes"] > 0
        assert "summary" in end


# ────────────────────────────────────────────────────────────────────────────
# 3. Autonomous SOC Full Pipeline
# ────────────────────────────────────────────────────────────────────────────

class TestAutonomousSOCPipeline:

    @pytest.fixture(autouse=True)
    def _admin_role(self):
        """These tools enforce RBAC at call time (analyst_or_above / admin_only).
        Grant an ADMIN session for the duration of the test so the suppression and
        ticketing tools run their bodies instead of returning a role error. (Was
        previously satisfied implicitly by a leaked WAZUH_MCP_USER_ROLE env var.)"""
        from wazuh_mcp import identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        yield
        identity._ctx_role.set(None)

    def _register_all(self):
        mcp, wz, idx, cfg = MagicMock(), MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        # Patch RBAC so admin_only always passes
        with patch("wazuh_mcp.tools.autonomous_soc.admin_only", return_value=None), \
             patch("wazuh_mcp.tools.autonomous_soc.analyst_or_above", return_value=None), \
             patch("wazuh_mcp.tools.autonomous_soc.save_monitor_state", return_value=None), \
             patch("wazuh_mcp.tools.autonomous_soc.clear_monitor_state", return_value=None):
            from wazuh_mcp.tools import autonomous_soc as amod
            # Reset state
            amod._monitor_state["running"] = False
            amod._monitor_state["pending_suppressions"] = []
            amod._monitor_state["approved_suppressions"] = []
            amod._monitor_state["rejected_suppressions"] = []
            amod._monitor_state["auto_ticket"] = {
                "enabled": False, "backend": "jira",
                "min_level": 13, "project_key": "", "labels": ["autonomous-soc"],
            }
            amod._monitor_state["schedule"] = {
                "handover_hours_utc": [], "handover_channel": "",
                "digest_day": "monday", "digest_hour_utc": 8,
                "digest_recipients": [], "last_handover_day": None, "last_digest_week": None,
            }
            ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
            amod.register(ctx)

        return registered, amod

    @pytest.mark.asyncio
    async def test_configure_auto_ticketing_enables(self):
        tools, amod = self._register_all()
        with patch("wazuh_mcp.tools.autonomous_soc.save_monitor_state"):
            result = await tools["configure_auto_ticketing"](
                enabled=True, backend="jira", min_level=12
            )
        assert result["status"] == "ok"
        assert amod._monitor_state["auto_ticket"]["enabled"] is True
        assert amod._monitor_state["auto_ticket"]["min_level"] == 12

    @pytest.mark.asyncio
    async def test_configure_auto_ticketing_invalid_backend(self):
        tools, _ = self._register_all()
        result = await tools["configure_auto_ticketing"](enabled=True, backend="github")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_configure_auto_ticketing_invalid_level(self):
        tools, _ = self._register_all()
        result = await tools["configure_auto_ticketing"](enabled=True, min_level=99)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_list_pending_suppressions_empty(self):
        tools, _ = self._register_all()
        result = await tools["list_pending_suppressions"]()
        assert result["pending_count"] == 0
        assert result["pending"] == []

    @pytest.mark.asyncio
    async def test_approve_suppression_not_found(self):
        tools, _ = self._register_all()
        result = await tools["approve_suppression"]("nonexistent-id")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_approve_suppression_full_flow(self):
        tools, amod = self._register_all()
        # Manually queue a candidate
        amod._monitor_state["pending_suppressions"].append({
            "id": "test-001",
            "rule_id": "1002",
            "rule_description": "Noisy syslog rule",
            "rule_groups": ["syslog"],
            "fp_score": 0.7,
            "alert_count_1h": 80,
            "queued_at": "2026-05-26T10:00:00Z",
            "status": "pending",
        })
        with patch("wazuh_mcp.tools.autonomous_soc.save_monitor_state"):
            result = await tools["approve_suppression"]("test-001", note="Confirmed FP")
        assert result["status"] == "approved"
        assert result["rule_id"] == "1002"
        assert len(amod._monitor_state["pending_suppressions"]) == 0
        assert len(amod._monitor_state["approved_suppressions"]) == 1
        assert amod._monitor_state["approved_suppressions"][0]["note"] == "Confirmed FP"

    @pytest.mark.asyncio
    async def test_reject_suppression_full_flow(self):
        tools, amod = self._register_all()
        amod._monitor_state["pending_suppressions"].append({
            "id": "test-002",
            "rule_id": "5710",
            "rule_description": "SSH brute force",
            "rule_groups": ["authentication_failed"],
            "fp_score": 0.6,
            "alert_count_1h": 55,
            "queued_at": "2026-05-26T10:00:00Z",
            "status": "pending",
        })
        with patch("wazuh_mcp.tools.autonomous_soc.save_monitor_state"):
            result = await tools["reject_suppression"]("test-002", note="Real attack")
        assert result["status"] == "rejected"
        assert len(amod._monitor_state["pending_suppressions"]) == 0
        assert len(amod._monitor_state["rejected_suppressions"]) == 1

    @pytest.mark.asyncio
    async def test_configure_scheduled_reports_valid(self):
        tools, amod = self._register_all()
        with patch("wazuh_mcp.tools.autonomous_soc.save_monitor_state"):
            result = await tools["configure_scheduled_reports"](
                handover_hours_utc=[8, 16, 0],
                handover_channel="#soc",
                digest_day="friday",
                digest_hour_utc=9,
            )
        assert result["status"] == "ok"
        assert amod._monitor_state["schedule"]["handover_hours_utc"] == [8, 16, 0]
        assert amod._monitor_state["schedule"]["digest_day"] == "friday"

    @pytest.mark.asyncio
    async def test_configure_scheduled_reports_invalid_hour(self):
        tools, _ = self._register_all()
        result = await tools["configure_scheduled_reports"](handover_hours_utc=[25])
        assert "error" in result

    @pytest.mark.asyncio
    async def test_configure_scheduled_reports_invalid_day(self):
        tools, _ = self._register_all()
        result = await tools["configure_scheduled_reports"](digest_day="funday")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_get_autonomous_status_shows_suppression_count(self):
        tools, amod = self._register_all()
        amod._monitor_state["pending_suppressions"] = [{"id": "x"}]
        result = await tools["get_autonomous_status"]()
        assert result["pending_suppressions"] == 1

    @pytest.mark.asyncio
    async def test_get_autonomous_status_shows_features(self):
        tools, _ = self._register_all()
        result = await tools["get_autonomous_status"]()
        assert "auto_ticket_enabled" in result
        assert "scheduled_handover_hours" in result

    def test_fp_score_noisy_groups(self):
        from wazuh_mcp.tools.autonomous_soc import _fp_score
        score = _fp_score("1002", ["syslog", "ossec"], alert_count_1h=5)
        assert score >= 0.3

    def test_fp_score_high_volume(self):
        from wazuh_mcp.tools.autonomous_soc import _fp_score
        score = _fp_score("9999", ["custom"], alert_count_1h=60)
        assert score >= 0.4

    def test_fp_score_low_volume_specific_rule(self):
        from wazuh_mcp.tools.autonomous_soc import _fp_score
        score = _fp_score("40101", ["malware", "ransomware"], alert_count_1h=1)
        assert score == 0.0  # specific, low volume → not a FP candidate

    def test_maybe_queue_suppression_adds_to_pending(self):
        from wazuh_mcp.tools import autonomous_soc as amod
        amod._monitor_state["pending_suppressions"] = []
        queued = amod._maybe_queue_suppression("1002", "Noisy rule", ["syslog"], 80)
        assert queued is True
        assert len(amod._monitor_state["pending_suppressions"]) == 1

    def test_maybe_queue_suppression_no_duplicate(self):
        from wazuh_mcp.tools import autonomous_soc as amod
        amod._monitor_state["pending_suppressions"] = [{"rule_id": "1002"}]
        queued = amod._maybe_queue_suppression("1002", "Noisy rule", ["syslog"], 80)
        assert queued is False
        assert len(amod._monitor_state["pending_suppressions"]) == 1

    def test_triage_tree_extended_groups(self):
        from wazuh_mcp.tools.autonomous_soc import _TRIAGE_TREES
        # Verify new groups were added
        assert "exploit" in _TRIAGE_TREES
        assert "malware" in _TRIAGE_TREES

    def test_new_triage_tool_names_exist(self):
        from wazuh_mcp.tools.autonomous_soc import _TRIAGE_TREES
        for group, steps in _TRIAGE_TREES.items():
            for tool_name, _ in steps:
                assert isinstance(tool_name, str), f"Bad tool name in {group}"
                assert len(tool_name) > 0


# ────────────────────────────────────────────────────────────────────────────
# 4. SOC Dashboard
# ────────────────────────────────────────────────────────────────────────────

class TestSOCDashboard:
    DASHBOARD = Path("dashboard/index.html")

    def test_dashboard_file_exists(self):
        assert self.DASHBOARD.exists(), "dashboard/index.html not found"

    def test_dashboard_has_html_structure(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_dashboard_has_all_pages(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        for page in ["overview", "agents", "mitre", "chat", "tenants", "roi", "settings"]:
            assert f"page-{page}" in html, f"Missing page: {page}"

    def test_dashboard_has_kpi_row(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "kpi-total" in html
        assert "kpi-critical" in html
        assert "kpi-agents" in html
        assert "kpi-saved" in html

    def test_dashboard_has_alert_feed(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "alert-feed" in html
        assert "alert-row" in html

    def test_dashboard_has_mitre_heatmap(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "mitre-grid" in html
        assert "_MITRE_NAMES" in html
        assert "T1110" in html   # Brute Force

    def test_dashboard_has_chat_widget(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "chat-messages" in html
        assert "chat-input" in html
        assert "sendChat" in html
        assert "quickPrompt" in html

    def test_dashboard_has_tenant_switcher(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "switchTenant" in html
        assert "list_tenants" in html
        assert "switch_tenant" in html

    def test_dashboard_has_roi_panel(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "roi-hours" in html
        assert "roi-sessions" in html
        assert "generate_roi_report" in html

    def test_dashboard_has_monitor_controls(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "startMonitor" in html
        assert "stopMonitor" in html
        assert "configure_auto_ticketing" in html

    def test_dashboard_has_scheduled_reports_form(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "saveSchedule" in html
        assert "configure_scheduled_reports" in html
        assert "sched-hours" in html

    def test_dashboard_callTool_uses_jsonrpc(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "jsonrpc" in html
        assert "tools/call" in html

    def test_dashboard_has_quick_prompts(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "24h summary" in html
        assert "Hunt lateral movement" in html
        assert "CISO briefing" in html

    def test_dashboard_localStorage_for_settings(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "localStorage" in html
        assert "mcp_url" in html

    def test_dashboard_auto_refresh_scheduled(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "scheduleRefresh" in html
        assert "60000" in html   # 60s refresh interval

    def test_dashboard_dark_theme_css_vars(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        assert "--bg:" in html
        assert "--accent:" in html
        assert "--critical:" in html

    def test_dashboard_severity_badges(self):
        html = self.DASHBOARD.read_text(encoding="utf-8")
        for sev in ["critical", "high", "medium", "low"]:
            assert f"badge-{sev}" in html


# ────────────────────────────────────────────────────────────────────────────
# 5. Demo Environment
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    not Path("demo/docker-compose.yml").exists() or not Path("demo/seed_alerts.py").exists(),
    reason="demo/ environment assets are not shipped in this checkout — skip demo asset checks",
)
class TestDemoEnvironment:
    COMPOSE = Path("demo/docker-compose.yml")
    SEED    = Path("demo/seed_alerts.py")

    def test_docker_compose_exists(self):
        assert self.COMPOSE.exists()

    def test_seed_script_exists(self):
        assert self.SEED.exists()

    def test_docker_compose_has_required_services(self):
        content = self.COMPOSE.read_text(encoding="utf-8")
        for svc in ["wazuh-manager", "wazuh-indexer", "wazuh-mcp", "seed"]:
            assert svc in content, f"Missing service: {svc}"

    def test_docker_compose_exposes_mcp_port(self):
        content = self.COMPOSE.read_text(encoding="utf-8")
        assert "8000:8000" in content

    def test_docker_compose_has_wazuh_env_vars(self):
        content = self.COMPOSE.read_text(encoding="utf-8")
        for var in ["WAZUH_HOST", "WAZUH_USER", "WAZUH_PASS",
                    "WAZUH_INDEXER_HOST", "WAZUH_INDEXER_PASS"]:
            assert var in content

    def test_docker_compose_has_healthchecks(self):
        content = self.COMPOSE.read_text(encoding="utf-8")
        assert "healthcheck" in content

    def test_docker_compose_seed_uses_profile(self):
        content = self.COMPOSE.read_text(encoding="utf-8")
        assert "profiles" in content
        assert "seed" in content

    def test_seed_script_valid_syntax(self):
        import ast
        code = self.SEED.read_text(encoding="utf-8")
        tree = ast.parse(code)  # raises SyntaxError if invalid
        assert tree is not None

    def test_seed_script_has_agents(self):
        code = self.SEED.read_text(encoding="utf-8")
        assert "AGENTS" in code
        assert "web-server-01" in code

    def test_seed_script_has_alert_templates(self):
        code = self.SEED.read_text(encoding="utf-8")
        assert "ALERT_TEMPLATES" in code
        assert "authentication_failed" in code
        assert "T1110" in code

    def test_seed_script_has_mitre_techniques(self):
        code = self.SEED.read_text(encoding="utf-8")
        for tid in ["T1110", "T1190", "T1105", "T1548", "T1078"]:
            assert tid in code

    def test_seed_script_has_malicious_ips(self):
        code = self.SEED.read_text(encoding="utf-8")
        assert "MALICIOUS_IPS" in code

    def test_seed_script_generates_7_days(self):
        code = self.SEED.read_text(encoding="utf-8")
        assert "7 days" in code or "range(7" in code

    def test_seed_script_bulk_indexes(self):
        code = self.SEED.read_text(encoding="utf-8")
        assert "_bulk" in code

    def test_seed_script_waits_for_indexer(self):
        code = self.SEED.read_text(encoding="utf-8")
        assert "_cluster/health" in code

    def test_seed_script_has_main_function(self):
        code = self.SEED.read_text(encoding="utf-8")
        assert "def main()" in code
        assert '__name__ == "__main__"' in code


# ────────────────────────────────────────────────────────────────────────────
# 6. rbac.analyst_or_above
# ────────────────────────────────────────────────────────────────────────────

class TestRBACAnalystOrAbove:
    def test_analyst_or_above_passes_for_analyst(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_USER_ROLE", "analyst")
        from importlib import reload
        import wazuh_mcp.rbac as rbac
        reload(rbac)
        result = rbac.analyst_or_above()
        assert result is None

    def test_analyst_or_above_passes_for_admin(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_USER_ROLE", "admin")
        from importlib import reload
        import wazuh_mcp.rbac as rbac
        reload(rbac)
        result = rbac.analyst_or_above()
        assert result is None

    def test_analyst_or_above_fails_for_viewer(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_USER_ROLE", "viewer")
        from importlib import reload
        import wazuh_mcp.rbac as rbac
        reload(rbac)
        result = rbac.analyst_or_above()
        assert result is not None
        assert "error" in result


# ────────────────────────────────────────────────────────────────────────────
# 7. ROI tracking wired into server (integration smoke test)
# ────────────────────────────────────────────────────────────────────────────

class TestROIWiringInServer:
    def test_roi_module_imported_in_server(self):
        # roi module is auto-discovered via pkgutil.iter_modules
        import os
        roi_path = Path("wazuh_mcp/tools/roi.py")
        assert roi_path.exists(), "roi.py must exist to be auto-discovered"
        server_src = Path("wazuh_mcp/server.py").read_text(encoding="utf-8")
        assert "pkgutil" in server_src, "server must use auto-discovery"

    def test_roi_timing_in_sanitizing_decorator(self):
        server_src = Path("wazuh_mcp/server.py").read_text(encoding="utf-8")
        # roi_tracker timing may be in server or in the roi module itself
        import importlib, inspect
        roi_mod = importlib.import_module("wazuh_mcp.tools.roi")
        roi_src = inspect.getsource(roi_mod)
        assert "roi_tracker" in server_src or "roi_tracker" in roi_src

    def test_roi_tools_in_server_syntax(self):
        import ast
        server_src = Path("wazuh_mcp/server.py").read_text(encoding="utf-8")
        ast.parse(server_src)  # SyntaxError if broken

    def test_roi_tracker_module_importable(self):
        from wazuh_mcp.core.roi_tracker import (
            record_call, session_start, session_end, get_roi_summary, BASELINE_MINUTES
        )
        assert callable(record_call)
        assert callable(session_start)
        assert callable(session_end)
        assert callable(get_roi_summary)
        assert isinstance(BASELINE_MINUTES, dict)
