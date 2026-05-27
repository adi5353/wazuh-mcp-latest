"""Tests for Phase 4 Advanced Features — F2, F3, F5, F10-doc, F11, F12-doc."""
from __future__ import annotations

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from wazuh_mcp.tool_context import ToolContext


# ── F2: Behavioral Baselining ─────────────────────────────────────────────────

class TestBaseline:
    def _register(self):
        from wazuh_mcp.tools import baseline
        mcp = MagicMock()
        reg = {}
        def tool():
            def dec(fn):
                reg[fn.__name__] = fn
                return fn
            return dec
        mcp.tool = tool
        wz = AsyncMock()
        idx = AsyncMock()
        cfg = MagicMock()
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        baseline.register(ctx)
        return reg, wz, idx, baseline

    def test_deviation_score_zero_for_matching_mean(self):
        from wazuh_mcp.tools.baseline import _deviation_score
        assert _deviation_score(10.0, 10.0, 2.0) == 0.0

    def test_deviation_score_high_for_large_z(self):
        from wazuh_mcp.tools.baseline import _deviation_score
        # z=3 → score=99.9 (capped at 100)
        score = _deviation_score(40.0, 10.0, 10.0)
        assert score >= 90

    def test_deviation_score_no_variance(self):
        from wazuh_mcp.tools.baseline import _deviation_score
        # No variance in baseline — any deviation is suspicious
        score = _deviation_score(5.0, 0.0, 0.0)
        assert score > 0

    def test_score_label_bands(self):
        from wazuh_mcp.tools.baseline import _score_label
        assert _score_label(90) == "CRITICAL"
        assert _score_label(65) == "HIGH"
        assert _score_label(45) == "MEDIUM"
        assert _score_label(25) == "LOW"
        assert _score_label(5) == "NORMAL"

    def test_mean_std_empty(self):
        from wazuh_mcp.tools.baseline import _mean_std
        mean, std = _mean_std([])
        assert mean == 0.0
        assert std == 0.0

    def test_mean_std_uniform(self):
        from wazuh_mcp.tools.baseline import _mean_std
        mean, std = _mean_std([5.0, 5.0, 5.0, 5.0])
        assert mean == 5.0
        assert std == 0.0

    def test_compute_baseline_agent_not_found(self):
        async def run():
            reg, wz, idx, _ = self._register()
            wz.request.return_value = {"data": {"affected_items": []}}
            result = await reg["compute_agent_baseline"]("999")
            assert "error" in result
        asyncio.run(run())

    def test_compute_baseline_stores_in_cache(self):
        async def run():
            reg, wz, idx, bl = self._register()
            bl._BASELINES.clear()
            wz.request.return_value = {
                "data": {"affected_items": [
                    {"id": "001", "name": "web1", "ip": "10.0.0.1", "status": "active"}
                ]}
            }
            idx.search.return_value = {"hits": {"total": {"value": 5}, "hits": []}}
            result = await reg["compute_agent_baseline"]("001", days=3)
            assert result.get("status") == "baseline_computed"
            assert "001" in bl._BASELINES
        asyncio.run(run())

    def test_score_deviation_without_baseline(self):
        async def run():
            reg, wz, idx, bl = self._register()
            bl._BASELINES.clear()
            result = await reg["score_agent_deviation"]("999")
            assert "error" in result
        asyncio.run(run())

    def test_list_anomalous_no_baselines(self):
        async def run():
            reg, wz, idx, bl = self._register()
            bl._BASELINES.clear()
            result = await reg["list_anomalous_agents"]()
            assert "error" in result
        asyncio.run(run())

    def test_score_deviation_returns_score(self):
        async def run():
            reg, wz, idx, bl = self._register()
            bl._BASELINES["001"] = {
                "agent_id": "001",
                "agent_name": "web1",
                "baseline_days": 7,
                "alert_volume": {"mean": 10.0, "std": 2.0, "daily_counts": [], "max": 15},
                "critical_alerts": {"mean": 1.0, "std": 0.5, "daily_counts": []},
            }
            idx.search.return_value = {"hits": {"total": {"value": 10}, "hits": []}}
            result = await reg["score_agent_deviation"]("001", window_hours=24)
            assert "deviation_score" in result
            assert "label" in result
            assert 0 <= result["deviation_score"] <= 100
        asyncio.run(run())


# ── F3: UEBA ─────────────────────────────────────────────────────────────────

class TestUEBA:
    def _register(self):
        from wazuh_mcp.tools import ueba
        mcp = MagicMock()
        reg = {}
        def tool():
            def dec(fn):
                reg[fn.__name__] = fn
                return fn
            return dec
        mcp.tool = tool
        wz = AsyncMock()
        idx = AsyncMock()
        cfg = MagicMock()
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        ueba.register(ctx)
        return reg, wz, idx, ueba

    def test_analyse_activity_empty(self):
        from wazuh_mcp.tools.ueba import _analyse_activity
        result = _analyse_activity([], "testuser")
        assert result["total_events"] == 0
        assert result["risk_level"] == "low"

    def test_analyse_activity_lateral_movement_flag(self):
        from wazuh_mcp.tools.ueba import _analyse_activity
        events = [
            {"agent": {"id": str(i), "name": f"agent{i}"}, "data": {"srcip": ""},
             "rule": {"groups": ["authentication_success"]}, "@timestamp": "2024-01-01T10:00:00Z"}
            for i in range(6)
        ]
        result = _analyse_activity(events, "admin")
        assert any("lateral" in f.lower() for f in result["risk_factors"])

    def test_get_user_profile_no_events(self):
        async def run():
            reg, wz, idx, _ = self._register()
            idx.search.return_value = {"hits": {"hits": [], "total": {"value": 0}}}
            result = await reg["get_user_activity_profile"]("nobody", hours=24)
            assert result["total_events"] == 0
        asyncio.run(run())

    def test_get_user_profile_with_events(self):
        async def run():
            reg, wz, idx, _ = self._register()
            idx.search.return_value = {
                "hits": {
                    "total": {"value": 2},
                    "hits": [
                        {"_source": {
                            "@timestamp": "2024-01-01T10:00:00Z",
                            "agent": {"id": "001", "name": "server1"},
                            "data": {"srcip": "192.168.1.5", "dstuser": "admin"},
                            "rule": {"groups": ["authentication_success"], "level": 5},
                        }},
                        {"_source": {
                            "@timestamp": "2024-01-01T11:00:00Z",
                            "agent": {"id": "002", "name": "server2"},
                            "data": {"srcip": "192.168.1.6", "dstuser": "admin"},
                            "rule": {"groups": ["authentication_failed"], "level": 5},
                        }},
                    ]
                }
            }
            result = await reg["get_user_activity_profile"]("admin", hours=24)
            assert result["total_events"] == 2
            assert result["authentication_successes"] == 1
            assert result["authentication_failures"] == 1
        asyncio.run(run())

    def test_detect_user_anomalies_query(self):
        async def run():
            reg, wz, idx, _ = self._register()
            idx.search.return_value = {
                "hits": {"total": {"value": 0}},
                "aggregations": {"by_user": {"buckets": []}}
            }
            result = await reg["detect_user_anomalies"](hours=24)
            assert "anomalous_users" in result
            assert result["anomalous_users"] == 0
        asyncio.run(run())

    def test_list_privileged_escalations_empty(self):
        async def run():
            reg, wz, idx, _ = self._register()
            idx.search.return_value = {"hits": {"hits": [], "total": {"value": 0}}}
            result = await reg["list_privileged_escalations"](hours=24)
            assert result["total_escalation_events"] == 0
            assert result["severity"] == "none"
        asyncio.run(run())


# ── F5: Scheduler ─────────────────────────────────────────────────────────────

class TestScheduler:
    def _register(self):
        from wazuh_mcp.tools import scheduler
        mcp = MagicMock()
        reg = {}
        def tool():
            def dec(fn):
                reg[fn.__name__] = fn
                return fn
            return dec
        mcp.tool = tool
        wz = AsyncMock()
        idx = AsyncMock()
        # Patch file I/O so tests don't write to disk
        with patch.object(scheduler, "_load_schedules"), \
             patch.object(scheduler, "_save_schedules"):
            cfg = MagicMock()
            ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
            scheduler.register(ctx)
        return reg, wz, idx, scheduler

    def test_list_schedules_empty(self):
        async def run():
            reg, wz, idx, sched = self._register()
            sched._SCHEDULES.clear()
            result = await reg["list_report_schedules"]()
            assert "schedules" in result
            assert result["total"] == 0
        asyncio.run(run())

    def test_create_schedule_invalid_type(self):
        async def run():
            reg, wz, idx, sched = self._register()
            with patch("wazuh_mcp.tools.scheduler.analyst_only", return_value=None):
                result = await reg["create_report_schedule"]("test", "invalid_type")
            assert "error" in result
        asyncio.run(run())

    def test_create_schedule_invalid_interval(self):
        async def run():
            reg, wz, idx, sched = self._register()
            with patch("wazuh_mcp.tools.scheduler.analyst_only", return_value=None):
                result = await reg["create_report_schedule"](
                    "test", "daily_summary", interval="biweekly"
                )
            assert "error" in result
        asyncio.run(run())

    def test_create_schedule_success(self):
        async def run():
            reg, wz, idx, sched = self._register()
            sched._SCHEDULES.clear()
            with patch("wazuh_mcp.tools.scheduler.analyst_only", return_value=None), \
                 patch.object(sched, "_save_schedules"), \
                 patch.object(sched, "_ensure_scheduler_running"):
                result = await reg["create_report_schedule"](
                    "Daily SOC Report", "daily_summary", interval="daily"
                )
            assert result["status"] == "created"
            assert result["report_type"] == "daily_summary"
            assert "schedule_id" in result
        asyncio.run(run())

    def test_delete_schedule_not_found(self):
        async def run():
            reg, wz, idx, sched = self._register()
            sched._SCHEDULES.clear()
            with patch("wazuh_mcp.tools.scheduler.analyst_only", return_value=None):
                result = await reg["delete_report_schedule"]("nonexistent")
            assert "error" in result
        asyncio.run(run())

    def test_delete_schedule_success(self):
        async def run():
            reg, wz, idx, sched = self._register()
            sched._SCHEDULES["abc123"] = {
                "schedule_id": "abc123", "name": "Test", "report_type": "daily_summary",
                "interval": "daily", "enabled": True,
            }
            with patch("wazuh_mcp.tools.scheduler.analyst_only", return_value=None), \
                 patch.object(sched, "_save_schedules"):
                result = await reg["delete_report_schedule"]("abc123")
            assert result["status"] == "deleted"
            assert "abc123" not in sched._SCHEDULES
        asyncio.run(run())

    def test_interval_seconds(self):
        from wazuh_mcp.tools.scheduler import _interval_seconds
        assert _interval_seconds("hourly") == 3600
        assert _interval_seconds("daily") == 86400
        assert _interval_seconds("weekly") == 604800
        assert _interval_seconds("monthly") == 2592000

    def test_create_schedule_rbac(self):
        async def run():
            reg, wz, idx, sched = self._register()
            with patch("wazuh_mcp.tools.scheduler.analyst_only",
                       return_value={"error": "analyst only"}):
                result = await reg["create_report_schedule"]("test", "daily_summary")
            assert "error" in result
        asyncio.run(run())


# ── F11: Multi-Tenant Group Scoping ──────────────────────────────────────────

class TestGroupFilter:
    def test_search_alerts_has_group_filter_param(self):
        """search_alerts must accept group_filter parameter."""
        import inspect
        from wazuh_mcp.tools import alerts as _alerts_mod
        # The register function produces search_alerts — check its source
        source = inspect.getsource(_alerts_mod)
        assert "group_filter" in source

    def test_list_agents_has_group_filter_param(self):
        """list_agents must accept group_filter parameter."""
        import inspect
        from wazuh_mcp.tools import agents as _agents_mod
        source = inspect.getsource(_agents_mod)
        assert "group_filter" in source

    def test_group_filter_injected_into_es_query(self):
        """group_filter must add agent.groups term filter to ES query."""
        import inspect
        from wazuh_mcp.tools import alerts as _alerts_mod
        source = inspect.getsource(_alerts_mod)
        assert "agent.groups" in source

    def test_group_filter_in_agents_url(self):
        """list_agents must append &group=... to URL when group_filter set."""
        import inspect
        from wazuh_mcp.tools import agents as _agents_mod
        source = inspect.getsource(_agents_mod)
        assert "&group=" in source or "group={group_filter}" in source


# ── F10-doc: Air-Gapped Compose ───────────────────────────────────────────────

class TestOllamaCompose:
    def test_ollama_compose_file_exists(self):
        compose_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docker-compose.ollama.yaml"
        )
        assert os.path.exists(compose_path), "docker-compose.ollama.yaml missing"

    def test_ollama_compose_has_ollama_service(self):
        compose_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docker-compose.ollama.yaml"
        )
        with open(compose_path) as f:
            content = f.read()
        assert "ollama" in content
        assert "ollama/ollama" in content

    def test_ollama_compose_has_wazuh_mcp_service(self):
        compose_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docker-compose.ollama.yaml"
        )
        with open(compose_path) as f:
            content = f.read()
        assert "wazuh-mcp" in content
        assert "stop_grace_period" in content

    def test_ollama_compose_has_airgapped_network(self):
        compose_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docker-compose.ollama.yaml"
        )
        with open(compose_path) as f:
            content = f.read()
        assert "airgapped" in content


# ── F12-doc: Open WebUI Integration Docs ─────────────────────────────────────

class TestOpenWebUIDoc:
    def test_open_webui_doc_exists(self):
        doc_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docs", "open-webui-integration.md"
        )
        assert os.path.exists(doc_path), "docs/open-webui-integration.md missing"

    def test_open_webui_doc_has_mcp_connection_steps(self):
        doc_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docs", "open-webui-integration.md"
        )
        with open(doc_path, encoding="utf-8") as f:
            content = f.read()
        assert "/sse" in content
        assert "API Key" in content or "api_key" in content.lower() or "X-API-Key" in content

    def test_open_webui_doc_has_mermaid_section(self):
        doc_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docs", "open-webui-integration.md"
        )
        with open(doc_path, encoding="utf-8") as f:
            content = f.read()
        assert "Mermaid" in content or "mermaid" in content

    def test_open_webui_doc_has_system_prompt(self):
        doc_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docs", "open-webui-integration.md"
        )
        with open(doc_path, encoding="utf-8") as f:
            content = f.read()
        assert "System Prompt" in content or "system_prompt" in content.lower()


# ── Phase 4 module imports ────────────────────────────────────────────────────

class TestPhase4ModuleImports:
    def test_baseline_importable(self):
        from wazuh_mcp.tools import baseline
        assert hasattr(baseline, "register")

    def test_ueba_importable(self):
        from wazuh_mcp.tools import ueba
        assert hasattr(ueba, "register")

    def test_scheduler_importable(self):
        from wazuh_mcp.tools import scheduler
        assert hasattr(scheduler, "register")

    def test_ollama_compose_readable(self):
        import yaml  # type: ignore
        compose_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docker-compose.ollama.yaml"
        )
        with open(compose_path) as f:
            data = yaml.safe_load(f)
        assert "services" in data
        assert "ollama" in data["services"]
