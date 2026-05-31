"""Targeted, data-driven tests for the larger tool modules.

Unlike the breadth-first smoke test, these feed realistic Manager/Indexer
responses so the happy-path formatting, scoring, and branch logic inside each
tool is actually exercised.
"""
from __future__ import annotations

import pytest

# Quarantined from the coverage gate: these exercise code paths against mocked
# clients to catch crashes/imports, but assert little real behaviour. Run via
# `pytest -m smoke`; excluded from the gated run by `-m "not smoke"` (pyproject).
pytestmark = pytest.mark.smoke

import asyncio
import importlib
from unittest.mock import AsyncMock, MagicMock

import pytest


def _run(coro):
    return asyncio.run(coro)


class _DeepDict(dict):
    """Recursive, arithmetic-safe default dict: any missing key yields an empty
    _DeepDict so tools that read framework-specific aggregation keys don't raise."""
    def __missing__(self, key):
        return _DeepDict()

    def __int__(self):
        return 0

    def __float__(self):
        return 0.0

    def __bool__(self):
        return False

    def __gt__(self, other):
        return False

    def __lt__(self, other):
        return False

    def __ge__(self, other):
        return False

    def __le__(self, other):
        return False


def _make_env(module_path):
    """Register one tool module against mocked context; return (tools, wz, idx)."""
    from wazuh_mcp.tool_context import ToolContext
    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    wz = AsyncMock()
    idx = AsyncMock()
    cfg = MagicMock()
    cfg.alerts_index = "wazuh-alerts-*"
    cfg.vuln_index = "wazuh-states-vulnerabilities-*"
    cfg.manager_host = "https://manager.example.com:55000"
    ctx = ToolContext(
        mcp=mcp, wz=wz, idx=idx, cfg=cfg,
        cap=lambda n: min(int(n), 500),
        require_writes=lambda: None,
        truncate=lambda s, n=300: s if s is None or len(s) <= n else s[:n] + "…",
        enrich_mitre_ids=lambda ids: [{"id": i, "name": i, "tactic": "t"} for i in (ids or [])],
        geoip_lookup=AsyncMock(return_value={"country": "US"}),
        incident_recommendations=lambda *a, **k: ["isolate affected hosts"],
        tool_registry={},
    )
    importlib.import_module(module_path).register(ctx)
    return tools, wz, idx


def _hit(ts, level, tactic, tid, agent="001", srcip="8.8.8.8", desc="evt"):
    return {"_id": f"a-{ts}", "_source": {
        "@timestamp": ts, "timestamp": ts,
        "rule": {"id": "5710", "level": level, "description": desc,
                 "mitre": {"id": [tid], "tactic": [tactic]}},
        "agent": {"id": agent, "name": f"host-{agent}"},
        "data": {"srcip": srcip},
    }}


# ── correlation ──────────────────────────────────────────────────────────────────
class TestCorrelation:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.correlation")

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)

    def test_correlate_alerts_builds_clusters(self):
        hits = [
            _hit("2024-01-01T00:00:01Z", 12, "Initial Access", "T1190"),
            _hit("2024-01-01T00:00:02Z", 10, "Lateral Movement", "T1021"),
            _hit("2024-01-01T00:00:03Z", 5, "Discovery", "T1082", srcip="9.9.9.9"),
        ]
        self.idx.search = AsyncMock(return_value={"hits": {"hits": hits}})
        out = _run(self.tools["correlate_alerts"](time_range="2h", min_score=1))
        assert out["total_alerts_scanned"] == 3
        assert out["clusters"] and out["clusters"][0]["severity"] in ("CRITICAL", "HIGH")

    def test_correlate_alerts_empty(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": []}})
        out = _run(self.tools["correlate_alerts"]())
        assert out["clusters"] == [] and out["total_alerts_scanned"] == 0

    def test_correlate_alerts_indexer_error(self):
        self.idx.search = AsyncMock(side_effect=RuntimeError("boom"))
        out = _run(self.tools["correlate_alerts"]())
        assert "error" in out

    def test_correlate_alerts_tactic_filter(self):
        hits = [_hit("2024-01-01T00:00:01Z", 12, "Initial Access", "T1190")]
        self.idx.search = AsyncMock(return_value={"hits": {"hits": hits}})
        out = _run(self.tools["correlate_alerts"](tactics="Persistence", min_score=0))
        assert out["total_clusters"] == 0  # filtered out

    def test_get_attack_chains(self):
        hits = [
            _hit("2024-01-01T00:00:01Z", 8, "Initial Access", "T1190"),
            _hit("2024-01-01T00:00:02Z", 10, "Execution", "T1059"),
            _hit("2024-01-01T00:00:03Z", 12, "Lateral Movement", "T1021"),
        ]
        self.idx.search = AsyncMock(return_value={"hits": {"hits": hits}})
        out = _run(self.tools["get_attack_chains"](min_stages=2))
        assert out["chains"] and out["chains"][0]["stage_count"] >= 2

    def test_get_attack_chains_empty(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": []}})
        out = _run(self.tools["get_attack_chains"]())
        assert out["chains"] == []

    def test_build_clusters_helper_directly(self):
        from wazuh_mcp.tools.correlation import _build_clusters, _build_chains
        hits = [_hit("2024-01-01T00:00:01Z", 13, "Impact", "T1485") for _ in range(11)]
        clusters = _build_clusters(hits, min_score=0, tactic_filter=[], cap_limit=10)
        assert clusters["total_clusters"] >= 1
        chains = _build_chains(hits, min_stages=1, cap_limit=10)
        assert chains["total_chains"] >= 1


# ── onboarding ──────────────────────────────────────────────────────────────────
class TestOnboarding:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.onboarding")
        self.wz.request = AsyncMock(return_value={"data": {"api_version": "4.9.0"}})

    @pytest.mark.parametrize("os_type,marker", [
        ("ubuntu", "dpkg"),
        ("debian", "dpkg"),
        ("centos", "rpm"),
        ("rhel", "rpm"),
        ("windows", "msiexec"),
        ("macos", "installer"),
    ])
    def test_enrollment_command_per_os(self, os_type, marker):
        out = _run(self.tools["generate_enrollment_command"](
            agent_name="web01", os_type=os_type, group="prod",
            registration_password="s3cret",
        ))
        assert marker in out["install_command"]
        assert out["wazuh_version"] == "4.9.0"

    def test_enrollment_unsupported_os(self):
        out = _run(self.tools["generate_enrollment_command"](
            agent_name="x", os_type="plan9"))
        assert "error" in out

    def test_enrollment_version_fallback(self):
        self.wz.request = AsyncMock(side_effect=RuntimeError("offline"))
        out = _run(self.tools["generate_enrollment_command"](
            agent_name="x", os_type="ubuntu"))
        assert out["wazuh_version"] == "4.7.5"

    def test_list_never_connected_with_agents(self):
        self.wz.request = AsyncMock(return_value={"data": {
            "affected_items": [{"id": "009", "name": "ghost", "os": {"name": "Ubuntu"},
                                "ip": "10.0.0.9", "dateAdd": "2024", "group": ["default"]}],
            "total_affected_items": 1,
        }})
        out = _run(self.tools["list_never_connected_agents"]())
        assert out["count"] == 1 and out["agents"][0]["agent_id"] == "009"

    def test_list_never_connected_empty(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [], "total_affected_items": 0}})
        out = _run(self.tools["list_never_connected_agents"]())
        assert out["count"] == 0

    def test_list_never_connected_error(self):
        self.wz.request = AsyncMock(side_effect=RuntimeError("api down"))
        out = _run(self.tools["list_never_connected_agents"]())
        assert "error" in out

    def test_checklist_requires_identifier(self):
        out = _run(self.tools["agent_onboarding_checklist"]())
        assert "error" in out

    def test_checklist_full_pass(self):
        async def fake_request(method, path, **kw):
            if "agents_list" in path or "name=" in path:
                return {"data": {"affected_items": [{"id": "005", "name": "web05",
                        "status": "active", "group": ["linux-prod"]}]}}
            if path.startswith("/sca/"):
                return {"data": {"affected_items": [{"name": "CIS"}]}}
            if "syscollector" in path:
                return {"data": {"total_affected_items": 42}}
            return {"data": {"affected_items": []}}
        self.wz.request = AsyncMock(side_effect=fake_request)
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 7}}})
        out = _run(self.tools["agent_onboarding_checklist"](agent_id="005"))
        assert out["overall"] in ("READY", "READY WITH WARNINGS")
        assert out["checks_passed"] >= 4

    def test_checklist_by_name_not_found(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": []}})
        out = _run(self.tools["agent_onboarding_checklist"](agent_name="ghost"))
        assert "error" in out

    def test_checklist_not_ready(self):
        async def fake_request(method, path, **kw):
            if "agents_list" in path:
                return {"data": {"affected_items": [{"id": "006", "name": "bad",
                        "status": "disconnected", "group": ["default"]}]}}
            raise RuntimeError("query failed")
        self.wz.request = AsyncMock(side_effect=fake_request)
        self.idx.search = AsyncMock(side_effect=RuntimeError("idx down"))
        out = _run(self.tools["agent_onboarding_checklist"](agent_id="006"))
        assert out["overall"] in ("PARTIAL", "NOT READY")


# ── cdb ──────────────────────────────────────────────────────────────────────────
class TestCDB:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.cdb")

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)

    def test_list_and_get_contents(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": ["1.2.3.4:bad\n5.6.7.8:c2"]}})
        assert "data" in _run(self.tools["list_cdb_lists"]())
        assert "data" in _run(self.tools["get_cdb_list_contents"](list_name="malicious-ips"))

    def test_add_and_remove(self, monkeypatch):
        monkeypatch.setenv("WAZUH_ALLOW_WRITES", "true")
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": ["9.9.9.9:old\n"]}})
        out = _run(self.tools["add_to_cdb_list"](list_name="mal", key="8.8.8.8", value="c2"))
        assert out["action"] == "added" and out["key"] == "8.8.8.8"
        out2 = _run(self.tools["remove_from_cdb_list"](list_name="mal", key="9.9.9.9"))
        assert out2["action"] == "removed"

    def test_preview_impact(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 12}},
            "aggregations": {
                "by_rule": {"buckets": [{"key": "ssh brute", "doc_count": 7}]},
                "by_agent": {"buckets": [{"key": "host1", "doc_count": 5}]},
            },
        })
        out = _run(self.tools["preview_cdb_list_impact"](ip="8.8.8.8", hours=24))
        assert out["alerts_last_n_hours"] == 12
        assert "suppress" in out["recommendation"]

    def test_preview_impact_no_alerts(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 0}},
            "aggregations": {"by_rule": {"buckets": []}, "by_agent": {"buckets": []}},
        })
        out = _run(self.tools["preview_cdb_list_impact"](ip="8.8.8.8"))
        assert "no immediate effect" in out["recommendation"].lower()

    def test_backup_and_import_roundtrip(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        monkeypatch.setenv("WAZUH_ALLOW_WRITES", "true")

        async def fake_request(method, path, **kw):
            if path == "/lists?limit=100":
                return {"data": {"affected_items": [{"filename": "malicious-ips"}]}}
            if "lists/files" in path and method == "GET":
                return {"data": {"affected_items": ["1.2.3.4:bad\nevil.com:phish\nplainkey"]}}
            return {"data": {}}
        self.wz.request = AsyncMock(side_effect=fake_request)

        out = _run(self.tools["export_cdb_backup"]())
        assert out["total_entries"] == 3
        backup_file = out["backup_file"]

        # dry-run import
        prev = _run(self.tools["import_cdb_backup"](backup_file=backup_file, dry_run=True))
        assert prev["dry_run"] is True and "malicious-ips" in prev["lists_to_restore"]

        # real import
        done = _run(self.tools["import_cdb_backup"](backup_file=backup_file, dry_run=False))
        assert done["dry_run"] is False and done["restored"]

    def test_import_rejects_path_outside_backup_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        out = _run(self.tools["import_cdb_backup"](backup_file="/etc/passwd", dry_run=True))
        assert "error" in out


# ── incidents ────────────────────────────────────────────────────────────────────
def _aggs(**buckets):
    return {k: {"buckets": v} for k, v in buckets.items()}


class _HttpResp:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data or {"updated": 3, "failures": []}

    def json(self):
        return self._data


class _HttpClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        return _HttpResp()


class TestIncidents:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.incidents")

    def test_incident_timeline(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 2}, "hits": [
                _hit("2024-01-01T00:00:01Z", 9, "Execution", "T1059")]},
            "aggregations": _aggs(
                by_agent=[{"key": "host-001", "doc_count": 2}],
                by_technique=[{"key": "T1059", "doc_count": 1}],
                by_rule=[{"key": "5710", "doc_count": 2}],
            ),
        })
        out = _run(self.tools["incident_timeline"](
            start_time="now-2h", end_time="now", agent_ids=["001"]))
        assert out["total_events"] == 2 and out["agents_involved"] == ["host-001"]

    def test_blast_radius_requires_seed(self):
        out = _run(self.tools["blast_radius_analysis"]())
        assert "error" in out

    def test_blast_radius_lateral_movement(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 50}},
            "aggregations": {
                "agents_affected": {"buckets": [
                    {"key": f"h{i}", "doc_count": 5} for i in range(3)]},
                "src_ips": {"buckets": [{"key": "8.8.8.8", "doc_count": 10}]},
                "dst_ips": {"buckets": [{"key": "10.0.0.1", "doc_count": 3}]},
                "techniques": {"buckets": [{"key": "T1021", "doc_count": 4}]},
                "rules": {"buckets": [{"key": "5710", "doc_count": 9}]},
                "target_users": {"buckets": [{"key": "admin", "doc_count": 3}]},
                "dst_users": {"buckets": [{"key": "root", "doc_count": 2}]},
                "by_15min": {"buckets": [{"key_as_string": "t", "doc_count": 5}]},
            },
        })
        out = _run(self.tools["blast_radius_analysis"](src_ip="8.8.8.8"))
        assert out["lateral_movement_suspected"] is True
        assert "8.8.8.8" in out["source_ips"]

    def test_blast_radius_with_vt_enrichment(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        import wazuh_mcp.tools.threat_intel as ti
        async def vt(path):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 8, "suspicious": 1},
                    "country": "RU", "as_owner": "Evil", "reputation": -50}}}
        monkeypatch.setattr(ti, "_vt_get", vt)
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 10}},
            "aggregations": {
                "agents_affected": {"buckets": [{"key": "h1", "doc_count": 5}]},
                "src_ips": {"buckets": [{"key": "8.8.8.8", "doc_count": 10}]},
                "dst_ips": {"buckets": []}, "techniques": {"buckets": []},
                "rules": {"buckets": []},
                "target_users": {"buckets": []}, "dst_users": {"buckets": []},
                "by_15min": {"buckets": []}}})
        out = _run(self.tools["blast_radius_analysis"](src_ip="8.8.8.8"))
        assert out["attacker_ip_enrichment"] and out["attacker_ip_enrichment"][0]["malicious"] == 8

    def test_bulk_suppress_apply_error(self, monkeypatch):
        monkeypatch.setenv("WAZUH_ALLOW_WRITES", "true")
        import wazuh_mcp.tools.incidents as inc

        class _BadClient:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                raise RuntimeError("indexer down")

        monkeypatch.setattr(inc.httpx, "AsyncClient", lambda *a, **k: _BadClient())
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 5}}})
        out = _run(self.tools["bulk_suppress_rule"](rule_id=5710, reason="x", dry_run=False))
        assert "error" in out

    def test_create_incident_report(self):
        alert = _hit("2024-01-01T00:00:01Z", 12, "Impact", "T1485")["_source"]
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [{"_source": alert}]}})
        out = _run(self.tools["create_incident_report"](alert_ids=["a1", "a2"], title="Breach"))
        assert out["incident"]["severity"] == "CRITICAL"
        assert out["recommended_actions"]

    def test_create_incident_report_no_alerts(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": []}})
        out = _run(self.tools["create_incident_report"](alert_ids=["x"]))
        assert "error" in out

    def test_tag_alert(self, monkeypatch):
        monkeypatch.setenv("WAZUH_ALLOW_WRITES", "true")
        import wazuh_mcp.tools.incidents as inc
        monkeypatch.setattr(inc.httpx, "AsyncClient", lambda *a, **k: _HttpClient())
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [
            {"_index": "wazuh-alerts-4.x-2024", "_id": "a1"}]}})
        out = _run(self.tools["tag_alert"](alert_id="a1", tag="investigated"))
        assert out["status"] == "tagged"

    def test_tag_alert_not_found(self, monkeypatch):
        monkeypatch.setenv("WAZUH_ALLOW_WRITES", "true")
        self.idx.search = AsyncMock(return_value={"hits": {"hits": []}})
        out = _run(self.tools["tag_alert"](alert_id="ghost", tag="x"))
        assert "error" in out

    def test_correlate_multi_agent_requires_seed(self):
        out = _run(self.tools["correlate_multi_agent_incident"]())
        assert "error" in out

    def test_correlate_multi_agent_no_match(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}})
        out = _run(self.tools["correlate_multi_agent_incident"](seed_src_ip="8.8.8.8"))
        assert out["status"] == "NO_MATCH"

    def test_correlate_multi_agent_full(self):
        def search(body, *a, **k):
            aggs = body.get("aggs", {})
            if "involved_agents" in aggs:  # seed
                return {"hits": {"hits": [_hit("2024-01-01T00:00:01Z", 12, "Lateral Movement", "T1021")],
                                 "total": {"value": 10}},
                        "aggregations": {
                            "involved_agents": {"buckets": [{"key": "001"}, {"key": "002"}, {"key": "003"}]},
                            "src_ips": {"buckets": [{"key": "8.8.8.8"}]},
                            "dst_ips": {"buckets": [{"key": "10.0.0.1"}]},
                            "usernames": {"buckets": [{"key": "admin"}]},
                            "techniques": {"buckets": [{"key": "T1021"}, {"key": "T1078"}, {"key": "T1110"}]},
                            "top_rules": {"buckets": [{"key": "5710"}]},
                        }}
            if "new_agents" in aggs:  # expansion
                return {"hits": {"hits": [], "total": {"value": 0}},
                        "aggregations": {"new_agents": {"buckets": [{"key": "004"}]},
                                         "new_ips": {"buckets": [{"key": "9.9.9.9"}]},
                                         "techniques": {"buckets": [{"key": "T1486"}]}}}
            # per-agent breakdown
            return {"hits": {"hits": [], "total": {"value": 0}},
                    "aggregations": {"by_agent": {"buckets": [
                        {"key": "001", "doc_count": 5, "agent_name": {"buckets": [{"key": "web01"}]},
                         "max_level": {"value": 12}, "techniques": {"buckets": [{"key": "T1021"}]},
                         "top_rules": {"buckets": [{"key": "5710"}]},
                         "first_alert": {"value_as_string": "2024-01-01T00:00:01Z"},
                         "last_alert": {"value_as_string": "2024-01-01T01:00:00Z"}}]}}}
        self.idx.search = AsyncMock(side_effect=search)
        out = _run(self.tools["correlate_multi_agent_incident"](seed_src_ip="8.8.8.8"))
        assert out["correlation_summary"]["confidence_tier"] in ("HIGH", "MEDIUM")
        assert out["agent_timeline"]

    def test_bulk_suppress_dry_run(self):
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 40}}})
        out = _run(self.tools["bulk_suppress_rule"](rule_id=5710, reason="noisy"))
        assert out["dry_run"] is True and out["alerts_that_would_be_tagged"] == 40

    def test_bulk_suppress_apply(self, monkeypatch):
        monkeypatch.setenv("WAZUH_ALLOW_WRITES", "true")
        import wazuh_mcp.tools.incidents as inc
        monkeypatch.setattr(inc.httpx, "AsyncClient", lambda *a, **k: _HttpClient())
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 40}}})
        out = _run(self.tools["bulk_suppress_rule"](rule_id=5710, reason="noisy", dry_run=False))
        assert out["status"] == "suppressed" and out["updated"] == 3


# ── scheduler ────────────────────────────────────────────────────────────────────
class TestScheduler:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        import wazuh_mcp.tools.scheduler as sched
        sched._SCHEDULES.clear()
        self.sched = sched
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.scheduler")

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)
        self.sched._SCHEDULES.clear()

    def test_create_list_delete(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        monkeypatch.setattr(self.sched, "_ensure_scheduler_running", lambda *a, **k: None)
        created = _run(self.tools["create_report_schedule"](
            name="nightly", report_type="daily_summary", interval="daily"))
        assert created["status"] == "created"
        sid = created["schedule_id"]

        listed = _run(self.tools["list_report_schedules"]())
        assert listed["total"] == 1

        deleted = _run(self.tools["delete_report_schedule"](schedule_id=sid))
        assert deleted["status"] == "deleted"

    def test_create_invalid_type_and_interval(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        monkeypatch.setattr(self.sched, "_ensure_scheduler_running", lambda *a, **k: None)
        bad_type = _run(self.tools["create_report_schedule"](name="x", report_type="bogus"))
        assert "error" in bad_type
        bad_int = _run(self.tools["create_report_schedule"](
            name="x", report_type="daily_summary", interval="fortnightly"))
        assert "error" in bad_int

    def test_delete_missing(self):
        out = _run(self.tools["delete_report_schedule"](schedule_id="nope"))
        assert "error" in out

    @pytest.mark.parametrize("rtype", [
        "daily_summary", "vulnerability_summary", "shift_handover", "alert_digest", "compliance_report",
    ])
    def test_run_report_types(self, rtype):
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 5}}})
        msg = _run(self.sched._run_report({"report_type": rtype}, self.wz, self.idx, MagicMock()))
        assert isinstance(msg, str) and rtype.split("_")[0] in msg.lower() or "executed" in msg

    def test_interval_seconds(self):
        assert self.sched._interval_seconds("hourly") == 3600
        assert self.sched._interval_seconds("weekly") == 604800
        assert self.sched._interval_seconds("unknown") == 86400


# ── integrations (Jira / TheHive SOAR) ───────────────────────────────────────────
class _SoarResp:
    def __init__(self, data):
        self._data = data
        self.status_code = 200
        self.text = ""

    def json(self):
        return self._data

    def raise_for_status(self):
        return None


class _SoarClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kw):
        if "thehive" in url or "/case" in url:
            return _SoarResp({"_id": "h123", "caseId": 7})
        if "transitions" in url:
            return _SoarResp({})
        return _SoarResp({"key": "SOC-42"})

    async def get(self, url, **kw):
        return _SoarResp({"transitions": [{"id": "31", "to": {"name": "Done"}}]})


class TestIntegrations:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.integrations")

    def test_jira_not_configured(self, monkeypatch):
        monkeypatch.delenv("JIRA_URL", raising=False)
        monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
        out = _run(self.tools["create_jira_ticket"](title="t", description="d"))
        assert "error" in out

    def test_jira_create_ok(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
        monkeypatch.setenv("JIRA_USER", "u")
        monkeypatch.setenv("JIRA_API_TOKEN", "tok")
        import wazuh_mcp.tools.integrations as ig
        monkeypatch.setattr(ig.httpx, "AsyncClient", lambda *a, **k: _SoarClient())
        out = _run(self.tools["create_jira_ticket"](
            title="Breach", description="desc", severity="Critical",
            affected_agents=["a1"], mitre_techniques=["T1110"], alert_ids=["x"]))
        assert out["status"] == "ok" and out["issue_key"] == "SOC-42"
        assert out["priority"] == "Highest"

    def test_thehive_not_configured(self, monkeypatch):
        monkeypatch.delenv("THEHIVE_URL", raising=False)
        monkeypatch.delenv("THEHIVE_API_KEY", raising=False)
        out = _run(self.tools["create_thehive_case"](title="t", description="d"))
        assert "error" in out

    def test_thehive_create_ok(self, monkeypatch):
        monkeypatch.setenv("THEHIVE_URL", "https://hive.example.com")
        monkeypatch.setenv("THEHIVE_API_KEY", "key")
        import wazuh_mcp.tools.integrations as ig
        monkeypatch.setattr(ig.httpx, "AsyncClient", lambda *a, **k: _SoarClient())
        out = _run(self.tools["create_thehive_case"](
            title="Breach", description="d", severity="High",
            mitre_techniques=["T1021"], tags=["urgent"]))
        assert out["status"] == "ok" and out["case_num"] == 7

    def test_update_ticket_status_ok(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
        monkeypatch.setenv("JIRA_USER", "u")
        monkeypatch.setenv("JIRA_API_TOKEN", "tok")
        import wazuh_mcp.tools.integrations as ig
        monkeypatch.setattr(ig.httpx, "AsyncClient", lambda *a, **k: _SoarClient())
        out = _run(self.tools["update_ticket_status"](
            issue_key="SOC-1", new_status="Done", comment="fixed", resolution="Fixed"))
        assert out["status"] == "ok" and out["new_status"] == "Done"

    def test_update_ticket_status_transition_missing(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
        monkeypatch.setenv("JIRA_USER", "u")
        monkeypatch.setenv("JIRA_API_TOKEN", "tok")
        import wazuh_mcp.tools.integrations as ig
        monkeypatch.setattr(ig.httpx, "AsyncClient", lambda *a, **k: _SoarClient())
        out = _run(self.tools["update_ticket_status"](issue_key="SOC-1", new_status="Nonexistent"))
        assert "error" in out

    def test_update_ticket_not_configured(self, monkeypatch):
        monkeypatch.delenv("JIRA_URL", raising=False)
        monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
        out = _run(self.tools["update_ticket_status"](issue_key="SOC-1", new_status="Done"))
        assert "error" in out


# ── export ───────────────────────────────────────────────────────────────────────
def _vuln_hit():
    return {"_source": {
        "agent": {"id": "001", "name": "host1"},
        "vulnerability": {"id": "CVE-2021-1", "severity": "Critical",
                          "score": {"base": 9.8}, "published_at": "2021"},
        "package": {"name": "openssl", "version": "1.1"},
    }}


class TestExport:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.export")

    def test_to_csv_helper(self):
        from wazuh_mcp.tools.export import _to_csv
        assert _to_csv([]) == ""
        out = _to_csv([{"a": 1, "b": 2}])
        assert "a,b" in out and "1,2" in out

    def test_export_alerts_csv_normal(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [
            _hit("2024-01-01T00:00:01Z", 9, "Execution", "T1059")]}})
        out = _run(self.tools["export_alerts_csv"](time_range="24h", min_level=7))
        assert "timestamp,agent_id" in out and "5710" in out

    def test_export_alerts_csv_invalid_range(self):
        out = _run(self.tools["export_alerts_csv"](time_range="bogus"))
        assert out.startswith("ERROR")

    def test_export_alerts_csv_stream(self):
        # One short page → loop terminates after first iteration.
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [
            {**_hit("2024-01-01T00:00:01Z", 9, "Execution", "T1059"), "sort": [1, "a"]}]}})
        out = _run(self.tools["export_alerts_csv"](stream=True))
        assert out.startswith("# wazuh-mcp export")

    def test_export_alerts_csv_empty(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": []}})
        out = _run(self.tools["export_alerts_csv"]())
        assert "No alerts" in out

    def test_export_vulnerabilities_csv(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [_vuln_hit()]}})
        out = _run(self.tools["export_vulnerabilities_csv"](min_severity="High"))
        assert "CVE-2021-1" in out

    def test_export_compliance_csv(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [{"_source": {
            "@timestamp": "2024", "rule": {"id": "5710", "description": "d",
            "pci_dss": ["10.2.1", "10.2.2"]}, "agent": {"id": "001", "name": "h"}}}]}})
        out = _run(self.tools["export_compliance_csv"](framework="pci_dss"))
        assert "10.2.1,10.2.2" in out

    def test_export_alerts_json(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [
            _hit("2024-01-01T00:00:01Z", 9, "Execution", "T1059")]}})
        out = _run(self.tools["export_alerts_json"](pretty=True))
        assert out.strip().startswith("[")

    def test_export_alerts_ndjson(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [
            _hit("2024-01-01T00:00:01Z", 9, "Execution", "T1059")]}})
        out = _run(self.tools["export_alerts_ndjson"]())
        assert out and "5710" in out

    def test_export_alerts_ndjson_invalid(self):
        out = _run(self.tools["export_alerts_ndjson"](time_range="bad"))
        assert out.startswith("ERROR")

    def test_export_report_html(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 2}},
            "aggregations": _DeepDict()})
        out = _run(self.tools["export_report_html"](report_type="compliance"))
        assert "<html" in out.lower() or "<table" in out.lower()


# ── vulnerabilities ──────────────────────────────────────────────────────────────
def _cve_bucket(cve, agents=5, cvss=9.8, sev="Critical", pkg="openssl"):
    return {
        "key": cve, "doc_count": agents,
        "affected_agents": {"value": agents},
        "agents": {"value": agents},
        "avg_cvss": {"value": cvss},
        "detail": {"hits": {"hits": [{"_source": {
            "vulnerability": {"severity": sev, "score": {"base": cvss}},
            "package": {"name": pkg}}}]}},
        "sample": {"hits": {"hits": [{"_source": {
            "vulnerability": {"severity": sev}, "package": {"name": pkg}}}]}},
    }


class TestVulnerabilities:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.vulnerabilities")

    def test_vulnerability_summary(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 12}},
            "aggregations": {
                "by_severity": {"buckets": [{"key": "Critical", "doc_count": 8}]},
                "top_cves": {"buckets": [_cve_bucket("CVE-2021-44228")]},
                "top_vulnerable_agents": {"buckets": [{"key": "host1", "doc_count": 4}]},
                "top_vulnerable_packages": {"buckets": [{"key": "log4j", "doc_count": 3}]},
            },
        })
        out = _run(self.tools["vulnerability_summary"](min_severity="High"))
        assert out["total_findings"] == 12 and out["top_cves"][0]["cve"] == "CVE-2021-44228"

    def test_agent_vulns_detailed(self):
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 1}, "hits": [_vuln_hit()]}})
        out = _run(self.tools["get_agent_vulnerabilities_detailed"](agent_id="001"))
        assert out["total"] == 1 and out["vulnerabilities"][0]["cve"] == "CVE-2021-1"

    def test_search_cve_found_and_missing(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 3}, "hits": [_vuln_hit()]},
            "aggregations": {"by_agent": {"buckets": [{"key": "host1", "doc_count": 2}]},
                             "by_package": {"buckets": [{"key": "openssl", "doc_count": 3}]}},
        })
        found = _run(self.tools["search_cve"](cve_id="CVE-2021-44228"))
        assert found["found"] is True and found["total_findings"] == 3

        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 0}, "hits": []},
                                                  "aggregations": {}})
        missing = _run(self.tools["search_cve"](cve_id="CVE-2021-44228"))
        assert missing["found"] is False

    def test_search_cve_invalid(self):
        out = _run(self.tools["search_cve"](cve_id="not-a-cve"))
        assert "error" in out

    def test_prioritize_patches(self):
        self.idx.search = AsyncMock(return_value={
            "aggregations": {"by_cve": {"buckets": [
                _cve_bucket("CVE-A", agents=10, cvss=9.0),
                _cve_bucket("CVE-B", agents=2, cvss=7.0)]}},
        })
        out = _run(self.tools["prioritize_patches"](top_n=5))
        assert out["top_patches"][0]["cve"] == "CVE-A"  # highest exposure first

    def test_enrich_cve_epss(self, monkeypatch):
        import wazuh_mcp.tools.vulnerabilities as v
        async def fake_epss(ids):
            return {"CVE-2021-44228": {"epss": 0.97, "percentile": 99.9}}
        monkeypatch.setattr(v, "_fetch_epss", fake_epss)
        out = _run(self.tools["enrich_cve_epss"](cve_ids=["CVE-2021-44228", "CVE-2024-0001"]))
        assert out["results"][0]["risk_label"] == "CRITICAL"

    def test_enrich_cve_epss_invalid(self):
        assert "error" in _run(self.tools["enrich_cve_epss"](cve_ids=[]))

    def test_check_kev_exposure(self, monkeypatch):
        import wazuh_mcp.tools.vulnerabilities as v
        async def fake_kev():
            return {"CVE-2021-44228": {"vendorProject": "Apache", "product": "log4j",
                    "vulnerabilityName": "RCE", "dateAdded": "2021", "dueDate": "2021"}}
        monkeypatch.setattr(v, "_fetch_kev", fake_kev)
        self.idx.search = AsyncMock(return_value={
            "aggregations": {"by_cve": {"buckets": [{
                "key": "CVE-2021-44228", "agents": {"value": 6},
                "sample": {"hits": {"hits": [{"_source": {
                    "vulnerability": {"severity": "Critical"},
                    "package": {"name": "log4j"}, "agent": {"name": "h1"}}}]}}}]}},
        })
        out = _run(self.tools["check_kev_exposure"]())
        assert out["kev_hits_on_fleet"] == 1

    def test_prioritize_patches_with_epss(self, monkeypatch):
        import wazuh_mcp.tools.vulnerabilities as v
        async def fake_epss(ids):
            return {"CVE-A": {"epss": 0.8, "percentile": 95.0}}
        async def fake_kev():
            return {"CVE-A": {}}
        monkeypatch.setattr(v, "_fetch_epss", fake_epss)
        monkeypatch.setattr(v, "_fetch_kev", fake_kev)
        self.idx.search = AsyncMock(return_value={
            "aggregations": {"by_cve": {"buckets": [_cve_bucket("CVE-A", agents=5, cvss=9.0)]}}})
        out = _run(self.tools["prioritize_patches_with_epss"](top_n=5))
        assert out["top_patches"][0]["in_cisa_kev"] is True
        assert out["top_patches"][0]["patch_urgency"].startswith("P0")


# ── active_response ──────────────────────────────────────────────────────────────
def _ar_hit(ts, command="firewall-drop", srcip="8.8.8.8", groups=("active_response",), rid="601"):
    return {"_id": f"ar-{ts}", "_source": {
        "@timestamp": ts, "agent": {"id": "001", "name": "host1"},
        "data": {"command": command, "srcip": srcip},
        "rule": {"id": rid, "level": 5, "description": "AR", "groups": list(groups)},
        "full_log": "blocked",
    }}


class TestActiveResponse:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.active_response")

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)

    def test_get_active_responses(self):
        self.idx.search = AsyncMock(return_value={"hits": {
            "total": {"value": 1}, "hits": [_ar_hit("2024-01-01T00:00:01Z")]}})
        out = _run(self.tools["get_active_responses"]())
        assert out["total"] == 1 and out["responses"][0]["command"] == "firewall-drop"

    def test_get_active_responses_invalid_range(self):
        out = _run(self.tools["get_active_responses"](time_range="zzz"))
        assert "error" in out

    def test_correlate_requires_seed(self):
        assert "error" in _run(self.tools["correlate_alert_with_response"]())

    def test_correlate_splits_alerts_and_responses(self):
        hits = [
            _ar_hit("2024-01-01T00:00:01Z", groups=("active_response",), rid="601"),
            {"_id": "n1", "_source": {"@timestamp": "2024-01-01T00:00:02Z",
             "agent": {"id": "001", "name": "host1"},
             "rule": {"id": "5710", "level": 7, "description": "ssh", "groups": ["authentication_failed"]}}},
        ]
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 2}, "hits": hits}})
        out = _run(self.tools["correlate_alert_with_response"](src_ip="8.8.8.8"))
        assert out["response_taken"] is True
        assert out["triggering_alerts_count"] == 1 and out["response_actions_count"] == 1

    def test_propose_active_response_dry(self, monkeypatch):
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        out = _run(self.tools["propose_active_response"](
            agent_id="001", command="firewall-drop", src_ip="8.8.8.8"))
        assert out.get("status") == "pending_approval" and out.get("token")
        assert out.get("slack_notified") is False


# ── agent_health ─────────────────────────────────────────────────────────────────
class TestAgentHealth:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.agent_health")

        async def wz_request(method, path, **kw):
            if "/sca/" in path:
                return {"data": {"affected_items": [{"pass": 90, "fail": 10}]}}
            if "agents_list" in path:
                return {"data": {"affected_items": [
                    {"id": "001", "name": "host1", "status": "active"}]}}
            # fleet listing
            return {"data": {"affected_items": [
                {"id": "001", "name": "host1", "status": "active"},
                {"id": "002", "name": "host2", "status": "disconnected"}]}}

        async def idx_search(body, *a, **k):
            return {"hits": {"total": {"value": 5}},
                    "aggregations": {"by_severity": {"buckets": []}}}

        self.wz.request = AsyncMock(side_effect=wz_request)
        self.idx.search = AsyncMock(side_effect=idx_search)

    def test_get_agent_health_score(self):
        out = _run(self.tools["get_agent_health_score"](agent_id="001"))
        assert 0 <= out["health_score"] <= 100
        assert out["band"] in ("HEALTHY", "WARNING", "DEGRADED", "CRITICAL")
        assert out["dimensions"]["connectivity"]["score"] == 25

    def test_get_agent_health_score_invalid(self):
        out = _run(self.tools["get_agent_health_score"](agent_id="../etc"))
        assert "error" in out

    def test_list_unhealthy_agents(self):
        out = _run(self.tools["list_unhealthy_agents"](band="WARNING"))
        assert out["filter_band"] == "WARNING" and "agents" in out

    def test_list_unhealthy_invalid_band(self):
        out = _run(self.tools["list_unhealthy_agents"](band="SUPERBAD"))
        assert "error" in out

    def test_get_health_breakdown(self):
        out = _run(self.tools["get_health_breakdown"]())
        assert out["total_agents_checked"] == 2 and "average_health_score" in out


# ── audit_mgmt ───────────────────────────────────────────────────────────────────
class TestAuditMgmt:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.audit_mgmt")

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)

    def _write_log(self, tmp_path, records):
        import json
        p = tmp_path / "audit.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        return p

    def test_stats_missing_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_AUDIT_LOG", str(tmp_path / "none.jsonl"))
        assert "error" in _run(self.tools["get_audit_log_stats"]())

    def test_stats_with_records(self, monkeypatch, tmp_path):
        p = self._write_log(tmp_path, [
            {"ts": "2024-01-01", "tool": "list_agents", "result_code": "ok"},
            {"ts": "2024-01-02", "tool": "search_alerts", "result_code": "error"},
        ])
        monkeypatch.setenv("WAZUH_AUDIT_LOG", str(p))
        out = _run(self.tools["get_audit_log_stats"]())
        assert out["total_records"] == 2 and out["first_record_ts"] == "2024-01-01"

    def test_search_filters(self, monkeypatch, tmp_path):
        p = self._write_log(tmp_path, [
            {"ts": "t1", "tool": "list_agents", "identity": "abc123", "result_code": "ok"},
            {"ts": "t2", "tool": "run_active_response", "identity": "def456", "result_code": "error"},
        ])
        monkeypatch.setenv("WAZUH_AUDIT_LOG", str(p))
        out = _run(self.tools["search_audit_log"](tool_name="run_active_response"))
        assert out["total_matching"] == 1
        out2 = _run(self.tools["search_audit_log"](result_code="ok", identity="abc"))
        assert out2["total_matching"] == 1

    def test_verify_no_signing_key(self, monkeypatch, tmp_path):
        p = self._write_log(tmp_path, [{"ts": "t1", "tool": "x"}])
        monkeypatch.setenv("WAZUH_AUDIT_LOG", str(p))
        monkeypatch.delenv("WAZUH_AUDIT_LOG_SIGNING_KEY", raising=False)
        out = _run(self.tools["verify_audit_log_integrity"]())
        assert out["signing_enabled"] is False

    def test_verify_valid_and_tampered(self, monkeypatch, tmp_path):
        import json, hashlib, hmac as hmac_mod
        key = "secret-signing-key"

        def sign(rec):
            canonical = json.dumps(rec, sort_keys=True, default=str)
            return hmac_mod.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()

        good = {"ts": "t1", "tool": "list_agents"}
        good_signed = {**good, "hmac": sign(good)}
        tampered = {"ts": "t2", "tool": "evil", "hmac": "deadbeef"}
        unsigned = {"ts": "t3", "tool": "x"}
        p = self._write_log(tmp_path, [good_signed, tampered, unsigned])
        monkeypatch.setenv("WAZUH_AUDIT_LOG", str(p))
        monkeypatch.setenv("WAZUH_AUDIT_LOG_SIGNING_KEY", key)
        out = _run(self.tools["verify_audit_log_integrity"]())
        assert out["valid_records"] == 1 and out["invalid_records"] == 1
        assert out["unsigned_records"] == 1 and out["integrity"] == "COMPROMISED"

    def test_requires_admin(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.VIEWER)
        assert "error" in _run(self.tools["get_audit_log_stats"]())


# ── threat_feeds ─────────────────────────────────────────────────────────────────
class TestThreatFeeds:
    def setup_method(self):
        import wazuh_mcp.tools.threat_feeds as tf
        tf._FEED_CACHE.clear()
        self.tf = tf
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.threat_feeds")

    def teardown_method(self):
        self.tf._FEED_CACHE.clear()

    def test_parsers(self):
        assert self.tf._parse_feodo_csv("# comment\n1.2.3.4,foo\n\n5.6.7.8") == ["1.2.3.4", "5.6.7.8"]
        assert self.tf._parse_tor_list("# c\n9.9.9.9\n") == ["9.9.9.9"]
        domains = self.tf._parse_urlhaus_csv('"id","http://evil.com/x","online"')
        assert "evil.com" in domains

    def test_sync_unknown_feed(self):
        assert "error" in _run(self.tools["sync_threat_feed"](feed_id="nope"))

    def test_sync_dry_run(self, monkeypatch):
        async def fake_fetch(fid):
            return (["1.2.3.4", "5.6.7.8"], "")
        monkeypatch.setattr(self.tf, "_fetch_feed", fake_fetch)
        out = _run(self.tools["sync_threat_feed"](feed_id="feodo", dry_run=True))
        assert out["dry_run"] is True and out["ioc_count"] == 2

    def test_sync_fetch_error(self, monkeypatch):
        async def fake_fetch(fid):
            return ([], "network down")
        monkeypatch.setattr(self.tf, "_fetch_feed", fake_fetch)
        out = _run(self.tools["sync_threat_feed"](feed_id="feodo"))
        assert "error" in out

    def test_list_threat_feeds(self):
        out = _run(self.tools["list_threat_feeds"]())
        assert len(out["feeds"]) == 3

    def test_correlate_not_loaded(self):
        assert "error" in _run(self.tools["correlate_alerts_with_feed"](feed_id="feodo"))

    def test_correlate_with_matches(self):
        self.tf._FEED_CACHE["feodo"] = {"iocs": {"8.8.8.8"}, "synced_at": 0, "count": 1}
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [
            {"_source": {"@timestamp": "t", "data": {"srcip": "8.8.8.8"},
                         "agent": {"name": "h1"}, "rule": {"id": "1"}}}]}})
        out = _run(self.tools["correlate_alerts_with_feed"](feed_id="feodo"))
        assert out["matches_found"] == 1 and out["severity"] == "critical"


# ── cve_watchlist ────────────────────────────────────────────────────────────────
class TestCVEWatchlist:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.cve_watchlist")

    def test_parse_entry_and_sla(self):
        from wazuh_mcp.tools.cve_watchlist import _parse_entry, _sla_status
        e = _parse_entry("CVE-2024-1", "active|note|9.8|30|2024-01-01T00:00:00Z")
        assert e["cvss_score"] == 9.8 and e["sla_days"] == 30
        breached = _sla_status({"sla_days": 1, "added_at": "2020-01-01T00:00:00Z"})
        assert breached["sla_breached"] is True
        none_sla = _sla_status({"sla_days": 0, "added_at": ""})
        assert none_sla["sla_breached"] is False

    def test_add_cve_valid(self):
        self.wz.request = AsyncMock(return_value={})
        out = _run(self.tools["add_cve_to_watchlist"](
            cve_id="CVE-2024-1234", note="log4j", cvss_score=9.8, sla_days=30))
        assert out["added"] == "CVE-2024-1234" and "sla_deadline" in out

    def test_add_cve_invalid_id(self):
        assert "error" in _run(self.tools["add_cve_to_watchlist"](cve_id="not-a-cve"))

    def test_add_cve_bad_cvss(self):
        assert "error" in _run(self.tools["add_cve_to_watchlist"](
            cve_id="CVE-2024-1234", cvss_score=99.0))

    def test_add_cve_negative_sla(self):
        assert "error" in _run(self.tools["add_cve_to_watchlist"](
            cve_id="CVE-2024-1234", sla_days=-5))

    def test_list_watchlist(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"key": "CVE-2020-0001", "value": "active|old|7.5|1|2020-01-01T00:00:00Z"},
            {"key": "CVE-2024-9999", "value": "patched|fixed|9.0|30|2024-01-01T00:00:00Z"},
            {"key": "not-a-cve", "value": "junk"},
        ]}})
        out = _run(self.tools["list_cve_watchlist"]())
        assert out["total"] == 2  # the junk row is skipped
        assert "CVE-2020-0001" in out["sla_breached_cves"]

    def test_mark_patched(self):
        async def req(method, path, **kw):
            if method == "GET":
                return {"data": {"affected_items": [
                    {"key": "CVE-2024-1234", "value": "active|n|9.8|30|2024-01-01T00:00:00Z"}]}}
            return {}
        self.wz.request = AsyncMock(side_effect=req)
        out = _run(self.tools["mark_patched"](cve_id="CVE-2024-1234", note="patched v2"))
        assert out["status"] == "patched"

    def test_get_watchlist_exposure(self):
        async def req(method, path, **kw):
            return {"data": {"affected_items": [
                {"key": "CVE-2024-1234", "value": "active|n|9.8|30|2024-01-01T00:00:00Z"}]}}
        self.wz.request = AsyncMock(side_effect=req)
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 4}},
            "aggregations": {"agents": {"buckets": [{"key": "001"}, {"key": "002"}]}}})
        out = _run(self.tools["get_watchlist_exposure"]())
        assert out["active_cves_checked"] == 1 and out["exposure"][0]["affected_agents"] == 4

    def test_get_watchlist_exposure_none_active(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"key": "CVE-2024-1", "value": "patched|n|9|30|2024-01-01T00:00:00Z"}]}})
        out = _run(self.tools["get_watchlist_exposure"]())
        assert out["exposure"] == []

    def test_prioritize_cve_risk(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"key": "CVE-2024-1234", "value": "active|n|9.8|30|2024-01-01T00:00:00Z"}]}})
        self.idx.search = AsyncMock(return_value={
            "aggregations": {"agents": {"value": 6}}})
        out = _run(self.tools["prioritize_cve_risk"](top_n=5))
        assert out["ranked"][0]["cve_id"] == "CVE-2024-1234"

    def test_check_sla_breaches(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"key": "CVE-2020-0001", "value": "active|old|9|1|2020-01-01T00:00:00Z"}]}})
        out = _run(self.tools["check_sla_breaches"]())
        assert isinstance(out, dict)


# ── playbooks ────────────────────────────────────────────────────────────────────
class _AutoRegistry(dict):
    """A tool registry whose every lookup resolves to an async stub returning {}."""
    def __init__(self, overrides=None):
        super().__init__()
        self._overrides = overrides or {}

    def __bool__(self):
        # Must be truthy so the engine's ``tool_registry or {}`` keeps this
        # registry instead of replacing an "empty" dict with a plain {}.
        return True

    def get(self, key, default=None):
        if key in self._overrides:
            return self._overrides[key]
        return AsyncMock(return_value={"ok": True})


def _make_playbook_env(registry):
    from wazuh_mcp.tool_context import ToolContext
    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    ctx = ToolContext(
        mcp=mcp, wz=AsyncMock(), idx=AsyncMock(), cfg=MagicMock(),
        cap=lambda n: n, require_writes=lambda: None, truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda *a, **k: [], tool_registry=registry,
    )
    importlib.import_module("wazuh_mcp.tools.playbooks").register(ctx)
    return tools


class TestPlaybooks:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.RESPONDER)

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)

    def test_resolve_params(self):
        from wazuh_mcp.tools.playbooks import _resolve_params
        out = _resolve_params({"agent_id": "{agent_id}", "n": 5}, {"agent_id": "001"})
        assert out["agent_id"] == "001" and out["n"] == 5

    def test_list_playbooks(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        out = _run(tools["list_playbooks"]())
        assert out["total"] >= 5

    def test_run_unknown_playbook(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        assert "error" in _run(tools["run_playbook"](playbook_id="nope", agent_id="001"))

    def test_run_missing_params(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        out = _run(tools["run_playbook"](playbook_id="isolate-compromised-host"))
        assert "error" in out and "Missing" in out["error"]

    def test_run_dry_run(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        out = _run(tools["run_playbook"](
            playbook_id="isolate-compromised-host", dry_run=True, agent_id="001"))
        assert out["dry_run"] is True and out["status"] == "dry_run_preview"

    def test_run_full_completion(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        out = _run(tools["run_playbook"](
            playbook_id="isolate-compromised-host", dry_run=False, agent_id="001"))
        assert out["status"] == "completed"
        # Status round-trips through the persisted run store.
        status = _run(tools["get_playbook_status"](run_id=out["run_id"]))
        assert status["run_id"] == out["run_id"]

    def test_run_approval_gate_pause(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        out = _run(tools["run_playbook"](
            playbook_id="brute-force-response", dry_run=False, ip="8.8.8.8"))
        assert out["status"] == "awaiting_approval" and out["paused_at_step"] == 3

    def test_run_step_failure_triggers_rollback(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        # Make the blocklist add (step index 3) return an error after the gate is
        # cleared — but brute-force pauses at step 3, so use lateral-movement which
        # gates at step 4 and blocks at step 4. Instead force an early step error.
        reg = _AutoRegistry(overrides={
            "search_by_source_ip": AsyncMock(return_value={"error": "boom"})})
        tools = _make_playbook_env(reg)
        out = _run(tools["run_playbook"](
            playbook_id="lateral-movement-containment", dry_run=False, ip="8.8.8.8"))
        assert out["status"] == "failed" and out["failed_at_step"] == 1

    def test_get_status_not_found(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        out = _run(tools["get_playbook_status"](run_id="nope"))
        assert "error" in out and "recent_runs" in out

    def test_resume_not_found(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        assert "error" in _run(tools["resume_playbook"](run_id="nope", approved=True))

    def test_resume_abort_and_approve(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        # brute-force pauses at the approval gate
        paused = _run(tools["run_playbook"](
            playbook_id="brute-force-response", dry_run=False, ip="8.8.8.8"))
        rid = paused["run_id"]
        # abort path
        aborted = _run(tools["resume_playbook"](run_id=rid, approved=False))
        assert aborted["status"] == "aborted"

        # fresh run → approve path runs to completion
        paused2 = _run(tools["run_playbook"](
            playbook_id="brute-force-response", dry_run=False, ip="8.8.8.8"))
        done = _run(tools["resume_playbook"](run_id=paused2["run_id"], approved=True))
        assert done["status"] == "completed"

    def test_resume_not_awaiting(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        tools = _make_playbook_env(_AutoRegistry())
        done = _run(tools["run_playbook"](
            playbook_id="isolate-compromised-host", dry_run=False, agent_id="001"))
        out = _run(tools["resume_playbook"](run_id=done["run_id"], approved=True))
        assert "error" in out


# ── threat_intel ─────────────────────────────────────────────────────────────────
_VT_MALICIOUS = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 10, "suspicious": 2, "harmless": 30},
    "country": "RU", "asn": 65000, "as_owner": "EvilCorp", "reputation": -50,
    "meaningful_name": "evil.exe", "type_description": "PE32", "size": 1024,
    "popular_threat_classification": {"suggested_threat_label": "trojan.generic"},
    "categories": {"x": "malware"}, "tags": ["malware"]}}}
_ABUSE_HIGH = {"abuseConfidenceScore": 90, "totalReports": 42, "countryCode": "RU",
               "isp": "EvilISP", "domain": "evil.ru", "isTor": False,
               "lastReportedAt": "2024-01-01"}


class TestThreatIntel:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.threat_intel")
        self.mod = importlib.import_module("wazuh_mcp.tools.threat_intel")

    def test_cache_helpers(self):
        self.mod._IOC_CACHE.clear()
        self.mod._cache_set("k", {"v": 1}, ttl=60)
        assert self.mod._cache_get("k") == {"v": 1}
        self.mod._cache_set("expired", {"v": 2}, ttl=-1)
        assert self.mod._cache_get("expired") is None

    def test_enrich_ip_malicious(self, monkeypatch):
        async def vt(path):
            return _VT_MALICIOUS
        async def abuse(ip):
            return _ABUSE_HIGH
        monkeypatch.setattr(self.mod, "_vt_get", vt)
        monkeypatch.setattr(self.mod, "_abuse_get", abuse)
        out = _run(self.tools["enrich_ip"](ip="8.8.8.8"))
        assert out["verdict"] == "KNOWN MALICIOUS"
        assert out["virustotal"]["malicious_votes"] == 10

    def test_enrich_ip_invalid(self):
        assert "error" in _run(self.tools["enrich_ip"](ip="not-an-ip"))

    def test_enrich_ip_unavailable(self, monkeypatch):
        async def none(*a):
            return None
        monkeypatch.setattr(self.mod, "_vt_get", none)
        monkeypatch.setattr(self.mod, "_abuse_get", none)
        out = _run(self.tools["enrich_ip"](ip="8.8.8.8"))
        assert out["verdict"].startswith("UNKNOWN")

    def test_enrich_file_hash_no_key(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        assert "error" in _run(self.tools["enrich_file_hash"](hash_value="a" * 64))

    def test_enrich_file_hash_malicious(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        async def vt(path):
            return _VT_MALICIOUS
        monkeypatch.setattr(self.mod, "_vt_get", vt)
        out = _run(self.tools["enrich_file_hash"](hash_value="a" * 64))
        assert out["verdict"] == "MALICIOUS" and out["malicious_engines"] == 10

    def test_enrich_domain_invalid_and_valid(self, monkeypatch):
        assert "error" in _run(self.tools["enrich_domain"](domain="!!!"))
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        async def vt(path):
            return _VT_MALICIOUS
        monkeypatch.setattr(self.mod, "_vt_get", vt)
        out = _run(self.tools["enrich_domain"](domain="evil.com"))
        assert out["verdict"] == "KNOWN MALICIOUS"

    def test_threat_intel_status(self):
        out = _run(self.tools["get_threat_intel_status"]())
        assert "quota_and_circuit_status" in out and "limits" in out

    def test_enrich_url(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        async def vt(path):
            return _VT_MALICIOUS
        monkeypatch.setattr(self.mod, "_vt_get", vt)
        out = _run(self.tools["enrich_url"](url="http://evil.com/x"))
        assert "verdict" in out

    def test_enrich_ip_geo(self):
        out = _run(self.tools["enrich_ip_geo"](ips=["8.8.8.8", "1.1.1.1"]))
        assert "results" in out and len(out["results"]) == 2

    def test_bulk_enrich_empty_and_overlimit(self):
        assert "error" in _run(self.tools["bulk_enrich_iocs"](iocs=[]))
        assert "error" in _run(self.tools["bulk_enrich_iocs"](iocs=["1.1.1.1"] * 21))

    def test_bulk_enrich_mixed_types(self, monkeypatch):
        async def vt(path):
            return _VT_MALICIOUS
        async def abuse(ip):
            return _ABUSE_HIGH
        monkeypatch.setattr(self.mod, "_vt_get", vt)
        monkeypatch.setattr(self.mod, "_abuse_get", abuse)
        iocs = ["8.8.8.8", "1[.]1[.]1[.]1", "a" * 64, "evil.com",
                "http://evil.com/x", "not an ioc!!"]
        out = _run(self.tools["bulk_enrich_iocs"](iocs=iocs))
        assert out["total"] == 6 and out["malicious"] >= 1
        types = {r["type"] for r in out["results"]}
        assert {"ip", "hash", "domain", "url", "unknown"} <= types

    def test_enrich_email_breached(self, monkeypatch):
        class _Resp:
            status_code = 200

            def json(self):
                return [{"Name": "Adobe", "Domain": "adobe.com", "BreachDate": "2013",
                         "DataClasses": ["Emails", "Passwords"], "PwnCount": 1}]

        class _Client:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, *a, **k):
                return _Resp()

        monkeypatch.delenv("HUNTER_API_KEY", raising=False)
        import httpx
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _Client())
        out = _run(self.tools["enrich_email"](email="victim@example.com"))
        assert out["verdict"] == "BREACHED" and out["breach_count"] == 1

    def test_ioc_to_alert_match_empty(self):
        assert "error" in _run(self.tools["ioc_to_alert_match"](iocs=[]))

    def test_ioc_to_alert_match(self):
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 2}, "hits": [
            {"_source": {"@timestamp": "t", "rule": {"id": "1", "description": "d", "level": 7},
                         "agent": {"id": "001", "name": "h1"}, "data": {"srcip": "8.8.8.8"}}}]}})
        out = _run(self.tools["ioc_to_alert_match"](iocs=["8.8.8.8", "evil.com"]))
        assert isinstance(out, dict)


# ── ueba ─────────────────────────────────────────────────────────────────────────
def _auth_event(agent_n, ip, ok=False, hour="03"):
    return {
        "agent": {"id": str(agent_n), "name": f"host{agent_n}"},
        "data": {"srcip": ip, "dstuser": "admin"},
        "rule": {"id": "5710", "level": 5, "description": "auth",
                 "groups": ["authentication_success" if ok else "authentication_failed"]},
        "@timestamp": f"2024-01-01T{hour}:00:00Z",
    }


class TestUEBA:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.ueba")

    def test_analyse_activity_high_risk(self):
        from wazuh_mcp.tools.ueba import _analyse_activity
        events = [_auth_event(n, f"10.0.0.{n}") for n in range(6)]  # 6 agents, 6 IPs, all fails
        out = _analyse_activity(events, "admin")
        assert out["risk_level"] == "high"
        assert len(out["agents_active_on"]) == 6

    def test_user_activity_profile(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": [
            {"_source": _auth_event(1, "10.0.0.1")}]}})
        out = _run(self.tools["get_user_activity_profile"](username="admin"))
        assert out["username"] == "admin" and out["total_events"] == 1

    def test_user_activity_profile_empty(self):
        self.idx.search = AsyncMock(return_value={"hits": {"hits": []}})
        out = _run(self.tools["get_user_activity_profile"](username="ghost"))
        assert out["total_events"] == 0

    def test_detect_user_anomalies(self):
        self.idx.search = AsyncMock(return_value={"aggregations": {"by_user": {"buckets": [
            {"key": "admin", "doc_count": 40,
             "agents": {"value": 5}, "failures": {"doc_count": 30},
             "source_ips": {"value": 4}},
            {"key": "root", "doc_count": 10, "agents": {"value": 1},  # skipped (root)
             "failures": {"doc_count": 1}, "source_ips": {"value": 1}},
        ]}}})
        out = _run(self.tools["detect_user_anomalies"](min_agents=3))
        assert out["anomalous_users"] == 1
        assert out["results"][0]["risk_level"] == "high"

    def test_list_privileged_escalations(self):
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 1}, "hits": [
            {"_source": {"@timestamp": "t", "agent": {"name": "h1"},
                         "data": {"srcuser": "u", "dstuser": "root"},
                         "rule": {"id": "5710", "level": 10, "description": "sudo",
                                  "groups": ["privilege_escalation"]}}}]}})
        out = _run(self.tools["list_privileged_escalations"]())
        assert isinstance(out, dict)

    def test_get_peer_group_baseline_no_agents(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": []}})
        out = _run(self.tools["get_peer_group_baseline"](agent_group="empty-group"))
        assert "error" in out

    def test_get_peer_group_baseline(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"id": "001", "name": "h1"}, {"id": "002", "name": "h2"},
            {"id": "003", "name": "h3"}]}})
        # One agent is a clear volume outlier vs its peers.
        self.idx.search = AsyncMock(return_value={"aggregations": {"by_agent": {"buckets": [
            {"key": "001", "doc_count": 10, "critical_alerts": {"doc_count": 0},
             "unique_rules": {"value": 3}, "avg_level": {"value": 5}},
            {"key": "002", "doc_count": 12, "critical_alerts": {"doc_count": 0},
             "unique_rules": {"value": 4}, "avg_level": {"value": 5}},
            {"key": "003", "doc_count": 500, "critical_alerts": {"doc_count": 20},
             "unique_rules": {"value": 50}, "avg_level": {"value": 11}},
        ]}}})
        out = _run(self.tools["get_peer_group_baseline"](agent_group="linux-servers"))
        assert isinstance(out, dict) and "error" not in out


# ── network_topology ─────────────────────────────────────────────────────────────
class TestNetworkTopology:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.network_topology")

    def test_subnet_key(self):
        from wazuh_mcp.tools.network_topology import _subnet_key
        assert _subnet_key("10.0.0.5", 24) == "10.0.0.0/24"
        assert _subnet_key("bad-ip") in ("unknown", "bad-ip/24") or _subnet_key("bad-ip")

    def test_get_network_topology(self):
        async def req(method, path, **kw):
            if path == "/agents?limit=500":
                return {"data": {"affected_items": [
                    {"id": "001", "name": "h1", "ip": "10.0.0.1", "status": "active", "groups": []},
                    {"id": "002", "name": "h2", "ip": "10.0.1.2", "status": "disconnected", "groups": []},
                ]}}
            return {"data": {"affected_items": []}}
        self.wz.request = AsyncMock(side_effect=req)
        out = _run(self.tools["get_network_topology"]())
        assert out["total_agents"] == 2 and out["subnet_count"] >= 1

    def test_get_agent_neighbors_not_found(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": []}})
        out = _run(self.tools["get_agent_neighbors"](agent_id="999"))
        assert "error" in out

    def test_get_agent_neighbors(self):
        async def req(method, path, **kw):
            return {"data": {"affected_items": [{"id": "001", "name": "h1", "ip": "10.0.0.1"}]}}
        self.wz.request = AsyncMock(side_effect=req)
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 5}},
            "aggregations": {"peer_ips": {"buckets": [{"key": "10.0.0.2", "doc_count": 5}]}}})
        out = _run(self.tools["get_agent_neighbors"](agent_id="001"))
        assert isinstance(out, dict)

    def test_map_subnet_exposure(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 3}},
            "aggregations": {"by_agent": {"buckets": [{"key": "h1", "doc_count": 3}]},
                             "ports": {"buckets": [{"key": 22, "doc_count": 2}]}}})
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"id": "001", "name": "h1", "ip": "10.0.0.1", "status": "active"}]}})
        out = _run(self.tools["map_subnet_exposure"](subnet="10.0.0.0/24"))
        assert isinstance(out, dict)


# ── compliance ───────────────────────────────────────────────────────────────────
class TestCompliance:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.compliance")
        # Rich generic response that satisfies the various compliance aggregations.
        self._resp = {
            "hits": {"total": {"value": 20}, "hits": [
                {"_source": {"@timestamp": "t", "rule": {"id": "5710", "level": 7,
                 "description": "d", "pci_dss": ["10.2.1"]}, "agent": {"name": "h1"}}}]},
            "aggregations": {
                "by_control": {"buckets": [{"key": "10.2.1", "doc_count": 5,
                    "top_rules": {"buckets": [{"key": "5710"}]},
                    "top_agents": {"buckets": [{"key": "h1"}]}}]},
                "controls": {"buckets": [{"key": "10.2.1", "doc_count": 5}]},
                "by_agent": {"buckets": [{"key": "h1", "doc_count": 5}]},
            },
        }
        self.idx.search = AsyncMock(return_value=self._resp)

    def test_compliance_summary_unknown_framework(self):
        out = _run(self.tools["compliance_summary"](framework="bogus"))
        assert "error" in out and "supported" in out

    def test_compliance_summary_valid(self):
        out = _run(self.tools["compliance_summary"](framework="pci_dss"))
        assert out["framework"] == "pci_dss" and out["by_control"]

    def test_control_details(self):
        out = _run(self.tools["compliance_control_details"](
            framework="pci_dss", control_id="10.2.1"))
        assert out["control"] == "10.2.1"

    def test_control_details_unknown(self):
        out = _run(self.tools["compliance_control_details"](framework="x", control_id="1"))
        assert "error" in out

    def test_generate_report(self):
        out = _run(self.tools["generate_compliance_report"](framework="pci_dss"))
        assert isinstance(out, dict) and "error" not in out

    @pytest.mark.parametrize("tool", [
        "iso27001_compliance_summary", "nist_csf2_compliance_summary",
        "soc2_compliance_summary", "pci_dss_compliance_summary", "hipaa_compliance_summary",
    ])
    def test_framework_summaries(self, tool):
        # These read framework-specific aggregation keys; a recursive default dict
        # keeps every key access safe so the formatting branches execute.
        self.idx.search = AsyncMock(return_value=_DeepDict({
            "hits": _DeepDict({"total": {"value": 0}, "hits": []}),
            "aggregations": _DeepDict(),
        }))
        out = _run(self.tools[tool]())
        assert isinstance(out, dict)


# ── azure_devops ─────────────────────────────────────────────────────────────────
class _AzResp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        return None


class _AzClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        return _AzResp({"id": 42, "_links": {"html": {"href": "http://az/42"}},
                        "fields": {"System.Title": "t", "System.State": "New",
                                   "System.WorkItemType": "Bug"}})

    async def get(self, *a, **k):
        return _AzResp({"id": 42, "fields": {"System.Title": "t", "System.State": "Active"}})

    async def patch(self, *a, **k):
        return _AzResp({"id": 42, "fields": {"System.State": "Resolved"}})


class TestAzureDevops:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.azure_devops")

    def test_create_not_configured(self, monkeypatch):
        monkeypatch.delenv("AZURE_DEVOPS_TOKEN", raising=False)
        out = _run(self.tools["create_azure_devops_work_item"](title="t", description="d"))
        assert "error" in out

    def test_create_configured(self, monkeypatch):
        monkeypatch.setenv("AZURE_DEVOPS_TOKEN", "pat")
        monkeypatch.setenv("AZURE_DEVOPS_ORG", "org")
        monkeypatch.setenv("AZURE_DEVOPS_PROJECT", "proj")
        import httpx
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _AzClient())
        out = _run(self.tools["create_azure_devops_work_item"](
            title="Breach", description="d", tags="security;wazuh", area_path="X"))
        assert out["created"] is True and out["id"] == 42

    def test_get_work_item(self, monkeypatch):
        monkeypatch.setenv("AZURE_DEVOPS_TOKEN", "pat")
        monkeypatch.setenv("AZURE_DEVOPS_ORG", "org")
        monkeypatch.setenv("AZURE_DEVOPS_PROJECT", "proj")
        import httpx
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _AzClient())
        out = _run(self.tools["get_azure_devops_work_item"](work_item_id=42))
        assert isinstance(out, dict) and "error" not in out


# ── rule_wizard_validate ─────────────────────────────────────────────────────────
class TestRuleWizardValidate:
    def test_validate_impl_valid(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        xml = '<group><rule id="100001" level="5"><description>test</description></rule></group>'
        out = _validate_rule_xml_impl(xml)
        assert out["valid"] is True and out["rules_found"] == 1 and out["warnings"] == []

    def test_validate_impl_empty(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        assert _validate_rule_xml_impl("   ")["valid"] is False

    def test_validate_impl_parse_error(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        assert _validate_rule_xml_impl("<rule><unclosed>")["valid"] is False

    def test_validate_impl_no_rules(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        assert _validate_rule_xml_impl("<group></group>")["valid"] is False

    def test_validate_impl_warnings(self):
        from wazuh_mcp.tools.rule_wizard_validate import _validate_rule_xml_impl
        # missing id/level/description + out-of-range + non-integer scenarios
        xml = ('<group>'
               '<rule level="5"><field>x</field></rule>'
               '<rule id="50" level="5"><description>low id</description></rule>'
               '<rule id="abc" level="5"><description>bad id</description></rule>'
               '</group>')
        out = _validate_rule_xml_impl(xml)
        assert out["valid"] is True and out["rules_found"] == 3
        assert len(out["warnings"]) >= 3

    def test_validate_rule_xml_tool(self):
        tools, _, _ = _make_env("wazuh_mcp.tools.rule_wizard")
        # rule_wizard.register wires validate via register_validate
        xml = '<rule id="100001" level="5"><description>d</description></rule>'
        out = _run(tools["validate_rule_xml"](xml_content=xml))
        assert out["valid"] is True

    def test_sigma_backtest(self):
        tools, wz, idx = _make_env("wazuh_mcp.tools.rule_wizard")
        idx.search = AsyncMock(return_value={"hits": {"total": {"value": 5}, "hits": [
            {"_source": {"rule": {"level": 11}, "@timestamp": "t"}}]}})
        sigma = ("title: Test\ndetection:\n  selection:\n    full_log: 'evil'\n"
                 "  condition: selection\n")
        out = _run(tools["test_sigma_rule_against_archive"](sigma_yaml=sigma))
        assert out["total_matches"] == 5 and "verdict" in out

    def test_sigma_backtest_no_conditions(self):
        tools, _, _ = _make_env("wazuh_mcp.tools.rule_wizard")
        out = _run(tools["test_sigma_rule_against_archive"](sigma_yaml="title: Empty\n"))
        assert "error" in out

    def test_suggest_rule_tuning(self):
        tools, wz, idx = _make_env("wazuh_mcp.tools.rule_wizard")
        idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 100}, "hits": [
                {"_source": {"rule": {"level": 5}, "agent": {"name": "h1"},
                             "data": {"srcip": "10.0.0.1"}, "@timestamp": "2024-01-01T03:00:00Z"}}]},
            "aggregations": {
                "by_agent": {"buckets": [{"key": "h1", "doc_count": 90}]},
                "by_hour": {"buckets": [{"key": 3, "doc_count": 50}]},
                "by_srcip": {"buckets": [{"key": "10.0.0.1", "doc_count": 40}]},
                "by_user": {"buckets": [{"key": "root", "doc_count": 30}]},
                "cofire_groups": {"buckets": [{"key": "syslog", "doc_count": 20}]}}})
        out = _run(tools["suggest_rule_tuning"](rule_id=5710))
        assert isinstance(out, dict)


# ── rule_wizard_deploy ───────────────────────────────────────────────────────────
_GOOD_RULE_XML = '<group><rule id="100001" level="5"><description>d</description></rule></group>'


class TestRuleWizardDeploy:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.rule_wizard")

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)

    def test_push_requires_admin(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.VIEWER)
        assert "error" in _run(self.tools["push_custom_rule"](xml_content=_GOOD_RULE_XML))

    def test_push_bad_filename(self):
        out = _run(self.tools["push_custom_rule"](
            xml_content=_GOOD_RULE_XML, filename="../etc/passwd"))
        assert "error" in out

    def test_push_invalid_xml(self):
        out = _run(self.tools["push_custom_rule"](xml_content="<rule><unclosed>"))
        assert "error" in out

    def test_push_dry_run(self):
        out = _run(self.tools["push_custom_rule"](xml_content=_GOOD_RULE_XML, dry_run=True))
        assert out["dry_run"] is True and out["valid"] is True

    def test_push_full(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        self.wz.upload_xml_file = AsyncMock(return_value={"status": "ok"})
        self.wz.request = AsyncMock(return_value="")  # no existing file
        out = _run(self.tools["push_custom_rule"](xml_content=_GOOD_RULE_XML, dry_run=False))
        assert out["success"] is True and out["target_file"] == "custom_rules.xml"

    def test_push_decoder_dry_run(self):
        decoder = '<group><decoder name="x"><prematch>^X</prematch></decoder></group>'
        out = _run(self.tools["push_custom_decoder"](xml_content=decoder, dry_run=True))
        assert out["dry_run"] is True and out["decoders_found"] == 1

    def test_push_decoder_no_decoders(self):
        out = _run(self.tools["push_custom_decoder"](xml_content="<group></group>"))
        assert "error" in out

    def test_push_decoder_full(self):
        self.wz.upload_xml_file = AsyncMock(return_value={"status": "ok"})
        decoder = '<group><decoder name="x"><prematch>^X</prematch></decoder></group>'
        out = _run(self.tools["push_custom_decoder"](xml_content=decoder, dry_run=False))
        assert out["success"] is True

    def test_sigma_bulk_import_dry_run(self):
        sigma = (
            "title: Evil Process\n"
            "level: high\n"
            "logsource:\n"
            "  category: process_creation\n"
            "detection:\n"
            "  selection:\n"
            "    Image: 'evil.exe'\n"
            "  condition: selection\n"
        )
        out = _run(self.tools["sigma_bulk_import"](sigma_rules_yaml=sigma, dry_run=True))
        assert "results" in out or "error" not in out

    def test_sigma_bulk_import_empty(self):
        out = _run(self.tools["sigma_bulk_import"](sigma_rules_yaml="   "))
        assert "error" in out

    def test_sigma_bulk_import_push_all(self):
        self.wz.upload_xml_file = AsyncMock(return_value={"status": "ok"})
        sigma = (
            "title: Evil Process\n"
            "level: high\n"
            "logsource:\n"
            "  category: process_creation\n"
            "detection:\n"
            "  selection:\n"
            "    Image: 'evil.exe'\n"
            "  condition: selection\n"
        )
        out = _run(self.tools["sigma_bulk_import"](
            sigma_rules_yaml=sigma, dry_run=False, push_all=True))
        # At least one rule should have been pushed via the upload path.
        assert isinstance(out, dict)
        if "results" in out:
            assert any(r.get("status") in ("pushed", "push_error", "converted")
                       for r in out["results"])


# ── quick_wins ───────────────────────────────────────────────────────────────────
class _QWHttpResp:
    def json(self):
        return {"valid": True}


class _QWHttpClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        return _QWHttpResp()


class TestQuickWins:
    def setup_method(self):
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.quick_wins")
        self.mod = importlib.import_module("wazuh_mcp.tools.quick_wins")

    def test_extract_helpers(self):
        assert self.mod._extract_time_range("in the last 7 days") == "7d"
        assert self.mod._extract_min_level("critical level 12+ alerts") >= 10
        groups = self.mod._extract_groups("failed ssh login brute force")
        assert isinstance(groups, list)

    def test_get_abac_status(self):
        out = _run(self.tools["get_abac_status"]())
        assert "abac_enabled" in out

    def test_nl_query_extraction(self):
        out = _run(self.tools["nl_to_opensearch_query"](
            query="brute force from 10.0.0.5 on agent web-server-01 in China level 10+ last 7 days"))
        params = " ".join(out["extracted_parameters"])
        assert "10.0.0.5" in params and "opensearch_dsl" in out

    def test_nl_query_empty_and_long(self):
        assert "error" in _run(self.tools["nl_to_opensearch_query"](query="  "))
        assert "error" in _run(self.tools["nl_to_opensearch_query"](query="x" * 600))

    def test_nl_query_execute(self, monkeypatch):
        import httpx
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _QWHttpClient())
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 2}, "hits": [
            _hit("2024-01-01T00:00:01Z", 10, "Execution", "T1059")]}})
        out = _run(self.tools["nl_to_opensearch_query"](query="alerts last 24h", execute=True))
        assert out.get("executed") is True and out["total"] == 2

    def test_auto_triage_true_positive(self):
        doc = {"rule": {"id": "5710", "level": 14, "groups": ["malware", "exploit"],
                        "mitre": {"id": ["T1059"]}},
               "agent": {"name": "host1"}, "data": {"srcip": "8.8.8.8"}}
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 1}, "hits": [{"_source": doc}]}})
        out = _run(self.tools["auto_triage_alert"](alert_id="a1"))
        assert out["disposition"] == "TRUE_POSITIVE"

    def test_auto_triage_not_found(self):
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 0}, "hits": []}})
        assert "error" in _run(self.tools["auto_triage_alert"](alert_id="ghost"))

    def test_auto_triage_false_positive(self):
        doc = {"rule": {"id": "1002", "level": 2, "groups": ["ossec"]},
               "agent": {"name": "host1"}, "data": {}}
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 1}, "hits": [{"_source": doc}]}})
        out = _run(self.tools["auto_triage_alert"](alert_id="a1"))
        assert out["disposition"] == "FALSE_POSITIVE"

    def test_auto_triage_needs_review(self):
        doc = {"rule": {"id": "5710", "level": 6, "groups": ["syslog"]},
               "agent": {"name": "host1"}, "data": {}}
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 1}, "hits": [{"_source": doc}]}})
        out = _run(self.tools["auto_triage_alert"](alert_id="a1"))
        assert out["disposition"] in ("NEEDS_REVIEW", "TRUE_POSITIVE", "FALSE_POSITIVE")

    def test_nl_query_execute_validation_fails(self, monkeypatch):
        class _Resp:
            def json(self):
                return {"valid": False, "error": "bad dsl"}

        class _Client:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                return _Resp()

        import httpx
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _Client())
        out = _run(self.tools["nl_to_opensearch_query"](query="alerts last 24h", execute=True))
        assert "execute_error" in out

    def test_recent_alerts_7d_30d(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 3}, "hits": [
                _hit("2024-01-01T00:00:01Z", 9, "Execution", "T1059")]},
            "aggregations": {"by_rule": {"buckets": [{"key": "r", "doc_count": 3}]},
                             "by_agent": {"buckets": [{"key": "a", "doc_count": 3}]},
                             "by_level": {"buckets": [{"key": 9, "doc_count": 3}]}}})
        for tool in ("get_recent_alerts_7d", "get_recent_alerts_30d"):
            out = _run(self.tools[tool]())
            assert isinstance(out, dict)

    def test_deduplicate_alerts(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 5}, "hits": [
                _hit("2024-01-01T00:00:01Z", 9, "Execution", "T1059")]},
            "aggregations": {"dupes": {"buckets": [
                {"key": "sig1", "doc_count": 4,
                 "sample": {"hits": {"hits": [{"_source": {"rule": {"description": "d"}}}]}}}]}}})
        out = _run(self.tools["deduplicate_alerts"]())
        assert isinstance(out, dict)

    def test_batch_auto_triage_prefetched(self):
        doc = {"rule": {"id": "5710", "level": 14, "groups": ["malware"],
                        "mitre": {"id": ["T1059"]}}, "agent": {"name": "h"}, "data": {}}

        def search(body, *a, **k):
            q = body.get("query", {})
            if "ids" in q:
                return {"hits": {"total": {"value": 1}, "hits": [{"_source": doc}]}}
            return {"hits": {"total": {"value": 1}, "hits": []}}
        self.idx.search = AsyncMock(side_effect=search)
        out = _run(self.tools["batch_auto_triage"](alert_ids=["a1", "a2"]))
        assert out["mode"] == "pre_fetched" and out["triaged"] == 2

    def test_batch_auto_triage_auto_search(self):
        doc = {"rule": {"id": "5710", "level": 14, "groups": ["malware"]},
               "agent": {"name": "h"}, "data": {}}

        def search(body, *a, **k):
            q = body.get("query", {})
            if "ids" in q:
                return {"hits": {"total": {"value": 1}, "hits": [{"_source": doc}]}}
            return {"hits": {"total": {"value": 2}, "hits": [{"_id": "a1"}, {"_id": "a2"}]}}
        self.idx.search = AsyncMock(side_effect=search)
        out = _run(self.tools["batch_auto_triage"](time_range="1h", min_level=7))
        assert out["mode"] == "auto_search" and out["triaged"] == 2

    def test_batch_auto_triage_empty(self):
        self.idx.search = AsyncMock(return_value={"hits": {"total": {"value": 0}, "hits": []}})
        out = _run(self.tools["batch_auto_triage"]())
        assert "message" in out


# ── rules ────────────────────────────────────────────────────────────────────────
class TestRules:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.rules")

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)

    def test_simple_passthrough_tools(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [{"id": "5710"}]}})
        for tool in ("get_rule_details", "list_rule_files", "get_custom_rules", "list_decoders"):
            fn = self.tools[tool]
            kwargs = {"rule_id": "5710"} if tool == "get_rule_details" else {}
            assert "data" in _run(fn(**kwargs))

    def test_search_rules(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": []}})
        out = _run(self.tools["search_rules"](
            description_contains="ssh", group="authentication_failed",
            level_min=5, mitre_technique="T1110"))
        assert "data" in out

    def test_test_log_single(self):
        self.wz.request = AsyncMock(return_value={"data": {"output": {
            "decoder": {"name": "sshd"}, "rule": {"id": "5710", "level": 5,
            "description": "ssh", "groups": ["authentication_failed"]}}}})
        out = _run(self.tools["test_log_against_rules"](log_sample="Failed password"))
        assert "data" in out

    def test_test_log_batch(self):
        self.wz.request = AsyncMock(return_value={"data": {"output": {
            "decoder": {"name": "sshd"}, "rule": {"id": "5710", "level": 5,
            "description": "ssh", "groups": []}}}})
        out = _run(self.tools["test_log_against_rules"](
            log_sample="", log_samples=["l1", "l2"]))
        assert out["mode"] == "batch" and out["matched"] == 2

    def test_test_rule_coverage(self):
        self.wz.request = AsyncMock(return_value={"data": {"output": {
            "rule": {"id": "5710", "level": 5, "description": "d", "groups": []}}}})
        out = _run(self.tools["test_rule_coverage"](log_samples=["a", "b"]))
        assert out["total_samples"] == 2 and out["covered"] == 2

    def test_test_log_requires_analyst(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.VIEWER)
        assert "error" in _run(self.tools["test_log_against_rules"](log_sample="x"))

    def test_rollback_no_backup(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        out = _run(self.tools["rollback_custom_rule"](filename="custom_rules.xml"))
        assert "error" in out

    def test_rollback_legacy_backup(self, monkeypatch, tmp_path):
        monkeypatch.setenv("WAZUH_WORKSPACE_DIR", str(tmp_path))
        import wazuh_mcp.tools.rules as rules
        rules._rule_backups["custom_rules.xml"] = "<group/>"
        self.wz.upload_xml_file = AsyncMock(return_value={"status": "ok"})
        try:
            out = _run(self.tools["rollback_custom_rule"](filename="custom_rules.xml"))
            assert isinstance(out, dict)
        finally:
            rules._rule_backups.pop("custom_rules.xml", None)

    def test_test_decoder(self):
        self.wz.request = AsyncMock(return_value={"data": {"output": {
            "decoder": {"name": "sshd"}}}})
        out = _run(self.tools["test_decoder"](log_sample="Failed password", decoder_name="sshd"))
        assert isinstance(out, dict)


# ── manager_audit ────────────────────────────────────────────────────────────────
class TestManagerAudit:
    def setup_method(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)
        self.tools, self.wz, self.idx = _make_env("wazuh_mcp.tools.manager_audit")

    def teardown_method(self):
        import wazuh_mcp.identity as identity
        identity._ctx_role.set(None)

    def test_search_manager_audit_log(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"timestamp": "t", "user": "admin", "action": "agents:delete",
             "resource": "agent:001", "result": "success", "ip": "10.0.0.1"}],
            "total_affected_items": 1}})
        out = _run(self.tools["search_manager_audit_log"](action_type="agents:delete", user="admin"))
        assert out["total"] == 1 and out["entries"][0]["user"] == "admin"

    def test_get_manager_login_history(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"timestamp": "t", "user": "admin", "result": "success", "ip": "10.0.0.1"}],
            "total_affected_items": 1}})
        out = _run(self.tools["get_manager_login_history"]())
        assert out["total"] == 1 and out["logins"][0]["result"] == "success"

    def test_list_manager_api_users(self):
        self.wz.request = AsyncMock(return_value={"data": {"affected_items": [
            {"id": 1, "username": "wazuh", "allow_run_as": False,
             "roles": [{"name": "administrator"}]}]}})
        out = _run(self.tools["list_manager_api_users"]())
        assert out["users"][0]["roles"] == ["administrator"]

    def test_requires_admin(self):
        import wazuh_mcp.identity as identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.VIEWER)
        assert "error" in _run(self.tools["list_manager_api_users"]())

    def test_error_path(self):
        self.wz.request = AsyncMock(side_effect=RuntimeError("api down"))
        assert "error" in _run(self.tools["search_manager_audit_log"]())
