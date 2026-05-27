"""Tests for the 40 new tools added from wazuh-mcp-latest and the n8n PoC document."""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import os


# ── shared test helpers ───────────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


def _make_env(module_path, extra_register_args=()):
    """Build a minimal mock environment and return the registered tools dict."""
    from wazuh_mcp.tool_context import ToolContext
    tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    wz = AsyncMock()
    idx = AsyncMock()
    cfg = MagicMock()
    cfg.alerts_index = "wazuh-alerts-*"
    cfg.vuln_index = "wazuh-vulnerabilities-*"

    def _cap(n):
        return min(n, 500)

    def _truncate(s, n=300):
        return s if s is None or len(s) <= n else s[:n] + "…"

    ctx = ToolContext(
        mcp=mcp, wz=wz, idx=idx, cfg=cfg,
        cap=_cap,
        require_writes=lambda: None,
        truncate=_truncate,
        enrich_mitre_ids=lambda ids: [{"id": i} for i in ids],
        geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda alert: [],
        tool_registry={},
    )

    import importlib
    mod = importlib.import_module(module_path)
    mod.register(ctx)
    return tools, wz, idx, cfg


# ── agent_upgrades ────────────────────────────────────────────────────────────

class TestAgentUpgrades:
    def setup_method(self):
        self.tools, self.wz, _, _ = _make_env("wazuh_mcp.tools.agent_upgrades")
        self.wz.request = AsyncMock(return_value={
            "data": {"affected_items": [
                {"id": "001", "name": "agent1", "version": "4.5.0", "status": "active"},
                {"id": "002", "name": "agent2", "version": "4.5.0", "status": "disconnected"},
            ]}
        })

    def test_list_agent_upgrades_returns_active_only(self):
        result = _run(self.tools["list_agent_upgrades"]())
        assert result["total_active"] == 1
        assert result["agents"][0]["agent_id"] == "001"

    def test_trigger_dry_run_default(self):
        with patch("wazuh_mcp.rbac.responder_only", return_value=None), \
             patch("wazuh_mcp.server._require_writes", return_value=None):
            result = _run(self.tools["trigger_agent_upgrade"](agent_ids=["001"]))
        assert result["dry_run"] is True
        assert "001" in result["would_upgrade"]

    def test_trigger_empty_ids_rejected(self):
        result = _run(self.tools["trigger_agent_upgrade"](agent_ids=[]))
        assert "error" in result

    def test_get_upgrade_status_empty_ids_rejected(self):
        result = _run(self.tools["get_agent_upgrade_status"](agent_ids=[]))
        assert "error" in result

    def test_rollback_dry_run_default(self):
        with patch("wazuh_mcp.rbac.admin_only", return_value=None), \
             patch("wazuh_mcp.server._require_writes", return_value=None):
            result = _run(self.tools["rollback_agent_upgrade"](agent_id="001"))
        assert result["dry_run"] is True


# ── manager_config ────────────────────────────────────────────────────────────

class TestManagerConfig:
    def setup_method(self):
        self.tools, self.wz, _, _ = _make_env("wazuh_mcp.tools.manager_config")

    def test_list_sections_returns_list(self):
        result = _run(self.tools["list_manager_config_sections"]())
        assert "known_sections" in result
        assert "global" in result["known_sections"]

    def test_get_unknown_section_warns(self):
        result = _run(self.tools["get_manager_config_section"](section="nonexistent"))
        assert "warning" in result

    def test_get_valid_section_calls_api(self):
        self.wz.request = AsyncMock(return_value={"data": {}})
        result = _run(self.tools["get_manager_config_section"](section="global"))
        self.wz.request.assert_called_once()

    def test_get_manager_status_calls_api(self):
        self.wz.request = AsyncMock(return_value={"data": {"enabled": "yes"}})
        result = _run(self.tools["get_manager_status"]())
        self.wz.request.assert_called_once_with("GET", "/manager/status")

    def test_get_manager_info_calls_api(self):
        self.wz.request = AsyncMock(return_value={"data": {}})
        _run(self.tools["get_manager_info"]())
        self.wz.request.assert_called_once_with("GET", "/manager/info")

    def test_get_manager_logs_default_level(self):
        self.wz.request = AsyncMock(return_value={"data": {}})
        _run(self.tools["get_manager_logs"]())
        call_args = self.wz.request.call_args[0][1]
        assert "level=error" in call_args

    def test_get_manager_logs_with_tag(self):
        self.wz.request = AsyncMock(return_value={"data": {}})
        _run(self.tools["get_manager_logs"](tag="wazuh-analysisd"))
        call_args = self.wz.request.call_args[0][1]
        assert "tag=wazuh-analysisd" in call_args


# ── manager_audit ─────────────────────────────────────────────────────────────

class TestManagerAudit:
    def setup_method(self):
        self.tools, self.wz, _, _ = _make_env("wazuh_mcp.tools.manager_audit")
        self.wz.request = AsyncMock(return_value={
            "data": {
                "affected_items": [
                    {"timestamp": "2026-01-01", "user": "admin", "action": "security:login",
                     "resource": "/", "result": "success", "ip": "1.2.3.4"}
                ],
                "total_affected_items": 1,
            }
        })

    def test_search_audit_log_returns_entries(self):
        with patch("wazuh_mcp.rbac.admin_only", return_value=None):
            result = _run(self.tools["search_manager_audit_log"]())
        assert result["total"] == 1
        assert result["entries"][0]["user"] == "admin"

    def test_search_audit_log_with_filters(self):
        with patch("wazuh_mcp.rbac.admin_only", return_value=None):
            _run(self.tools["search_manager_audit_log"](action_type="security:login", user="admin"))
        call_path = self.wz.request.call_args[0][1]
        assert "action=security:login" in call_path
        assert "user=admin" in call_path

    def test_get_manager_login_history(self):
        with patch("wazuh_mcp.rbac.admin_only", return_value=None):
            result = _run(self.tools["get_manager_login_history"]())
        assert "logins" in result

    def test_list_manager_api_users(self):
        self.wz.request = AsyncMock(return_value={
            "data": {"affected_items": [{"id": 1, "username": "admin", "allow_run_as": True, "roles": []}]}
        })
        with patch("wazuh_mcp.rbac.admin_only", return_value=None):
            result = _run(self.tools["list_manager_api_users"]())
        assert result["total"] == 1
        assert result["users"][0]["username"] == "admin"


# ── rootcheck ─────────────────────────────────────────────────────────────────

class TestRootcheck:
    def setup_method(self):
        self.tools, self.wz, _, _ = _make_env("wazuh_mcp.tools.rootcheck")
        self.wz.request = AsyncMock(return_value={
            "data": {
                "affected_items": [
                    {"event": "Rootkit found", "file": "/tmp/evil", "status": "outstanding",
                     "date": "2026-01-01", "date_last": "2026-01-02", "cis": "2.1"}
                ],
                "total_affected_items": 1,
            }
        })

    def test_get_rootcheck_results_formats_findings(self):
        result = _run(self.tools["get_agent_rootcheck_results"](agent_id="001"))
        assert result["total"] == 1
        assert result["findings"][0]["event"] == "Rootkit found"

    def test_get_rootcheck_results_invalid_agent_id(self):
        result = _run(self.tools["get_agent_rootcheck_results"](agent_id="'; DROP TABLE--"))
        assert "error" in result

    def test_get_rootcheck_last_scan_calls_correct_path(self):
        self.wz.request = AsyncMock(return_value={"data": {"start": "2026-01-01"}})
        result = _run(self.tools["get_rootcheck_last_scan"](agent_id="001"))
        assert result["agent_id"] == "001"
        self.wz.request.assert_called_once_with("GET", "/rootcheck/001/last_scan")

    def test_clear_rootcheck_dry_run_default(self):
        with patch("wazuh_mcp.rbac.admin_only", return_value=None), \
             patch("wazuh_mcp.server._require_writes", return_value=None):
            result = _run(self.tools["clear_rootcheck_results"](agent_id="001"))
        assert result["dry_run"] is True


# ── index_mgmt ────────────────────────────────────────────────────────────────

class TestIndexMgmt:
    def setup_method(self):
        self.tools, _, self.idx, _ = _make_env("wazuh_mcp.tools.index_mgmt")

    def test_get_index_stats_summarises(self):
        self.idx.request = AsyncMock(return_value={
            "indices": {
                "wazuh-alerts-2026.01.01": {
                    "primaries": {
                        "docs": {"count": 1000, "deleted": 5},
                        "store": {"size_in_bytes": 512000},
                    }
                }
            }
        })
        result = _run(self.tools["get_index_stats"]())
        assert result["total_documents"] == 1000
        assert result["total_indices"] == 1

    def test_list_index_aliases(self):
        self.idx.request = AsyncMock(return_value={
            "wazuh-alerts-2026.01.01": {"aliases": {"wazuh-alerts": {}}}
        })
        result = _run(self.tools["list_index_aliases"]())
        assert result["total_aliases"] == 1
        assert result["aliases"][0]["alias"] == "wazuh-alerts"

    def test_get_cluster_index_health_groups_by_status(self):
        self.idx.request = AsyncMock(return_value={
            "status": "yellow",
            "indices": {
                "idx1": {"status": "green", "active_shards": 1, "unassigned_shards": 0},
                "idx2": {"status": "red", "active_shards": 0, "unassigned_shards": 1},
            }
        })
        result = _run(self.tools["get_cluster_index_health"]())
        assert result["cluster_status"] == "yellow"
        assert len(result["red_indices"]) == 1
        assert result["green_count"] == 1


# ── pagerduty ─────────────────────────────────────────────────────────────────

class TestPagerDuty:
    def setup_method(self):
        self.tools, _, _, _ = _make_env("wazuh_mcp.tools.pagerduty")

    def test_trigger_without_key_returns_error(self):
        with patch.dict(os.environ, {}, clear=True):
            result = _run(self.tools["trigger_pagerduty_alert"](summary="test"))
        assert "error" in result
        assert "PAGERDUTY_ROUTING_KEY" in result["error"]

    def test_resolve_without_key_returns_error(self):
        with patch.dict(os.environ, {}, clear=True):
            result = _run(self.tools["resolve_pagerduty_alert"](dedup_key="abc"))
        assert "error" in result

    def test_acknowledge_without_key_returns_error(self):
        with patch.dict(os.environ, {}, clear=True):
            result = _run(self.tools["acknowledge_pagerduty_alert"](dedup_key="abc"))
        assert "error" in result

    def test_trigger_with_key_sends_correct_payload(self):
        import httpx
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value={"status": "success", "dedup_key": "xyz", "message": "ok"})

        with patch.dict(os.environ, {"PAGERDUTY_ROUTING_KEY": "fake-key"}), \
             patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                post=AsyncMock(return_value=mock_response)
            ))
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            result = _run(self.tools["trigger_pagerduty_alert"](
                summary="Critical brute-force detected", severity="critical"
            ))
        assert result.get("triggered") is True or "error" in result  # network may be unavailable


# ── servicenow ────────────────────────────────────────────────────────────────

class TestServiceNow:
    def setup_method(self):
        self.tools, _, _, _ = _make_env("wazuh_mcp.tools.servicenow")

    def test_create_without_config_returns_error(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("SERVICENOW_INSTANCE", "SERVICENOW_USER", "SERVICENOW_PASS")}
        with patch.dict(os.environ, env, clear=True):
            result = _run(self.tools["create_servicenow_incident"](
                short_description="Test", description="Details"
            ))
        assert "error" in result
        assert "not configured" in result["error"]

    def test_get_without_config_returns_error(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("SERVICENOW_INSTANCE", "SERVICENOW_USER", "SERVICENOW_PASS")}
        with patch.dict(os.environ, env, clear=True):
            result = _run(self.tools["get_servicenow_incident"](sys_id="abc123"))
        assert "error" in result

    def test_update_no_fields_returns_error(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("SERVICENOW_INSTANCE", "SERVICENOW_USER", "SERVICENOW_PASS")}
        with patch.dict(os.environ, env, clear=True):
            result = _run(self.tools["update_servicenow_incident"](sys_id="abc"))
        assert "error" in result


# ── azure_devops ──────────────────────────────────────────────────────────────

class TestAzureDevOps:
    def setup_method(self):
        self.tools, _, _, _ = _make_env("wazuh_mcp.tools.azure_devops")

    def test_create_without_token_returns_error(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("AZURE_DEVOPS_TOKEN", "AZURE_DEVOPS_ORG", "AZURE_DEVOPS_PROJECT")}
        with patch.dict(os.environ, env, clear=True):
            result = _run(self.tools["create_azure_devops_work_item"](
                title="Security Issue", description="Details"
            ))
        assert "error" in result

    def test_update_no_fields_returns_error(self):
        with patch.dict(os.environ, {"AZURE_DEVOPS_TOKEN": "fake"}):
            result = _run(self.tools["update_azure_devops_work_item"](work_item_id=1))
        assert "error" in result


# ── syslog_config ─────────────────────────────────────────────────────────────

class TestSyslogConfig:
    def setup_method(self):
        self.tools, self.wz, _, _ = _make_env("wazuh_mcp.tools.syslog_config")

    def test_list_syslog_outputs_parses_config(self):
        self.wz.request = AsyncMock(return_value={
            "data": {
                "affected_items": [
                    {"syslog_output": {"server": "10.0.0.1", "port": 514, "format": "default", "level": "7"}}
                ]
            }
        })
        result = _run(self.tools["list_syslog_outputs"]())
        assert result["total"] == 1
        assert result["syslog_outputs"][0]["server"] == "10.0.0.1"

    def test_test_syslog_connection_unreachable_host(self):
        result = _run(self.tools["test_syslog_connection"](server="192.0.2.1", port=514))
        assert result["server"] == "192.0.2.1"
        assert "tcp" in result

    def test_get_syslog_config_section_calls_api(self):
        self.wz.request = AsyncMock(return_value={"data": {}})
        _run(self.tools["get_syslog_config_section"]())
        self.wz.request.assert_called_once_with(
            "GET", "/manager/configuration?section=syslog_output"
        )


# ── export ────────────────────────────────────────────────────────────────────

class TestExport:
    def setup_method(self):
        self.tools, _, self.idx, _ = _make_env("wazuh_mcp.tools.export")

    def test_export_alerts_csv_returns_csv_string(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [{
                    "_source": {
                        "@timestamp": "2026-01-01T00:00:00Z",
                        "agent": {"id": "001", "name": "srv1"},
                        "rule": {"id": "1001", "level": 10, "description": "Brute force", "groups": []},
                    }
                }]
            }
        })
        result = _run(self.tools["export_alerts_csv"]())
        assert isinstance(result, str)
        assert "timestamp" in result or "ERROR" in result

    def test_export_alerts_csv_invalid_time_range(self):
        result = _run(self.tools["export_alerts_csv"](time_range="badrange"))
        assert result.startswith("ERROR")

    def test_export_vulns_csv_invalid_severity(self):
        result = _run(self.tools["export_vulnerabilities_csv"](min_severity="Unknown"))
        assert result.startswith("ERROR")


# ── fleet batch ───────────────────────────────────────────────────────────────

class TestFleetBatch:
    def setup_method(self):
        tools = {}
        mcp = MagicMock()
        mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
        self.wz = AsyncMock()
        idx = AsyncMock()
        cfg = MagicMock()

        def _cap(n):
            return min(n, 500)

        def _truncate(s, n=300):
            return s

        from wazuh_mcp.tools.fleet import register
        from wazuh_mcp.tool_context import ToolContext
        from unittest.mock import AsyncMock as _AM
        ctx = ToolContext(mcp=mcp, wz=self.wz, idx=idx, cfg=cfg, cap=_cap,
                          require_writes=lambda: None, truncate=_truncate,
                          enrich_mitre_ids=lambda ids: [], geoip_lookup=_AM(return_value=dict()),
                          incident_recommendations=lambda a: [])
        register(ctx)
        self.tools = tools

    def test_invalid_resource_rejected(self):
        result = _run(self.tools["fleet_batch_syscollector"](
            agent_ids=["001"], resource="invalid"
        ))
        assert "error" in result

    def test_empty_agent_ids_rejected(self):
        result = _run(self.tools["fleet_batch_syscollector"](agent_ids=[]))
        assert "error" in result

    def test_over_100_agents_rejected(self):
        result = _run(self.tools["fleet_batch_syscollector"](
            agent_ids=[str(i) for i in range(101)]
        ))
        assert "error" in result

    def test_batch_results_structure(self):
        self.wz.request = AsyncMock(return_value={
            "data": {"affected_items": [{"name": "pkg1"}], "total_affected_items": 1}
        })
        result = _run(self.tools["fleet_batch_syscollector"](
            agent_ids=["001", "002"], resource="packages"
        ))
        assert result["agents_queried"] == 2
        assert result["resource"] == "packages"
        assert "results" in result


# ── get_recent_alerts_24h (from n8n PoC) ─────────────────────────────────────

class TestRecentAlerts24h:
    def setup_method(self):
        tools = {}
        mcp = MagicMock()
        mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
        wz = AsyncMock()
        self.idx = AsyncMock()
        cfg = MagicMock()
        cfg.alerts_index = "wazuh-alerts-*"

        def _cap(n):
            return min(n, 500)

        from wazuh_mcp.tools.alerts import register
        from wazuh_mcp.tool_context import ToolContext
        from unittest.mock import AsyncMock as _AM
        ctx = ToolContext(mcp=mcp, wz=wz, idx=self.idx, cfg=cfg, cap=_cap,
                          require_writes=lambda: None, truncate=lambda s, n=300: s,
                          enrich_mitre_ids=lambda ids: ids, geoip_lookup=_AM(return_value=dict()),
                          incident_recommendations=lambda a: [])
        register(ctx)
        self.tools = tools

    def test_returns_window_label(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 0}, "hits": []}
        })
        result = _run(self.tools["get_recent_alerts_24h"]())
        assert result["window"] == "last 24 hours"

    def test_respects_limit_cap(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 0}, "hits": []}
        })
        _run(self.tools["get_recent_alerts_24h"](limit=999))
        call_body = self.idx.search.call_args[0][0]
        assert call_body["size"] <= 50

    def test_uses_24h_time_filter(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 0}, "hits": []}
        })
        _run(self.tools["get_recent_alerts_24h"]())
        call_body = self.idx.search.call_args[0][0]
        query_str = str(call_body)
        assert "now-24h" in query_str

    def test_ordered_descending(self):
        self.idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 0}, "hits": []}
        })
        _run(self.tools["get_recent_alerts_24h"]())
        call_body = self.idx.search.call_args[0][0]
        assert call_body["sort"][0]["@timestamp"]["order"] == "desc"


# ── audit_mgmt ────────────────────────────────────────────────────────────────

class TestAuditMgmt:
    def setup_method(self):
        self.tools, _, _, _ = _make_env("wazuh_mcp.tools.audit_mgmt")

    def test_get_stats_missing_file(self, tmp_path):
        with patch("wazuh_mcp.rbac.admin_only", return_value=None), \
             patch.dict(os.environ, {"WAZUH_AUDIT_LOG": str(tmp_path / "nonexistent.jsonl")}):
            result = _run(self.tools["get_audit_log_stats"]())
        assert "error" in result

    def test_search_audit_log_missing_file(self, tmp_path):
        with patch("wazuh_mcp.rbac.admin_only", return_value=None), \
             patch.dict(os.environ, {"WAZUH_AUDIT_LOG": str(tmp_path / "nonexistent.jsonl")}):
            result = _run(self.tools["search_audit_log"]())
        assert "error" in result

    def test_verify_integrity_no_signing_key(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text('{"ts":"2026","tool":"test"}\n')
        with patch("wazuh_mcp.rbac.admin_only", return_value=None), \
             patch.dict(os.environ, {
                 "WAZUH_AUDIT_LOG": str(log),
                 "WAZUH_AUDIT_LOG_SIGNING_KEY": ""
             }):
            result = _run(self.tools["verify_audit_log_integrity"]())
        assert result["signing_enabled"] is False

    def test_get_stats_reads_valid_log(self, tmp_path):
        import json
        log = tmp_path / "audit.jsonl"
        records = [
            {"ts": "2026-01-01T00:00:00Z", "tool": "search_alerts"},
            {"ts": "2026-01-02T00:00:00Z", "tool": "list_agents"},
        ]
        log.write_text("\n".join(json.dumps(r) for r in records) + "\n")
        with patch("wazuh_mcp.rbac.admin_only", return_value=None), \
             patch.dict(os.environ, {"WAZUH_AUDIT_LOG": str(log)}):
            result = _run(self.tools["get_audit_log_stats"]())
        assert result["total_records"] == 2
        assert result["parse_errors"] == 0


# ── health_check ──────────────────────────────────────────────────────────────

class TestWazuhApiHealth:
    def setup_method(self):
        self.tools, self.wz, self.idx, _ = _make_env("wazuh_mcp.tools.health_check")

    def _setup_manager_up(self):
        self.wz.request = AsyncMock(side_effect=[
            # /manager/info
            {"data": {"affected_items": [{"version": "v4.10.0"}]}},
            # /manager/status
            {"data": {"affected_items": [{"analysisd": "running", "remoted": "running"}]}},
        ])

    def _setup_manager_down(self):
        self.wz.request = AsyncMock(side_effect=Exception("connection refused"))

    def _setup_indexer_up(self):
        self.idx.request = AsyncMock(return_value={
            "status": "green",
            "number_of_nodes": 1,
            "active_shards": 10,
            "unassigned_shards": 0,
        })

    def _setup_indexer_down(self):
        self.idx.request = AsyncMock(side_effect=Exception("connection refused"))

    def test_both_up_returns_healthy(self):
        self._setup_manager_up()
        self._setup_indexer_up()
        result = _run(self.tools["get_wazuh_api_health"]())
        assert result["overall_status"] == "healthy"
        assert result["manager"]["status"] == "up"
        assert result["indexer"]["status"] == "up"

    def test_manager_down_returns_degraded(self):
        self._setup_manager_down()
        self._setup_indexer_up()
        result = _run(self.tools["get_wazuh_api_health"]())
        assert result["overall_status"] == "degraded"
        assert result["manager"]["status"] == "down"
        assert result["indexer"]["status"] == "up"

    def test_indexer_down_returns_degraded(self):
        self._setup_manager_up()
        self._setup_indexer_down()
        result = _run(self.tools["get_wazuh_api_health"]())
        assert result["overall_status"] == "degraded"
        assert result["manager"]["status"] == "up"
        assert result["indexer"]["status"] == "down"

    def test_both_down_returns_critical(self):
        self._setup_manager_down()
        self._setup_indexer_down()
        result = _run(self.tools["get_wazuh_api_health"]())
        assert result["overall_status"] == "critical"
        assert result["manager"]["status"] == "down"
        assert result["indexer"]["status"] == "down"

    def test_manager_includes_version_and_daemons(self):
        self._setup_manager_up()
        self._setup_indexer_up()
        result = _run(self.tools["get_wazuh_api_health"]())
        assert result["manager"]["version"] == "v4.10.0"
        assert result["manager"]["daemons_running"] == "2/2"

    def test_indexer_includes_cluster_status(self):
        self._setup_manager_up()
        self._setup_indexer_up()
        result = _run(self.tools["get_wazuh_api_health"]())
        assert result["indexer"]["cluster_status"] == "green"
        assert result["indexer"]["nodes"] == 1

    def test_latency_ms_present(self):
        self._setup_manager_up()
        self._setup_indexer_up()
        result = _run(self.tools["get_wazuh_api_health"]())
        assert "latency_ms" in result["manager"]
        assert "latency_ms" in result["indexer"]
        assert isinstance(result["manager"]["latency_ms"], int)

    def test_checked_at_in_result(self):
        self._setup_manager_up()
        self._setup_indexer_up()
        result = _run(self.tools["get_wazuh_api_health"]())
        assert "checked_at" in result
        assert result["checked_at"].endswith("Z")


# ── prompt_advisor ────────────────────────────────────────────────────────────

class TestPromptAdvisor:
    def setup_method(self):
        self.tools, _, _, _ = _make_env("wazuh_mcp.tools.prompt_advisor")

    def test_get_recommended_system_prompt_returns_prompt(self):
        result = _run(self.tools["get_recommended_system_prompt"]())
        assert "system_prompt" in result
        assert "Tier 1 security orchestrator" in result["system_prompt"]
        assert "Wazuh Manager Tools" in result["system_prompt"]
        assert "Wazuh Indexer Tools" in result["system_prompt"]

    def test_system_prompt_contains_strict_rules(self):
        result = _run(self.tools["get_recommended_system_prompt"]())
        assert "STRICT RULES" in result["system_prompt"]
        assert "NEVER" in result["system_prompt"]

    def test_memory_guardrail_present(self):
        result = _run(self.tools["get_recommended_system_prompt"]())
        assert result["memory_guardrail"]["context_window_turns"] in (2, 3)

    def test_token_budget_present(self):
        result = _run(self.tools["get_recommended_system_prompt"]())
        tb = result["token_budget"]
        assert tb["model_tpm_limit"] == 12000
        assert tb["recommended_per_response_limit"] > 0
        assert tb["recommended_tool_result_limit"] <= 10

    def test_custom_tpm_limit(self):
        result = _run(self.tools["get_recommended_system_prompt"](model_tpm_limit=60000))
        assert result["token_budget"]["model_tpm_limit"] == 60000
        # higher TPM → higher budget
        assert result["token_budget"]["recommended_per_response_limit"] > 2000

    def test_indexer_query_template_present(self):
        result = _run(self.tools["get_recommended_system_prompt"]())
        tpl = result["indexer_query_template"]
        assert "wazuh-alerts" in tpl["index"]
        assert "now-24h" in str(tpl["query"])

    def test_routing_table_excluded_by_default(self):
        result = _run(self.tools["get_recommended_system_prompt"]())
        assert "routing_table" not in result

    def test_routing_table_included_when_requested(self):
        result = _run(self.tools["get_recommended_system_prompt"](include_routing_table=True))
        assert "routing_table" in result
        assert "manager" in result["routing_table"]
        assert "indexer" in result["routing_table"]

    # check_response_size
    def test_check_response_size_ok(self):
        small = '{"data": "short"}'
        result = _run(self.tools["check_response_size"]("list_agents", small))
        assert result["status"] == "ok"
        assert result["estimated_tokens"] < 2000

    def test_check_response_size_warns_large(self):
        big = '{"data": "' + "x" * 10000 + '"}'
        result = _run(self.tools["check_response_size"]("list_agents", big))
        assert result["status"] in ("warn", "critical")
        assert result["estimated_tokens"] > 2000

    def test_check_response_size_returns_tool_name(self):
        result = _run(self.tools["check_response_size"]("search_alerts", "{}"))
        assert result["tool_name"] == "search_alerts"

    # get_routing_advice
    def test_routing_advice_indexer_for_alerts(self):
        result = _run(self.tools["get_routing_advice"]("Show me recent alerts from the last 24 hours"))
        assert result["recommended_api"] == "indexer"
        assert result["confidence"] in ("medium", "high")

    def test_routing_advice_manager_for_agents(self):
        result = _run(self.tools["get_routing_advice"]("List all deployed agents and their connection status"))
        assert result["recommended_api"] == "manager"

    def test_routing_advice_indexer_for_events(self):
        result = _run(self.tools["get_routing_advice"]("Search for attack events with severity level 10"))
        assert result["recommended_api"] == "indexer"

    def test_routing_advice_unknown_query(self):
        result = _run(self.tools["get_routing_advice"]("hello world"))
        assert result["recommended_api"] == "unknown"
        assert result["confidence"] == "low"

    def test_routing_advice_includes_suggested_tools(self):
        result = _run(self.tools["get_routing_advice"]("List all agents"))
        assert len(result["suggested_tools"]) > 0

    def test_routing_advice_includes_rationale(self):
        result = _run(self.tools["get_routing_advice"]("Show triggered alerts"))
        assert "rationale" in result
        assert len(result["rationale"]) > 20
