"""Tests for Phase 3 High-Value Features — F1, F4, F8, F9-doc, F10."""
from __future__ import annotations

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from wazuh_mcp.tool_context import ToolContext


# ── F8: Extended GeoIP & ASN Intelligence ────────────────────────────────────

class TestGeoIntel:
    def test_is_private_detects_rfc1918(self):
        from wazuh_mcp.tools.geo_intel import _is_private
        assert _is_private("192.168.1.1")
        assert _is_private("10.0.0.1")
        assert _is_private("172.16.0.1")
        assert not _is_private("8.8.8.8")
        assert not _is_private("1.1.1.1")

    def test_classify_infra_hosting_flag(self):
        from wazuh_mcp.tools.geo_intel import _classify_infra
        assert _classify_infra({}, {"hosting": True}) == "datacenter/hosting"

    def test_classify_infra_proxy_flag(self):
        from wazuh_mcp.tools.geo_intel import _classify_infra
        assert _classify_infra({}, {"proxy": True}) == "proxy/vpn"

    def test_classify_infra_mobile_flag(self):
        from wazuh_mcp.tools.geo_intel import _classify_infra
        assert _classify_infra({}, {"mobile": True}) == "mobile"

    def test_classify_infra_datacenter_org_keyword(self):
        from wazuh_mcp.tools.geo_intel import _classify_infra
        assert _classify_infra({"org": "AS16509 Amazon.com, Inc."}, {}) == "datacenter/hosting"
        assert _classify_infra({"org": "AS15169 Google LLC"}, {}) == "datacenter/hosting"

    def test_classify_infra_residential_fallback(self):
        from wazuh_mcp.tools.geo_intel import _classify_infra
        assert _classify_infra({"org": "AS12345 Some ISP"}, {}) == "residential/isp"

    def test_enrich_ip_extended_private_returns_early(self):
        async def run():
            mcp = MagicMock()
            registered_fn = {}
            def capture_tool():
                def decorator(fn):
                    registered_fn[fn.__name__] = fn
                    return fn
                return decorator
            mcp.tool = capture_tool
            from wazuh_mcp.tools import geo_intel
            geo_intel.register(ToolContext(mcp=mcp, wz=None, idx=None, cfg=None, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: []))
            result = await registered_fn["enrich_ip_extended"]("192.168.1.100")
            assert result["classification"] == "private/rfc1918"
        asyncio.run(run())

    def test_enrich_ip_extended_public_ip(self):
        async def run():
            mcp = MagicMock()
            registered_fn = {}
            def capture_tool():
                def decorator(fn):
                    registered_fn[fn.__name__] = fn
                    return fn
                return decorator
            mcp.tool = capture_tool
            from wazuh_mcp.tools import geo_intel

            mock_ipinfo = {"org": "AS16509 Amazon.com, Inc.", "country": "US", "city": "Ashburn"}
            mock_ipapi = {"country": "US", "isp": "Amazon.com", "hosting": True}

            with patch.object(geo_intel, "_ipinfo_get", return_value=mock_ipinfo), \
                 patch.object(geo_intel, "_ip_api_get", return_value=mock_ipapi), \
                 patch.object(geo_intel, "_is_tor_exit", return_value=False):
                geo_intel.register(ToolContext(mcp=mcp, wz=None, idx=None, cfg=None, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: []))
                result = await registered_fn["enrich_ip_extended"]("54.1.2.3")

            assert result["ip"] == "54.1.2.3"
            assert "datacenter" in result["classification"]
            assert result["is_tor_exit"] is False
            assert result["location"]["country"] == "US"
        asyncio.run(run())

    def test_enrich_ip_tor_exit_overrides_classification(self):
        async def run():
            mcp = MagicMock()
            registered_fn = {}
            def capture_tool():
                def decorator(fn):
                    registered_fn[fn.__name__] = fn
                    return fn
                return decorator
            mcp.tool = capture_tool
            from wazuh_mcp.tools import geo_intel

            with patch.object(geo_intel, "_ipinfo_get", return_value={}), \
                 patch.object(geo_intel, "_ip_api_get", return_value={}), \
                 patch.object(geo_intel, "_is_tor_exit", return_value=True):
                geo_intel.register(ToolContext(mcp=mcp, wz=None, idx=None, cfg=None, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: []))
                result = await registered_fn["enrich_ip_extended"]("185.220.101.1")

            assert result["classification"] == "tor-exit-node"
            assert result["risk_level"] == "high"
            assert result["is_tor_exit"] is True
        asyncio.run(run())

    def test_classify_ip_infrastructure_private(self):
        async def run():
            mcp = MagicMock()
            registered_fn = {}
            def capture_tool():
                def decorator(fn):
                    registered_fn[fn.__name__] = fn
                    return fn
                return decorator
            mcp.tool = capture_tool
            from wazuh_mcp.tools import geo_intel
            geo_intel.register(ToolContext(mcp=mcp, wz=None, idx=None, cfg=None, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: []))
            result = await registered_fn["classify_ip_infrastructure"]("10.10.10.1")
            assert result["classification"] == "private/rfc1918"
        asyncio.run(run())


# ── F10: Threat Feeds ─────────────────────────────────────────────────────────

class TestThreatFeeds:
    def _register(self):
        from wazuh_mcp.tools import threat_feeds
        mcp = MagicMock()
        registered = {}
        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec
        mcp.tool = capture_tool
        wz = AsyncMock()
        idx = AsyncMock()
        cfg = MagicMock()
        require_writes = MagicMock(return_value=None)
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        threat_feeds.register(ctx)
        return registered, threat_feeds

    def test_list_threat_feeds_returns_all_feeds(self):
        async def run():
            fns, _ = self._register()
            result = await fns["list_threat_feeds"]()
            assert "feeds" in result
            feed_ids = {f["feed_id"] for f in result["feeds"]}
            assert "feodo" in feed_ids
            assert "urlhaus" in feed_ids
            assert "torstats" in feed_ids
        asyncio.run(run())

    def test_sync_unknown_feed_returns_error(self):
        async def run():
            fns, _ = self._register()
            result = await fns["sync_threat_feed"]("nonexistent")
            assert "error" in result
        asyncio.run(run())

    def test_sync_feed_dry_run_caches_iocs(self):
        async def run():
            fns, tf_module = self._register()
            tf_module._FEED_CACHE.clear()
            fake_iocs = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
            with patch.object(tf_module, "_fetch_feed", return_value=(fake_iocs, "")):
                result = await fns["sync_threat_feed"]("feodo", dry_run=True)
            assert result["dry_run"] is True
            assert result["ioc_count"] == 3
            assert "feodo" in tf_module._FEED_CACHE
            assert tf_module._FEED_CACHE["feodo"]["count"] == 3
        asyncio.run(run())

    def test_correlate_requires_cached_feed(self):
        async def run():
            fns, tf_module = self._register()
            tf_module._FEED_CACHE.clear()
            result = await fns["correlate_alerts_with_feed"]("feodo")
            assert "error" in result
        asyncio.run(run())

    def test_correlate_finds_matches(self):
        async def run():
            from wazuh_mcp.tools import threat_feeds as tf
            tf._FEED_CACHE["feodo"] = {
                "iocs": {"1.2.3.4"},
                "synced_at": 0,
                "count": 1,
            }
            mcp2 = MagicMock()
            reg2 = {}
            def cap():
                def d(fn):
                    reg2[fn.__name__] = fn
                    return fn
                return d
            mcp2.tool = cap
            idx = AsyncMock()
            idx.search.return_value = {
                "hits": {
                    "hits": [
                        {"_source": {
                            "@timestamp": "2024-01-01T00:00:00Z",
                            "agent": {"id": "001", "name": "server"},
                            "data": {"srcip": "1.2.3.4"},
                            "rule": {"level": 10},
                        }}
                    ]
                }
            }
            ctx2 = ToolContext(mcp=mcp2, wz=AsyncMock(), idx=idx, cfg=MagicMock(), cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
            tf.register(ctx2)
            result = await reg2["correlate_alerts_with_feed"]("feodo", hours=24)
            assert result["matches_found"] == 1
            assert result["severity"] == "critical"
        asyncio.run(run())

    def test_parse_feodo_csv(self):
        from wazuh_mcp.tools.threat_feeds import _parse_feodo_csv
        csv_text = "# Comment line\n1.2.3.4,feodo,botnet\n5.6.7.8,bazarloader,c2\n"
        result = _parse_feodo_csv(csv_text)
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result
        assert len(result) == 2

    def test_parse_tor_list(self):
        from wazuh_mcp.tools.threat_feeds import _parse_tor_list
        text = "# Tor exit nodes\n185.220.101.1\n185.220.101.2\n"
        result = _parse_tor_list(text)
        assert "185.220.101.1" in result
        assert "185.220.101.2" in result


# ── F4: Playbooks ─────────────────────────────────────────────────────────────

class TestPlaybooks:
    def _register(self):
        from wazuh_mcp.tools import playbooks
        mcp = MagicMock()
        registered = {}
        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec
        mcp.tool = capture_tool
        ctx = ToolContext(mcp=mcp, wz=AsyncMock(), idx=AsyncMock(), cfg=MagicMock(), cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        playbooks.register(ctx)
        return registered, playbooks

    def test_list_playbooks_returns_all(self):
        async def run():
            fns, _ = self._register()
            result = await fns["list_playbooks"]()
            assert "playbooks" in result
            ids = {p["id"] for p in result["playbooks"]}
            assert "isolate-compromised-host" in ids
            assert "brute-force-response" in ids
            assert "cve-triage" in ids
            assert "incident-response" in ids
        asyncio.run(run())

    def test_run_playbook_unknown_returns_error(self):
        async def run():
            fns, _ = self._register()
            result = await fns["run_playbook"]("nonexistent")
            assert "error" in result
        asyncio.run(run())

    def test_run_playbook_missing_param_returns_error(self):
        async def run():
            fns, _ = self._register()
            result = await fns["run_playbook"]("isolate-compromised-host", dry_run=True)
            assert "error" in result
            assert "agent_id" in str(result)
        asyncio.run(run())

    def test_run_playbook_dry_run_shows_steps(self):
        async def run():
            fns, _ = self._register()
            result = await fns["run_playbook"](
                "isolate-compromised-host", dry_run=True, agent_id="001"
            )
            assert result["dry_run"] is True
            assert "steps" in result
            assert len(result["steps"]) > 0
            assert result["steps"][0]["tool"] == "get_agent"
        asyncio.run(run())

    def test_run_playbook_dry_run_resolves_params(self):
        async def run():
            fns, _ = self._register()
            result = await fns["run_playbook"](
                "brute-force-response", dry_run=True, ip="1.2.3.4"
            )
            assert result["dry_run"] is True
            first_step = result["steps"][0]
            assert "1.2.3.4" in str(first_step["params"])
        asyncio.run(run())

    def test_get_playbook_status_not_found(self):
        async def run():
            fns, _ = self._register()
            result = await fns["get_playbook_status"]("nonexistent-run-id")
            assert "error" in result
        asyncio.run(run())

    def test_run_playbook_live_creates_run_record(self):
        async def run():
            fns, pb_module = self._register()
            result = await fns["run_playbook"](
                "isolate-compromised-host", dry_run=False, agent_id="001"
            )
            assert "run_id" in result
            run_id = result["run_id"]
            assert run_id in pb_module._RUN_HISTORY
            assert result["status"] in ("completed", "failed", "awaiting_approval")
        asyncio.run(run())


# ── F1: Network Topology ──────────────────────────────────────────────────────

class TestNetworkTopology:
    def _register(self):
        from wazuh_mcp.tools import network_topology
        mcp = MagicMock()
        registered = {}
        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec
        mcp.tool = capture_tool
        wz = AsyncMock()
        idx = AsyncMock()
        cfg = MagicMock()
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        network_topology.register(ctx)
        return registered, wz, idx, network_topology

    def test_subnet_key_ipv4(self):
        from wazuh_mcp.tools.network_topology import _subnet_key
        assert _subnet_key("192.168.1.100", 24) == "192.168.1.0/24"
        assert _subnet_key("10.0.1.50", 16) == "10.0.0.0/16"

    def test_subnet_key_invalid(self):
        from wazuh_mcp.tools.network_topology import _subnet_key
        result = _subnet_key("not-an-ip", 24)
        assert result == "unknown"

    def test_get_network_topology_groups_by_subnet(self):
        async def run():
            fns, wz, idx, mod = self._register()
            wz.request.return_value = {
                "data": {
                    "affected_items": [
                        {"id": "001", "name": "web1", "ip": "192.168.1.10",
                         "status": "active", "groups": []},
                        {"id": "002", "name": "web2", "ip": "192.168.1.11",
                         "status": "active", "groups": []},
                        {"id": "003", "name": "db1", "ip": "10.0.1.5",
                         "status": "active", "groups": []},
                    ]
                }
            }
            with patch.object(mod, "_get_agent_ports", return_value=[]):
                result = await fns["get_network_topology"](subnet_prefix=24)
            assert "topology" in result
            subnets = {t["subnet"] for t in result["topology"]}
            assert "192.168.1.0/24" in subnets
            assert "10.0.1.0/24" in subnets
            assert result["total_agents"] == 3
        asyncio.run(run())

    def test_map_subnet_exposure_invalid_subnet(self):
        async def run():
            fns, wz, idx, mod = self._register()
            result = await fns["map_subnet_exposure"]("not-a-subnet")
            assert "error" in result
        asyncio.run(run())

    def test_map_subnet_exposure_filters_by_subnet(self):
        async def run():
            fns, wz, idx, mod = self._register()
            wz.request.return_value = {
                "data": {
                    "affected_items": [
                        {"id": "001", "name": "web1", "ip": "192.168.1.10",
                         "status": "active", "groups": []},
                        {"id": "002", "name": "db1", "ip": "10.0.1.5",
                         "status": "active", "groups": []},
                    ]
                }
            }
            with patch.object(mod, "_get_agent_ports", return_value=[]):
                result = await fns["map_subnet_exposure"]("192.168.1.0/24")
            assert result["agents_in_subnet"] == 1
            assert result["nodes"][0]["name"] == "web1"
        asyncio.run(run())

    def test_get_agent_neighbors_agent_not_found(self):
        async def run():
            fns, wz, idx, mod = self._register()
            wz.request.return_value = {"data": {"affected_items": []}}
            result = await fns["get_agent_neighbors"]("999")
            assert "error" in result
        asyncio.run(run())


# ── F9-doc: Autonomous SOC Monitor ───────────────────────────────────────────

class TestAutonomousSOC:
    def _register(self):
        from wazuh_mcp.tools import autonomous_soc
        mcp = MagicMock()
        registered = {}
        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec
        mcp.tool = capture_tool
        wz = AsyncMock()
        idx = AsyncMock()
        cfg = MagicMock()
        cfg.slack_bot_token = ""
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        autonomous_soc.register(ctx)
        return registered, autonomous_soc

    def test_get_autonomous_status_not_running(self):
        async def run():
            fns, mod = self._register()
            mod._monitor_state["running"] = False
            mod._monitor_state["started_at"] = None
            result = await fns["get_autonomous_status"]()
            assert result["running"] is False
        asyncio.run(run())

    def test_stop_monitor_when_not_running(self):
        async def run():
            fns, mod = self._register()
            mod._monitor_state["running"] = False
            with patch("wazuh_mcp.tools.autonomous_soc.admin_only", return_value=None):
                result = await fns["stop_autonomous_monitor"]()
            assert result["status"] == "not_running"
        asyncio.run(run())

    def test_start_monitor_rbac_blocks_non_admin(self):
        async def run():
            fns, mod = self._register()
            mod._monitor_state["running"] = False
            with patch("wazuh_mcp.tools.autonomous_soc.admin_only",
                       return_value={"error": "admin only"}):
                result = await fns["start_autonomous_monitor"]()
            assert "error" in result
        asyncio.run(run())

    def test_start_monitor_returns_started(self):
        async def run():
            fns, mod = self._register()
            mod._monitor_state["running"] = False
            with patch("wazuh_mcp.tools.autonomous_soc.admin_only", return_value=None), \
                 patch("wazuh_mcp.tools.autonomous_soc._monitor_loop",
                       new=AsyncMock(return_value=None)):
                mock_task = MagicMock()
                mock_task.done.return_value = True
                with patch("asyncio.get_event_loop") as mock_loop:
                    mock_loop.return_value.create_task.return_value = mock_task
                    result = await fns["start_autonomous_monitor"](interval_seconds=30)
            assert result["status"] == "started"
            assert result["interval_seconds"] == 30
            mod._monitor_state["running"] = False
        asyncio.run(run())
    def test_start_monitor_already_running(self):
        async def run():
            fns, mod = self._register()
            mod._monitor_state["running"] = True
            mod._monitor_state["started_at"] = "2024-01-01T00:00:00Z"
            with patch("wazuh_mcp.tools.autonomous_soc.admin_only", return_value=None):
                result = await fns["start_autonomous_monitor"]()
            assert result["status"] == "already_running"
            mod._monitor_state["running"] = False
        asyncio.run(run())

    def test_status_reflects_state(self):
        async def run():
            fns, mod = self._register()
            mod._monitor_state.update({
                "running": False,
                "alerts_processed": 42,
                "actions_taken": 7,
                "severity_threshold": 12,
            })
            result = await fns["get_autonomous_status"]()
            assert result["alerts_processed"] == 42
            assert result["actions_taken"] == 7
            assert result["severity_threshold"] == 12
        asyncio.run(run())


# ── Module import smoke tests ─────────────────────────────────────────────────

class TestPhase3ModuleImports:
    def test_geo_intel_importable(self):
        from wazuh_mcp.tools import geo_intel
        assert hasattr(geo_intel, "register")

    def test_threat_feeds_importable(self):
        from wazuh_mcp.tools import threat_feeds
        assert hasattr(threat_feeds, "register")

    def test_playbooks_importable(self):
        from wazuh_mcp.tools import playbooks
        assert hasattr(playbooks, "register")

    def test_network_topology_importable(self):
        from wazuh_mcp.tools import network_topology
        assert hasattr(network_topology, "register")

    def test_autonomous_soc_importable(self):
        from wazuh_mcp.tools import autonomous_soc
        assert hasattr(autonomous_soc, "register")
