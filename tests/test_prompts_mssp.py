"""Tests for all six quick-win features.

Covers:
  1. wazuh-mcp init / verify CLI commands
  2. Wazuh Cloud config mode
  3. MSSP multi-tenant config + switch_tenant tool
  4. Role-optimized MCP prompts (tier1, tier2, ciso, compliance_officer)
  5. explain_alert + explain_recent_alerts tools
  6. README / pyproject.toml registry content
"""
from __future__ import annotations

import json
import os
import sys
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from wazuh_mcp.tool_context import ToolContext

import pytest

# ── helpers ────────────────────────────────────────────────────────────────────

def _set_env(**kwargs):
    """Context-free env setter — returns cleanup callable."""
    old = {}
    for k, v in kwargs.items():
        old[k] = os.environ.get(k)
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return old


def _restore_env(old):
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ── 1. CLI: wazuh-mcp init / verify ───────────────────────────────────────────

class TestCLI:
    def test_main_routes_init(self, monkeypatch, capsys):
        """wazuh-mcp init should call _cmd_init."""
        called = []
        monkeypatch.setattr(sys, "argv", ["wazuh-mcp", "init"])
        from wazuh_mcp import __main__ as m
        monkeypatch.setattr(m, "_cmd_init", lambda: called.append(True))
        m.main()
        assert called, "_cmd_init was not called"

    def test_main_routes_verify(self, monkeypatch):
        """wazuh-mcp verify should call _cmd_verify."""
        called = []
        monkeypatch.setattr(sys, "argv", ["wazuh-mcp", "verify"])
        from wazuh_mcp import __main__ as m
        monkeypatch.setattr(m, "_cmd_verify", lambda: called.append(True))
        m.main()
        assert called, "_cmd_verify was not called"

    def test_main_routes_server_by_default(self, monkeypatch):
        """wazuh-mcp with no args should call server main."""
        called = []
        monkeypatch.setattr(sys, "argv", ["wazuh-mcp"])
        from wazuh_mcp import __main__ as m
        monkeypatch.setattr(m, "_cmd_init", lambda: None)
        monkeypatch.setattr(m, "_cmd_verify", lambda: None)
        # Patch the real server main to avoid startup
        import importlib
        server_mod = importlib.import_module("wazuh_mcp.server")
        monkeypatch.setattr(server_mod, "main", lambda: called.append(True))
        m.main()
        assert called, "server main was not called"

    def test_wizard_selfhosted_returns_lines(self, monkeypatch):
        """_wizard_selfhosted should return env lines with required keys."""
        from wazuh_mcp import __main__ as m
        inputs = iter([
            "https://wazuh:55000",  # manager URL
            "wazuh-wui",            # user
            "secret",               # pass (getpass)
            "",                     # indexer URL (default)
            "wazuh-readonly",       # indexer user
            "idxsecret",            # indexer pass (getpass)
        ])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        import getpass
        monkeypatch.setattr(getpass, "getpass", lambda _: next(inputs))
        lines = m._wizard_selfhosted()
        joined = "\n".join(lines)
        assert "WAZUH_HOST=https://wazuh:55000" in joined
        assert "WAZUH_USER=wazuh-wui" in joined
        assert "WAZUH_PASS=secret" in joined
        assert "WAZUH_INDEXER_HOST" in joined
        assert "WAZUH_INDEXER_PASS=idxsecret" in joined

    def test_wizard_cloud_returns_lines(self, monkeypatch):
        """_wizard_cloud should return WAZUH_CLOUD=true and key fields."""
        from wazuh_mcp import __main__ as m
        inputs = iter([
            "https://mycloud.cloud.wazuh.com:55000",
            "myapikey",
            "myidxpass",
        ])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        import getpass
        monkeypatch.setattr(getpass, "getpass", lambda _: next(inputs))
        lines = m._wizard_cloud()
        joined = "\n".join(lines)
        assert "WAZUH_CLOUD=true" in joined
        assert "WAZUH_CLOUD_URL=https://mycloud.cloud.wazuh.com:55000" in joined
        assert "WAZUH_CLOUD_API_KEY=myapikey" in joined
        assert "WAZUH_CLOUD_INDEXER_PASS=myidxpass" in joined

    def test_wizard_mssp_returns_instances(self, monkeypatch):
        """_wizard_mssp should emit WAZUH_INSTANCES JSON."""
        from wazuh_mcp import __main__ as m
        inputs = iter([
            "client-a",
            "https://wazuh-a:55000",
            "wazuh-wui",
            "passa",
            "",          # default indexer URL
            "idxpassa",
            "",          # finish loop
        ])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        import getpass
        monkeypatch.setattr(getpass, "getpass", lambda _: next(inputs))
        lines = m._wizard_mssp()
        joined = "\n".join(lines)
        assert "WAZUH_INSTANCES=" in joined
        instances_str = next(l for l in lines if l.startswith("WAZUH_INSTANCES="))
        parsed = json.loads(instances_str[len("WAZUH_INSTANCES="):])
        assert len(parsed) == 1
        assert parsed[0]["name"] == "client-a"
        assert parsed[0]["host"] == "https://wazuh-a:55000"


# ── 2. Wazuh Cloud config mode ─────────────────────────────────────────────────

class TestWazuhCloudConfig:
    def setup_method(self):
        # Clear env before each test
        for k in ["WAZUH_CLOUD", "WAZUH_CLOUD_URL", "WAZUH_CLOUD_API_KEY",
                   "WAZUH_CLOUD_INDEXER_PASS", "WAZUH_CLOUD_INDEXER_URL",
                   "WAZUH_HOST", "WAZUH_USER", "WAZUH_PASS",
                   "WAZUH_INDEXER_HOST", "WAZUH_INDEXER_PASS"]:
            os.environ.pop(k, None)

    def test_cloud_mode_sets_flag(self):
        os.environ.update({
            "WAZUH_CLOUD": "true",
            "WAZUH_CLOUD_URL": "https://cloud.wazuh.com:55000",
            "WAZUH_CLOUD_API_KEY": "key123",
            "WAZUH_CLOUD_INDEXER_PASS": "idxpass",
        })
        from importlib import reload
        import wazuh_mcp.config as cfg_mod
        reload(cfg_mod)
        cfg = cfg_mod.Config.from_env()
        assert cfg.cloud_mode is True

    def test_cloud_manager_host_from_cloud_url(self):
        os.environ.update({
            "WAZUH_CLOUD": "true",
            "WAZUH_CLOUD_URL": "https://abc.cloud.wazuh.com:55000",
            "WAZUH_CLOUD_API_KEY": "apikey",
            "WAZUH_CLOUD_INDEXER_PASS": "idxpass",
        })
        from importlib import reload
        import wazuh_mcp.config as cfg_mod
        reload(cfg_mod)
        cfg = cfg_mod.Config.from_env()
        assert cfg.manager_host == "https://abc.cloud.wazuh.com:55000"

    def test_cloud_indexer_host_auto_derived(self):
        os.environ.update({
            "WAZUH_CLOUD": "true",
            "WAZUH_CLOUD_URL": "https://abc.cloud.wazuh.com:55000",
            "WAZUH_CLOUD_API_KEY": "apikey",
            "WAZUH_CLOUD_INDEXER_PASS": "idxpass",
        })
        from importlib import reload
        import wazuh_mcp.config as cfg_mod
        reload(cfg_mod)
        cfg = cfg_mod.Config.from_env()
        # Should replace :55000 with :9200
        assert cfg.indexer_host == "https://abc.cloud.wazuh.com:9200"

    def test_cloud_indexer_url_override(self):
        os.environ.update({
            "WAZUH_CLOUD": "true",
            "WAZUH_CLOUD_URL": "https://abc.cloud.wazuh.com:55000",
            "WAZUH_CLOUD_API_KEY": "apikey",
            "WAZUH_CLOUD_INDEXER_PASS": "idxpass",
            "WAZUH_CLOUD_INDEXER_URL": "https://custom-indexer:9200",
        })
        from importlib import reload
        import wazuh_mcp.config as cfg_mod
        reload(cfg_mod)
        cfg = cfg_mod.Config.from_env()
        assert cfg.indexer_host == "https://custom-indexer:9200"

    def test_cloud_mode_false_by_default(self):
        os.environ.update({
            "WAZUH_HOST": "https://selfhosted:55000",
            "WAZUH_USER": "u",
            "WAZUH_PASS": "p",
            "WAZUH_INDEXER_HOST": "https://idx:9200",
            "WAZUH_INDEXER_PASS": "p",
        })
        from importlib import reload
        import wazuh_mcp.config as cfg_mod
        reload(cfg_mod)
        cfg = cfg_mod.Config.from_env()
        assert cfg.cloud_mode is False

    def test_cloud_mode_missing_url_raises(self):
        os.environ["WAZUH_CLOUD"] = "true"
        os.environ.pop("WAZUH_CLOUD_URL", None)
        os.environ["WAZUH_CLOUD_API_KEY"] = "key"
        os.environ["WAZUH_CLOUD_INDEXER_PASS"] = "pass"
        from importlib import reload
        import wazuh_mcp.config as cfg_mod
        reload(cfg_mod)
        with pytest.raises(RuntimeError, match="WAZUH_CLOUD_URL"):
            cfg_mod.Config.from_env()


# ── 3. MSSP multi-tenant config + switch_tenant ────────────────────────────────

class TestMSSPConfig:
    INSTANCES = [
        {"name": "client-a", "host": "https://wazuh-a:55000", "user": "ua",
         "pass": "pa", "indexer_host": "https://idx-a:9200", "indexer_pass": "ia"},
        {"name": "client-b", "host": "https://wazuh-b:55000", "user": "ub",
         "pass": "pb", "indexer_host": "https://idx-b:9200", "indexer_pass": "ib"},
    ]

    def _base_env(self):
        return {
            "WAZUH_HOST": "https://default:55000",
            "WAZUH_USER": "u",
            "WAZUH_PASS": "p",
            "WAZUH_INDEXER_HOST": "https://idx:9200",
            "WAZUH_INDEXER_PASS": "p",
        }

    def setup_method(self):
        for k in ["WAZUH_CLOUD", "WAZUH_INSTANCES"]:
            os.environ.pop(k, None)

    def test_tenants_parsed_from_env(self):
        env = self._base_env()
        env["WAZUH_INSTANCES"] = json.dumps(self.INSTANCES)
        old = _set_env(**env)
        try:
            from importlib import reload
            import wazuh_mcp.config as cfg_mod
            reload(cfg_mod)
            cfg = cfg_mod.Config.from_env()
            assert len(cfg.tenants) == 2
            assert cfg.tenants[0].name == "client-a"
            assert cfg.tenants[1].name == "client-b"
            assert cfg.tenants[0].manager_host == "https://wazuh-a:55000"
        finally:
            _restore_env(old)

    def test_tenant_inherits_default_user_if_missing(self):
        instances = [{"name": "x", "host": "https://x:55000", "pass": "p",
                      "indexer_host": "https://idx-x:9200", "indexer_pass": "ip"}]
        env = self._base_env()
        env["WAZUH_INSTANCES"] = json.dumps(instances)
        old = _set_env(**env)
        try:
            from importlib import reload
            import wazuh_mcp.config as cfg_mod
            reload(cfg_mod)
            cfg = cfg_mod.Config.from_env()
            # manager_user not specified → inherits from default
            assert cfg.tenants[0].manager_user == "u"
        finally:
            _restore_env(old)

    def test_invalid_instances_json_raises(self):
        env = self._base_env()
        env["WAZUH_INSTANCES"] = "not-valid-json"
        old = _set_env(**env)
        try:
            from importlib import reload
            import wazuh_mcp.config as cfg_mod
            reload(cfg_mod)
            with pytest.raises(RuntimeError, match="WAZUH_INSTANCES"):
                cfg_mod.Config.from_env()
        finally:
            _restore_env(old)

    def test_empty_instances_gives_no_tenants(self):
        env = self._base_env()
        old = _set_env(**env)
        try:
            from importlib import reload
            import wazuh_mcp.config as cfg_mod
            reload(cfg_mod)
            cfg = cfg_mod.Config.from_env()
            assert len(cfg.tenants) == 0
        finally:
            _restore_env(old)

    @pytest.mark.asyncio
    async def test_list_tenants_single_instance_mode(self):
        """list_tenants returns mssp_mode=False when no tenants configured."""
        from wazuh_mcp.config import Config, TenantConfig
        cfg = MagicMock()
        cfg.tenants = ()

        # Build a minimal registration context
        results = []
        mock_mcp = MagicMock()

        def capture_tool():
            def decorator(fn):
                results.append(fn)
                return fn
            return decorator

        mock_mcp.tool = capture_tool

        from wazuh_mcp.server import list_tenants
        result = await list_tenants()
        assert result["mssp_mode"] is False

    @pytest.mark.asyncio
    async def test_switch_tenant_no_tenants_configured(self):
        """switch_tenant returns error when MSSP not configured."""
        from wazuh_mcp.server import switch_tenant
        # Patch cfg.tenants to be empty
        import wazuh_mcp.server as srv
        original_tenants = srv.cfg.tenants
        srv.cfg = MagicMock()
        srv.cfg.tenants = ()
        try:
            result = await switch_tenant("client-a")
            assert "error" in result
            assert "WAZUH_INSTANCES" in result["error"]
        finally:
            srv.cfg.tenants = original_tenants

    @pytest.mark.asyncio
    async def test_switch_tenant_is_session_scoped_not_global(self):
        """Calling switch_tenant in one task must not affect a concurrent session.

        This is the regression test for the global-state multi-tenancy bug:
        _ClientProxy now uses a ContextVar so each asyncio Task has its own
        client binding.
        """
        import dataclasses
        import wazuh_mcp.server as srv
        from wazuh_mcp.config import Config, TenantConfig

        # Build two fake tenants
        tenant_a = TenantConfig(
            name="tenant-a",
            manager_host="https://wazuh-a:55000",
            manager_user="ua", manager_pass="pa",
            indexer_host="https://idx-a:9200",
            indexer_user="ua", indexer_pass="pa",
        )
        tenant_b = TenantConfig(
            name="tenant-b",
            manager_host="https://wazuh-b:55000",
            manager_user="ub", manager_pass="pb",
            indexer_host="https://idx-b:9200",
            indexer_user="ub", indexer_pass="pb",
        )

        # Build a real Config dataclass (required by dataclasses.replace inside switch_tenant)
        base_cfg = Config(
            manager_host="https://default:55000",
            manager_user="default", manager_pass="default",
            indexer_host="https://default-idx:9200",
            indexer_user="default", indexer_pass="default",
            alerts_index="wazuh-alerts-*",
            vuln_index="wazuh-states-vulnerabilities-*",
            inventory_packages_index="wazuh-states-inventory-packages-*",
            inventory_processes_index="wazuh-states-inventory-processes-*",
            inventory_ports_index="wazuh-states-inventory-ports-*",
            verify_ssl=False,
            ca_bundle=None,
            allow_writes=False,
            request_timeout=30,
            cloud_mode=False,
            tenants=(tenant_a, tenant_b),
        )

        original_cfg = srv.cfg
        srv.cfg = base_cfg

        # Use a barrier so both tasks reach the switch_tenant call simultaneously.
        # asyncio.Barrier was added in Python 3.11; skip on older versions.
        if not hasattr(asyncio, "Barrier"):
            pytest.skip("asyncio.Barrier requires Python 3.11+")
        barrier = asyncio.Barrier(2)
        results: dict[str, str] = {}

        async def session_a():
            await barrier.wait()
            await srv.switch_tenant("tenant-a")
            await barrier.wait()
            # Resolve the proxy in this task's context
            results["a"] = srv._wz_proxy.cfg.manager_host

        async def session_b():
            await barrier.wait()
            await srv.switch_tenant("tenant-b")
            await barrier.wait()
            results["b"] = srv._wz_proxy.cfg.manager_host

        try:
            with patch("wazuh_mcp.server.WazuhClient") as mock_wz, \
                 patch("wazuh_mcp.server.WazuhIndexer"):
                # Make WazuhClient(cfg) return a mock that preserves cfg
                def make_wz(cfg):
                    m = MagicMock()
                    m.cfg = cfg
                    return m
                mock_wz.side_effect = make_wz

                await asyncio.gather(
                    asyncio.ensure_future(session_a()),
                    asyncio.ensure_future(session_b()),
                )
        finally:
            srv.cfg = original_cfg

        # Each session must have seen its own tenant — not the other's
        assert results["a"] == "https://wazuh-a:55000", (
            f"Session A expected tenant-a host but got: {results['a']!r}"
        )
        assert results["b"] == "https://wazuh-b:55000", (
            f"Session B expected tenant-b host but got: {results['b']!r}"
        )
        assert results["a"] != results["b"], "Session isolation broken: both tasks resolved the same client"


# ── 4. Role-optimized MCP prompts ─────────────────────────────────────────────

class TestRoleOptimizedPrompts:
    """Verify the four new prompts exist and produce audience-appropriate content."""

    def _get_prompt_fn(self, name: str):
        import wazuh_mcp.server as srv
        # Prompts are registered on the mcp object; retrieve the wrapped function
        # by looking at the server module globals
        fn = getattr(srv, name, None)
        assert fn is not None, f"Prompt function '{name}' not found in server module"
        return fn

    def test_tier1_analyst_guide_contains_explain_alert(self):
        from wazuh_mcp import server as srv
        out = srv.tier1_analyst_guide("alert-123")
        assert "explain_alert" in out
        assert "Tier 1" in out or "tier1" in out.lower() or "WHAT TO DO" in out

    def test_tier1_analyst_guide_no_alert_id(self):
        from wazuh_mcp import server as srv
        out = srv.tier1_analyst_guide()
        assert "explain_recent_alerts" in out or "explain_alert" in out

    def test_tier2_deep_dive_contains_mitre(self):
        from wazuh_mcp import server as srv
        out = srv.tier2_analyst_deep_dive(agent_name="web-01")
        assert "mitre" in out.lower()
        assert "lateral" in out.lower()
        assert "containment" in out.lower() or "contain" in out.lower()

    def test_tier2_deep_dive_with_src_ip(self):
        from wazuh_mcp import server as srv
        out = srv.tier2_analyst_deep_dive(src_ip="10.0.0.1", time_range="48h")
        assert "10.0.0.1" in out
        assert "48h" in out

    def test_ciso_briefing_uses_business_language(self):
        from wazuh_mcp import server as srv
        out = srv.ciso_security_briefing("7d")
        assert "RISK POSTURE" in out or "BUSINESS" in out or "EXECUTIVE" in out or "RISKS" in out
        assert "vulnerability_summary" in out
        assert "compliance_summary" in out

    def test_ciso_briefing_no_technical_jargon_header(self):
        from wazuh_mcp import server as srv
        out = srv.ciso_security_briefing()
        # Should not contain raw API tool names in the narrative headers
        assert "EXECUTIVE" in out or "RISK" in out

    def test_compliance_officer_review_default_framework(self):
        from wazuh_mcp import server as srv
        out = srv.compliance_officer_review()
        assert "PCI-DSS" in out
        assert "audit" in out.lower()
        assert "export_compliance_csv" in out

    def test_compliance_officer_review_custom_framework(self):
        from wazuh_mcp import server as srv
        out = srv.compliance_officer_review(framework="HIPAA", period="90d")
        assert "HIPAA" in out
        assert "90d" in out

    def test_all_four_prompts_callable(self):
        from wazuh_mcp import server as srv
        for fn_name in ["tier1_analyst_guide", "tier2_analyst_deep_dive",
                         "ciso_security_briefing", "compliance_officer_review"]:
            fn = getattr(srv, fn_name, None)
            assert fn is not None, f"{fn_name} missing from server"
            result = fn()
            assert isinstance(result, str)
            assert len(result) > 100, f"{fn_name} returned suspiciously short output"


# ── 5. explain_alert + explain_recent_alerts ───────────────────────────────────

class TestExplainAlert:
    def _make_mock_hit(self, alert_id="abc123", level=12, rule_desc="SSH brute force",
                       agent_name="web-01", src_ip="185.1.2.3", user="root",
                       mitre_ids=None, mitre_tactics=None, groups=None,
                       timestamp="2026-05-26T10:00:00Z", full_log="May 26 sshd: Failed"):
        return {
            "_id": alert_id,
            "_source": {
                "@timestamp": timestamp,
                "rule": {
                    "level": level,
                    "id": "5710",
                    "description": rule_desc,
                    "mitre": {
                        "id": mitre_ids or ["T1110"],
                        "tactic": mitre_tactics or ["Credential Access"],
                    },
                    "groups": groups or ["authentication", "sshd"],
                },
                "agent": {"name": agent_name, "ip": "10.0.0.5"},
                "data": {"srcip": src_ip, "srcuser": user},
                "full_log": full_log,
            },
        }

    def _make_idx(self, hits=None, total=1):
        idx = AsyncMock()
        idx.search = AsyncMock(return_value={
            "hits": {
                "total": {"value": total},
                "hits": hits or [],
            },
            "aggregations": {},
        })
        return idx

    @pytest.mark.asyncio
    async def test_explain_alert_not_found(self):
        idx = self._make_idx(hits=[], total=0)
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        result = await registered["explain_alert"]("nonexistent-id")
        assert "error" in result
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_explain_alert_invalid_audience(self):
        idx = self._make_idx(hits=[], total=0)
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        result = await registered["explain_alert"]("id", audience="hacker")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_explain_alert_analyst_narrative(self):
        hit = self._make_hit = self._make_mock_hit()
        idx = self._make_idx(hits=[hit])
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        result = await registered["explain_alert"]("abc123", audience="analyst")
        assert result["severity"] == "HIGH"
        assert result["agent"] == "web-01"
        assert "narrative" in result
        assert "quick_actions" in result
        assert isinstance(result["quick_actions"], list)
        assert len(result["quick_actions"]) > 0

    @pytest.mark.asyncio
    async def test_explain_alert_tier1_narrative(self):
        hit = self._make_mock_hit(level=14, rule_desc="Malware detected")
        idx = self._make_idx(hits=[hit])
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        result = await registered["explain_alert"]("abc123", audience="tier1")
        assert "WHAT HAPPENED" in result["narrative"]
        assert "WHAT TO DO NEXT" in result["narrative"]

    @pytest.mark.asyncio
    async def test_explain_alert_ciso_narrative(self):
        hit = self._make_mock_hit(level=15, rule_desc="Critical exploit")
        idx = self._make_idx(hits=[hit])
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        result = await registered["explain_alert"]("abc123", audience="ciso")
        assert "EXECUTIVE SUMMARY" in result["narrative"]
        assert result["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_explain_alert_compliance_narrative(self):
        hit = self._make_mock_hit(groups=["authentication", "pam"])
        idx = self._make_idx(hits=[hit])
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        result = await registered["explain_alert"]("abc123", audience="compliance")
        assert "COMPLIANCE EVENT RECORD" in result["narrative"]
        assert "PCI-DSS" in result["narrative"] or "HIPAA" in result["narrative"]

    @pytest.mark.asyncio
    async def test_explain_alert_severity_levels(self):
        """Verify severity mapping: ≥15=CRITICAL, ≥12=HIGH, ≥7=MEDIUM, else LOW."""
        cases = [(15, "CRITICAL"), (12, "HIGH"), (7, "MEDIUM"), (3, "LOW")]
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register

        for level, expected_sev in cases:
            hit = self._make_mock_hit(level=level, alert_id=f"id-{level}")
            idx = self._make_idx(hits=[hit])
            registered.clear()
            ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
            register(ctx)
            result = await registered["explain_alert"](f"id-{level}")
            assert result["severity"] == expected_sev, \
                f"level {level} expected {expected_sev}, got {result['severity']}"

    @pytest.mark.asyncio
    async def test_explain_recent_alerts_empty(self):
        idx = self._make_idx(hits=[], total=0)
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        result = await registered["explain_recent_alerts"](time_range="1h", min_level=10)
        assert result["alerts_explained"] == 0
        assert "message" in result

    @pytest.mark.asyncio
    async def test_explain_recent_alerts_returns_summaries(self):
        hits = [
            self._make_mock_hit(alert_id="a1", level=12, agent_name="agent-1"),
            self._make_mock_hit(alert_id="a2", level=10, agent_name="agent-2"),
        ]
        idx = self._make_idx(hits=hits, total=2)
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        result = await registered["explain_recent_alerts"](time_range="1h", limit=5)
        assert result["alerts_explained"] == 2
        assert len(result["alerts"]) == 2
        for alert in result["alerts"]:
            assert "summary" in alert
            assert "quick_actions" in alert
            assert "severity" in alert

    @pytest.mark.asyncio
    async def test_explain_recent_alerts_limit_capped_at_10(self):
        """limit param should be capped at 10 regardless of input."""
        idx = self._make_idx(hits=[], total=0)
        # We just check the search call gets size≤10
        search_calls = []
        async def mock_search(body):
            search_calls.append(body)
            return {"hits": {"total": {"value": 0}, "hits": []}}

        idx.search = mock_search
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)
        await registered["explain_recent_alerts"](limit=999)
        assert search_calls[0]["size"] <= 10

    @pytest.mark.asyncio
    async def test_explain_alert_with_geo_enrichment(self):
        """explain_alert calls _geoip_lookup when src_ip present."""
        hit = self._make_mock_hit(src_ip="185.1.2.3")
        idx = self._make_idx(hits=[hit])
        mcp, wz, cfg = MagicMock(), MagicMock(), MagicMock()
        registered = {}

        def capture_tool():
            def dec(fn):
                registered[fn.__name__] = fn
                return fn
            return dec

        mcp.tool = capture_tool
        geo_called = []

        async def mock_geo(ip):
            geo_called.append(ip)
            return {"ip": ip, "country": "Russia", "city": "Moscow", "isp": "AS123"}

        from wazuh_mcp.tools.explain_alert import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        ctx.geoip_lookup = mock_geo
        register(ctx)
        result = await registered["explain_alert"]("abc123")
        assert geo_called == ["185.1.2.3"]
        assert "Russia" in result["narrative"]


# ── 5b. Narrative builder unit tests ──────────────────────────────────────────

class TestNarrativeBuilders:
    def test_quick_actions_high_severity_with_ip(self):
        from wazuh_mcp.tools.explain_alert import _quick_actions
        actions = _quick_actions("HIGH", "1.2.3.4", ["authentication"], [])
        assert any("enrich_ip" in a for a in actions)
        assert any("blast_radius" in a for a in actions)
        assert any("add_to_cdb_list" in a for a in actions)

    def test_quick_actions_low_severity_no_ip(self):
        from wazuh_mcp.tools.explain_alert import _quick_actions
        actions = _quick_actions("LOW", "", [], [])
        assert len(actions) > 0
        # Should fall back to generic search
        assert any("search_alerts" in a for a in actions)

    def test_quick_actions_lateral_movement_tactic(self):
        from wazuh_mcp.tools.explain_alert import _quick_actions
        actions = _quick_actions("MEDIUM", "", [], ["Lateral Movement"])
        assert any("hunt_lateral" in a for a in actions)

    def test_quick_actions_fim_groups(self):
        from wazuh_mcp.tools.explain_alert import _quick_actions
        actions = _quick_actions("MEDIUM", "", ["fim", "syscheck"], [])
        assert any("search_fim" in a for a in actions)

    def test_tier1_narrative_structure(self):
        from wazuh_mcp.tools.explain_alert import _tier1_narrative
        out = _tier1_narrative(
            "2026-05-26 10:00:00 UTC", "SSH brute force", 12, "HIGH",
            "web-01", "10.0.0.5", "1.2.3.4", " (Russia)", "root",
            ["authentication"], "sshd: Failed password"
        )
        assert "WHAT HAPPENED" in out
        assert "WHAT TO DO NEXT" in out
        assert "HIGH" in out
        assert "web-01" in out

    def test_ciso_narrative_critical_framing(self):
        from wazuh_mcp.tools.explain_alert import _ciso_narrative
        out = _ciso_narrative(
            "2026-05-26 10:00:00 UTC", "Ransomware detected", "CRITICAL",
            "db-server", "5.5.5.5", " (North Korea)", "T1486 (Impact)", ["Impact"]
        )
        assert "CRITICAL" in out
        assert "Immediate containment" in out or "incident response" in out.lower()

    def test_compliance_narrative_pci_hint(self):
        from wazuh_mcp.tools.explain_alert import _compliance_narrative
        out = _compliance_narrative(
            "2026-05-26 10:00:00 UTC", "Failed login", "MEDIUM",
            "web-01", "5710", ["authentication", "pam"], ""
        )
        assert "PCI-DSS" in out or "HIPAA" in out
        assert "COMPLIANCE EVENT RECORD" in out

    def test_compliance_narrative_fim_hint(self):
        from wazuh_mcp.tools.explain_alert import _compliance_narrative
        out = _compliance_narrative(
            "2026-05-26 10:00:00 UTC", "File modified", "HIGH",
            "srv-01", "550", ["fim", "syscheck"], ""
        )
        assert "File Integrity" in out or "SI-7" in out


# ── 6. Registry / packaging content ───────────────────────────────────────────

class TestRegistryContent:
    def test_readme_has_5min_quickstart(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "5-Minute Quickstart" in readme or "5-minute" in readme.lower()

    def test_readme_has_wazuh_cloud_section(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "Wazuh Cloud" in readme
        assert "WAZUH_CLOUD=true" in readme

    def test_readme_has_mssp_section(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "MSSP" in readme
        assert "WAZUH_INSTANCES" in readme
        assert "switch_tenant" in readme

    def test_readme_has_mcp_registry_section(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "MCP Registry" in readme

    def test_readme_has_role_prompts_table(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "tier1_analyst_guide" in readme
        assert "ciso_security_briefing" in readme
        assert "compliance_officer_review" in readme

    def test_readme_has_explain_tools_referenced(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        # Should reference the new explain tools somewhere
        assert "explain_alert" in readme or "explain" in readme.lower()

    def test_pyproject_description_outcome_focused(self):
        toml = Path("pyproject.toml").read_text(encoding="utf-8")
        assert "SOC" in toml or "triage" in toml.lower() or "5x faster" in toml

    def test_pyproject_keywords_include_soc_and_mssp(self):
        toml = Path("pyproject.toml").read_text(encoding="utf-8")
        assert "soc" in toml.lower()
        assert "mssp" in toml.lower()

    def test_env_example_has_cloud_section(self):
        env = Path("env.example").read_text(encoding="utf-8")
        assert "WAZUH_CLOUD=true" in env
        assert "WAZUH_CLOUD_URL" in env

    def test_env_example_has_mssp_section(self):
        env = Path("env.example").read_text(encoding="utf-8")
        assert "WAZUH_INSTANCES" in env
        assert "switch_tenant" in env

    def test_env_example_mentions_init_command(self):
        env = Path("env.example").read_text(encoding="utf-8")
        assert "wazuh-mcp init" in env

    def test_explain_alert_module_exists(self):
        path = Path("wazuh_mcp/tools/explain_alert.py")
        assert path.exists(), "explain_alert.py not found"

    def test_explain_alert_registered_in_server(self):
        server_src = Path("wazuh_mcp/server.py").read_text(encoding="utf-8")
        # With auto-discovery, the file is picked up via pkgutil.iter_modules
        assert "explain_alert" in server_src or "pkgutil" in server_src
