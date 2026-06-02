"""Regression tests for the Critical/High review-remediation fixes.

Covers:
  C1  agent_id fan-out validation on active-response / restart / get_agent
  C1  propose_active_response validates the full proposal up front
  C2  ABAC scoping injected centrally into every indexer query
  C2  switch_tenant / list_tenants require ADMIN
  #1  /ws/alerts authentication decision (_ws_request_authorized)
  #4  autonomous SOC GeoIP enrichment is HTTPS-only and skips private IPs
  #5  audit log hash-chaining detects deletion/reordering
  #6  Vault secret path uses removeprefix (not the lstrip char-set bug)
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── C1: single-agent validator rejects fleet fan-out keywords ─────────────────

class TestAgentIdFanoutValidation:
    def test_validate_agent_id_rejects_reserved(self):
        from wazuh_mcp.validators import validate_agent_id
        for bad in ("all", "ALL", "All", "*", "  all  "):
            with pytest.raises(ValueError):
                validate_agent_id(bad)

    def test_validate_agent_id_rejects_lists(self):
        from wazuh_mcp.validators import validate_agent_id
        with pytest.raises(ValueError):
            validate_agent_id("001,002,003")

    def test_validate_agent_id_accepts_single(self):
        from wazuh_mcp.validators import validate_agent_id
        assert validate_agent_id("001") == "001"
        assert validate_agent_id("agent-01_x") == "agent-01_x"


def _register_agents_tools(*, allow_writes=True):
    from wazuh_mcp.tools.agents import register
    from wazuh_mcp.tool_context import ToolContext

    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    cfg = MagicMock()
    cfg.allow_writes = allow_writes
    require_writes = (lambda: None) if allow_writes else (lambda: {"error": "writes off"})
    wz = AsyncMock()
    wz.request = AsyncMock(return_value={"data": "ok"})
    ctx = ToolContext(
        mcp=mcp, wz=wz, idx=AsyncMock(), cfg=cfg,
        cap=lambda x: x, require_writes=require_writes,
        truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [],
        geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda a: [],
    )
    register(ctx)
    return tools, wz


class TestActiveResponseFanoutBlocked:
    def _admin(self):
        from wazuh_mcp import identity
        from wazuh_mcp.rbac import ROLE
        identity.set_session_role(ROLE.ADMIN)

    def test_run_active_response_blocks_all(self):
        async def run():
            self._admin()
            tools, wz = _register_agents_tools(allow_writes=True)
            res = await tools["run_active_response"]("all", "firewall-drop",
                                                     arguments=["1.2.3.4"], dry_run=False)
            assert "error" in res
            wz.request.assert_not_awaited()  # never reached the Manager
        asyncio.run(run())

    def test_restart_agent_blocks_all(self):
        async def run():
            self._admin()
            tools, wz = _register_agents_tools(allow_writes=True)
            res = await tools["restart_agent"]("all", dry_run=False)
            assert "error" in res
            wz.request.assert_not_awaited()
        asyncio.run(run())

    def test_get_agent_blocks_wildcard(self):
        async def run():
            self._admin()
            tools, wz = _register_agents_tools()
            res = await tools["get_agent"]("*")
            assert "error" in res
            wz.request.assert_not_awaited()
        asyncio.run(run())

    def test_run_active_response_allows_single_agent(self):
        async def run():
            self._admin()
            tools, wz = _register_agents_tools(allow_writes=True)
            res = await tools["run_active_response"]("001", "firewall-drop",
                                                     arguments=["1.2.3.4"], dry_run=False)
            assert "error" not in res
            wz.request.assert_awaited_once()
        asyncio.run(run())


class TestProposeValidatesUpFront:
    def test_propose_blocks_all_agent(self):
        from wazuh_mcp.tools.active_response import register
        from wazuh_mcp.tool_context import ToolContext
        from wazuh_mcp import identity
        from wazuh_mcp.rbac import ROLE

        async def run():
            identity.set_session_role(ROLE.ADMIN)
            tools: dict = {}
            mcp = MagicMock()
            mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
            cfg = MagicMock(); cfg.allow_writes = True
            ctx = ToolContext(
                mcp=mcp, wz=AsyncMock(), idx=AsyncMock(), cfg=cfg,
                cap=lambda x: x, require_writes=lambda: None,
                truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [],
                geoip_lookup=AsyncMock(return_value={}),
                incident_recommendations=lambda a: [],
            )
            register(ctx)
            store = MagicMock(); store.acreate = AsyncMock(return_value="tok")
            with patch("wazuh_mcp.approval.approval_store", store), \
                 patch.dict(os.environ, {"SLACK_WEBHOOK_URL": ""}):
                res = await tools["propose_active_response"]("firewall-drop", "all", "1.2.3.4")
            assert "error" in res
            store.acreate.assert_not_awaited()  # never stored an unsafe proposal
        asyncio.run(run())


# ── C2: ABAC scoping is injected into every indexer query ─────────────────────

class TestAbacScopeInjection:
    def test_noop_when_disabled(self):
        from wazuh_mcp import wazuh_indexer as wi
        body = {"query": {"term": {"rule.level": 10}}, "size": 5}
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WAZUH_MCP_ALLOWED_GROUPS", None)
            os.environ.pop("WAZUH_MCP_ALLOWED_AGENTS", None)
            os.environ.pop("WAZUH_MCP_DENIED_GROUPS", None)
            assert wi._apply_abac_scope(body) == body

    def test_wraps_and_filters_when_enabled(self):
        from wazuh_mcp import wazuh_indexer as wi
        body = {"query": {"term": {"rule.level": 10}}, "size": 5}
        with patch.dict(os.environ, {"WAZUH_MCP_ALLOWED_GROUPS": "linux-prod"}):
            out = wi._apply_abac_scope(body)
        assert out["query"]["bool"]["must"] == [{"term": {"rule.level": 10}}]
        assert {"terms": {"agent.groups": ["linux-prod"]}} in out["query"]["bool"]["filter"]
        assert out["size"] == 5

    def test_defaults_to_match_all_when_no_query(self):
        from wazuh_mcp import wazuh_indexer as wi
        with patch.dict(os.environ, {"WAZUH_MCP_ALLOWED_AGENTS": "001"}):
            out = wi._apply_abac_scope({"size": 0, "aggs": {}})
        assert out["query"]["bool"]["must"] == [{"match_all": {}}]
        assert {"terms": {"agent.id": ["001"]}} in out["query"]["bool"]["filter"]


# ── C2: tenant operations require ADMIN ───────────────────────────────────────

class TestTenantToolsRequireAdmin:
    def test_list_tenants_denied_for_viewer(self):
        async def run():
            from wazuh_mcp import identity
            from wazuh_mcp.rbac import ROLE
            from wazuh_mcp.server import list_tenants
            identity.set_session_role(ROLE.VIEWER)
            res = await list_tenants()
            assert "error" in res
        asyncio.run(run())

    def test_switch_tenant_denied_for_viewer(self):
        async def run():
            from wazuh_mcp import identity
            from wazuh_mcp.rbac import ROLE
            from wazuh_mcp.server import switch_tenant
            identity.set_session_role(ROLE.VIEWER)
            res = await switch_tenant("anything")
            assert "error" in res
        asyncio.run(run())


# ── #1: WebSocket auth decision ───────────────────────────────────────────────

class TestWebSocketAuthDecision:
    def _f(self, **kw):
        from wazuh_mcp.server import _ws_request_authorized
        return _ws_request_authorized(**kw)

    def test_key_required_when_configured(self):
        assert self._f(token="", origin="", api_key="K", is_loopback=True, allowed_origins=set()) is False
        assert self._f(token="K", origin="", api_key="K", is_loopback=True, allowed_origins=set()) is True
        assert self._f(token="x", origin="", api_key="K", is_loopback=True, allowed_origins=set()) is False

    def test_origin_enforced_even_with_valid_key(self):
        assert self._f(token="K", origin="http://evil", api_key="K",
                       is_loopback=True, allowed_origins={"http://ok"}) is False

    def test_loopback_dev_without_key_allowed(self):
        assert self._f(token="", origin="", api_key="", is_loopback=True, allowed_origins=set()) is True

    def test_nonloopback_originless_without_key_denied(self):
        assert self._f(token="", origin="", api_key="", is_loopback=False, allowed_origins=set()) is False


# ── #4: autonomous GeoIP enrichment is HTTPS + private-IP-safe ────────────────

class TestAutonomousGeoEgress:
    def test_no_plaintext_ip_api(self):
        src = (importlib.import_module("wazuh_mcp.tools.autonomous_soc").__file__)
        text = open(src, encoding="utf-8").read()
        assert "http://ip-api.com" not in text          # no cleartext leak
        assert "https://ip-api.com" in text
        assert "ipaddress.ip_address" in text           # private-IP guard present


# ── #5: audit hash-chain detects deletion ─────────────────────────────────────

class TestAuditHashChain:
    def test_deletion_detected(self):
        d = tempfile.mkdtemp()
        with patch.dict(os.environ, {"WAZUH_AUDIT_LOG": os.path.join(d, "a.jsonl"),
                                     "WAZUH_AUDIT_LOG_SIGNING_KEY": "k-secret"}):
            import wazuh_mcp.audit as a
            importlib.reload(a)
            try:
                for i in range(5):
                    with a.audit_logger.record(f"t{i}", {"i": i}, identity="id"):
                        pass
                clean = a.verify_audit_log_integrity()
                assert clean["integrity"] == "OK"
                assert clean["verified"] == 5
                assert clean["chain_breaks"] == 0

                # Delete a middle record — a plain per-record HMAC would miss this.
                p = os.path.join(d, "a.jsonl")
                lines = open(p).read().splitlines()
                del lines[2]
                open(p, "w").write("\n".join(lines) + "\n")

                tampered = a.verify_audit_log_integrity()
                assert tampered["chain_breaks"] >= 1
                assert tampered["integrity"] == "COMPROMISED"
            finally:
                importlib.reload(a)  # restore module to env-default state


# ── #6: Vault secret path prefix handling (removeprefix, not lstrip) ──────────

class TestVaultPathPrefix:
    def test_secret_path_is_relative_to_mount(self):
        captured = {}

        class _KV:
            def read_secret_version(self, path, mount_point):
                captured["path"] = path
                captured["mount"] = mount_point
                return {"data": {"data": {"WAZUH_PASS": "s3cr3t"}}}

        class _Secrets:
            kv = MagicMock()

        fake_hvac = MagicMock()
        client = MagicMock()
        client.secrets.kv.v2 = _KV()
        fake_hvac.Client.return_value = client

        env = {
            "WAZUH_SECRET_BACKEND": "vault",
            "VAULT_ADDR": "https://vault:8200",
            "VAULT_TOKEN": "t",
            "VAULT_SECRET_PATH": "secret/staging",   # the lstrip bug -> "taging"
            "VAULT_MOUNT_POINT": "secret",
        }
        with patch.dict(sys.modules, {"hvac": fake_hvac}), patch.dict(os.environ, env):
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            try:
                val = sb.get_secret("WAZUH_PASS", default="wazuh")
                assert captured["path"] == "staging"   # removeprefix, NOT "taging"
                assert val == "s3cr3t"
            finally:
                # Restore the module to its env-default (no backend) state.
                os.environ.pop("WAZUH_SECRET_BACKEND", None)
                importlib.reload(sb)
