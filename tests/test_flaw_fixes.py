"""Tests for all 10 flaw fixes — run: pytest tests/test_flaw_fixes.py -v"""
from __future__ import annotations
import asyncio
import json
import time
import pytest


class TestIocCache:
    def test_miss(self):
        from wazuh_mcp.tools.threat_intel import _cache_get, _IOC_CACHE
        _IOC_CACHE.clear()
        assert _cache_get("vt:ip_addresses/1.2.3.4") is None

    def test_hit(self):
        from wazuh_mcp.tools.threat_intel import _cache_get, _cache_set, _IOC_CACHE
        _IOC_CACHE.clear()
        p = {"data": {}}
        _cache_set("vt:ip_addresses/1.2.3.4", p, ttl=300)
        assert _cache_get("vt:ip_addresses/1.2.3.4") == p

    def test_expires(self):
        from wazuh_mcp.tools.threat_intel import _cache_get, _cache_set, _IOC_CACHE
        _IOC_CACHE.clear()
        _cache_set("vt:test", {"x": 1}, ttl=0)
        time.sleep(0.01)
        assert _cache_get("vt:test") is None

    def test_eviction(self):
        from wazuh_mcp.tools.threat_intel import _cache_set, _IOC_CACHE
        _IOC_CACHE.clear()
        for i in range(2010):
            _cache_set(f"vt:{i}", {"i": i}, ttl=60)
        assert len(_IOC_CACHE) < 2010


class TestIocDefanging:
    @staticmethod
    def d(ioc):
        return (ioc.strip()
                .replace("[.]", ".").replace("(.)", ".")
                .replace("[:]", ":").replace("hxxp", "http")
                .replace("hXXp", "http").replace("hxxps", "https")
                .replace("hXXps", "https"))

    def test_defanged_ip(self):     assert self.d("1[.]1[.]1[.]1") == "1.1.1.1"
    def test_hxxps_url(self):       assert self.d("hxxps[:]//evil.com") == "https://evil.com"
    def test_defanged_domain(self): assert self.d("evil[.]com") == "evil.com"
    def test_clean_unchanged(self): assert self.d("8.8.8.8") == "8.8.8.8"
    def test_hXXp(self):            assert self.d("hXXp://x.com") == "http://x.com"


class TestPlaybookRollback:
    @pytest.mark.asyncio
    async def test_no_steps_ok(self):
        from wazuh_mcp.tools.playbooks import _run_rollback
        r, ok = await _run_rollback({"rollback_steps": []}, [0], {}, {})
        assert r == [] and ok is True

    @pytest.mark.asyncio
    async def test_success_ok(self):
        from wazuh_mcp.tools.playbooks import _run_rollback
        async def good(**kw): return {"ok": True}
        pb = {"rollback_steps": [{"name":"r","tool":"g","params":{},"rollback_for_step":0}]}
        r, ok = await _run_rollback(pb, [0], {}, {"g": good})
        assert ok is True and r[0]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_failure_not_ok(self):
        from wazuh_mcp.tools.playbooks import _run_rollback
        async def bad(**kw): raise RuntimeError("boom")
        pb = {"rollback_steps": [{"name":"r","tool":"b","params":{},"rollback_for_step":0}]}
        r, ok = await _run_rollback(pb, [0], {}, {"b": bad})
        assert ok is False and "boom" in r[0]["error"]


class TestFpHeuristic:
    def _mod(self, mp, **env):
        for k, v in env.items(): mp.setenv(k, v)
        import importlib, wazuh_mcp.tools.autonomous_soc as m
        importlib.reload(m); return m

    def test_default_noisy(self, monkeypatch):
        m = self._mod(monkeypatch)
        assert m._fp_score("x", ["syscheck"], 0) > 0.0

    def test_custom_noisy(self, monkeypatch):
        m = self._mod(monkeypatch, WAZUH_FP_NOISY_GROUPS="mine", WAZUH_FP_NOISY_SCORE="0.6")
        assert m._fp_score("x", ["mine"], 0) == pytest.approx(0.6)
        assert m._fp_score("x", ["syscheck"], 0) == 0.0

    def test_high_vol(self, monkeypatch):
        m = self._mod(monkeypatch, WAZUH_FP_NOISY_GROUPS="none",
                      WAZUH_FP_HIGH_VOL_THR="10", WAZUH_FP_HIGH_VOL_SCORE="0.5")
        assert m._fp_score("x", [], 15) == pytest.approx(0.5)

    def test_suppress_thr(self, monkeypatch):
        m = self._mod(monkeypatch, WAZUH_FP_SUPPRESS_THR="0.8")
        assert m._FP_AUTO_SUPP_THR == pytest.approx(0.8)


class TestInstancesFile:
    def test_inline_ok(self, monkeypatch):
        monkeypatch.delenv("WAZUH_INSTANCES_FILE", raising=False)
        from wazuh_mcp.config import _load_instances_json
        t = _load_instances_json(json.dumps([{"name":"a","host":"h"}]),"u","p","h","u","p")
        assert t[0].name == "a"

    def test_file_overrides(self, tmp_path, monkeypatch):
        f = tmp_path / "i.json"
        f.write_text(json.dumps([{"name":"file-t","host":"h"}]))
        monkeypatch.setenv("WAZUH_INSTANCES_FILE", str(f))
        from wazuh_mcp.config import _load_instances_json
        t = _load_instances_json("[]","u","p","h","u","p")
        assert t[0].name == "file-t"

    def test_missing_name_raises(self, monkeypatch):
        monkeypatch.delenv("WAZUH_INSTANCES_FILE", raising=False)
        from wazuh_mcp.config import _load_instances_json
        with pytest.raises(RuntimeError, match="missing required fields"):
            _load_instances_json(json.dumps([{"host":"h"}]),"u","p","h","u","p")

    def test_bad_json_raises(self, monkeypatch):
        monkeypatch.delenv("WAZUH_INSTANCES_FILE", raising=False)
        from wazuh_mcp.config import _load_instances_json
        with pytest.raises(RuntimeError, match="Invalid JSON"):
            _load_instances_json("bad","u","p","h","u","p")

    def test_missing_file_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("WAZUH_INSTANCES_FILE", str(tmp_path/"no.json"))
        from wazuh_mcp.config import _load_instances_json
        with pytest.raises(RuntimeError, match="Cannot read WAZUH_INSTANCES_FILE"):
            _load_instances_json("","u","p","h","u","p")

    def test_empty_returns_empty(self, monkeypatch):
        monkeypatch.delenv("WAZUH_INSTANCES_FILE", raising=False)
        from wazuh_mcp.config import _load_instances_json
        assert _load_instances_json("","u","p","h","u","p") == ()


class TestDeduplication:
    @pytest.mark.asyncio
    async def test_three_identical_queries_one_wire_call(self, monkeypatch):
        calls = 0
        from wazuh_mcp.config import Config
        from wazuh_mcp.wazuh_indexer import WazuhIndexer
        cfg = Config(
            manager_host="https://x:55000", manager_user="u", manager_pass="p",
            indexer_host="https://i:9200", indexer_user="u", indexer_pass="p",
            alerts_index="wazuh-alerts-*", vuln_index="v",
            inventory_packages_index="i", inventory_processes_index="i",
            inventory_ports_index="i", verify_ssl=False, ca_bundle=None,
            allow_writes=False, request_timeout=10, cloud_mode=False,
        )
        idx = WazuhIndexer(cfg)
        async def fake(body, index=None):
            nonlocal calls; calls += 1
            await asyncio.sleep(0.05)
            return {"hits": {"total": {"value": 7}, "hits": []}}
        monkeypatch.setattr(idx, "_search_impl", fake)
        from wazuh_mcp import circuit_breaker as cb
        monkeypatch.setattr(cb.opensearch_breaker, "allow", lambda: True)
        monkeypatch.setattr(cb.opensearch_breaker, "record_success", lambda: None)
        body = {"query": {"match_all": {}}}
        rs = await asyncio.gather(
            idx.search(body, "wazuh-alerts-*"),
            idx.search(body, "wazuh-alerts-*"),
            idx.search(body, "wazuh-alerts-*"),
        )
        assert all(r["hits"]["total"]["value"] == 7 for r in rs)
        assert calls == 1, f"Expected 1 wire call got {calls}"


class TestMaxBodySize:
    def test_default_4mb(self):
        from wazuh_mcp.body_limit import _DEFAULT_MAX_KB
        assert _DEFAULT_MAX_KB == 4096

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_MAX_BODY_KB", "512")
        import importlib, wazuh_mcp.body_limit as bl
        importlib.reload(bl)
        assert bl._max_bytes() == 512 * 1024
