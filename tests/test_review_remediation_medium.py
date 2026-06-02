"""Regression tests for the Medium review-remediation fixes.

  M2  rate limiter parses the tool name from the body so write/admin per-tool
      limits actually fire; anonymous callers are bucketed per client IP;
      identity dicts are pruned past a cap.
  --  result cache is bounded (max entries + eviction).
  --  indexer page-size guard raises (not assert, which `python -O` strips).
  M3  ApprovalStore sync methods don't call run_until_complete on a live loop;
      in-memory pending dict is capped.
"""
from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ── M2: rate limiter tool-name parsing + per-tool limits + per-IP identity ────

class TestRateLimitToolName:
    def test_tool_name_parsed_from_body(self):
        from wazuh_mcp.rate_limit import _tool_name_from_body
        body = json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                            "params": {"name": "run_active_response"}}).encode()
        assert _tool_name_from_body(body) == "run_active_response"

    def test_tool_name_none_for_non_toolcall(self):
        from wazuh_mcp.rate_limit import _tool_name_from_body
        assert _tool_name_from_body(json.dumps({"method": "tools/list"}).encode()) is None
        assert _tool_name_from_body(b"") is None
        assert _tool_name_from_body(b"not json") is None

    def test_write_tool_limit_actually_fires(self):
        import wazuh_mcp.rate_limit as rl
        rl._write_windows.clear()
        with patch.dict(os.environ, {"WAZUH_MCP_RATE_LIMIT_WRITES_RPM": "3"}):
            ident = "ident-A"
            results = [rl._is_tool_throttled(ident, "run_active_response")[0] for _ in range(5)]
        # First 3 allowed, then throttled — previously this never triggered
        # because the tool name was read from a scope key nothing ever set.
        assert results[:3] == [False, False, False]
        assert results[3] is True

    def test_anonymous_bucketed_per_ip(self):
        from wazuh_mcp.rate_limit import _identity_from_scope
        a = _identity_from_scope({"headers": [], "client": ("10.0.0.1", 5)})
        b = _identity_from_scope({"headers": [], "client": ("10.0.0.2", 5)})
        assert a.startswith("ip:") and b.startswith("ip:")
        assert a != b  # distinct anonymous sources don't share a bucket

    def test_authenticated_bucketed_by_header(self):
        from wazuh_mcp.rate_limit import _identity_from_scope
        ident = _identity_from_scope({"headers": [(b"authorization", b"Bearer K")],
                                      "client": ("10.0.0.1", 5)})
        assert not ident.startswith("ip:")

    def test_identity_dicts_pruned_past_cap(self):
        import wazuh_mcp.rate_limit as rl
        rl._windows.clear()
        with patch.object(rl, "_MAX_IDENTITIES", 5):
            # Seed many stale identities (timestamps far in the past).
            for i in range(20):
                rl._windows[f"stale-{i}"].append(0.0)
            rl._is_throttled("fresh")  # triggers _prune_if_needed
        assert len(rl._windows) <= 6  # stale entries dropped, 'fresh' kept


# ── Cache is bounded ──────────────────────────────────────────────────────────

class TestCacheBounded:
    def test_cache_respects_max_entries(self):
        import wazuh_mcp.cache as c
        c.invalidate_all()
        with patch.object(c, "_MAX_ENTRIES", 10), patch.object(c, "_TTL", 60):
            for i in range(100):
                c._put(f"key-{i}", "tool", {"v": i})
            assert len(c._store) <= 10
        c.invalidate_all()

    def test_cache_evicts_expired_first(self):
        import time
        import wazuh_mcp.cache as c
        c.invalidate_all()
        with patch.object(c, "_MAX_ENTRIES", 5), patch.object(c, "_TTL", 60):
            # Insert one already-expired entry directly, then fill to the cap.
            c._store["expired"] = (time.monotonic() - 1, {"old": True}, "tool")
            for i in range(10):
                c._put(f"k{i}", "tool", {"v": i})
            assert "expired" not in c._store
            assert len(c._store) <= 5
        c.invalidate_all()


# ── Indexer page-size guard raises (assert-free) ──────────────────────────────

class TestIndexerSizeGuard:
    def test_oversize_raises_valueerror(self):
        from wazuh_mcp.wazuh_indexer import WazuhIndexer
        cfg = SimpleNamespace(
            ca_bundle=None, verify_ssl=False, indexer_user="u", indexer_pass="p",
            request_timeout=30, indexer_host="http://x:9200", alerts_index="idx",
        )
        idx = WazuhIndexer(cfg)

        async def run():
            try:
                with pytest.raises(ValueError):
                    await idx._search_impl({"size": 501})
            finally:
                await idx.aclose()
        asyncio.run(run())


# ── M3: ApprovalStore sync safety + bounded pending ───────────────────────────

class TestApprovalStore:
    def test_sync_create_works_outside_loop(self):
        from wazuh_mcp.approval import ApprovalStore
        store = ApprovalStore()              # memory backend (no REDIS_URL)
        token = store.create("run_active_response", {"agent_id": "001"}, ttl=300)
        assert token
        entry = store.approve(token)
        assert entry is not None and entry["params"]["agent_id"] == "001"

    def test_sync_method_raises_inside_running_loop_with_redis(self):
        from wazuh_mcp.approval import ApprovalStore
        store = ApprovalStore()
        store._redis = MagicMock()  # force the redis branch of the sync method

        async def run():
            # Old code called loop.run_until_complete() here -> opaque RuntimeError.
            with pytest.raises(RuntimeError):
                store.create("run_active_response", {"agent_id": "001"})
        asyncio.run(run())

    def test_pending_dict_is_capped(self):
        import wazuh_mcp.approval as ap
        store = ap.ApprovalStore()
        with patch.object(ap, "_MAX_PENDING", 10):
            for i in range(50):
                store.create("run_active_response", {"i": i}, ttl=300)
        assert len(store._pending) <= 10
