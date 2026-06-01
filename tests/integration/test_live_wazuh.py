"""Live contract tests against a running Wazuh Manager + Indexer.

Purpose: verify this server's client code against the REAL Wazuh API — auth,
response envelopes, and index access — so contract drift is caught here instead
of in production. Every test depends on ``live_config`` and therefore SKIPS when
no live backend is reachable (see conftest).

Run with:  pytest -m integration -v
"""
from __future__ import annotations

import pytest

from wazuh_mcp.wazuh_client import WazuhClient
from wazuh_mcp.wazuh_indexer import WazuhIndexer

# Mark every test in this module as integration so the default (unit) run, which
# excludes `-m integration`, never collects them.
pytestmark = pytest.mark.integration


async def test_manager_authenticates_and_returns_envelope(live_config):
    """JWT auth succeeds and the API root returns Wazuh's data envelope."""
    async with WazuhClient(live_config) as wz:
        data = await wz.request("GET", "/")
        assert isinstance(data, dict)
        # Wazuh wraps responses in {"data": {...}, "error": 0, ...}.
        assert "data" in data, f"unexpected API root shape: {sorted(data)[:5]}"


async def test_detect_api_version_is_v4_or_newer(live_config):
    """detect_api_version parses a real version (Wazuh 4.x+)."""
    async with WazuhClient(live_config) as wz:
        ver = await wz.detect_api_version()
        assert ver["major"] >= 4, f"unexpected Wazuh major version: {ver}"


async def test_manager_agent_000_present(live_config):
    """The Manager is always registered as agent 000 — a stable contract."""
    async with WazuhClient(live_config) as wz:
        data = await wz.request("GET", "/agents", params={"agents_list": "000"})
        items = data["data"]["affected_items"]
        assert len(items) == 1
        assert items[0]["id"] == "000"


async def test_indexer_alerts_index_searchable(live_config):
    """The Indexer answers a search over the alerts pattern with a hits envelope.

    A fresh stack may have zero alerts; an empty result is fine. We assert the
    response *shape* (hits.total) the rest of the codebase relies on.
    """
    async with WazuhIndexer(live_config) as idx:
        result = await idx.search({"size": 1, "query": {"match_all": {}}})
        assert "hits" in result, f"unexpected indexer response: {sorted(result)[:5]}"
        assert "total" in result["hits"]


async def test_indexer_count_returns_int(live_config):
    """count() returns a real integer from the live Indexer."""
    async with WazuhIndexer(live_config) as idx:
        n = await idx.count({"match_all": {}})
        assert isinstance(n, int)
        assert n >= 0
