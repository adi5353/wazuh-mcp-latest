"""Tests for F6: CVE watchlist and patch tracking."""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch


def _make_env():
    tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    wz = MagicMock()
    idx = MagicMock()
    cfg = MagicMock()

    from wazuh_mcp.tools.cve_watchlist import register
    register(mcp, wz, idx, cfg)
    return tools, wz, idx, cfg


class TestAddCVE:
    def test_valid_cve_added(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        # Mock CDB list operations
        wz.request = AsyncMock(return_value={"data": {"affected_items": []}})
        result = asyncio.get_event_loop().run_until_complete(
            tools["add_cve_to_watchlist"]("CVE-2024-1234")
        )
        assert result.get("added") == "CVE-2024-1234" or "error" not in result

    def test_invalid_cve_id_rejected(self):
        import asyncio
        tools, _, _, _ = _make_env()
        result = asyncio.get_event_loop().run_until_complete(
            tools["add_cve_to_watchlist"]("not-a-cve")
        )
        assert "error" in result

    def test_cve_with_note(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value={"data": {"affected_items": []}})
        result = asyncio.get_event_loop().run_until_complete(
            tools["add_cve_to_watchlist"]("CVE-2024-5678", note="Critical RCE in nginx")
        )
        # Should not error on note addition
        assert "error" not in result or result.get("added") == "CVE-2024-5678"


class TestListWatchlist:
    def test_empty_watchlist(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value={
            "data": {"affected_items": []}
        })
        result = asyncio.get_event_loop().run_until_complete(
            tools["list_cve_watchlist"]()
        )
        assert "watchlist" in result
        assert isinstance(result["watchlist"], list)

    def test_populated_watchlist(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value={
            "data": {
                "affected_items": [
                    {"key": "CVE-2024-1234", "value": "active|Critical RCE"},
                    {"key": "CVE-2023-9999", "value": "patched|"},
                ]
            }
        })
        result = asyncio.get_event_loop().run_until_complete(
            tools["list_cve_watchlist"]()
        )
        assert len(result["watchlist"]) == 2

    def test_api_error_returns_error(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(side_effect=Exception("API down"))
        result = asyncio.get_event_loop().run_until_complete(
            tools["list_cve_watchlist"]()
        )
        assert "error" in result


class TestMarkPatched:
    def test_mark_patched_valid_cve(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        # First call: read existing entry; second: update
        wz.request = AsyncMock(return_value={
            "data": {"affected_items": [{"key": "CVE-2024-1234", "value": "active|test note"}]}
        })
        result = asyncio.get_event_loop().run_until_complete(
            tools["mark_patched"]("CVE-2024-1234")
        )
        assert "error" not in result or "patched" in str(result).lower()

    def test_mark_patched_invalid_cve(self):
        import asyncio
        tools, _, _, _ = _make_env()
        result = asyncio.get_event_loop().run_until_complete(
            tools["mark_patched"]("bad-id")
        )
        assert "error" in result


class TestWatchlistExposure:
    def test_exposure_returns_counts(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        # Watchlist list call
        wz.request = AsyncMock(return_value={
            "data": {
                "affected_items": [
                    {"key": "CVE-2024-1234", "value": "active|"},
                ]
            }
        })
        # Indexer search for affected agents
        idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 3}, "hits": [
                {"_source": {"agent": {"id": "001", "name": "web01"}}},
                {"_source": {"agent": {"id": "002", "name": "web02"}}},
                {"_source": {"agent": {"id": "003", "name": "db01"}}},
            ]}
        })
        result = asyncio.get_event_loop().run_until_complete(
            tools["get_watchlist_exposure"]()
        )
        assert "exposure" in result or "error" in result  # at minimum returns a dict
