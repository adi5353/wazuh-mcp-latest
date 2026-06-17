"""Tests for F6: CVE watchlist and patch tracking."""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wazuh_mcp.tool_context import ToolContext


def _raw(*lines: str) -> dict:
    """Build a Manager (non-raw) CDB read response.

    Each "CVE-ID:value" line becomes a single-key {cve_id: value} dict in
    affected_items, matching the JSON envelope the Manager returns for a
    default GET /lists/files/{name} (the ?raw=true variant returns text/plain).
    """
    items = []
    for ln in lines:
        k, v = ln.split(":", 1)
        items.append({k: v})
    return {"data": {"affected_items": items}}


def _make_env():
    tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    wz = MagicMock()
    # Writes go through the octet-stream upload helper (overwrite=true); mock it
    # as awaitable so write-path tests don't await a bare MagicMock.
    wz.upload_xml_file = AsyncMock(return_value={"error": 0})
    idx = MagicMock()
    cfg = MagicMock()

    from wazuh_mcp.tools.cve_watchlist import register
    ctx = ToolContext(mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
    register(ctx)
    return tools, wz, idx, cfg


class TestAddCVE:
    def test_valid_cve_added(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        # Read for merge returns an empty list; write goes through upload_xml_file.
        wz.request = AsyncMock(return_value=_raw())
        result = asyncio.run(
            tools["add_cve_to_watchlist"]("CVE-2024-1234")
        )
        assert result.get("added") == "CVE-2024-1234"
        assert "error" not in result
        # The full list is rewritten via the octet-stream upload helper.
        wz.upload_xml_file.assert_awaited_once()
        path, content = wz.upload_xml_file.await_args.args[:2]
        assert path == "/lists/files/cve-watchlist"
        assert content.startswith("CVE-2024-1234:active|")

    def test_invalid_cve_id_rejected(self):
        import asyncio
        tools, _, _, _ = _make_env()
        result = asyncio.run(
            tools["add_cve_to_watchlist"]("not-a-cve")
        )
        assert "error" in result

    def test_cve_with_note(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value=_raw())
        result = asyncio.run(
            tools["add_cve_to_watchlist"]("CVE-2024-5678", note="Critical RCE in nginx")
        )
        assert result.get("added") == "CVE-2024-5678"
        assert "error" not in result

    def test_existing_entries_preserved(self):
        """Adding a CVE must not wipe other entries (full-file rewrite)."""
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value=_raw("CVE-2023-1111:active|old"))
        result = asyncio.run(
            tools["add_cve_to_watchlist"]("CVE-2024-2222", cvss_score=9.8)
        )
        assert result.get("added") == "CVE-2024-2222"
        _, content = wz.upload_xml_file.await_args.args[:2]
        assert "CVE-2023-1111:active|old" in content  # prior entry retained
        assert "CVE-2024-2222:active|" in content

    def test_note_with_colon_sanitized(self):
        """A note containing ':' / '|' must not corrupt the CDB key:value format."""
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value=_raw())
        result = asyncio.run(
            tools["add_cve_to_watchlist"]("CVE-2024-3333", note="see http://x exploit|RCE")
        )
        assert result.get("added") == "CVE-2024-3333"
        line = wz.upload_xml_file.await_args.args[1].strip()
        stored_value = line.split(":", 1)[1]
        assert ":" not in stored_value and "\n" not in stored_value
        # The note field (index 1) carries no stray '|' that would shift fields.
        assert len(stored_value.split("|")) == 5

    def test_write_failure_surfaces_error(self):
        """A Manager body-level rejection (HTTP 200 + error) must not report success."""
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value=_raw())
        wz.upload_xml_file = AsyncMock(return_value={
            "error": 1,
            "data": {"failed_items": [{"error": {"code": 1800, "message": "Bad format in CDB list"}}]},
        })
        result = asyncio.run(
            tools["add_cve_to_watchlist"]("CVE-2024-4444")
        )
        assert "error" in result
        assert "added" not in result


class TestListWatchlist:
    def test_empty_watchlist(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value=_raw())
        result = asyncio.run(
            tools["list_cve_watchlist"]()
        )
        assert "watchlist" in result
        assert isinstance(result["watchlist"], list)
        assert result["total"] == 0

    def test_populated_watchlist(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value=_raw(
            "CVE-2024-1234:active|Critical RCE",
            "CVE-2023-9999:patched|",
        ))
        result = asyncio.run(
            tools["list_cve_watchlist"]()
        )
        assert len(result["watchlist"]) == 2

    def test_api_error_returns_error(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(side_effect=Exception("API down"))
        result = asyncio.run(
            tools["list_cve_watchlist"]()
        )
        assert "error" in result


class TestMarkPatched:
    def test_mark_patched_valid_cve(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value=_raw("CVE-2024-1234:active|test note|9.8|30|2026-01-01T00:00:00Z"))
        result = asyncio.run(
            tools["mark_patched"]("CVE-2024-1234")
        )
        assert "error" not in result
        assert result.get("status") == "patched"
        # CVSS + SLA preserved when flipping to patched, and the written value is
        # colon-free (the ISO added_at is normalised to a Unix epoch).
        _, content = wz.upload_xml_file.await_args.args[:2]
        line = content.strip()
        assert line.startswith("CVE-2024-1234:patched|")
        stored_value = line.split(":", 1)[1]
        assert ":" not in stored_value  # colon-free => valid Wazuh CDB record
        fields = stored_value.split("|")
        assert fields[2] == "9.8" and fields[3] == "30"
        assert fields[4].isdigit()  # added_at is epoch, not ISO

    def test_mark_patched_invalid_cve(self):
        import asyncio
        tools, _, _, _ = _make_env()
        result = asyncio.run(
            tools["mark_patched"]("bad-id")
        )
        assert "error" in result


class TestWatchlistExposure:
    def test_exposure_returns_counts(self):
        import asyncio
        tools, wz, idx, cfg = _make_env()
        wz.request = AsyncMock(return_value=_raw("CVE-2024-1234:active|"))
        idx.search = AsyncMock(return_value={
            "hits": {"total": {"value": 3}},
            "aggregations": {"agents": {"buckets": [
                {"key": "001"}, {"key": "002"}, {"key": "003"},
            ]}},
        })
        result = asyncio.run(
            tools["get_watchlist_exposure"]()
        )
        assert "exposure" in result
        assert result["exposure"][0]["cve_id"] == "CVE-2024-1234"
        assert result["exposure"][0]["affected_agents"] == 3
