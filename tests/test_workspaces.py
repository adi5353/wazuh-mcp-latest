"""Tests for F12: Investigation Workspaces."""
import os
import json
import pytest
from unittest.mock import MagicMock, patch


def _make_env(tmp_path):
    tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    cfg = MagicMock()

    with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
        from wazuh_mcp.tools.workspaces import register
        register(mcp, cfg)
    return tools, cfg


class TestCreateWorkspace:
    def test_create_returns_id(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            result = asyncio.get_event_loop().run_until_complete(
                tools["create_workspace"]("Ransomware Investigation")
            )
        assert "workspace_id" in result
        assert result["name"] == "Ransomware Investigation"

    def test_workspace_file_created(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            result = asyncio.get_event_loop().run_until_complete(
                tools["create_workspace"]("Test WS")
            )
        ws_id = result["workspace_id"]
        ws_file = tmp_path / f"{ws_id}.json"
        assert ws_file.exists()

    def test_empty_name_rejected(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            result = asyncio.get_event_loop().run_until_complete(
                tools["create_workspace"]("")
            )
        assert "error" in result


class TestAddToWorkspace:
    def test_add_note(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            created = asyncio.get_event_loop().run_until_complete(
                tools["create_workspace"]("Incident WS")
            )
            ws_id = created["workspace_id"]
            result = asyncio.get_event_loop().run_until_complete(
                tools["add_to_workspace"](ws_id, item_type="note", content="Suspicious process on web01")
            )
        assert result.get("added") is True

    def test_add_alert_id(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            created = asyncio.get_event_loop().run_until_complete(
                tools["create_workspace"]("Incident WS 2")
            )
            ws_id = created["workspace_id"]
            result = asyncio.get_event_loop().run_until_complete(
                tools["add_to_workspace"](ws_id, item_type="alert_id", content="abc123def456")
            )
        assert result.get("added") is True

    def test_nonexistent_workspace_returns_error(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            result = asyncio.get_event_loop().run_until_complete(
                tools["add_to_workspace"]("nonexistent-id", item_type="note", content="test")
            )
        assert "error" in result


class TestGetWorkspace:
    def test_get_returns_items(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            created = asyncio.get_event_loop().run_until_complete(
                tools["create_workspace"]("Get Test")
            )
            ws_id = created["workspace_id"]
            asyncio.get_event_loop().run_until_complete(
                tools["add_to_workspace"](ws_id, item_type="note", content="note1")
            )
            result = asyncio.get_event_loop().run_until_complete(
                tools["get_workspace"](ws_id)
            )
        assert result["workspace_id"] == ws_id
        assert len(result["items"]) == 1

    def test_get_nonexistent_returns_error(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            result = asyncio.get_event_loop().run_until_complete(
                tools["get_workspace"]("does-not-exist")
            )
        assert "error" in result


class TestExportWorkspace:
    def test_export_json(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            created = asyncio.get_event_loop().run_until_complete(
                tools["create_workspace"]("Export Test")
            )
            ws_id = created["workspace_id"]
            asyncio.get_event_loop().run_until_complete(
                tools["add_to_workspace"](ws_id, item_type="note", content="export note")
            )
            result = asyncio.get_event_loop().run_until_complete(
                tools["export_workspace"](ws_id, fmt="json")
            )
        assert "export" in result
        exported = json.loads(result["export"])
        assert exported["workspace_id"] == ws_id

    def test_export_markdown(self, tmp_path):
        import asyncio
        tools, _ = _make_env(tmp_path)
        with patch.dict(os.environ, {"WAZUH_WORKSPACE_DIR": str(tmp_path)}):
            created = asyncio.get_event_loop().run_until_complete(
                tools["create_workspace"]("MD Export")
            )
            ws_id = created["workspace_id"]
            result = asyncio.get_event_loop().run_until_complete(
                tools["export_workspace"](ws_id, fmt="markdown")
            )
        assert "export" in result
        assert "# Investigation" in result["export"] or "MD Export" in result["export"]
