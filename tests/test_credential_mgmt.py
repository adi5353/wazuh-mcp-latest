"""Tests for H8: credential age reporting and rotation."""
import os
import time
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from wazuh_mcp.tool_context import ToolContext


def _make_tool_env():
    """Build minimal mocks to call register() and extract tools."""
    tools = {}
    mcp = MagicMock()
    mcp.tool = lambda: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)

    wz = MagicMock()
    cfg = MagicMock()
    cfg.manager_user = "wazuh-mcp"

    def _require_writes():
        return None  # writes allowed in tests

    from wazuh_mcp.tools.credential_mgmt import register
    ctx = ToolContext(mcp=mcp, wz=wz, idx=None, cfg=cfg, cap=lambda x: x, require_writes=lambda: None, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
    register(ctx)
    return tools, wz, cfg


class TestCredentialAge:
    def test_no_env_var_returns_unknown(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        env = {k: v for k, v in os.environ.items() if k != "WAZUH_CRED_CREATED_AT"}
        with patch.dict(os.environ, env, clear=True):
            result = asyncio.run(
                tools["get_credential_age"]()
            )
        assert result["status"] == "unknown"
        assert "WAZUH_CRED_CREATED_AT" in result["message"]

    def test_fresh_credentials_are_ok(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        ts = str(int(time.time()))
        with patch.dict(os.environ, {"WAZUH_CRED_CREATED_AT": ts}):
            result = asyncio.run(
                tools["get_credential_age"]()
            )
        assert result["status"] == "ok"
        assert result["age_days"] < 1

    def test_60_day_old_creds_are_warning(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        ts = str(int(time.time()) - 61 * 86400)
        with patch.dict(os.environ, {"WAZUH_CRED_CREATED_AT": ts}):
            result = asyncio.run(
                tools["get_credential_age"]()
            )
        assert result["status"] == "warning"

    def test_90_day_old_creds_are_critical(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        ts = str(int(time.time()) - 91 * 86400)
        with patch.dict(os.environ, {"WAZUH_CRED_CREATED_AT": ts}):
            result = asyncio.run(
                tools["get_credential_age"]()
            )
        assert result["status"] == "critical"

    def test_invalid_timestamp_returns_error(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        with patch.dict(os.environ, {"WAZUH_CRED_CREATED_AT": "not-a-number"}):
            result = asyncio.run(
                tools["get_credential_age"]()
            )
        assert "error" in result


class TestPasswordRotation:
    def test_dry_run_returns_preview(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        with patch.dict(os.environ, {"WAZUH_MCP_USER_ROLE": "admin"}):
            result = asyncio.run(
                tools["rotate_wazuh_api_password"]("NewP@ss123", dry_run=True)
            )
        assert result.get("dry_run") is True
        assert "wazuh-mcp" in result["message"]

    def test_short_password_rejected(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        with patch.dict(os.environ, {"WAZUH_MCP_USER_ROLE": "admin"}):
            result = asyncio.run(
                tools["rotate_wazuh_api_password"]("short", dry_run=False)
            )
        assert "error" in result
        assert "8 characters" in result["error"]

    def test_viewer_blocked_by_rbac(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        with patch.dict(os.environ, {"WAZUH_MCP_USER_ROLE": "viewer"}):
            result = asyncio.run(
                tools["rotate_wazuh_api_password"]("NewP@ss123", dry_run=False)
            )
        assert "error" in result
        assert "admin" in result["error"]

    def test_responder_blocked_by_rbac(self):
        tools, _, _ = _make_tool_env()
        import asyncio
        with patch.dict(os.environ, {"WAZUH_MCP_USER_ROLE": "responder"}):
            result = asyncio.run(
                tools["rotate_wazuh_api_password"]("NewP@ss123", dry_run=False)
            )
        assert "error" in result

    def test_writes_disabled_blocked(self):
        tools_w_block = {}
        mcp = MagicMock()
        mcp.tool = lambda: (lambda fn: tools_w_block.__setitem__(fn.__name__, fn) or fn)
        wz = MagicMock()
        cfg = MagicMock()
        cfg.manager_user = "wazuh-mcp"

        def _require_writes_blocked():
            return {"error": "Write operations are disabled."}

        from wazuh_mcp.tools.credential_mgmt import register
        ctx = ToolContext(mcp=mcp, wz=wz, idx=None, cfg=cfg, cap=lambda x: x, require_writes=_require_writes_blocked, truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value=dict()), incident_recommendations=lambda a: [])
        register(ctx)

        import asyncio
        with patch.dict(os.environ, {"WAZUH_MCP_USER_ROLE": "admin"}):
            result = asyncio.run(
                tools_w_block["rotate_wazuh_api_password"]("NewP@ss123", dry_run=False)
            )
        assert "error" in result
        assert "disabled" in result["error"].lower()
