"""F2: standardized tool error contract.

The failure breaker and metrics error counter must reliably detect failures
regardless of which key a tool uses ("error" vs "execute_error"), while treating
a "degraded" partial-success result as NOT a failure.
"""
import os

import pytest
from unittest.mock import patch

from wazuh_mcp.tool_failure_breaker import is_failure_result, ToolFailureBreaker


class TestFailurePredicate:
    def test_error_key_is_failure(self):
        assert is_failure_result({"error": "boom"}) is True

    def test_execute_error_key_is_failure(self):
        assert is_failure_result({"executed": False, "execute_error": "bad DSL"}) is True

    def test_degraded_is_not_failure(self):
        # Partial success — primary data valid, enrichment sub-query failed.
        assert is_failure_result({"total_alerts": 5, "trend": {"degraded": True}}) is False

    def test_plain_success_is_not_failure(self):
        assert is_failure_result({"ok": 1}) is False

    def test_non_dict_is_not_failure(self):
        assert is_failure_result("a string") is False
        assert is_failure_result(["list"]) is False


@pytest.mark.asyncio
async def test_middleware_counts_execute_error_shape():
    """A tool that fails using the {"execute_error": ...} shape (not "error")
    must still trip the breaker after the threshold."""
    from wazuh_mcp.middleware.tool_middleware import ToolMiddleware
    from wazuh_mcp.tool_failure_breaker import tool_failure_breaker

    tool_failure_breaker.reset()

    class _FakeMcp:
        def tool(self, *a, **k):
            return lambda fn: fn

    registry: dict = {}
    mw = ToolMiddleware(_FakeMcp(), registry)

    @mw.tool()
    async def deferred_exec(q: str) -> dict:
        return {"executed": False, "execute_error": "invalid query"}

    with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "3"}):
        for _ in range(3):
            out = await registry["deferred_exec"](q="x")
            assert "execute_error" in out
        # 4th identical call is short-circuited by the now-open breaker.
        out = await registry["deferred_exec"](q="x")
        assert out.get("circuit_open") is True

    tool_failure_breaker.reset()


@pytest.mark.asyncio
async def test_middleware_does_not_count_degraded():
    """A 'degraded' partial-success result must NOT trip the breaker."""
    from wazuh_mcp.middleware.tool_middleware import ToolMiddleware
    from wazuh_mcp.tool_failure_breaker import tool_failure_breaker

    tool_failure_breaker.reset()

    class _FakeMcp:
        def tool(self, *a, **k):
            return lambda fn: fn

    registry: dict = {}
    mw = ToolMiddleware(_FakeMcp(), registry)

    @mw.tool()
    async def partial(q: str) -> dict:
        return {"total_alerts": 5, "trend": {"degraded": True}}

    with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "2"}):
        for _ in range(5):
            out = await registry["partial"](q="x")
            assert out["total_alerts"] == 5  # never short-circuited

    tool_failure_breaker.reset()
