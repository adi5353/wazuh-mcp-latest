"""Tests for the per-(identity, tool, args) failure circuit breaker.

Verifies that repeated identical failures open the breaker (stopping LLM retry
loops) and that a success resets the streak.
"""
import os
import pytest
from unittest.mock import patch

from wazuh_mcp.tool_failure_breaker import ToolFailureBreaker


def fresh_breaker():
    return ToolFailureBreaker()


class TestFailureBreaker:
    def test_closed_before_threshold(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "3"}):
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            # 2 failures < threshold 3 → still closed
            assert b.check("id1", "search_alerts", {"q": "bad"}) is None

    def test_opens_after_threshold(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {
            "WAZUH_MCP_TOOL_FAIL_THRESHOLD": "3",
            "WAZUH_MCP_TOOL_FAIL_RESET_SECONDS": "60",
        }):
            for _ in range(3):
                b.record_failure("id1", "search_alerts", {"q": "bad"})
            err = b.check("id1", "search_alerts", {"q": "bad"})
            assert err is not None
            assert err["circuit_open"] is True
            assert err["retry"] is False
            assert err["tool"] == "search_alerts"
            assert err["circuit_resets_in_seconds"] > 0

    def test_success_resets_streak(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "3"}):
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            b.record_success("id1", "search_alerts", {"q": "bad"})
            # Streak cleared — two more failures should not yet open it
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            assert b.check("id1", "search_alerts", {"q": "bad"}) is None

    def test_different_args_isolated(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "2"}):
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            # Same tool + identity but different args → independent circuit
            assert b.check("id1", "search_alerts", {"q": "good"}) is None
            assert b.check("id1", "search_alerts", {"q": "bad"}) is not None

    def test_different_identity_isolated(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "2"}):
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            b.record_failure("id1", "search_alerts", {"q": "bad"})
            # Different caller is not affected by id1's retry loop
            assert b.check("id2", "search_alerts", {"q": "bad"}) is None

    def test_args_order_independent(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "2"}):
            b.record_failure("id1", "search_alerts", {"a": 1, "b": 2})
            b.record_failure("id1", "search_alerts", {"b": 2, "a": 1})
            # Same args in a different dict order map to the same circuit
            assert b.check("id1", "search_alerts", {"a": 1, "b": 2}) is not None

    def test_cooldown_elapsed_resets(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {
            "WAZUH_MCP_TOOL_FAIL_THRESHOLD": "2",
            "WAZUH_MCP_TOOL_FAIL_RESET_SECONDS": "60",
        }):
            for _ in range(2):
                b.record_failure("id1", "t", {})
            assert b.check("id1", "t", {}) is not None
            # Simulate cooldown elapsing by forcing open_until into the past.
            key = ToolFailureBreaker._key("id1", "t", {})
            b._entries[key].open_until = 0.0
            b._entries[key].consecutive_failures = 0
            assert b.check("id1", "t", {}) is None

    def test_open_circuits_listing(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "1"}):
            b.record_failure("id1", "t", {})
            circuits = b.open_circuits()
            assert len(circuits) == 1
            assert circuits[0]["circuit_resets_in_seconds"] > 0


@pytest.mark.asyncio
async def test_middleware_short_circuits_without_invoking_handler():
    """The 4th identical failing call must be short-circuited by the breaker
    without ever invoking the underlying tool handler."""
    from wazuh_mcp.middleware.tool_middleware import ToolMiddleware
    from wazuh_mcp.tool_failure_breaker import tool_failure_breaker

    tool_failure_breaker.reset()

    calls = {"n": 0}

    # Minimal fake mcp whose .tool() returns an identity decorator.
    class _FakeMcp:
        def tool(self, *a, **k):
            def deco(fn):
                return fn
            return deco

    registry: dict = {}
    mw = ToolMiddleware(_FakeMcp(), registry)

    @mw.tool()
    async def always_fails(q: str) -> dict:
        calls["n"] += 1
        return {"error": "bad index"}

    with patch.dict(os.environ, {"WAZUH_MCP_TOOL_FAIL_THRESHOLD": "3"}):
        # 3 calls actually run and fail, opening the breaker.
        for _ in range(3):
            out = await registry["always_fails"](q="x")
            assert out["error"] == "bad index"
        assert calls["n"] == 3

        # 4th call is short-circuited — handler not invoked.
        out = await registry["always_fails"](q="x")
        assert out["circuit_open"] is True
        assert out["retry"] is False
        assert calls["n"] == 3  # handler count unchanged

    tool_failure_breaker.reset()
