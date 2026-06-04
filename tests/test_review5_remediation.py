"""Regression tests for the fifth-review remediation (M1).

Idempotency-aware retry: a non-idempotent Manager write (e.g. PUT active-response,
agent restart) that times out AFTER reaching the server must not be retried —
otherwise the action fires twice. Reads (GET) and connection-phase failures
(the request never reached the server) still retry.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest


def _run(coro):
    return asyncio.run(coro)


# ── Pure policy ───────────────────────────────────────────────────────────────

class TestIsRetryableForMethod:
    def test_write_not_retried_on_read_timeout(self):
        from wazuh_mcp.http_policy import is_retryable_for_method
        # Read timeout = request may already have been applied → never retry a write.
        assert is_retryable_for_method(httpx.ReadTimeout("t"), "PUT") is False
        assert is_retryable_for_method(httpx.ReadTimeout("t"), "POST") is False

    def test_write_retried_on_connect_phase(self):
        from wazuh_mcp.http_policy import is_retryable_for_method
        # Connection never established → request never reached server → safe to retry.
        assert is_retryable_for_method(httpx.ConnectError("c"), "PUT") is True
        assert is_retryable_for_method(httpx.ConnectTimeout("c"), "DELETE") is True

    def test_write_not_retried_on_5xx(self):
        from wazuh_mcp.http_policy import is_retryable_for_method
        resp = httpx.Response(503, request=httpx.Request("PUT", "http://x"))
        exc = httpx.HTTPStatusError("503", request=resp.request, response=resp)
        assert is_retryable_for_method(exc, "PUT") is False

    def test_read_retried_on_any_transient(self):
        from wazuh_mcp.http_policy import is_retryable_for_method
        assert is_retryable_for_method(httpx.ReadTimeout("t"), "GET") is True
        resp = httpx.Response(503, request=httpx.Request("GET", "http://x"))
        exc = httpx.HTTPStatusError("503", request=resp.request, response=resp)
        assert is_retryable_for_method(exc, "GET") is True


# ── Client integration ────────────────────────────────────────────────────────

class TestClientRetryRespectsIdempotency:
    def _client(self):
        from wazuh_mcp.wazuh_client import WazuhClient
        cfg = SimpleNamespace(ca_bundle=None, verify_ssl=False, request_timeout=30)
        return WazuhClient(cfg)

    def test_put_read_timeout_not_retried(self):
        import wazuh_mcp.wazuh_client as wc

        async def run():
            client = self._client()
            once = AsyncMock(side_effect=httpx.ReadTimeout("timeout"))
            with patch.object(client, "_request_once", once), \
                 patch.object(wc, "_retry_sleep", AsyncMock()):
                with pytest.raises(httpx.ReadTimeout):
                    await client._request_impl("PUT", "/active-response?agents_list=001")
            assert once.await_count == 1  # exactly one attempt — no double-fire
            await client.aclose()

        _run(run())

    def test_put_connect_error_retried(self):
        import wazuh_mcp.wazuh_client as wc

        async def run():
            client = self._client()
            once = AsyncMock(side_effect=httpx.ConnectError("refused"))
            with patch.object(client, "_request_once", once), \
                 patch.object(wc, "_retry_sleep", AsyncMock()):
                with pytest.raises(httpx.ConnectError):
                    await client._request_impl("PUT", "/agents/001/restart")
            assert once.await_count == wc._MAX_RETRIES + 1  # retried the full budget
            await client.aclose()

        _run(run())

    def test_get_read_timeout_still_retried(self):
        import wazuh_mcp.wazuh_client as wc

        async def run():
            client = self._client()
            once = AsyncMock(side_effect=httpx.ReadTimeout("timeout"))
            with patch.object(client, "_request_once", once), \
                 patch.object(wc, "_retry_sleep", AsyncMock()):
                with pytest.raises(httpx.ReadTimeout):
                    await client._request_impl("GET", "/agents")
            assert once.await_count == wc._MAX_RETRIES + 1  # reads keep full retry
            await client.aclose()

        _run(run())
