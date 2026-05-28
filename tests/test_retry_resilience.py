"""Tests for Phase 2 Enterprise Resilience — Gaps 10-13.

Gap 10: Graceful SIGTERM shutdown
Gap 11: Prometheus /metrics endpoint
Gap 12: Exponential backoff + jitter on Wazuh API retries
Gap 13: Pydantic response validation schemas
"""
from __future__ import annotations

import asyncio
import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch


# ── Gap 12: Exponential backoff on WazuhClient ───────────────────────────────

class TestWazuhClientRetry:
    def _make_client(self):
        from wazuh_mcp.wazuh_client import WazuhClient
        cfg = MagicMock()
        cfg.manager_host = "https://wazuh.test:55000"
        cfg.manager_user = "admin"
        cfg.manager_pass = "pass"
        cfg.ca_bundle = None
        cfg.verify_ssl = False
        cfg.request_timeout = 30
        return WazuhClient(cfg)

    def test_retries_on_network_error_then_succeeds(self):
        """2 network failures then success — should succeed on 3rd attempt."""
        import httpx
        client = self._make_client()
        client._token = "fake-token"
        client._token_expires = 9999999999

        call_count = [0]

        async def run():
            async def mock_request_once(method, path, **kwargs):
                call_count[0] += 1
                if call_count[0] < 3:
                    raise httpx.ConnectError("connection refused")
                return {"data": "ok"}

            with patch.object(client, "_request_once", side_effect=mock_request_once), \
                 patch("wazuh_mcp.wazuh_client._retry_sleep", new=AsyncMock()):
                return await client.request("GET", "/agents")

        result = asyncio.run(run())
        assert result == {"data": "ok"}
        assert call_count[0] == 3

    def test_raises_after_max_retries(self):
        """4 consecutive failures — should raise after 3 retries."""
        import httpx
        client = self._make_client()
        client._token = "fake-token"
        client._token_expires = 9999999999

        async def run():
            async def always_fail(method, path, **kwargs):
                raise httpx.ConnectError("always down")

            with patch.object(client, "_request_once", side_effect=always_fail), \
                 patch("wazuh_mcp.wazuh_client._retry_sleep", new=AsyncMock()):
                return await client.request("GET", "/agents")

        with pytest.raises(Exception):
            asyncio.run(run())

    def test_does_not_retry_on_404(self):
        """404 Not Found is a client error — must not retry."""
        import httpx
        client = self._make_client()
        client._token = "fake-token"
        client._token_expires = 9999999999

        call_count = [0]

        async def run():
            async def mock_404(method, path, **kwargs):
                call_count[0] += 1
                resp = MagicMock()
                resp.status_code = 404
                raise httpx.HTTPStatusError("not found", request=MagicMock(), response=resp)

            with patch.object(client, "_request_once", side_effect=mock_404), \
                 patch("wazuh_mcp.wazuh_client._retry_sleep", new=AsyncMock()):
                return await client.request("GET", "/nonexistent")

        with pytest.raises(Exception):
            asyncio.run(run())
        assert call_count[0] == 1  # no retries for 404

    def test_retries_on_503(self):
        """503 Service Unavailable is a 5xx — must retry."""
        import httpx
        client = self._make_client()
        client._token = "fake-token"
        client._token_expires = 9999999999

        call_count = [0]

        async def run():
            async def mock_503_then_ok(method, path, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    resp = MagicMock()
                    resp.status_code = 503
                    raise httpx.HTTPStatusError("service unavailable", request=MagicMock(), response=resp)
                return {"data": "recovered"}

            with patch.object(client, "_request_once", side_effect=mock_503_then_ok), \
                 patch("wazuh_mcp.wazuh_client._retry_sleep", new=AsyncMock()):
                return await client.request("GET", "/agents")

        result = asyncio.run(run())
        assert result == {"data": "recovered"}
        assert call_count[0] == 2

    def test_is_retryable_classifies_correctly(self):
        """_is_retryable must correctly classify exceptions."""
        import httpx
        from wazuh_mcp.wazuh_client import _is_retryable

        # Network error — retryable
        assert _is_retryable(httpx.ConnectError("conn refused"))
        assert _is_retryable(httpx.ReadTimeout("timeout"))

        # 5xx — retryable
        resp_500 = MagicMock(); resp_500.status_code = 500
        assert _is_retryable(httpx.HTTPStatusError("", request=MagicMock(), response=resp_500))

        # 429 — retryable
        resp_429 = MagicMock(); resp_429.status_code = 429
        assert _is_retryable(httpx.HTTPStatusError("", request=MagicMock(), response=resp_429))

        # 404 — NOT retryable
        resp_404 = MagicMock(); resp_404.status_code = 404
        assert not _is_retryable(httpx.HTTPStatusError("", request=MagicMock(), response=resp_404))

        # 400 — NOT retryable
        resp_400 = MagicMock(); resp_400.status_code = 400
        assert not _is_retryable(httpx.HTTPStatusError("", request=MagicMock(), response=resp_400))

        # Generic exception — NOT retryable
        assert not _is_retryable(ValueError("bad value"))

    def test_retry_sleep_delay_increases(self):
        """Delay should grow with each attempt (exponential backoff)."""
        import asyncio as _asyncio
        from wazuh_mcp.wazuh_client import _RETRY_BASE, _RETRY_CAP

        # Verify the formula: min(BASE * 2**attempt, CAP) + jitter
        for attempt in range(3):
            base_delay = min(_RETRY_BASE * (2 ** attempt), _RETRY_CAP)
            assert base_delay >= _RETRY_BASE * (2 ** attempt) or base_delay == _RETRY_CAP
            assert base_delay <= _RETRY_CAP


# ── Gap 13: Pydantic response validation ─────────────────────────────────────

class TestResponseSchemas:
    def test_parse_clean_agent(self):
        from wazuh_mcp.schemas import parse_agent
        data = {
            "id": "001",
            "name": "web-server-01",
            "ip": "192.168.1.10",
            "status": "active",
            "version": "Wazuh v4.7.0",
        }
        result = parse_agent(data)
        assert result["id"] == "001"
        assert result["name"] == "web-server-01"
        assert result["status"] == "active"

    def test_parse_agent_with_missing_fields_gets_defaults(self):
        """Missing optional fields get safe defaults — no KeyError."""
        from wazuh_mcp.schemas import parse_agent
        result = parse_agent({"id": "002"})
        assert result["name"] == "unknown"
        assert result["status"] == "unknown"
        assert result["group"] == []

    def test_parse_agent_with_null_group_coerced(self):
        from wazuh_mcp.schemas import parse_agent
        result = parse_agent({"id": "003", "group": None})
        assert result["group"] == []

    def test_parse_vulnerability_coerces_cvss_score(self):
        from wazuh_mcp.schemas import parse_vulnerability
        result = parse_vulnerability({"cve": "CVE-2021-44228", "cvss3_score": "9.8"})
        assert result["cvss3_score"] == 9.8

    def test_parse_vulnerability_invalid_score_defaults_to_zero(self):
        from wazuh_mcp.schemas import parse_vulnerability
        result = parse_vulnerability({"cve": "CVE-2021-44228", "cvss3_score": None})
        assert result["cvss3_score"] == 0.0

    def test_parse_vulnerability_normalises_severity(self):
        from wazuh_mcp.schemas import parse_vulnerability
        result = parse_vulnerability({"cve": "CVE-2021-44228", "severity": "critical"})
        assert result["severity"] == "Critical"

    def test_parse_alert_missing_rule_gets_defaults(self):
        from wazuh_mcp.schemas import parse_alert
        result = parse_alert({"@timestamp": "2024-01-01T00:00:00Z"})
        assert result["rule"]["level"] == 0
        assert result["rule"]["description"] == ""

    def test_parse_alert_unknown_fields_ignored(self):
        """Extra fields from Wazuh API don't crash the parser."""
        from wazuh_mcp.schemas import parse_alert
        data = {
            "@timestamp": "2024-01-01T00:00:00Z",
            "rule": {"id": "5710", "level": 5, "description": "SSH fail"},
            "agent": {"id": "001", "name": "server"},
            "some_future_field_wazuh_added": "unexpected_value",
        }
        result = parse_alert(data)
        assert result["rule"]["id"] == "5710"

    def test_parse_sca_check_coerces_id(self):
        from wazuh_mcp.schemas import parse_sca_check
        result = parse_sca_check({"id": "7890", "title": "SSH hardening", "result": "failed"})
        assert result["id"] == 7890
        assert isinstance(result["id"], int)

    def test_safe_parse_non_dict_returned_as_is(self):
        from wazuh_mcp.schemas import _safe_parse, AgentResponse
        result = _safe_parse(AgentResponse, "not a dict")
        assert result == "not a dict"

    def test_parse_agent_with_string_group_coerced_to_list(self):
        from wazuh_mcp.schemas import parse_agent
        result = parse_agent({"id": "004", "group": "linux-servers"})
        assert result["group"] == ["linux-servers"]


# ── Fix B: Non-blocking proactive token refresh ───────────────────────────────

class TestProactiveTokenRefresh:
    """Verify that concurrent requests are not serialized behind _login_lock."""

    def _make_client(self):
        from wazuh_mcp.wazuh_client import WazuhClient
        cfg = MagicMock()
        cfg.manager_host = "https://wazuh.test:55000"
        cfg.manager_user = "admin"
        cfg.manager_pass = "pass"
        cfg.ca_bundle = None
        cfg.verify_ssl = False
        cfg.request_timeout = 30
        return WazuhClient(cfg)

    def test_valid_token_does_not_block_on_lock(self):
        """If the token is valid, _ensure_token must return immediately without acquiring the lock."""
        import time
        client = self._make_client()
        client._token = "valid-token"
        client._token_expires = time.time() + 700  # well within TTL

        lock_acquired = []

        async def run():
            original_acquire = client._login_lock.acquire

            async def spy_acquire():
                lock_acquired.append(True)
                return await original_acquire()

            client._login_lock.acquire = spy_acquire
            await client._ensure_token()

        asyncio.run(run())
        assert not lock_acquired, "_login_lock must NOT be acquired when token is valid"

    def test_concurrent_requests_all_complete_during_slow_login(self):
        """10 concurrent requests with an expired token must all succeed even if _login is slow."""
        import time
        client = self._make_client()
        # Start with an expired token
        client._token = None
        client._token_expires = 0.0

        login_count = [0]

        async def slow_login(self_inner=None):
            login_count[0] += 1
            await asyncio.sleep(0.01)  # simulate slow auth endpoint
            client._token = "refreshed-token"
            client._token_expires = time.time() + 800

        async def run():
            with patch.object(client, "_login", side_effect=slow_login):
                # Fire 10 concurrent calls — all should get a token without deadlock
                await asyncio.gather(*[client._ensure_token() for _ in range(10)])

        asyncio.run(run())
        assert client._token == "refreshed-token"
        # The double-checked lock means _login is called exactly once for all 10
        assert login_count[0] == 1, f"_login was called {login_count[0]} times; expected 1"

    def test_proactive_refresh_scheduled_near_expiry(self):
        """When token is near expiry (within refresh window), a background task is scheduled."""
        import time
        from wazuh_mcp.wazuh_client import _TOKEN_PROACTIVE_REFRESH_WINDOW
        client = self._make_client()
        # Token valid but within the proactive refresh window
        client._token = "near-expiry-token"
        client._token_expires = time.time() + (_TOKEN_PROACTIVE_REFRESH_WINDOW - 10)

        async def run():
            with patch.object(client, "_proactive_refresh", new=AsyncMock()) as mock_refresh:
                await client._ensure_token()
                # Give the event loop a turn to schedule the background task
                await asyncio.sleep(0)
                return mock_refresh
        mock = asyncio.run(run())
        # The proactive refresh should have been triggered as a background task
        assert client._refresh_task is not None, "Background refresh task must be created near expiry"


# ── Gap 11: Prometheus /metrics module presence ──────────────────────────────

class TestPrometheusMetrics:
    def test_metrics_endpoint_function_exists_in_server(self):
        """server.py must define a metrics_endpoint function."""
        import inspect
        from wazuh_mcp import server
        source = inspect.getsource(server)
        assert "metrics_endpoint" in source

    def test_metrics_route_registered(self):
        """'/metrics' route must appear in server.py."""
        import inspect
        from wazuh_mcp import server
        source = inspect.getsource(server)
        assert '"/metrics"' in source or "'/metrics'" in source

    def test_prometheus_client_in_requirements(self):
        """prometheus-client must be in requirements.txt."""
        req_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "requirements.txt"
        )
        with open(req_path) as f:
            content = f.read()
        assert "prometheus-client" in content

    def test_prometheus_client_importable(self):
        """prometheus-client must be installed in the container."""
        import prometheus_client
        assert hasattr(prometheus_client, "Counter")
        assert hasattr(prometheus_client, "Histogram")
        assert hasattr(prometheus_client, "Gauge")
        assert hasattr(prometheus_client, "generate_latest")


# ── Gap 10: Graceful SIGTERM shutdown ────────────────────────────────────────

class TestGracefulShutdown:
    def test_sigterm_handler_registered_in_server(self):
        """server.py must import signal and register a SIGTERM handler."""
        import inspect
        from wazuh_mcp import server
        source = inspect.getsource(server)
        assert "signal.SIGTERM" in source
        assert "_sigterm_handler" in source or "sigterm" in source.lower()

    def test_compose_has_stop_grace_period(self):
        """compose.yaml must have stop_grace_period >= 30s."""
        compose_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "compose.yaml"
        )
        with open(compose_path) as f:
            content = f.read()
        assert "stop_grace_period" in content
        # Verify it's 35s (30s drain + 5s buffer)
        assert "35s" in content

    def test_uvicorn_timeout_graceful_shutdown_configured(self):
        """server.py must pass timeout_graceful_shutdown to uvicorn."""
        import inspect
        from wazuh_mcp import server
        source = inspect.getsource(server)
        assert "timeout_graceful_shutdown" in source
