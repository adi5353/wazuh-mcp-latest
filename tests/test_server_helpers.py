"""Unit tests for server.py module-level helpers (no HTTP app needed):
the session-scoped client proxy, write/cap/truncate guards, and the PII
compliance-warning logic added for the cloud-LLM data-exposure fix."""
from __future__ import annotations

import contextvars

import pytest


@pytest.fixture(autouse=True)
def server(monkeypatch):
    """Import server *inside* a test (never at collection time).

    server.py freezes a Config at first import. Importing it at module top would
    pre-empt other test modules (e.g. test_core_coverage) that legitimately set
    WAZUH_ALLOW_WRITES before their first server import. Deferring keeps the
    first import where it belongs and avoids cross-module pollution.
    """
    import wazuh_mcp.server as _server
    return _server


class TestClientProxy:
    def test_proxy_resolves_default_and_override(self, server):
        var: contextvars.ContextVar = contextvars.ContextVar("t", default=None)

        class _Default:
            name = "default"

        class _Tenant:
            name = "tenant"

        proxy = server._ClientProxy(_Default(), var)
        assert proxy.name == "default"
        token = proxy.replace(_Tenant())
        assert proxy.name == "tenant"
        proxy.reset(token)
        assert proxy.name == "default"


class TestGuards:
    def test_cap(self, server):
        assert server._cap(10) == 10
        assert server._cap(10_000) == server.MAX_RESULTS_GLOBAL

    def test_truncate(self, server):
        assert server._truncate(None) is None
        assert server._truncate("short") == "short"
        assert server._truncate("x" * 400, 10).endswith("…")

    def test_require_writes(self, server, monkeypatch):
        import types
        monkeypatch.setattr(server, "cfg", types.SimpleNamespace(allow_writes=False))
        assert server._require_writes()["error"]
        monkeypatch.setattr(server, "cfg", types.SimpleNamespace(allow_writes=True))
        assert server._require_writes() is None


class TestCloudLLMAndPII:
    def test_cloud_llm_suspected_local_override(self, server, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_LOCAL_LLM", "true")
        assert server._cloud_llm_suspected() is False

    def test_cloud_llm_suspected_http_transport(self, server, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_LOCAL_LLM", "false")
        monkeypatch.setenv("WAZUH_MCP_TRANSPORT", "http")
        assert server._cloud_llm_suspected() is True

    def test_cloud_llm_suspected_api_key(self, server, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_LOCAL_LLM", "false")
        monkeypatch.setenv("WAZUH_MCP_TRANSPORT", "stdio")
        for k in server._CLOUD_LLM_ENV_SIGNALS:
            monkeypatch.delenv(k, raising=False)
        assert server._cloud_llm_suspected() is False
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        assert server._cloud_llm_suspected() is True

    def test_pii_scrub_config_warns_loudly(self, server, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("WAZUH_MCP_SCRUB_PII", "false")
        monkeypatch.setenv("WAZUH_MCP_TRANSPORT", "http")
        monkeypatch.setenv("WAZUH_MCP_LOCAL_LLM", "false")
        monkeypatch.delenv("WAZUH_MCP_PII_SCRUB_ACK", raising=False)
        with caplog.at_level(logging.ERROR):
            server._check_pii_scrub_config()
        assert any("PII SCRUBBING IS DISABLED" in r.getMessage() for r in caplog.records)

    def test_pii_scrub_config_acknowledged_downgrades(self, server, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("WAZUH_MCP_SCRUB_PII", "false")
        monkeypatch.setenv("WAZUH_MCP_TRANSPORT", "http")
        monkeypatch.setenv("WAZUH_MCP_PII_SCRUB_ACK", "true")
        with caplog.at_level(logging.WARNING):
            server._check_pii_scrub_config()
        msgs = " ".join(r.getMessage() for r in caplog.records)
        assert "Opt-out acknowledged" in msgs

    def test_pii_scrub_config_silent_when_enabled(self, server, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("WAZUH_MCP_SCRUB_PII", "true")
        with caplog.at_level(logging.WARNING):
            server._check_pii_scrub_config()
        assert not any("PII SCRUBBING" in r.getMessage() for r in caplog.records)


class TestBindSecurity:
    def test_loopback_no_key_ok(self, server):
        server._check_bind_security("http", "127.0.0.1", "")

    def test_nonloopback_no_key_refuses(self, server, monkeypatch):
        monkeypatch.delenv("WAZUH_MCP_ALLOW_INSECURE_BIND", raising=False)
        with pytest.raises(SystemExit):
            server._check_bind_security("http", "0.0.0.0", "")

    def test_deprecated_insecure_bind_ignored(self, server, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_ALLOW_INSECURE_BIND", "true")
        with pytest.raises(SystemExit):
            server._check_bind_security("http", "0.0.0.0", "")
        # A key still satisfies the guard.
        server._check_bind_security("http", "0.0.0.0", "secret")
