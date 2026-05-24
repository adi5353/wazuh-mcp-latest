"""Tests for H5: TLS/mTLS configuration for the MCP server."""
import os
import pytest
from unittest.mock import patch, MagicMock


class TestTLSConfig:
    def test_no_tls_vars_gives_empty_uvicorn_kwargs(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("WAZUH_MCP_TLS_CERT", "WAZUH_MCP_TLS_KEY", "WAZUH_MCP_CLIENT_CA")}
        with patch.dict(os.environ, env, clear=True):
            from wazuh_mcp.tls_config import build_uvicorn_tls_kwargs
            kwargs = build_uvicorn_tls_kwargs()
        assert kwargs == {}

    def test_cert_and_key_enables_tls(self, tmp_path):
        cert = tmp_path / "server.crt"
        key = tmp_path / "server.key"
        cert.write_text("CERT")
        key.write_text("KEY")
        env = {
            "WAZUH_MCP_TLS_CERT": str(cert),
            "WAZUH_MCP_TLS_KEY": str(key),
        }
        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("WAZUH_MCP_TLS_CERT", "WAZUH_MCP_TLS_KEY", "WAZUH_MCP_CLIENT_CA")}
        env_clean.update(env)
        with patch.dict(os.environ, env_clean, clear=True):
            from wazuh_mcp.tls_config import build_uvicorn_tls_kwargs
            kwargs = build_uvicorn_tls_kwargs()
        assert kwargs["ssl_certfile"] == str(cert)
        assert kwargs["ssl_keyfile"] == str(key)
        assert "ssl_ca_certs" not in kwargs

    def test_client_ca_enables_mtls(self, tmp_path):
        cert = tmp_path / "server.crt"
        key = tmp_path / "server.key"
        ca = tmp_path / "ca.crt"
        cert.write_text("CERT")
        key.write_text("KEY")
        ca.write_text("CA")
        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("WAZUH_MCP_TLS_CERT", "WAZUH_MCP_TLS_KEY", "WAZUH_MCP_CLIENT_CA")}
        env_clean.update({
            "WAZUH_MCP_TLS_CERT": str(cert),
            "WAZUH_MCP_TLS_KEY": str(key),
            "WAZUH_MCP_CLIENT_CA": str(ca),
        })
        with patch.dict(os.environ, env_clean, clear=True):
            from wazuh_mcp.tls_config import build_uvicorn_tls_kwargs
            kwargs = build_uvicorn_tls_kwargs()
        assert kwargs["ssl_certfile"] == str(cert)
        assert kwargs["ssl_keyfile"] == str(key)
        assert kwargs["ssl_ca_certs"] == str(ca)

    def test_cert_without_key_raises(self, tmp_path):
        cert = tmp_path / "server.crt"
        cert.write_text("CERT")
        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("WAZUH_MCP_TLS_CERT", "WAZUH_MCP_TLS_KEY", "WAZUH_MCP_CLIENT_CA")}
        env_clean["WAZUH_MCP_TLS_CERT"] = str(cert)
        with patch.dict(os.environ, env_clean, clear=True):
            from wazuh_mcp.tls_config import build_uvicorn_tls_kwargs
            with pytest.raises(ValueError, match="WAZUH_MCP_TLS_KEY"):
                build_uvicorn_tls_kwargs()

    def test_key_without_cert_raises(self, tmp_path):
        key = tmp_path / "server.key"
        key.write_text("KEY")
        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("WAZUH_MCP_TLS_CERT", "WAZUH_MCP_TLS_KEY", "WAZUH_MCP_CLIENT_CA")}
        env_clean["WAZUH_MCP_TLS_KEY"] = str(key)
        with patch.dict(os.environ, env_clean, clear=True):
            from wazuh_mcp.tls_config import build_uvicorn_tls_kwargs
            with pytest.raises(ValueError, match="WAZUH_MCP_TLS_CERT"):
                build_uvicorn_tls_kwargs()

    def test_nonexistent_cert_file_raises(self, tmp_path):
        key = tmp_path / "server.key"
        key.write_text("KEY")
        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("WAZUH_MCP_TLS_CERT", "WAZUH_MCP_TLS_KEY", "WAZUH_MCP_CLIENT_CA")}
        env_clean.update({
            "WAZUH_MCP_TLS_CERT": "/nonexistent/server.crt",
            "WAZUH_MCP_TLS_KEY": str(key),
        })
        with patch.dict(os.environ, env_clean, clear=True):
            from wazuh_mcp.tls_config import build_uvicorn_tls_kwargs
            with pytest.raises(FileNotFoundError):
                build_uvicorn_tls_kwargs()
