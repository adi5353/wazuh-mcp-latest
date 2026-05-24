"""Tests for H4: pluggable secrets backend (Vault / AWS / env fallback)."""
import os
import pytest
from unittest.mock import patch, MagicMock


class TestEnvFallback:
    def test_no_backend_returns_env_value(self):
        env = {"WAZUH_SECRET_BACKEND": "", "MY_SECRET": "env_value"}
        with patch.dict(os.environ, env, clear=False):
            from wazuh_mcp.secrets_backend import get_secret
            assert get_secret("MY_SECRET") == "env_value"

    def test_no_backend_missing_key_returns_none(self):
        env = {"WAZUH_SECRET_BACKEND": ""}
        # Ensure key absent
        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("WAZUH_SECRET_BACKEND", "TOTALLY_ABSENT_KEY_XYZ")}
        env_clean["WAZUH_SECRET_BACKEND"] = ""
        with patch.dict(os.environ, env_clean, clear=True):
            from wazuh_mcp.secrets_backend import get_secret
            assert get_secret("TOTALLY_ABSENT_KEY_XYZ") is None

    def test_no_backend_default_returned(self):
        env_clean = {k: v for k, v in os.environ.items()
                     if k not in ("WAZUH_SECRET_BACKEND", "ABSENT_KEY_2")}
        env_clean["WAZUH_SECRET_BACKEND"] = ""
        with patch.dict(os.environ, env_clean, clear=True):
            from wazuh_mcp.secrets_backend import get_secret
            assert get_secret("ABSENT_KEY_2", default="fallback") == "fallback"


class TestVaultBackend:
    def test_vault_fetches_secret(self):
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"WAZUH_PASS": "vault_password"}}
        }
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "vault",
            "VAULT_ADDR": "http://vault:8200",
            "VAULT_TOKEN": "test-token",
            "VAULT_SECRET_PATH": "secret/wazuh-mcp",
        }), patch("hvac.Client", return_value=mock_client):
            # Force reimport with fresh env
            import importlib
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
            assert result == "vault_password"

    def test_vault_missing_key_returns_none(self):
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"OTHER_KEY": "value"}}
        }
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "vault",
            "VAULT_ADDR": "http://vault:8200",
            "VAULT_TOKEN": "test-token",
            "VAULT_SECRET_PATH": "secret/wazuh-mcp",
        }), patch("hvac.Client", return_value=mock_client):
            import importlib
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
            assert result is None

    def test_vault_unavailable_falls_back_to_env(self):
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "vault",
            "VAULT_ADDR": "http://vault:8200",
            "VAULT_TOKEN": "bad-token",
            "VAULT_SECRET_PATH": "secret/wazuh-mcp",
            "WAZUH_PASS": "env_fallback_pass",
        }):
            mock_client = MagicMock()
            mock_client.secrets.kv.v2.read_secret_version.side_effect = Exception("connection refused")
            with patch("hvac.Client", return_value=mock_client):
                import importlib
                import wazuh_mcp.secrets_backend as sb
                importlib.reload(sb)
                result = sb.get_secret("WAZUH_PASS")
                # Falls back to env on Vault error
                assert result == "env_fallback_pass"


class TestAWSBackend:
    def test_aws_fetches_secret(self):
        mock_boto = MagicMock()
        mock_client = MagicMock()
        mock_boto.client.return_value = mock_client
        mock_client.get_secret_value.return_value = {
            "SecretString": '{"WAZUH_PASS": "aws_password", "WAZUH_USER": "wazuh-mcp"}'
        }
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "aws",
            "AWS_SECRET_NAME": "wazuh-mcp/secrets",
            "AWS_REGION": "us-east-1",
        }), patch("boto3.client", return_value=mock_client):
            import importlib
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
            assert result == "aws_password"

    def test_aws_missing_key_returns_none(self):
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": '{"OTHER": "value"}'
        }
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "aws",
            "AWS_SECRET_NAME": "wazuh-mcp/secrets",
            "AWS_REGION": "us-east-1",
        }), patch("boto3.client", return_value=mock_client):
            import importlib
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
            assert result is None

    def test_aws_unavailable_falls_back_to_env(self):
        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = Exception("NoCredentials")
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "aws",
            "AWS_SECRET_NAME": "wazuh-mcp/secrets",
            "AWS_REGION": "us-east-1",
            "WAZUH_PASS": "env_fallback",
        }), patch("boto3.client", return_value=mock_client):
            import importlib
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
            assert result == "env_fallback"


class TestUnknownBackend:
    def test_unknown_backend_falls_back_to_env(self):
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "someunknownbackend",
            "WAZUH_PASS": "env_val",
        }):
            import importlib
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
            assert result == "env_val"
