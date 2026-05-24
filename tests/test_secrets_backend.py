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


def _inject_hvac(mock_client):
    """Inject a fake hvac module into sys.modules so patch targets resolve."""
    import sys
    fake_hvac = MagicMock()
    fake_hvac.Client.return_value = mock_client
    sys.modules.setdefault("hvac", fake_hvac)
    # Always update Client on the already-registered fake
    sys.modules["hvac"].Client.return_value = mock_client
    return fake_hvac


def _inject_boto3(mock_client):
    """Inject a fake boto3 module into sys.modules so patch targets resolve."""
    import sys
    fake_boto3 = MagicMock()
    fake_boto3.client.return_value = mock_client
    sys.modules.setdefault("boto3", fake_boto3)
    sys.modules["boto3"].client.return_value = mock_client
    return fake_boto3


class TestVaultBackend:
    def test_vault_fetches_secret(self):
        import importlib, sys
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"WAZUH_PASS": "vault_password"}}
        }
        _inject_hvac(mock_client)
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "vault",
            "VAULT_ADDR": "http://vault:8200",
            "VAULT_TOKEN": "test-token",
            "VAULT_SECRET_PATH": "secret/wazuh-mcp",
        }):
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
        assert result == "vault_password"

    def test_vault_missing_key_returns_none(self):
        import importlib
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"OTHER_KEY": "value"}}
        }
        _inject_hvac(mock_client)
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "vault",
            "VAULT_ADDR": "http://vault:8200",
            "VAULT_TOKEN": "test-token",
            "VAULT_SECRET_PATH": "secret/wazuh-mcp",
        }):
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
        assert result is None

    def test_vault_unavailable_falls_back_to_env(self):
        import importlib
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.side_effect = Exception("connection refused")
        _inject_hvac(mock_client)
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "vault",
            "VAULT_ADDR": "http://vault:8200",
            "VAULT_TOKEN": "bad-token",
            "VAULT_SECRET_PATH": "secret/wazuh-mcp",
            "WAZUH_PASS": "env_fallback_pass",
        }):
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
        # Falls back to env on Vault error
        assert result == "env_fallback_pass"


class TestAWSBackend:
    def test_aws_fetches_secret(self):
        import importlib
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": '{"WAZUH_PASS": "aws_password", "WAZUH_USER": "wazuh-mcp"}'
        }
        _inject_boto3(mock_client)
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "aws",
            "AWS_SECRET_NAME": "wazuh-mcp/secrets",
            "AWS_REGION": "us-east-1",
        }):
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
        assert result == "aws_password"

    def test_aws_missing_key_returns_none(self):
        import importlib
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": '{"OTHER": "value"}'
        }
        _inject_boto3(mock_client)
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "aws",
            "AWS_SECRET_NAME": "wazuh-mcp/secrets",
            "AWS_REGION": "us-east-1",
        }):
            import wazuh_mcp.secrets_backend as sb
            importlib.reload(sb)
            result = sb.get_secret("WAZUH_PASS")
        assert result is None

    def test_aws_unavailable_falls_back_to_env(self):
        import importlib
        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = Exception("NoCredentials")
        _inject_boto3(mock_client)
        with patch.dict(os.environ, {
            "WAZUH_SECRET_BACKEND": "aws",
            "AWS_SECRET_NAME": "wazuh-mcp/secrets",
            "AWS_REGION": "us-east-1",
            "WAZUH_PASS": "env_fallback",
        }):
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
