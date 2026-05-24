import os
import pytest
from unittest.mock import patch
from wazuh_mcp.config import Config


def test_config_loads():
    cfg = Config.from_env()
    assert cfg.manager_host.startswith("https://")
    assert cfg.manager_user is not None
    assert cfg.allow_writes is False


def test_config_defaults():
    cfg = Config.from_env()
    assert cfg.request_timeout == 30
    # ca_bundle defaults to None when WAZUH_CA_BUNDLE is not set
    assert cfg.ca_bundle is None


def test_ssl_default_is_true():
    """H9: When WAZUH_VERIFY_SSL is not set, default must be True (production-safe)."""
    env_without_ssl = {k: v for k, v in os.environ.items() if k != "WAZUH_VERIFY_SSL"}
    with patch.dict(os.environ, env_without_ssl, clear=True):
        cfg = Config.from_env()
        assert cfg.verify_ssl is True, (
            "WAZUH_VERIFY_SSL must default to True — set it explicitly to false only in dev/lab"
        )


def test_ssl_can_be_disabled_explicitly():
    """Explicit WAZUH_VERIFY_SSL=false must still work for lab environments."""
    with patch.dict(os.environ, {"WAZUH_VERIFY_SSL": "false"}):
        cfg = Config.from_env()
        assert cfg.verify_ssl is False


def test_ca_bundle_set():
    """WAZUH_CA_BUNDLE env var is picked up correctly."""
    with patch.dict(os.environ, {"WAZUH_CA_BUNDLE": "/etc/ssl/wazuh-ca.pem"}):
        cfg = Config.from_env()
        assert cfg.ca_bundle == "/etc/ssl/wazuh-ca.pem"
