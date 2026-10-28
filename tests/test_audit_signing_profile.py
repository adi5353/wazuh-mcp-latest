"""F3: production profile requires audit-log HMAC signing.

In the production profile a missing WAZUH_AUDIT_LOG_SIGNING_KEY must be fatal at
import (fail loud). In dev (default) it must degrade to a warning.
"""
import importlib
import os

import pytest
from unittest.mock import patch

import wazuh_mcp.audit as audit


def _reload_with(env: dict):
    with patch.dict(os.environ, env, clear=False):
        return importlib.reload(audit)


@pytest.fixture(autouse=True)
def _restore_audit():
    # Ensure the module is restored to the default (dev, signed) state afterward
    # so other tests see a normal audit module.
    yield
    with patch.dict(os.environ, {"WAZUH_MCP_PROFILE": "dev",
                                 "WAZUH_AUDIT_LOG_SIGNING_KEY": "test-key"}):
        importlib.reload(audit)


def test_production_without_signing_key_is_fatal():
    env = {"WAZUH_MCP_PROFILE": "production"}
    # Remove any signing key for this scenario.
    with patch.dict(os.environ, env, clear=False):
        os.environ.pop("WAZUH_AUDIT_LOG_SIGNING_KEY", None)
        with pytest.raises(RuntimeError, match="without audit log signing"):
            importlib.reload(audit)


def test_production_with_signing_key_ok():
    mod = _reload_with({"WAZUH_MCP_PROFILE": "production",
                        "WAZUH_AUDIT_LOG_SIGNING_KEY": "s3cret"})
    assert mod._SIGNING_KEY == "s3cret"


def test_dev_without_signing_key_warns_not_fatal(caplog):
    with patch.dict(os.environ, {"WAZUH_MCP_PROFILE": "dev"}, clear=False):
        os.environ.pop("WAZUH_AUDIT_LOG_SIGNING_KEY", None)
        # Should not raise.
        mod = importlib.reload(audit)
        assert mod._SIGNING_KEY == ""
