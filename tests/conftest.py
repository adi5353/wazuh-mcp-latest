import pytest
import os

@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("WAZUH_HOST", "https://127.0.0.1:55000")
    monkeypatch.setenv("WAZUH_USER", "wazuh-mcp")
    monkeypatch.setenv("WAZUH_PASS", "test-password-not-real")
    monkeypatch.setenv("WAZUH_INDEXER_HOST", "https://127.0.0.1:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "wazuh-mcp-readonly")
    monkeypatch.setenv("WAZUH_INDEXER_PASS", "test-password-not-real")
    monkeypatch.setenv("WAZUH_VERIFY_SSL", "false")
    monkeypatch.setenv("WAZUH_ALLOW_WRITES", "false")
