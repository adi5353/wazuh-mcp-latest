import pytest
import os

@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("WAZUH_HOST", "https://192.168.56.50:55000")
    monkeypatch.setenv("WAZUH_USER", "wazuh-mcp")
    monkeypatch.setenv("WAZUH_PASS", "Vedansh@201095")
    monkeypatch.setenv("WAZUH_INDEXER_HOST", "https://192.168.56.50:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "wazuh-mcp-readonly")
    monkeypatch.setenv("WAZUH_INDEXER_PASS", "Vedansh@201095")
    monkeypatch.setenv("WAZUH_VERIFY_SSL", "false")
    monkeypatch.setenv("WAZUH_ALLOW_WRITES", "false")
