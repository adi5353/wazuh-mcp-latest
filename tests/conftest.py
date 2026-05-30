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


@pytest.fixture(autouse=True)
def reset_session_identity():
    """Reset the task-local identity ContextVars between tests.

    ``effective_role()`` and the injection-lockout counter live in process-wide
    ContextVars (and a module-level persistent dict). A test that sets a session
    role or trips the injection lockout would otherwise leak that state into
    every test that runs after it, making RBAC assertions order-dependent. This
    fixture restores a clean slate before and after each test so the suite is
    deterministic regardless of collection order.
    """
    from wazuh_mcp import identity

    def _clear():
        identity._ctx_role.set(None)
        identity._ctx_injection_count.set(0)
        identity._ctx_identity_key.set(None)
        with identity._persistent_injection_lock:
            identity._persistent_injection_counts.clear()

    _clear()
    yield
    _clear()
