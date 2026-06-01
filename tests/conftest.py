import os
import sys

import pytest

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


@pytest.fixture(autouse=True)
def reset_shared_http_clients():
    """Reset cached module-level httpx client singletons between tests.

    Several integration modules memoize a pooled ``httpx.AsyncClient`` in a
    module global (``_SOAR_CLIENT``, ``_SNOW_CLIENT``, the threat-intel clients)
    so a long-lived server reuses one connection pool. Tests that swap
    ``httpx.AsyncClient`` for a fake build that fake on first call and cache it;
    without a reset the fake leaks into every later test. Because the fakes do
    not implement ``is_closed``, the next ``_get_*_client()`` call raises
    ``AttributeError`` and tools return ``{"error": ...}`` — surfacing as
    ``KeyError: 'status'`` and the shared-client identity assertions failing.

    Clearing the globals to ``None`` before and after each test makes the suite
    order-independent. Production is unaffected — these globals are only touched
    by the server lifecycle, never by another test.
    """
    def _clear():
        for mod_name, attrs in (
            ("wazuh_mcp.tools.notifications", ("_SOAR_CLIENT",)),
            ("wazuh_mcp.tools.servicenow", ("_SNOW_CLIENT",)),
            ("wazuh_mcp.tools.threat_intel", ("_VT_CLIENT", "_ABUSE_CLIENT")),
        ):
            mod = sys.modules.get(mod_name)
            if mod is None:
                continue
            for attr in attrs:
                if hasattr(mod, attr):
                    setattr(mod, attr, None)

    _clear()
    yield
    _clear()
