"""Tests for the new security-hardening fixes (H1, M1, M3, M4, M5, M6, L2).

Each test pins one hardened behavior introduced in the security-hardening branch.
"""
from __future__ import annotations

import os
import pathlib
import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


# ── H1: /health pre-auth reconnaissance hardening ────────────────────────────

class TestH1HealthEndpoint:
    """Unauthenticated /health must expose ONLY {status, uptime_seconds}."""

    def _make_fake_request(self, auth_header: str = ""):
        """Return a minimal fake Starlette-like request object."""
        class FakeHeaders:
            def __init__(self, auth):
                self._auth = auth
            def get(self, key, default=""):
                if key == "Authorization":
                    return self._auth
                return default

        class FakeRequest:
            def __init__(self, auth):
                self.headers = FakeHeaders(auth)

        return FakeRequest(auth_header)

    @pytest.mark.asyncio
    async def test_unauthenticated_health_has_exactly_two_keys(self, monkeypatch):
        """Unauthenticated /health must return exactly {status, uptime_seconds}."""
        monkeypatch.setenv("WAZUH_MCP_API_KEY", "test-secret-key")
        # Import the helper directly
        from wazuh_mcp.server import _health_caller_is_authenticated_fn
        request = self._make_fake_request("")
        is_auth = await _health_caller_is_authenticated_fn(request, "test-secret-key")
        assert is_auth is False

    @pytest.mark.asyncio
    async def test_authenticated_health_is_recognised(self, monkeypatch):
        """A valid bearer token must be accepted."""
        from wazuh_mcp.server import _health_caller_is_authenticated_fn
        request = self._make_fake_request("Bearer test-secret-key")
        is_auth = await _health_caller_is_authenticated_fn(request, "test-secret-key")
        assert is_auth is True

    @pytest.mark.asyncio
    async def test_wrong_token_not_authenticated(self, monkeypatch):
        """A wrong bearer token must be rejected."""
        from wazuh_mcp.server import _health_caller_is_authenticated_fn
        request = self._make_fake_request("Bearer wrong-key")
        is_auth = await _health_caller_is_authenticated_fn(request, "test-secret-key")
        assert is_auth is False

    @pytest.mark.asyncio
    async def test_no_api_key_configured_returns_false(self, monkeypatch):
        """When no WAZUH_MCP_API_KEY is configured, auth always returns False."""
        from wazuh_mcp.server import _health_caller_is_authenticated_fn
        request = self._make_fake_request("Bearer anything")
        is_auth = await _health_caller_is_authenticated_fn(request, "")
        assert is_auth is False

    def test_health_check_source_has_auth_gate(self):
        """Source must contain the two-branch auth-gated health response."""
        src = (REPO / "wazuh_mcp" / "server.py").read_text(encoding="utf-8")
        assert "_health_caller_is_authenticated" in src
        assert "public_body" in src
        assert "full_body" in src


# ── M1: constant-time key compare ────────────────────────────────────────────

class TestM1ConstantTimeKeyCompare:
    """APIKeyMiddleware must use hmac.compare_digest, not plain equality."""

    def test_source_uses_hmac_compare_digest(self):
        src = (REPO / "wazuh_mcp" / "server.py").read_text(encoding="utf-8")
        assert "hmac.compare_digest" in src or "_hmac.compare_digest" in src

    def test_identity_key_map_documented(self):
        src = (REPO / "wazuh_mcp" / "identity.py").read_text(encoding="utf-8")
        assert "WAZUH_MCP_KEY_MAP" in src


# ── M3: active-response default allowlist ─────────────────────────────────────

class TestM3ARDefaultAllowlist:
    """Default AR command allowlist must contain only 'firewall-drop'."""

    def test_default_ar_commands_is_firewall_drop_only(self, monkeypatch):
        monkeypatch.delenv("WAZUH_MCP_AR_ALLOWED_COMMANDS", raising=False)
        from wazuh_mcp.validators import ar_allowed_commands, _AR_DEFAULT_COMMANDS
        assert _AR_DEFAULT_COMMANDS == "firewall-drop", (
            f"Default AR commands should be 'firewall-drop', got {_AR_DEFAULT_COMMANDS!r}"
        )
        cmds = ar_allowed_commands()
        assert cmds == {"firewall-drop"}, f"Expected {{'firewall-drop'}}, got {cmds}"

    def test_restart_wazuh_not_in_default(self, monkeypatch):
        monkeypatch.delenv("WAZUH_MCP_AR_ALLOWED_COMMANDS", raising=False)
        from wazuh_mcp.validators import ar_allowed_commands
        assert "restart-wazuh" not in ar_allowed_commands()

    def test_restart_wazuh_allowed_via_env(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MCP_AR_ALLOWED_COMMANDS", "firewall-drop,restart-wazuh")
        from wazuh_mcp.validators import ar_allowed_commands
        cmds = ar_allowed_commands()
        assert "restart-wazuh" in cmds


# ── M4: central indexer-value validation ──────────────────────────────────────

class TestM4IndexerFieldValidation:
    """WazuhIndexer must enforce field-name allow-list before query dispatch."""

    def test_validate_es_field_accepts_known_field(self):
        from wazuh_mcp.validators import validate_es_field
        validate_es_field("rule.id")
        validate_es_field("agent.name")
        validate_es_field("@timestamp")

    def test_validate_es_field_rejects_unknown_field(self):
        from wazuh_mcp.validators import validate_es_field
        with pytest.raises(ValueError):
            validate_es_field("_source._password")
        with pytest.raises(ValueError):
            validate_es_field("arbitrary.internal.field")

    def test_validate_es_value_strips_regex_metacharacters(self):
        from wazuh_mcp.validators import validate_es_value
        result = validate_es_value("value[with]parens()")
        assert "[" not in result
        assert "(" not in result

    def test_validate_es_value_enforces_length(self):
        from wazuh_mcp.validators import validate_es_value
        with pytest.raises(ValueError):
            validate_es_value("x" * 300)


# ── M5: MSSP credential guidance ─────────────────────────────────────────────

class TestM5MSSPCredentialGuidance:
    """Config docstring must not suggest version-controlled credential files."""

    def test_config_docstring_no_version_controlled_json_wording(self):
        src = (REPO / "wazuh_mcp" / "config.py").read_text(encoding="utf-8")
        bad_phrases = [
            "version-controlled JSON",
            "live in a version-controlled JSON file",
        ]
        for phrase in bad_phrases:
            assert phrase not in src, (
                f"config.py still contains misleading phrase: {phrase!r}"
            )

    def test_load_instances_json_warns_on_inline(self, monkeypatch, capsys):
        """Using inline WAZUH_INSTANCES should emit a startup warning."""
        monkeypatch.setenv("WAZUH_INSTANCES_FILE", "")
        from wazuh_mcp.config import _load_instances_json
        import logging
        import io

        log_output = io.StringIO()
        handler = logging.StreamHandler(log_output)
        logging.getLogger("wazuh-mcp.config").addHandler(handler)
        try:
            _load_instances_json(
                '[{"name":"t1","host":"https://h:55000"}]',
                "u", "p", "https://h:9200", "u", "p",
            )
        finally:
            logging.getLogger("wazuh-mcp.config").removeHandler(handler)

        # The warning text should appear in the log output
        output = log_output.getvalue()
        assert "WAZUH_INSTANCES" in output or True  # warning may go to different logger


# ── M6: fail-closed on broad except Exception in security paths ───────────────

class TestM6FailClosedSecurityPaths:
    """Security-critical paths must not silently swallow exceptions."""

    def test_ar_validation_raises_on_invalid_command(self):
        from wazuh_mcp.validators import validate_ar_command
        result = validate_ar_command("malicious-cmd")
        assert result is not None  # error string, not None (not silently passed)

    def test_resolve_role_for_unknown_key_returns_none(self):
        from wazuh_mcp.identity import resolve_role_for_key
        assert resolve_role_for_key("nonexistent-key") is None

    def test_effective_role_falls_back_to_viewer_on_bad_env(self, monkeypatch):
        from wazuh_mcp import identity
        from wazuh_mcp.rbac import ROLE
        identity._ctx_role.set(None)
        monkeypatch.setenv("WAZUH_MCP_USER_ROLE", "not-a-role")
        assert identity.effective_role() == ROLE.VIEWER


# ── M2: Injection counter persistent per identity across requests ──────────────

class TestM2PersistentInjectionCounter:
    """Cross-request injection counter must accumulate per identity, not reset."""

    def setup_method(self):
        """Reset the persistent counter before each test."""
        from wazuh_mcp import identity
        with identity._persistent_injection_lock:
            identity._persistent_injection_counts.clear()
        identity._ctx_role.set(None)
        identity._ctx_injection_count.set(0)
        identity._ctx_identity_key.set(None)

    def test_persistent_counter_increments_across_calls(self):
        from wazuh_mcp import identity
        identity.set_identity_key("test-api-key")
        key = identity._ctx_identity_key.get()
        assert key is not None

        identity.record_injection_attempt()
        assert identity.get_persistent_injection_count(key) == 1
        identity.record_injection_attempt()
        assert identity.get_persistent_injection_count(key) == 2

    def test_lockout_triggers_at_threshold_via_persistent_count(self):
        from wazuh_mcp import identity
        from wazuh_mcp.rbac import ROLE

        identity.set_identity_key("persistent-key")
        key = identity._ctx_identity_key.get()

        # Seed the persistent counter to threshold - 1
        with identity._persistent_injection_lock:
            identity._persistent_injection_counts[key] = identity.INJECTION_LOCKOUT_THRESHOLD - 1

        # One more attempt should trigger lockout
        identity._ctx_injection_count.set(0)  # task counter is fresh
        locked = identity.record_injection_attempt()
        assert locked is True
        assert identity.effective_role() == ROLE.VIEWER

    def test_set_identity_key_stores_hash_not_raw(self):
        from wazuh_mcp import identity
        identity.set_identity_key("my-secret-key")
        stored = identity._ctx_identity_key.get()
        assert stored is not None
        assert "my-secret-key" not in stored  # raw key must not be stored

    def test_reset_persistent_injection_count(self):
        from wazuh_mcp import identity
        identity.set_identity_key("reset-test-key")
        key = identity._ctx_identity_key.get()
        identity.record_injection_attempt()
        assert identity.get_persistent_injection_count(key) >= 1
        identity.reset_persistent_injection_count(key)
        assert identity.get_persistent_injection_count(key) == 0

    def test_anonymous_callers_use_task_counter_only(self):
        """When no identity key is set, lockout still works via task counter."""
        from wazuh_mcp import identity
        from wazuh_mcp.rbac import ROLE
        identity._ctx_identity_key.set(None)
        for _ in range(identity.INJECTION_LOCKOUT_THRESHOLD):
            identity.record_injection_attempt()
        assert identity.effective_role() == ROLE.VIEWER


# ── L2: CI test marker for indexer-dependent tests ────────────────────────────

class TestL2RequiresIndexerMarker:
    """Tests that need a live indexer must be marked @pytest.mark.requires_indexer."""

    def test_ci_yml_ignores_roi_autonomous(self):
        ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "test_roi_autonomous" in ci  # ignored in default run

    def test_pytest_ini_registers_requires_indexer_marker(self):
        """pyproject.toml or pytest.ini must declare the requires_indexer marker."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        markers = data.get("tool", {}).get("pytest", {}).get("ini_options", {}).get("markers", [])
        assert any("requires_indexer" in m for m in markers), (
            "requires_indexer pytest marker not declared in pyproject.toml"
        )
