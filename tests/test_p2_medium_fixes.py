"""Regression tests for the P2-Medium review fixes.

Covers:
  * #7 — secret redaction must not depend on structlog (stdlib fallback path)
  * #9 — httpx/httpcore loggers clamped to WARNING so DEBUG can't leak API keys

(#8 — audit HMAC startup warning — was already implemented in audit.py and is
 exercised by the existing audit tests; no new test needed here.)
"""
from __future__ import annotations

import logging

import pytest


# ── #7: stdlib-path redaction ───────────────────────────────────────────────

class TestRedactText:
    def test_redacts_bearer_token(self):
        from wazuh_mcp.logging_config import redact_text
        out = redact_text("Authorization: Bearer abc123DEF456ghi789")
        assert "abc123DEF456ghi789" not in out
        assert "[REDACTED]" in out

    def test_redacts_basic_auth(self):
        from wazuh_mcp.logging_config import redact_text
        out = redact_text("header Basic dXNlcjpwYXNzd29yZA==")
        assert "dXNlcjpwYXNzd29yZA==" not in out
        assert "[REDACTED]" in out

    def test_redacts_key_value_secrets(self):
        from wazuh_mcp.logging_config import redact_text
        for s in (
            "api_key=sk-supersecretvalue",
            "password: hunter2hunter2",
            'token="eyJhbGciOiJI"',
            "VT_API_KEY=deadbeefcafe",
        ):
            out = redact_text(s)
            assert "[REDACTED]" in out, s

    def test_leaves_clean_text_untouched(self):
        from wazuh_mcp.logging_config import redact_text
        clean = "agent 003 reported 12 alerts at level >= 10"
        assert redact_text(clean) == clean


class TestRedactingFilter:
    def test_filter_scrubs_record_message(self):
        from wazuh_mcp.logging_config import RedactingFilter
        f = RedactingFilter()
        rec = logging.LogRecord(
            name="x", level=logging.INFO, pathname=__file__, lineno=1,
            msg="calling VT with Authorization: Bearer SECRETTOKEN12345",
            args=(), exc_info=None,
        )
        assert f.filter(rec) is True
        assert "SECRETTOKEN12345" not in rec.getMessage()
        assert "[REDACTED]" in rec.getMessage()

    def test_filter_scrubs_positional_args(self):
        from wazuh_mcp.logging_config import RedactingFilter
        f = RedactingFilter()
        rec = logging.LogRecord(
            name="x", level=logging.INFO, pathname=__file__, lineno=1,
            msg="key=%s", args=("api_key=topsecretvalue",), exc_info=None,
        )
        f.filter(rec)
        assert "topsecretvalue" not in rec.getMessage()


# ── #9: noisy logger clamp ──────────────────────────────────────────────────

class TestQuietNoisyLoggers:
    def test_httpx_and_httpcore_pinned_to_warning(self):
        from wazuh_mcp.logging_config import quiet_noisy_loggers
        # Pretend something set them to DEBUG (the leak scenario).
        for name in ("httpx", "httpcore"):
            logging.getLogger(name).setLevel(logging.DEBUG)
        quiet_noisy_loggers()
        for name in ("httpx", "httpcore", "hpack", "urllib3"):
            assert logging.getLogger(name).level == logging.WARNING

    def test_server_import_clamps_httpx(self):
        """Importing the server (which runs the module-level setup) must leave
        httpx no more verbose than WARNING."""
        import wazuh_mcp.server  # noqa: F401
        assert logging.getLogger("httpx").level >= logging.WARNING
