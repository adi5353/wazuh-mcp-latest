import os
import re
import uuid
import structlog
import logging
from typing import Any, MutableMapping, Union

# Fields whose values must never appear in log output.
_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|token|api_key|apikey|secret|authorization|auth|credential)",
    re.IGNORECASE,
)

# Log format: "json" (default, machine-parseable) or "console" (human-readable)
_LOG_FORMAT = os.getenv("WAZUH_MCP_LOG_FORMAT", "json").lower()


def _redact_sensitive(
    logger: Any, method: str, event_dict: MutableMapping[str, Any]
) -> Union[MutableMapping[str, Any], str, bytes, bytearray, tuple[Any, ...]]:  # noqa: ARG001
    """structlog processor: replace sensitive field values with [REDACTED]."""
    for key in list(event_dict.keys()):
        if _SENSITIVE_KEYS.search(key):
            event_dict[key] = "[REDACTED]"
        elif isinstance(event_dict[key], str) and len(event_dict[key]) > 6:
            event_dict[key] = redact_text(event_dict[key])
    return event_dict


# ── Plain-text redaction (used by the stdlib-logging fallback) ─────────────────
# The structlog pipeline above redacts structured event dicts. When structlog is
# unavailable and we fall back to stdlib logging, messages are plain strings, so
# we need a text-level scrubber. Patterns cover both `Bearer <tok>` / `Basic
# <tok>` auth headers and `key=value` / `key: value` secret assignments.
_SECRET_TEXT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(Bearer|Basic)\s+[A-Za-z0-9+/=._\-]{8,}", re.IGNORECASE), r"\1 [REDACTED]"),
    (re.compile(
        r"(?i)(password|passwd|token|api[_-]?key|apikey|secret|authorization|credential)"
        r"(\"?\s*[:=]\s*\"?)([^\s\"',}]+)"
    ), r"\1\2[REDACTED]"),
]


def redact_text(text: str) -> str:
    """Scrub auth tokens and key=value secrets from an arbitrary log string."""
    for pattern, repl in _SECRET_TEXT_PATTERNS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    """stdlib logging filter that scrubs secrets from every emitted record.

    Attached to the root logger in the fallback path so the redaction guarantee
    does NOT depend on structlog being importable. Collapses args into the
    rendered message first (so positional/`%s` secrets are caught too).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_text(record.getMessage())
            record.args = ()
        except Exception:
            # Never let redaction failure drop a log line entirely.
            pass
        return True


def quiet_noisy_loggers() -> None:
    """Clamp chatty third-party loggers that can leak secrets at DEBUG level.

    httpx/httpcore log full request lines — including the ``Authorization``
    header carrying VirusTotal/AbuseIPDB API keys — at DEBUG. Pin them to
    WARNING regardless of the app log level so enabling DEBUG on our own code
    can never spill third-party credentials to stderr.
    """
    for name in ("httpx", "httpcore", "hpack", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)


def bind_request_context(tool_name: str, identity_hash: str) -> None:
    """Bind per-request context to the current structlog context vars.

    Call at the start of each tool invocation so all log lines emitted
    during that call carry tool_name, identity, and a unique trace_id.
    """
    structlog.contextvars.bind_contextvars(
        tool=tool_name,
        identity=identity_hash[:8],
        trace_id=uuid.uuid4().hex[:12],
    )


def clear_request_context() -> None:
    """Clear per-request context vars after a tool call completes."""
    structlog.contextvars.clear_contextvars()


def configure_logging(log_level: str = "INFO"):
    logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO))

    renderer = (
        structlog.dev.ConsoleRenderer()
        if _LOG_FORMAT == "console"
        else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,   # ← inject tool/identity/trace_id
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.PositionalArgumentsFormatter(),
            _redact_sensitive,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    quiet_noisy_loggers()


logger = structlog.get_logger("wazuh_mcp")
