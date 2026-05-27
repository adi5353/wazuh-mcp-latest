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
            event_dict[key] = re.sub(
                r"(Bearer|Basic)\s+[A-Za-z0-9+/=._\-]{8,}",
                r"\1 [REDACTED]",
                event_dict[key],
            )
    return event_dict


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


logger = structlog.get_logger("wazuh_mcp")
