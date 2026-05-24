import re
import structlog
import logging
from typing import Any

# Fields whose values must never appear in log output.
_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|token|api_key|apikey|secret|authorization|auth|credential)",
    re.IGNORECASE,
)


def _redact_sensitive(logger: Any, method: str, event_dict: dict) -> dict:  # noqa: ARG001
    """structlog processor: replace sensitive field values with [REDACTED]."""
    for key in list(event_dict.keys()):
        if _SENSITIVE_KEYS.search(key):
            event_dict[key] = "[REDACTED]"
        elif isinstance(event_dict[key], str) and len(event_dict[key]) > 6:
            # Redact Bearer / Basic tokens that may appear inside string values.
            event_dict[key] = re.sub(
                r"(Bearer|Basic)\s+[A-Za-z0-9+/=._\-]{8,}",
                r"\1 [REDACTED]",
                event_dict[key],
            )
    return event_dict


def configure_logging(log_level: str = "INFO"):
    logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO))
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.PositionalArgumentsFormatter(),
            _redact_sensitive,                         # ← strip secrets before rendering
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),       # JSON lines → feed into Wazuh!
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

logger = structlog.get_logger("wazuh_mcp")
