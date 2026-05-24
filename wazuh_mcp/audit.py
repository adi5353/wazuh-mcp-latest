"""Structured audit trail for every MCP tool invocation.

Writes one JSONL record per tool call to the audit log file.
The record intentionally omits raw result payloads and credential values.

Also provides:
  sanitize_response() — strips secrets + prompt injection payloads from tool responses
  before they are serialized and sent to the LLM client.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|token|api_key|apikey|secret|authorization|credential)",
    re.IGNORECASE,
)

# ── Prompt injection / adversarial AI patterns ─────────────────────────────────
# These patterns neutralize known LLM boundary-crossing tokens that an attacker
# could embed in log data (e.g. User-Agent strings stored in Wazuh alerts).
_PROMPT_INJECTION_PATTERNS = [
    # System prompt override tokens
    re.compile(r"</?system[^>]*>", re.IGNORECASE),
    re.compile(r"</?admin[^>]*>", re.IGNORECASE),
    re.compile(r"\[/?INST\]", re.IGNORECASE),
    re.compile(r"<</?SYS>>", re.IGNORECASE),
    re.compile(r"</s>", re.IGNORECASE),
    # Common LLM meta-control sequences
    re.compile(r"###\s*(System|Instruction|Human|Assistant|User)\s*:", re.IGNORECASE),
    re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions?"),
    re.compile(r"(?i)you\s+are\s+now\s+(a\s+)?(?:an?\s+)?(?:unrestricted|jailbreak|DAN)"),
]

# Executable code block patterns that could trick LLMs into running code
_CODE_EXECUTION_PATTERNS = re.compile(
    r"(eval\(|exec\(|subprocess\.|os\.system|__import__|`[^`]{1,200}`)",
    re.IGNORECASE,
)

# ── Value-level secret pattern (for response payloads) ────────────────────────
_SECRET_VALUE_RE = re.compile(
    r"(?i)(password|passwd|token|api_key|apikey|secret|bearer)\s*[=:]\s*\S+",
)


def _sanitize_string(value: str) -> str:
    """Strip prompt injection tokens and secret values from a string."""
    for pat in _PROMPT_INJECTION_PATTERNS:
        value = pat.sub("[FILTERED]", value)
    value = _CODE_EXECUTION_PATTERNS.sub("[CODE_FILTERED]", value)
    value = _SECRET_VALUE_RE.sub(r"\1=[REDACTED]", value)
    return value


def _sanitize_value(value: Any, _depth: int = 0) -> Any:
    """Recursively sanitize a response value (dict, list, str)."""
    if _depth > 10:  # prevent infinite recursion on deeply nested data
        return value
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, dict):
        return {k: _sanitize_value(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(item, _depth + 1) for item in value]
    return value


def sanitize_response(result: dict) -> dict:
    """Sanitize a tool response dict before sending to the LLM client.

    Removes:
    - Prompt injection tokens (<system>, [INST], ###System:, etc.)
    - Executable code patterns (eval, exec, subprocess)
    - Plaintext secrets in values (password=xxx, token=xxx)

    Safe on tool error responses — returns them unchanged structurally,
    only scanning string content within them.
    """
    if not isinstance(result, dict):
        return result
    return _sanitize_value(result)

_log = logging.getLogger("wazuh_mcp.audit")

# Audit log path — override with WAZUH_AUDIT_LOG env var.
_AUDIT_LOG_PATH = Path(os.getenv("WAZUH_AUDIT_LOG", "logs/audit.jsonl"))


def _scrub_params(params: dict) -> dict:
    """Return a copy of params with sensitive values replaced by [REDACTED]."""
    scrubbed: dict = {}
    for k, v in params.items():
        if _SENSITIVE_KEYS.search(k):
            scrubbed[k] = "[REDACTED]"
        elif isinstance(v, str) and len(v) > 6:
            scrubbed[k] = re.sub(
                r"(Bearer|Basic)\s+[A-Za-z0-9+/=._\-]{8,}",
                r"\1 [REDACTED]",
                v,
            )
        else:
            scrubbed[k] = v
    return scrubbed


def _params_fingerprint(params: dict) -> str:
    """SHA-256 fingerprint of scrubbed params — for correlation without leaking values."""
    canonical = json.dumps(_scrub_params(params), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _write_record(record: dict) -> None:
    """Append a JSONL record to the audit log, creating the file/dir if needed."""
    try:
        _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception as exc:  # noqa: BLE001
        _log.error("audit_write_failed error=%s", exc)


class AuditLogger:
    """
    Wraps a MCP tool call with audit logging.

    Usage in server.py::

        from .audit import AuditLogger
        audit = AuditLogger()
        ...
        with audit.record("search_alerts", params, identity="api-key-hash"):
            result = await original_tool(**params)
    """

    def record(
        self,
        tool_name: str,
        params: dict[str, Any],
        identity: str = "unknown",
    ):
        return _AuditContext(tool_name, params, identity)


class _AuditContext:
    def __init__(self, tool_name: str, params: dict, identity: str) -> None:
        self._tool_name = tool_name
        self._params = params
        self._identity = identity
        self._start = time.time()

    def __enter__(self):
        return self

    def set_result_code(self, code: str) -> None:
        self._result_code = code

    def __exit__(self, exc_type, exc_val, exc_tb):
        result_code = "error" if exc_type else getattr(self, "_result_code", "ok")
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": self._tool_name,
            "identity": self._identity,
            "params_fp": _params_fingerprint(self._params),
            "params_scrubbed": _scrub_params(self._params),
            "result_code": result_code,
            "duration_ms": round((time.time() - self._start) * 1000),
        }
        _write_record(record)
        return False  # never suppress exceptions


# Module-level singleton for import convenience.
audit_logger = AuditLogger()
