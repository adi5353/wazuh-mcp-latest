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

_MAX_OUTPUT_CHARS: int = int(os.getenv("WAZUH_MCP_MAX_OUTPUT_CHARS", "20000"))

_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|token|api_key|apikey|secret|authorization|credential)",
    re.IGNORECASE,
)

# ── Prompt injection / adversarial AI patterns ────────────────────────────────
# Neutralize LLM boundary-crossing tokens that an attacker could embed in
# log data (e.g. User-Agent strings stored in Wazuh alerts).
_PROMPT_INJECTION_PATTERNS = [
    # System prompt override tokens
    re.compile(r"</?system[^>]*>",  re.IGNORECASE),
    re.compile(r"</?admin[^>]*>",   re.IGNORECASE),
    re.compile(r"</?claude[^>]*>",  re.IGNORECASE),
    re.compile(r"\[/?INST\]",       re.IGNORECASE),
    re.compile(r"<</?SYS>>",        re.IGNORECASE),
    re.compile(r"</s>",             re.IGNORECASE),
    # Common LLM meta-control sequences
    re.compile(r"###\s*(System|Instruction|Human|Assistant|User)\s*:", re.IGNORECASE),
    re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions?"),
    re.compile(r"(?i)you\s+are\s+now\s+(a\s+)?(?:an?\s+)?(?:unrestricted|jailbreak|DAN)"),
    # Claude / ChatML conversation delimiters
    re.compile(r"Human:\s*\n|Assistant:\s*\n",                    re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>",                   re.IGNORECASE),
    # Role-override and jailbreak phrases
    re.compile(r"(?i)act\s+as\s+(if\s+you\s+are|an?\s+)?(?:unrestricted|evil|hacker)"),
    re.compile(r"(?i)pretend\s+(you\s+are|to\s+be)\s+(?:a\s+)?(?:different|unrestricted)"),
    re.compile(r"(?i)your\s+(new\s+)?instructions?\s+(are|is)\s*:"),
    # Data-exfiltration via output reflection
    re.compile(r"(?i)repeat\s+(everything|all|the)\s+(above|before|prior|previous)"),
    re.compile(r"(?i)print\s+(your\s+)?(system\s+prompt|instructions|context)"),
    # Indirect injection via embedded markup
    re.compile(r"<!--.*?-->",    re.DOTALL),
    re.compile(r"\{\{[^}]+\}\}"),
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

# ── PII patterns (scrub from tool outputs) ────────────────────────────────────
_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
     "[CC_NUMBER]"),
]


def _scrub_pii(value: str) -> str:
    """Replace PII patterns (emails, SSNs, credit card numbers) with placeholders."""
    for pattern, placeholder in _PII_PATTERNS:
        value = pattern.sub(placeholder, value)
    return value


def _sanitize_string(value: str) -> str:
    """Strip prompt injection tokens, executable code, secrets, and PII from a string."""
    for pat in _PROMPT_INJECTION_PATTERNS:
        value = pat.sub("[FILTERED]", value)
    value = _CODE_EXECUTION_PATTERNS.sub("[CODE_FILTERED]", value)
    value = _SECRET_VALUE_RE.sub(r"\1=[REDACTED]", value)
    value = _scrub_pii(value)
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
    - PII (emails, SSNs, credit card numbers)

    Safe on tool error responses — returns them unchanged structurally,
    only scanning string content within them.
    """
    if not isinstance(result, dict):
        return result
    return _sanitize_value(result)


def cap_response_size(result: Any) -> Any:
    """Truncate oversized tool responses before they reach the LLM.

    If the JSON-serialized response exceeds WAZUH_MCP_MAX_OUTPUT_CHARS
    (default 20 000 chars ≈ 5 000 tokens), returns a structured warning
    with a preview instead of the raw truncated payload.  This prevents
    single tool calls from exhausting the LLM context window.
    """
    try:
        serialized = json.dumps(result, default=str)
    except Exception:
        return result
    if len(serialized) <= _MAX_OUTPUT_CHARS:
        return result
    # Truncate at a valid JSON object boundary by slicing the top-level list/dict.
    # Naively slicing the serialized string almost always produces malformed JSON.
    preview: Any
    if isinstance(result, dict):
        # Return as many top-level keys as fit within the limit
        preview = {}
        running = 2  # account for '{}'
        for k, v in result.items():
            entry = json.dumps({k: v}, default=str)
            if running + len(entry) + 1 > _MAX_OUTPUT_CHARS:
                break
            preview[k] = v
            running += len(entry) + 1
    elif isinstance(result, list):
        # Return as many list items as fit within the limit
        preview = []
        running = 2  # account for '[]'
        for item in result:
            entry = json.dumps(item, default=str)
            if running + len(entry) + 1 > _MAX_OUTPUT_CHARS:
                break
            preview.append(item)
            running += len(entry) + 1
    else:
        preview = serialized[: _MAX_OUTPUT_CHARS]

    return {
        "warning": "Response truncated — use more specific filters to narrow results",
        "total_chars": len(serialized),
        "limit_chars": _MAX_OUTPUT_CHARS,
        "preview": preview,
    }

_log = logging.getLogger("wazuh_mcp.audit")

# Audit log path — override with WAZUH_AUDIT_LOG env var.
_AUDIT_LOG_PATH = Path(os.getenv("WAZUH_AUDIT_LOG", "logs/audit.jsonl"))

# Rotation config — WAZUH_AUDIT_MAX_BYTES (default 50 MB) and WAZUH_AUDIT_BACKUP_COUNT (default 7).
_AUDIT_MAX_BYTES:    int = int(os.getenv("WAZUH_AUDIT_MAX_BYTES",    str(50 * 1024 * 1024)))
_AUDIT_BACKUP_COUNT: int = int(os.getenv("WAZUH_AUDIT_BACKUP_COUNT", "7"))

# Optional HMAC signing key — set WAZUH_AUDIT_LOG_SIGNING_KEY to enable tamper detection.
_SIGNING_KEY: str = os.getenv("WAZUH_AUDIT_LOG_SIGNING_KEY", "")

if not _SIGNING_KEY:
    logging.getLogger("wazuh_mcp.audit").warning(
        "WAZUH_AUDIT_LOG_SIGNING_KEY is not set — audit records will be written "
        "WITHOUT HMAC signatures. Tamper detection is disabled. "
        "Set this env var to a random secret (e.g. `openssl rand -hex 32`) "
        "to enable integrity verification for compliance and forensic audit trails."
    )

# ── Rotating file handler (lazy-initialised on first write) ───────────────────
import threading as _threading
from logging.handlers import RotatingFileHandler as _RotatingFileHandler

_audit_handler: _RotatingFileHandler | None = None
_audit_handler_lock = _threading.Lock()


def _get_audit_handler() -> _RotatingFileHandler:
    """Return (or initialise) the module-level rotating file handler.

    Re-initialises if _AUDIT_LOG_PATH has changed (supports monkeypatching in tests).
    """
    global _audit_handler
    with _audit_handler_lock:
        current_path = str(_AUDIT_LOG_PATH)
        if _audit_handler is not None and _audit_handler.baseFilename == current_path:
            return _audit_handler
        # Path changed or first call — (re)create the handler.
        if _audit_handler is not None:
            try:
                _audit_handler.close()
            except Exception:
                pass
        _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        handler = _RotatingFileHandler(
            current_path,
            maxBytes=_AUDIT_MAX_BYTES,
            backupCount=_AUDIT_BACKUP_COUNT,
            encoding="utf-8",
        )
        _audit_handler = handler
        return handler


def _sign_record(record: dict) -> dict:
    """Append an HMAC-SHA256 signature to an audit record if a signing key is configured."""
    if not _SIGNING_KEY:
        return record
    import hmac as _hmac
    canonical = json.dumps(record, sort_keys=True, default=str)
    sig = _hmac.new(_SIGNING_KEY.encode(), canonical.encode(), "sha256").hexdigest()
    return {**record, "hmac": sig}


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
    """Append a JSONL record to the rotating audit log."""
    try:
        handler = _get_audit_handler()
        line = json.dumps(record, default=str) + "\n"
        encoded_len = len(line.encode("utf-8"))
        # Write directly to the handler's stream so we control exact byte layout.
        # Check for rollover manually — shouldRollover() requires a LogRecord object.
        handler.acquire()
        try:
            stream = handler.stream
            if handler.maxBytes > 0:
                stream.seek(0, 2)  # seek to end
                if stream.tell() + encoded_len >= handler.maxBytes:
                    handler.doRollover()
                    stream = handler.stream  # doRollover reopens a fresh stream
            stream.write(line)
            stream.flush()
        finally:
            handler.release()
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
        _write_record(_sign_record(record))
        return False  # never suppress exceptions


# Module-level singleton for import convenience.
audit_logger = AuditLogger()


def verify_audit_log_integrity(log_path: str | None = None) -> dict:
    """Verify HMAC signatures on every record in the audit log.

    Reads the log file line-by-line and re-computes each record's expected HMAC,
    then compares it to the stored value. Returns a summary of verified, tampered,
    and unsigned records.

    Only meaningful when WAZUH_AUDIT_LOG_SIGNING_KEY is configured.
    If no signing key is set, all records appear as 'unsigned' which is expected.

    log_path: path to the JSONL audit log (defaults to WAZUH_AUDIT_LOG env var).
    """
    import hmac as _hmac

    path = Path(log_path or str(_AUDIT_LOG_PATH))
    if not path.exists():
        return {"error": f"Audit log not found: {path}"}

    verified = 0
    tampered: list[dict] = []
    unsigned = 0
    unreadable = 0
    total = 0

    try:
        with path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    record = json.loads(line)
                except Exception:
                    unreadable += 1
                    continue

                stored_hmac = record.pop("hmac", None)
                if stored_hmac is None:
                    unsigned += 1
                    continue

                if not _SIGNING_KEY:
                    unsigned += 1
                    continue

                canonical = json.dumps(record, sort_keys=True, default=str)
                expected = _hmac.new(_SIGNING_KEY.encode(), canonical.encode(), "sha256").hexdigest()

                if _hmac.compare_digest(expected, stored_hmac):
                    verified += 1
                else:
                    tampered.append({
                        "line":    lineno,
                        "ts":      record.get("ts"),
                        "tool":    record.get("tool"),
                        "stored":  stored_hmac[:16] + "…",
                        "expected": expected[:16] + "…",
                    })
    except Exception as exc:
        return {"error": f"Failed to read audit log: {exc}"}

    return {
        "log_path":       str(path),
        "total_records":  total,
        "verified":       verified,
        "tampered":       len(tampered),
        "unsigned":       unsigned,
        "unreadable":     unreadable,
        "integrity":      "OK" if len(tampered) == 0 else "COMPROMISED",
        "tampered_records": tampered[:20],
        "note": (
            "Set WAZUH_AUDIT_LOG_SIGNING_KEY to enable HMAC signing. "
            "Without a signing key all records appear as 'unsigned' — this is expected."
        ) if not _SIGNING_KEY else None,
    }
