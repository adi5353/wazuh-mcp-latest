"""Automatic input sanitization for all MCP tool parameters.

Every string/list/dict parameter passed to any MCP tool is screened
before the tool function body runs. Raises ValueError for any input
that contains injection patterns, exceeds size limits, or carries
dangerous characters that could escape into Wazuh API calls or
active-response commands.
"""
from __future__ import annotations

import re
from typing import Any

# ── Hard limits ───────────────────────────────────────────────────────────────
MAX_STRING_LEN: int = 1000   # per-parameter string length cap
MAX_LIST_ITEMS: int = 200    # per-parameter list length cap
MAX_DICT_KEYS:  int = 50     # nested dict key count cap

# ── Patterns rejected in all tool string inputs ───────────────────────────────
# Each entry is (compiled_pattern, human_readable_label).
_INJECTION_CHECKS: list[tuple[re.Pattern, str]] = [
    # LLM boundary / prompt-override tokens
    (re.compile(r"</?system[^>]*>",  re.IGNORECASE), "LLM boundary tag"),
    (re.compile(r"</?claude[^>]*>",  re.IGNORECASE), "LLM boundary tag"),
    (re.compile(r"\[/?INST\]",       re.IGNORECASE), "LLM instruction token"),
    (re.compile(r"<</?SYS>>",        re.IGNORECASE), "LLM system token"),
    (re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions?"),
     "prompt override attempt"),
    (re.compile(r"(?i)your\s+(new\s+)?instructions?\s+(are|is)\s*:"),
     "prompt override attempt"),
    (re.compile(
        r"(?i)act\s+as\s+(if\s+you\s+are|an?\s+)?(?:unrestricted|jailbreak|DAN)"),
     "jailbreak attempt"),
    # Shell metacharacters that could escape into active-response CLI calls
    (re.compile(r"[;\|&`]"),         "shell metacharacter"),
    # Template / expression injection
    (re.compile(r"\$\{[^}]*\}"),     "template injection"),
    (re.compile(r"\{\{[^}]*\}\}"),   "template injection"),
    # Path traversal
    (re.compile(r"\.\./|\.\.\\"),    "path traversal"),
    # SQL / command injection keywords
    (re.compile(
        r"(?i)\b(union\s+select|drop\s+table|insert\s+into|exec\s*\(|xp_cmdshell)\b"),
     "SQL/command injection"),
]


def sanitize_input_string(value: str, field: str = "input") -> str:
    """Screen a single string parameter.

    Raises ValueError if the value exceeds the length cap or matches
    any injection pattern.  Returns the original value unchanged when
    all checks pass — no silent mutation of caller-provided data.
    """
    if len(value) > MAX_STRING_LEN:
        raise ValueError(
            f"'{field}' exceeds maximum allowed length of {MAX_STRING_LEN} chars "
            f"(got {len(value)})"
        )
    for pattern, label in _INJECTION_CHECKS:
        if pattern.search(value):
            raise ValueError(f"'{field}' contains disallowed pattern: {label}")
    return value


def sanitize_input_value(value: Any, field: str = "input") -> Any:
    """Recursively sanitize an arbitrary input value.

    - str        → length + injection check
    - list       → size check + recurse into items
    - dict       → key count check + recurse into values
    - int/float/bool/None → pass through unchanged (safe primitives)
    """
    if isinstance(value, str):
        return sanitize_input_string(value, field)
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise ValueError(
                f"'{field}' list exceeds maximum of {MAX_LIST_ITEMS} items "
                f"(got {len(value)})"
            )
        return [sanitize_input_value(item, field) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_DICT_KEYS:
            raise ValueError(
                f"'{field}' dict exceeds maximum of {MAX_DICT_KEYS} keys "
                f"(got {len(value)})"
            )
        return {k: sanitize_input_value(v, k) for k, v in value.items()}
    return value
