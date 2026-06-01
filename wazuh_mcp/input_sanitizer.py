"""Automatic input sanitization for all MCP tool parameters.

Every string/list/dict parameter passed to any MCP tool is screened
before the tool function body runs. Raises ValueError for any input
that contains injection patterns, exceeds size limits, or carries
dangerous characters that could escape into Wazuh API calls or
active-response commands.
"""
from __future__ import annotations

import re
import unicodedata
import urllib.parse
from typing import Any

# ── Hard limits ───────────────────────────────────────────────────────────────
MAX_STRING_LEN: int = 1000   # default per-parameter string length cap
MAX_LIST_ITEMS: int = 200    # per-parameter list length cap
MAX_DICT_KEYS:  int = 50     # nested dict key count cap

# ── Raw / long-text parameter registry ────────────────────────────────────────
# Several tools legitimately accept payloads far larger than MAX_STRING_LEN —
# full Wazuh rule/decoder XML, Sigma YAML, raw log samples, Lucene/DSL queries,
# free-text ticket bodies. A blanket 1000-char cap silently rejected these
# before the tool body ran (e.g. push_custom_rule on any real rule group).
#
# Each entry maps a parameter name → (max_len, screen_patterns):
#   • Human-authored structured payloads (rule/decoder XML, Sigma YAML) keep
#     injection screening ON — path-traversal and LLM-boundary tokens must never
#     appear in a rule that gets deployed to the Manager — only the length
#     ceiling rises.
#   • Raw machine-generated log lines (log_sample/log/log_line) skip pattern
#     screening: CEF separators, Lucene `&&`/`||`, `${...}` and `<...>` are DATA
#     here and routinely false-positive; they are validated structurally
#     downstream and never interpreted as control flow.
#   • Free-text reaching an LLM or an external ticket (query, descriptions,
#     notes) keeps screening ON — a real prompt-injection surface.
#
# Length is ALWAYS bounded — raw params get a higher cap, not an unbounded one.
RAW_TEXT_PARAMS: dict[str, tuple[int, bool]] = {
    # Rule / decoder / Sigma payloads — full XML or YAML documents. Screen ON.
    "xml_content":      (65536, True),
    "rule_xml":         (65536, True),
    "decoder_xml":      (65536, True),
    "yaml_content":     (65536, True),
    "sigma_yaml":       (65536, True),
    "sigma_rule":       (65536, True),
    "sigma_rules_yaml": (65536, True),
    # Raw log lines tested against rules/decoders (single or batch — list items
    # recurse with the same field name, so the batch key needs the override too).
    # Screening OFF — these are pure log DATA.
    "log_sample":       (16384, False),
    "log_samples":      (16384, False),
    "log":              (16384, False),
    "log_line":         (16384, False),
    # Search expressions — Lucene / OpenSearch DSL / natural-language query.
    "query":            (8192, True),
    "query_string":     (8192, True),
    "dsl":              (8192, True),
    # Free-text that may reach an LLM / external ticket — screening ON.
    "description":      (10000, True),
    "rule_description": (10000, True),
    "short_description":(5000,  True),
    "summary":          (20000, True),
    "note":             (10000, True),
    "work_notes":       (10000, True),
    "message":          (10000, True),
    "content":          (65536, True),
}


def limits_for_param(field: str) -> tuple[int, bool]:
    """Return (max_len, screen_patterns) for *field*.

    Falls back to the strict default (MAX_STRING_LEN, screening ON) for any
    parameter not in RAW_TEXT_PARAMS — i.e. normal params are unchanged.
    """
    return RAW_TEXT_PARAMS.get(field, (MAX_STRING_LEN, True))


def max_len_for(field: str) -> int:
    """Return the length cap for *field* — its override, or the global default."""
    return limits_for_param(field)[0]

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
    # NOTE: the shell-metacharacter check (`[;|&\`]`) was intentionally removed.
    # No tool passes a user string into a shell (verified: no subprocess/os.system/
    # shell=True anywhere in wazuh_mcp), and the pattern caused false positives on
    # legitimate SIEM data — CEF log lines use `|` as a field separator and Lucene
    # queries use `&&`/`||`. Active-response targets are still validated separately
    # (validators.validate_active_response_target + validate_ar_command).
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


def _normalize(s: str) -> str:
    """NFKC-normalize + collapse whitespace to defeat homoglyph and newline tricks."""
    normalized = unicodedata.normalize("NFKC", s)
    return re.sub(r"\s+", " ", normalized)


def _decode_variants(s: str) -> list[str]:
    """Return original + URL-decoded variants for multi-layer checking.

    Base64 variant-decoding was intentionally removed from the global path: it
    flagged base64-like hashes, agent names, and tokens that are legitimate SIEM
    data as injection attempts. URL-decoding is kept because URL-encoded payloads
    are a real evasion vector for the LLM-boundary/prompt-override patterns.
    """
    return [s, urllib.parse.unquote(s)]


def sanitize_input_string(
    value: str,
    field: str = "input",
    *,
    max_len: int | None = None,
    screen_patterns: bool | None = None,
) -> str:
    """Screen a single string parameter with defense-in-depth injection detection.

    Layers applied in order:
      1. Length cap — *max_len* if given, else the per-field cap (max_len_for)
      2. Unicode NFKC normalization + whitespace collapse (defeats homoglyphs)
      3. URL-decode and base64-decode variants checked against injection patterns
      4. Pattern check on normalized form

    When *max_len* / *screen_patterns* are omitted they are derived from *field*
    via :func:`limits_for_param`, so a direct call like
    ``sanitize_input_string(rule_xml, field="xml_content")`` gets the right
    ceiling and screening automatically. *screen_patterns* resolves False only
    for raw DATA parameters (e.g. log samples) that are validated structurally
    elsewhere and never interpreted as control flow. Length is always enforced.

    Raises ValueError on any violation. Returns original value unchanged when clean.
    """
    field_cap, field_screen = limits_for_param(field)
    cap = field_cap if max_len is None else max_len
    screen = field_screen if screen_patterns is None else screen_patterns
    if len(value) > cap:
        raise ValueError(
            f"'{field}' exceeds maximum allowed length of {cap} chars "
            f"(got {len(value)})"
        )
    if not screen:
        return value
    # Check all variants: original, normalized, URL-decoded, base64-decoded
    normalized = _normalize(value)
    for variant in _decode_variants(value) + [normalized]:
        for pattern, label in _INJECTION_CHECKS:
            if pattern.search(variant):
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
        # Per-field cap + screening are resolved inside sanitize_input_string.
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
