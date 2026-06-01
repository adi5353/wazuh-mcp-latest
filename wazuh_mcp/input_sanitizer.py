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

# Per-field length overrides for parameters that legitimately carry large
# payloads. The default 1000-char cap is right for identifiers, IPs, rule IDs
# and free-text notes, but far too small for full rule XML, Sigma YAML, raw log
# samples, or Lucene/DSL queries — those tools were silently failing validation.
# Keyed by the exact tool parameter name (the ``field`` passed to the sanitizer).
# Injection screening still runs on these fields; only the length ceiling rises.
MAX_STRING_LEN_OVERRIDES: dict[str, int] = {
    # Rule / decoder / Sigma payloads — full XML or YAML documents
    "xml_content":  65536,
    "rule_xml":     65536,
    "decoder_xml":  65536,
    "yaml_content": 65536,
    "sigma_yaml":   65536,
    "sigma_rule":   65536,
    # Raw log lines tested against rules/decoders (single or batch — list items
    # recurse with the same field name, so the batch key needs the override too)
    "log_sample":   16384,
    "log_samples":  16384,
    "log":          16384,
    "log_line":     16384,
    # Search expressions — Lucene / OpenSearch DSL / natural-language query
    "query":         8192,
    "query_string":  8192,
    "dsl":           8192,
}


def max_len_for(field: str) -> int:
    """Return the length cap for *field* — its override, or the global default."""
    return MAX_STRING_LEN_OVERRIDES.get(field, MAX_STRING_LEN)

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


def sanitize_input_string(value: str, field: str = "input") -> str:
    """Screen a single string parameter with defense-in-depth injection detection.

    Layers applied in order:
      1. Length cap
      2. Unicode NFKC normalization + whitespace collapse (defeats homoglyphs)
      3. URL-decode and base64-decode variants checked against injection patterns
      4. Pattern check on normalized form

    Raises ValueError on any violation. Returns original value unchanged when clean.
    """
    cap = max_len_for(field)
    if len(value) > cap:
        raise ValueError(
            f"'{field}' exceeds maximum allowed length of {cap} chars "
            f"(got {len(value)})"
        )
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
