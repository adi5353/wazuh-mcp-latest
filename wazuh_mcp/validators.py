"""Input validation helpers for all MCP tool parameters.

Validates and sanitizes user-supplied parameters before they reach
Indexer queries or Manager API calls.
"""
from __future__ import annotations

import re
import ipaddress
from typing import Any


# ── Patterns ──────────────────────────────────────────────────────────────────

_TIME_RANGE_RE = re.compile(r"^\d+[smhdwMy]$")          # e.g. 24h, 7d, 30m
_AGENT_ID_RE   = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")  # alphanumeric + - _
_RULE_ID_RE    = re.compile(r"^\d{1,6}$")                # 1-6 digit integer
_CVE_ID_RE     = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_INDEX_PAT_RE  = re.compile(r"^[a-zA-Z0-9_\-\*\.]+$")   # safe index pattern

_DANGEROUS_CHARS = re.compile(r"[;\|&`$<>()\{\}]")       # shell / query injection chars


# ── Public validators — raise ValueError on bad input ─────────────────────────

def validate_time_range(value: str, field: str = "time_range") -> str:
    """Validate Elasticsearch relative time range like '24h', '7d', '30m'."""
    value = value.strip()
    if not _TIME_RANGE_RE.match(value):
        raise ValueError(
            f"Invalid {field} '{value}'. Expected format: <number><unit> "
            "where unit is s/m/h/d/w/M/y (e.g. '24h', '7d')."
        )
    return value


def validate_agent_id(value: str, field: str = "agent_id") -> str:
    """Validate Wazuh agent ID (alphanumeric, dashes, underscores, max 64 chars)."""
    value = value.strip()
    if not _AGENT_ID_RE.match(value):
        raise ValueError(
            f"Invalid {field} '{value}'. Must be alphanumeric with optional - or _ (max 64 chars)."
        )
    return value


def validate_rule_id(value: str | int, field: str = "rule_id") -> str:
    """Validate Wazuh rule ID (1–6 digit integer)."""
    value = str(value).strip()
    if not _RULE_ID_RE.match(value):
        raise ValueError(
            f"Invalid {field} '{value}'. Must be a numeric rule ID (1–6 digits)."
        )
    return value


def validate_ip_address(value: str, field: str = "ip") -> str:
    """Validate a single IPv4 or IPv6 address."""
    value = value.strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"Invalid {field} '{value}'. Must be a valid IPv4 or IPv6 address.")
    return value


def validate_ip_list(values: list[str], field: str = "ips", max_count: int = 50) -> list[str]:
    """Validate a list of IP addresses."""
    if len(values) > max_count:
        raise ValueError(f"{field} list exceeds maximum of {max_count} entries.")
    return [validate_ip_address(v, field) for v in values]


def validate_cve_id(value: str, field: str = "cve_id") -> str:
    """Validate a CVE identifier like 'CVE-2021-44228'."""
    value = value.strip()
    if not _CVE_ID_RE.match(value):
        raise ValueError(
            f"Invalid {field} '{value}'. Must match CVE-YYYY-NNNNN format."
        )
    return value.upper()


def validate_min_level(value: int, field: str = "min_level") -> int:
    """Validate Wazuh alert severity level (1–15)."""
    if not isinstance(value, int) or not (1 <= value <= 15):
        raise ValueError(f"Invalid {field} '{value}'. Must be an integer between 1 and 15.")
    return value


def validate_limit(value: int, field: str = "limit", max_val: int = 500) -> int:
    """Validate a pagination limit."""
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"Invalid {field} '{value}'. Must be a positive integer.")
    return min(value, max_val)


def validate_free_text(value: str, field: str = "query", max_len: int = 500) -> str:
    """Sanitize a free-text search string — strip dangerous shell/injection chars."""
    if len(value) > max_len:
        raise ValueError(f"{field} exceeds maximum length of {max_len} characters.")
    sanitized = _DANGEROUS_CHARS.sub("", value)
    return sanitized.strip()


def validate_index_pattern(value: str, field: str = "index") -> str:
    """Validate an Elasticsearch index pattern."""
    value = value.strip()
    if not _INDEX_PAT_RE.match(value):
        raise ValueError(
            f"Invalid {field} '{value}'. Index patterns may only contain "
            "alphanumerics, -, _, *, and ."
        )
    return value


def validate_severity(value: str, field: str = "severity") -> str:
    """Validate a vulnerability severity label."""
    allowed = {"critical", "high", "medium", "low", "none"}
    normalized = value.strip().lower()
    if normalized not in allowed:
        raise ValueError(
            f"Invalid {field} '{value}'. Must be one of: Critical, High, Medium, Low, None."
        )
    return normalized.capitalize()


def validate_framework(value: str, field: str = "framework") -> str:
    """Validate a compliance framework name."""
    allowed = {"pci_dss", "hipaa", "gdpr", "nist_800_53", "tsc"}
    normalized = value.strip().lower()
    if normalized not in allowed:
        raise ValueError(
            f"Invalid {field} '{value}'. Must be one of: {', '.join(sorted(allowed))}."
        )
    return normalized


# ── Convenience wrapper ───────────────────────────────────────────────────────

def validate_offset(value: int, field: str = "offset") -> int:
    """Validate a pagination offset (non-negative integer)."""
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"Invalid {field} '{value}'. Must be a non-negative integer.")
    return value


# ── Elasticsearch DSL field / value allow-lists ───────────────────────────────

_ALLOWED_ES_FIELDS = {
    # Alert fields
    "@timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
    "rule.mitre.id", "rule.mitre.tactic", "rule.pci_dss", "rule.hipaa",
    "rule.gdpr", "rule.nist_800_53", "rule.tsc",
    "agent.id", "agent.name", "agent.ip",
    "data.srcip", "data.dstip", "data.srcuser", "data.dstuser",
    "data.win.system.eventID", "location", "full_log", "decoder.name",
    # Vulnerability fields
    "vulnerability.id", "vulnerability.severity", "vulnerability.score.base",
    "package.name", "package.version",
    # FIM fields
    "syscheck.path", "syscheck.event", "syscheck.md5_after", "syscheck.sha256_after",
    # SCA fields
    "data.sca.policy_id", "data.sca.check.result", "data.sca.check.id",
}

_ES_VALUE_MAX_LEN = 256


def validate_es_field(field: str) -> str:
    """Validate that an Elasticsearch field name is in the allow-list.

    Prevents users from querying arbitrary internal or sensitive fields.
    """
    if field not in _ALLOWED_ES_FIELDS:
        raise ValueError(
            f"Field '{field}' is not permitted in queries. "
            f"Allowed fields: {sorted(_ALLOWED_ES_FIELDS)}"
        )
    return field


def validate_es_value(value: str, field: str = "value") -> str:
    """Validate an Elasticsearch query value.

    Strips dangerous regex / query-string metacharacters and enforces
    a length cap to prevent query bloat.
    """
    if len(value) > _ES_VALUE_MAX_LEN:
        raise ValueError(
            f"Query value for '{field}' exceeds maximum length of {_ES_VALUE_MAX_LEN} chars."
        )
    # Strip characters that could manipulate query_string or regex queries
    cleaned = re.sub(r'[/\\^${}()\[\]+?]', "", value)
    return cleaned.strip()


def validation_error(field: str, message: str) -> dict:
    """Return a standardised error dict for MCP tool responses."""
    return {"error": f"Validation error on '{field}': {message}"}


def safe_validate(fn, *args, **kwargs) -> tuple[Any, dict | None]:
    """
    Call a validator safely; return (result, None) on success or
    (None, error_dict) on failure — lets tools return early cleanly.

    Example::
        value, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
    """
    try:
        return fn(*args, **kwargs), None
    except ValueError as exc:
        parts = str(exc).split("'", 2)
        field = parts[1] if len(parts) >= 2 else "input"
        return None, validation_error(field, str(exc))
