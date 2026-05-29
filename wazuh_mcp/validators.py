"""Input validation helpers for all MCP tool parameters.

Validates and sanitizes user-supplied parameters before they reach
Indexer queries or Manager API calls.
"""
from __future__ import annotations

import os
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
    """Validate a compliance framework name.

    Accepts both hyphenated and snake_case forms (e.g. 'PCI-DSS' or 'pci_dss').
    Always returns the canonical snake_case form used in Wazuh field names.
    """
    # Normalise: lowercase, replace hyphens with underscores
    normalized = value.strip().lower().replace("-", "_")
    # Map common aliases to canonical names
    _ALIASES = {
        "nist_800_53r4": "nist_800_53",
        "nist800_53": "nist_800_53",
        "pci_dss_v3": "pci_dss",
        "pci_dss_v4": "pci_dss",
    }
    normalized = _ALIASES.get(normalized, normalized)
    allowed = {"pci_dss", "hipaa", "gdpr", "nist_800_53", "tsc"}
    if normalized not in allowed:
        raise ValueError(
            f"Invalid {field} '{value}'. Must be one of: PCI-DSS, HIPAA, GDPR, NIST-800-53, TSC."
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


def validate_active_response_target(src_ip: str | None) -> str | None:
    """Return an error string if src_ip is in a protected CIDR range, else None.

    Blocks active responses targeting private RFC-1918 ranges, localhost,
    link-local, and any CIDRs listed in WAZUH_AR_BLOCKED_CIDRS (comma-separated).
    This prevents accidental self-inflicted outages (e.g. blocking 8.8.8.8 or
    a corporate gateway).

    Returns None when the target is safe to act on.
    """
    if not src_ip:
        return None

    # Parse the target — reject unparseable values
    try:
        addr = ipaddress.ip_address(src_ip.strip())
    except ValueError:
        return f"Invalid src_ip '{src_ip}': must be a valid IPv4 or IPv6 address."

    # Operator-defined never-block allowlist (Issue 6) — exact-match IPs.
    safe_ips = {ip.strip() for ip in os.getenv("WAZUH_MCP_AR_SAFE_IPS", "").split(",") if ip.strip()}
    if str(addr) in safe_ips or src_ip.strip() in safe_ips:
        return (
            f"Active response blocked: {src_ip} is in the WAZUH_MCP_AR_SAFE_IPS "
            f"never-block allowlist."
        )

    # Built-in protected networks (always blocked regardless of config)
    _BUILTIN_PROTECTED: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
        ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
        ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918
        ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918
        ipaddress.ip_network("127.0.0.0/8"),       # loopback
        ipaddress.ip_network("::1/128"),            # IPv6 loopback
        ipaddress.ip_network("169.254.0.0/16"),    # link-local
        ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
        ipaddress.ip_network("0.0.0.0/8"),          # "this" network
        ipaddress.ip_network("255.255.255.255/32"), # broadcast
    ]

    # Operator-supplied additional protected CIDRs
    _extra: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    raw_extra = os.getenv("WAZUH_AR_BLOCKED_CIDRS", "").strip()
    for cidr in raw_extra.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            _extra.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass  # ignore malformed env var entries

    for net in _BUILTIN_PROTECTED + _extra:
        if addr in net:
            return (
                f"Active response blocked: target IP {src_ip} falls within "
                f"protected range {net}. To override, remove the IP from "
                f"WAZUH_AR_BLOCKED_CIDRS or review the target."
            )
    return None


# Default allowlist of active-response command names. Override with
# WAZUH_MCP_AR_ALLOWED_COMMANDS (comma-separated). Commands outside this set are
# rejected before any PUT /active-response is issued (Issue 10).
_AR_DEFAULT_COMMANDS = "firewall-drop,restart-wazuh"


def ar_allowed_commands() -> set[str]:
    """Return the configured set of permitted active-response command names."""
    raw = os.getenv("WAZUH_MCP_AR_ALLOWED_COMMANDS", _AR_DEFAULT_COMMANDS)
    return {c.strip() for c in raw.split(",") if c.strip()}


def validate_ar_command(command: str) -> str | None:
    """Return an error string if *command* is not in the AR allowlist, else None."""
    allowed = ar_allowed_commands()
    name = (command or "").strip()
    if name not in allowed:
        return (
            f"Active-response command '{command}' is not allowed. "
            f"Permitted commands: {sorted(allowed)}. "
            f"Set WAZUH_MCP_AR_ALLOWED_COMMANDS to change this."
        )
    return None


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
