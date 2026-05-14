"""Payload trim helpers — keep MCP responses small enough not to blow LLM context."""
from __future__ import annotations


def trim_alert(hit: dict) -> dict:
    """Strip a raw alert document down to the fields useful for triage."""
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    data = src.get("data", {})
    return {
        "id": hit.get("_id"),
        "timestamp": src.get("@timestamp") or src.get("timestamp"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule.get("groups", []),
        "mitre": rule.get("mitre", {}),
        "location": src.get("location"),
        "srcip": data.get("srcip"),
        "dstip": data.get("dstip"),
        "user": data.get("dstuser") or data.get("srcuser"),
        "decoder": (src.get("decoder") or {}).get("name"),
        "log_snippet": (src.get("full_log") or "")[:500],
    }


def trim_vuln(hit: dict) -> dict:
    """Strip a vulnerability state document to triage-relevant fields."""
    src = hit.get("_source", {})
    v = src.get("vulnerability", {})
    p = src.get("package", {})
    a = src.get("agent", {})
    return {
        "agent_id": a.get("id"),
        "agent_name": a.get("name"),
        "cve": v.get("id"),
        "severity": v.get("severity"),
        "cvss_score": (v.get("score") or {}).get("base"),
        "cvss_version": (v.get("score") or {}).get("version"),
        "package": p.get("name"),
        "installed_version": p.get("version"),
        "published": v.get("published_at"),
        "detected": v.get("detected_at"),
        "reference": v.get("reference"),
    }


def severities_at_or_above(min_severity: str) -> list[str]:
    """Return all severities at or above the given level (Critical > High > Medium > Low)."""
    order = ["Critical", "High", "Medium", "Low"]
    if min_severity not in order:
        return order
    return order[: order.index(min_severity) + 1]


def time_window(start: str, end: str | None = None) -> dict:
    """Build an @timestamp range filter from OpenSearch date-math strings.

    Examples:
        time_window("now-7d")                  -> last 7 days up to now
        time_window("now-14d", "now-7d")       -> the 7-day window 14d..7d ago
    """
    rng: dict = {"gte": start}
    if end:
        rng["lt"] = end
    return {"range": {"@timestamp": rng}}
