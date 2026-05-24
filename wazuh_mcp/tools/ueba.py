"""User Entity Behavior Analytics (UEBA) — F3.

Tracks per-user login patterns, privilege escalation, and cross-agent activity.
Correlates authentication events across all agents by username to detect
credential-based attacks (T1078) invisible to per-agent rules.

Tools: get_user_activity_profile, detect_user_anomalies, list_privileged_escalations
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

log = logging.getLogger("wazuh-mcp")


async def _query_auth_events(idx, username: str, hours: int) -> list[dict]:
    """Fetch authentication events for a username across all agents."""
    now = datetime.now(timezone.utc)
    gte = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = {
        "size": 500,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": gte}}},
                    {"bool": {"should": [
                        {"term": {"data.dstuser": username}},
                        {"term": {"data.srcuser": username}},
                        {"wildcard": {"data.win.eventdata.targetUserName": username}},
                    ], "minimum_should_match": 1}},
                    {"bool": {"should": [
                        {"terms": {"rule.groups": [
                            "authentication_success", "authentication_failed",
                            "login", "sudo", "syslog",
                        ]}},
                    ], "minimum_should_match": 1}},
                ]
            }
        },
        "_source": [
            "@timestamp", "agent.id", "agent.name", "agent.ip",
            "data.srcip", "data.srcuser", "data.dstuser", "data.protocol",
            "rule.id", "rule.level", "rule.description", "rule.groups",
            "data.win.eventdata.logonType",
        ],
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    try:
        raw = await idx.search("wazuh-alerts-*", query)
        return [(h.get("_source") or {}) for h in (raw.get("hits") or {}).get("hits") or []]
    except Exception as exc:
        log.debug("UEBA auth query error: %s", exc)
        return []


async def _query_privilege_escalations(idx, hours: int, limit: int = 200) -> list[dict]:
    """Fetch privilege escalation events across all users."""
    now = datetime.now(timezone.utc)
    gte = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = {
        "size": limit,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": gte}}},
                    {"bool": {"should": [
                        {"terms": {"rule.groups": ["sudo", "su", "privilege_escalation"]}},
                        {"match": {"rule.description": "privilege"}},
                        {"range": {"rule.level": {"gte": 10}}},
                    ], "minimum_should_match": 1}},
                ]
            }
        },
        "_source": [
            "@timestamp", "agent.id", "agent.name",
            "data.srcuser", "data.dstuser", "data.srcip",
            "rule.id", "rule.level", "rule.description",
        ],
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    try:
        raw = await idx.search("wazuh-alerts-*", query)
        return [(h.get("_source") or {}) for h in (raw.get("hits") or {}).get("hits") or []]
    except Exception as exc:
        log.debug("UEBA escalation query error: %s", exc)
        return []


def _analyse_activity(events: list[dict], username: str) -> dict:
    """Derive behavioral patterns from a list of authentication events."""
    agents_seen: set[str] = set()
    source_ips: set[str] = set()
    success_count = 0
    failure_count = 0
    hour_buckets: dict[int, int] = defaultdict(int)
    agents_detail: dict[str, dict] = {}

    for ev in events:
        agent_name = (ev.get("agent") or {}).get("name", "")
        agent_id = (ev.get("agent") or {}).get("id", "")
        if agent_name:
            agents_seen.add(agent_name)
        src_ip = ev.get("data", {}).get("srcip", "")
        if src_ip and src_ip not in ("::1", "127.0.0.1"):
            source_ips.add(src_ip)

        groups = ev.get("rule", {}).get("groups") or []
        if "authentication_success" in groups or "login" in groups:
            success_count += 1
        if "authentication_failed" in groups:
            failure_count += 1

        ts = ev.get("@timestamp", "")
        if ts:
            try:
                hour = int(ts[11:13])
                hour_buckets[hour] += 1
            except (ValueError, IndexError):
                pass

        if agent_id and agent_id not in agents_detail:
            agents_detail[agent_id] = {
                "agent_id": agent_id,
                "agent_name": agent_name,
                "event_count": 0,
            }
        if agent_id:
            agents_detail[agent_id]["event_count"] += 1

    # Peak activity hours
    peak_hours = sorted(hour_buckets.items(), key=lambda x: x[1], reverse=True)[:3]

    risk_factors = []
    if len(agents_seen) >= 5:
        risk_factors.append(f"Activity on {len(agents_seen)} agents — potential lateral movement")
    if failure_count > success_count * 2 and failure_count > 5:
        risk_factors.append(f"High failure rate ({failure_count} failures vs {success_count} successes)")
    if len(source_ips) >= 3:
        risk_factors.append(f"Login from {len(source_ips)} distinct source IPs")

    return {
        "username": username,
        "total_events": len(events),
        "agents_active_on": sorted(agents_seen),
        "distinct_source_ips": sorted(source_ips),
        "authentication_successes": success_count,
        "authentication_failures": failure_count,
        "peak_activity_hours": [{"hour": h, "event_count": c} for h, c in peak_hours],
        "per_agent": list(agents_detail.values()),
        "risk_factors": risk_factors,
        "risk_level": (
            "high" if len(risk_factors) >= 2
            else "medium" if len(risk_factors) == 1
            else "low"
        ),
    }


def register(mcp, wz, idx, cfg, _cap):

    @mcp.tool()
    async def get_user_activity_profile(username: str, hours: int = 24) -> dict:
        """Build a cross-agent activity profile for a specific user.

        Aggregates authentication and login events for the username across
        ALL Wazuh agents to reveal multi-agent lateral movement patterns
        invisible to per-agent alerting.

        username: OS username to profile (e.g. 'admin', 'john.doe')
        hours: look-back window in hours (default 24)
        """
        events = await _query_auth_events(idx, username, hours)
        if not events:
            return {
                "username": username,
                "hours": hours,
                "total_events": 0,
                "message": "No authentication events found for this user in the time window.",
            }

        profile = _analyse_activity(events, username)
        profile["time_window_hours"] = hours
        profile["generated_at"] = datetime.now(timezone.utc).isoformat()
        return profile

    @mcp.tool()
    async def detect_user_anomalies(hours: int = 24, min_agents: int = 3) -> dict:
        """Detect users exhibiting cross-agent anomalous behavior.

        Finds users active on multiple agents (lateral movement indicator),
        with high failure rates (brute-force indicator), or logging in from
        multiple source IPs simultaneously.

        hours: look-back window (default 24h)
        min_agents: minimum agents for a user to be flagged (default 3)
        """
        now = datetime.now(timezone.utc)
        gte = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": gte}}},
                        {"bool": {"should": [
                            {"terms": {"rule.groups": [
                                "authentication_success", "authentication_failed",
                                "login", "sudo",
                            ]}},
                        ], "minimum_should_match": 1}},
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "data.dstuser", "size": 100},
                    "aggs": {
                        "agents": {"cardinality": {"field": "agent.id"}},
                        "failures": {
                            "filter": {"terms": {"rule.groups": ["authentication_failed"]}},
                        },
                        "source_ips": {"cardinality": {"field": "data.srcip"}},
                    },
                }
            },
        }
        try:
            raw = await idx.search("wazuh-alerts-*", query)
        except Exception as exc:
            return {"error": f"Indexer query failed: {exc}"}

        buckets = ((raw.get("aggregations") or {}).get("by_user") or {}).get("buckets") or []

        anomalous = []
        for b in buckets:
            user = b.get("key", "")
            if not user or user in ("-", "SYSTEM", "root"):
                continue
            agent_count = b.get("agents", {}).get("value", 0)
            event_count = b.get("doc_count", 0)
            failure_count = b.get("failures", {}).get("doc_count", 0)
            ip_count = b.get("source_ips", {}).get("value", 0)

            flags = []
            if agent_count >= min_agents:
                flags.append(f"Active on {agent_count} agents (lateral movement risk)")
            if failure_count > 10 and failure_count > event_count * 0.5:
                flags.append(f"High failure rate ({failure_count}/{event_count})")
            if ip_count >= 3:
                flags.append(f"Login from {ip_count} distinct IPs")

            if flags:
                anomalous.append({
                    "username": user,
                    "agents_active_on": agent_count,
                    "total_events": event_count,
                    "authentication_failures": failure_count,
                    "distinct_source_ips": ip_count,
                    "anomaly_flags": flags,
                    "risk_level": "high" if len(flags) >= 2 else "medium",
                })

        anomalous.sort(key=lambda x: len(x["anomaly_flags"]), reverse=True)

        return {
            "time_window_hours": hours,
            "users_analyzed": len(buckets),
            "anomalous_users": len(anomalous),
            "results": anomalous[:20],
            "severity": "critical" if anomalous else "none",
            "tip": "Run get_user_activity_profile(username) for full detail on any flagged user.",
        }

    @mcp.tool()
    async def list_privileged_escalations(hours: int = 24, limit: int = 50) -> dict:
        """List privilege escalation events (sudo, su, UAC) across all agents.

        Groups escalations by user and agent to surface accounts accumulating
        elevated access — a key indicator of insider threat or compromised creds.

        hours: look-back window (default 24h)
        limit: maximum events to return (default 50)
        """
        events = await _query_privilege_escalations(idx, hours, min(200, limit * 4))

        # Group by user
        by_user: dict[str, list[dict]] = defaultdict(list)
        for ev in events:
            user = (ev.get("data") or {}).get("dstuser") or (ev.get("data") or {}).get("srcuser") or "unknown"
            by_user[user].append(ev)

        summary = []
        for user, evs in sorted(by_user.items(), key=lambda x: len(x[1]), reverse=True):
            agents = {(e.get("agent") or {}).get("name", "") for e in evs}
            levels = [e.get("rule", {}).get("level", 0) for e in evs]
            summary.append({
                "username": user,
                "escalation_count": len(evs),
                "agents": sorted(agents),
                "max_rule_level": max(levels) if levels else 0,
                "recent_events": evs[:3],
            })

        return {
            "time_window_hours": hours,
            "total_escalation_events": len(events),
            "unique_users": len(by_user),
            "by_user": summary[:20],
            "severity": "high" if any(s["escalation_count"] > 5 for s in summary) else
                        "medium" if summary else "none",
        }
