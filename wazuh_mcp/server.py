"""Wazuh MCP Server — exposes Wazuh manager + indexer capabilities as MCP tools.

Logging note: in STDIO mode, never print() to stdout — it corrupts the JSON-RPC stream.
The logging module below is configured to write to stderr.
"""
from __future__ import annotations
import asyncio
import datetime
import logging
import os
import sys

import httpx
from mcp.server.fastmcp import FastMCP

from .config import Config
from .helpers import trim_alert, trim_vuln, severities_at_or_above, time_window
from .wazuh_client import WazuhClient
from .wazuh_indexer import WazuhIndexer

# Configure logging to stderr — safe for STDIO transport.
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("wazuh-mcp")

cfg = Config.from_env()
wz = WazuhClient(cfg)
idx = WazuhIndexer(cfg)

mcp = FastMCP("wazuh")


def _require_writes() -> dict | None:
    """Return an error dict if writes are disabled, else None."""
    if not cfg.allow_writes:
        return {
            "error": "Write operations are disabled. "
                     "Set WAZUH_ALLOW_WRITES=true to enable destructive tools."
        }
    return None


# ============================================================================
# Manager API tools — agents and operational state
# ============================================================================

@mcp.tool()
async def list_agents(status: str = "active", limit: int = 50) -> dict:
    """List Wazuh agents filtered by status.

    status: active | disconnected | pending | never_connected
    """
    return await wz.request("GET", f"/agents?status={status}&limit={limit}")


@mcp.tool()
async def get_agent(agent_id: str) -> dict:
    """Get detailed info for a single agent by its ID (e.g. '001')."""
    return await wz.request("GET", f"/agents?agents_list={agent_id}")


@mcp.tool()
async def restart_agent(agent_id: str) -> dict:
    """Restart a Wazuh agent. Destructive — requires WAZUH_ALLOW_WRITES=true."""
    blocked = _require_writes()
    if blocked:
        return blocked
    return await wz.request("PUT", f"/agents/{agent_id}/restart")


@mcp.tool()
async def run_active_response(
    agent_id: str, command: str, arguments: list | None = None
) -> dict:
    """Trigger an active response command on an agent (e.g. firewall-drop).
    Destructive — requires WAZUH_ALLOW_WRITES=true.
    """
    blocked = _require_writes()
    if blocked:
        return blocked
    body = {"command": command, "arguments": arguments or [], "alert": {}}
    return await wz.request(
        "PUT", f"/active-response?agents_list={agent_id}", json=body
    )


# ============================================================================
# Indexer tools — alerts
# ============================================================================

@mcp.tool()
async def alert_summary(time_range: str = "24h", min_level: int = 7) -> dict:
    """Aggregated summary of alerts over a time window — counts by rule, agent, MITRE.

    Call this BEFORE search_alerts for broad questions like 'what happened today'.
    Returns aggregations only, not raw alerts — much smaller payload.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        },
        "aggs": {
            "by_level": {"terms": {"field": "rule.level", "size": 20}},
            "top_rules": {
                "terms": {"field": "rule.id", "size": 10},
                "aggs": {
                    "detail": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["rule.description", "rule.level"],
                        }
                    }
                },
            },
            "top_agents": {"terms": {"field": "agent.name", "size": 10}},
            "top_mitre": {"terms": {"field": "rule.mitre.id", "size": 10}},
            "top_groups": {"terms": {"field": "rule.groups", "size": 15}},
        },
    }
    res = await idx.search(body)
    aggs = res["aggregations"]
    return {
        "time_range": time_range,
        "total_alerts": res["hits"]["total"]["value"],
        "by_level": [
            {"level": b["key"], "count": b["doc_count"]}
            for b in aggs["by_level"]["buckets"]
        ],
        "top_rules": [
            {
                "rule_id": b["key"],
                "count": b["doc_count"],
                "description": b["detail"]["hits"]["hits"][0]["_source"]["rule"]["description"],
                "level": b["detail"]["hits"]["hits"][0]["_source"]["rule"]["level"],
            }
            for b in aggs["top_rules"]["buckets"]
        ],
        "top_agents": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in aggs["top_agents"]["buckets"]
        ],
        "top_mitre_techniques": [
            {"technique": b["key"], "count": b["doc_count"]}
            for b in aggs["top_mitre"]["buckets"]
        ],
        "top_rule_groups": [
            {"group": b["key"], "count": b["doc_count"]}
            for b in aggs["top_groups"]["buckets"]
        ],
    }


@mcp.tool()
async def search_alerts(
    time_range: str = "24h",
    min_level: int = 7,
    agent_id: str | None = None,
    rule_groups: list | None = None,
    limit: int = 50,
) -> dict:
    """Search Wazuh alerts in the Indexer.

    time_range: relative time like '15m', '1h', '24h', '7d'
    min_level: minimum rule level (default 7)
    agent_id: optional agent filter
    rule_groups: optional rule-group filter (e.g. ['authentication_failed', 'ssh'])
    """
    filters = [
        {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]
    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})
    if rule_groups:
        filters.append({"terms": {"rule.groups": rule_groups}})

    body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": filters}},
    }
    res = await idx.search(body)
    return {
        "total": res["hits"]["total"]["value"],
        "alerts": [trim_alert(h) for h in res["hits"]["hits"]],
    }


@mcp.tool()
async def search_by_mitre(
    technique_id: str, time_range: str = "7d", limit: int = 50
) -> dict:
    """Find alerts mapped to a specific MITRE ATT&CK technique.

    technique_id: e.g. 'T1110' (brute force), 'T1059' (command interpreter)
    """
    body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"rule.mitre.id": technique_id}},
                ]
            }
        },
    }
    res = await idx.search(body)
    return {
        "technique": technique_id,
        "total": res["hits"]["total"]["value"],
        "alerts": [trim_alert(h) for h in res["hits"]["hits"]],
    }


@mcp.tool()
async def search_by_source_ip(
    src_ip: str, time_range: str = "7d", limit: int = 100
) -> dict:
    """Find all alerts originating from a specific source IP. Useful for IoC pivoting."""
    body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"data.srcip": src_ip}},
                ]
            }
        },
        "aggs": {
            "targeted_agents": {"terms": {"field": "agent.name", "size": 20}},
            "rules_triggered": {"terms": {"field": "rule.id", "size": 20}},
        },
    }
    res = await idx.search(body)
    return {
        "src_ip": src_ip,
        "total": res["hits"]["total"]["value"],
        "targeted_agents": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["targeted_agents"]["buckets"]
        ],
        "rules_triggered": [
            {"rule_id": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["rules_triggered"]["buckets"]
        ],
        "recent_alerts": [trim_alert(h) for h in res["hits"]["hits"][:20]],
    }


@mcp.tool()
async def search_authentication_failures(
    time_range: str = "1h", threshold: int = 5
) -> dict:
    """Find source IPs with repeated authentication failures (brute force candidates).
    Returns sources with more than `threshold` failures in the time range.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"terms": {"rule.groups": [
                        "authentication_failed", "authentication_failures"
                    ]}},
                ]
            }
        },
        "aggs": {
            "by_src_ip": {
                "terms": {
                    "field": "data.srcip",
                    "size": 50,
                    "min_doc_count": threshold,
                },
                "aggs": {
                    "targets": {"terms": {"field": "agent.name", "size": 10}},
                    "users_tried": {"terms": {"field": "data.dstuser", "size": 10}},
                },
            }
        },
    }
    res = await idx.search(body)
    return {
        "time_range": time_range,
        "threshold": threshold,
        "suspicious_sources": [
            {
                "src_ip": b["key"],
                "failure_count": b["doc_count"],
                "targets": [t["key"] for t in b["targets"]["buckets"]],
                "users_tried": [u["key"] for u in b["users_tried"]["buckets"]],
            }
            for b in res["aggregations"]["by_src_ip"]["buckets"]
        ],
    }


@mcp.tool()
async def alert_timeline(time_range: str = "24h", interval: str = "1h") -> dict:
    """Date-histogram of alerts over time — spot spikes and quiet periods.

    interval: '1m', '5m', '1h', '1d'
    """
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
        "aggs": {
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                },
                "aggs": {
                    "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}}
                },
            }
        },
    }
    res = await idx.search(body)
    return {
        "interval": interval,
        "buckets": [
            {
                "time": b["key_as_string"],
                "total": b["doc_count"],
                "critical": b["critical"]["doc_count"],
            }
            for b in res["aggregations"]["timeline"]["buckets"]
        ],
    }


@mcp.tool()
async def get_alert_by_id(alert_id: str) -> dict:
    """Retrieve a single alert with FULL details by document ID.
    Use only after triaging via summary tools, when full log content matters.
    """
    body = {"size": 1, "query": {"term": {"_id": alert_id}}}
    res = await idx.search(body)
    hits = res["hits"]["hits"]
    if not hits:
        return {"error": "Alert not found", "alert_id": alert_id}
    return {"alert_id": alert_id, "source": hits[0]["_source"]}


# ============================================================================
# Vulnerability state index
# ============================================================================

@mcp.tool()
async def vulnerability_summary(min_severity: str = "High") -> dict:
    """Aggregated view of unpatched vulnerabilities across the fleet.

    Call this BEFORE listing specific CVEs for broad 'how exposed are we' questions.
    min_severity: Critical | High | Medium | Low
    """
    included = severities_at_or_above(min_severity)
    body = {
        "size": 0,
        "query": {"terms": {"vulnerability.severity": included}},
        "aggs": {
            "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
            "top_cves": {
                "terms": {"field": "vulnerability.id", "size": 15},
                "aggs": {
                    "affected_agents": {"cardinality": {"field": "agent.id"}},
                    "detail": {
                        "top_hits": {
                            "size": 1,
                            "_source": [
                                "vulnerability.severity",
                                "vulnerability.score.base",
                                "package.name",
                            ],
                        }
                    },
                },
            },
            "top_vulnerable_agents": {"terms": {"field": "agent.name", "size": 15}},
            "top_vulnerable_packages": {"terms": {"field": "package.name", "size": 15}},
        },
    }
    res = await idx.search(body, index=cfg.vuln_index)
    aggs = res["aggregations"]
    return {
        "min_severity": min_severity,
        "total_findings": res["hits"]["total"]["value"],
        "by_severity": [
            {"severity": b["key"], "count": b["doc_count"]}
            for b in aggs["by_severity"]["buckets"]
        ],
        "top_cves": [
            {
                "cve": b["key"],
                "total_findings": b["doc_count"],
                "affected_agents": b["affected_agents"]["value"],
                "severity": b["detail"]["hits"]["hits"][0]["_source"]["vulnerability"]["severity"],
                "cvss": (b["detail"]["hits"]["hits"][0]["_source"]["vulnerability"]
                         .get("score", {}).get("base")),
                "package": b["detail"]["hits"]["hits"][0]["_source"]["package"]["name"],
            }
            for b in aggs["top_cves"]["buckets"]
        ],
        "most_vulnerable_agents": [
            {"agent": b["key"], "findings": b["doc_count"]}
            for b in aggs["top_vulnerable_agents"]["buckets"]
        ],
        "most_vulnerable_packages": [
            {"package": b["key"], "findings": b["doc_count"]}
            for b in aggs["top_vulnerable_packages"]["buckets"]
        ],
    }


@mcp.tool()
async def get_agent_vulnerabilities_detailed(
    agent_id: str, min_severity: str = "High", limit: int = 100
) -> dict:
    """List all unpatched CVEs on a specific agent, worst CVSS first."""
    included = severities_at_or_above(min_severity)
    body = {
        "size": limit,
        "sort": [{"vulnerability.score.base": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"agent.id": agent_id}},
                    {"terms": {"vulnerability.severity": included}},
                ]
            }
        },
    }
    res = await idx.search(body, index=cfg.vuln_index)
    return {
        "agent_id": agent_id,
        "total": res["hits"]["total"]["value"],
        "vulnerabilities": [trim_vuln(h) for h in res["hits"]["hits"]],
    }


@mcp.tool()
async def search_cve(cve_id: str) -> dict:
    """Find every agent and package affected by a specific CVE.

    cve_id: e.g. 'CVE-2024-3094'
    """
    body = {
        "size": 500,
        "query": {"term": {"vulnerability.id": cve_id}},
        "aggs": {
            "by_agent": {"terms": {"field": "agent.name", "size": 100}},
            "by_package": {"terms": {"field": "package.name", "size": 50}},
        },
    }
    res = await idx.search(body, index=cfg.vuln_index)
    if res["hits"]["total"]["value"] == 0:
        return {"cve": cve_id, "found": False, "message": "No agents affected."}

    sample = res["hits"]["hits"][0]["_source"]
    return {
        "cve": cve_id,
        "found": True,
        "total_findings": res["hits"]["total"]["value"],
        "severity": sample.get("vulnerability", {}).get("severity"),
        "cvss_score": (sample.get("vulnerability") or {}).get("score", {}).get("base"),
        "reference": sample.get("vulnerability", {}).get("reference"),
        "published": sample.get("vulnerability", {}).get("published_at"),
        "affected_agents": [
            {"agent": b["key"], "instances": b["doc_count"]}
            for b in res["aggregations"]["by_agent"]["buckets"]
        ],
        "affected_packages": [
            {"package": b["key"], "instances": b["doc_count"]}
            for b in res["aggregations"]["by_package"]["buckets"]
        ],
    }


@mcp.tool()
async def prioritize_patches(top_n: int = 20) -> dict:
    """Rank patches by exposure — agents × CVSS, not raw count or severity alone.

    Answers 'what should I patch first?' the way a SOC lead actually means it.
    """
    body = {
        "size": 0,
        "query": {"terms": {"vulnerability.severity": ["Critical", "High"]}},
        "aggs": {
            "by_cve": {
                "terms": {"field": "vulnerability.id", "size": top_n * 3},
                "aggs": {
                    "agents": {"cardinality": {"field": "agent.id"}},
                    "avg_cvss": {"avg": {"field": "vulnerability.score.base"}},
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["vulnerability.severity", "package.name"],
                        }
                    },
                },
            }
        },
    }
    res = await idx.search(body, index=cfg.vuln_index)
    items = []
    for b in res["aggregations"]["by_cve"]["buckets"]:
        agents = b["agents"]["value"]
        cvss = b["avg_cvss"]["value"] or 0
        items.append({
            "cve": b["key"],
            "affected_agents": agents,
            "cvss": round(cvss, 1),
            "severity": b["sample"]["hits"]["hits"][0]["_source"]["vulnerability"]["severity"],
            "package": b["sample"]["hits"]["hits"][0]["_source"]["package"]["name"],
            "priority_score": round(agents * cvss, 1),
        })
    items.sort(key=lambda x: x["priority_score"], reverse=True)
    return {"top_patches": items[:top_n]}


# ============================================================================
# Active response correlation
# ============================================================================

AR_RULE_IDS = ["601", "602", "603", "651", "652"]
AR_GROUPS = ["active_response", "ar"]


@mcp.tool()
async def get_active_responses(time_range: str = "24h", limit: int = 50) -> dict:
    """List active-response actions Wazuh took recently, with triggering context."""
    body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {
                        "bool": {
                            "should": [
                                {"terms": {"rule.groups": AR_GROUPS}},
                                {"terms": {"rule.id": AR_RULE_IDS}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
    }
    res = await idx.search(body)
    responses = []
    for h in res["hits"]["hits"]:
        src = h["_source"]
        data = src.get("data", {})
        responses.append({
            "timestamp": src.get("@timestamp"),
            "agent": src.get("agent", {}).get("name"),
            "agent_id": src.get("agent", {}).get("id"),
            "command": data.get("command") or data.get("extra_data"),
            "src_ip_blocked": data.get("srcip"),
            "user_affected": data.get("dstuser") or data.get("srcuser"),
            "rule_description": src.get("rule", {}).get("description"),
            "rule_id": src.get("rule", {}).get("id"),
            "rule_level": src.get("rule", {}).get("level"),
            "log_snippet": (src.get("full_log") or "")[:300],
        })
    return {
        "time_range": time_range,
        "total": res["hits"]["total"]["value"],
        "responses": responses,
    }


@mcp.tool()
async def correlate_alert_with_response(
    src_ip: str | None = None,
    agent_id: str | None = None,
    time_range: str = "1h",
) -> dict:
    """Given a source IP or agent, return both the triggering alerts AND any AR taken."""
    if not src_ip and not agent_id:
        return {"error": "Provide src_ip or agent_id"}

    filters = [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}]
    if src_ip:
        filters.append({"term": {"data.srcip": src_ip}})
    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})

    body = {
        "size": 200,
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": filters}},
    }
    res = await idx.search(body)

    triggering, responses = [], []
    for h in res["hits"]["hits"]:
        src = h["_source"]
        groups = src.get("rule", {}).get("groups", [])
        rule_id = str(src.get("rule", {}).get("id", ""))
        is_ar = any(g in AR_GROUPS for g in groups) or rule_id in AR_RULE_IDS
        entry = {
            "timestamp": src.get("@timestamp"),
            "rule_id": rule_id,
            "rule_description": src.get("rule", {}).get("description"),
            "level": src.get("rule", {}).get("level"),
            "agent": src.get("agent", {}).get("name"),
        }
        if is_ar:
            entry["command"] = (src.get("data", {}).get("command")
                                or src.get("data", {}).get("extra_data"))
            responses.append(entry)
        else:
            triggering.append(entry)

    return {
        "query": {"src_ip": src_ip, "agent_id": agent_id, "time_range": time_range},
        "response_taken": len(responses) > 0,
        "triggering_alerts_count": len(triggering),
        "response_actions_count": len(responses),
        "triggering_alerts": triggering[:30],
        "response_actions": responses,
        "verdict": (
            "Active response was triggered."
            if responses
            else "Alerts fired but no active response was executed in this window."
        ),
    }


@mcp.tool()
async def active_response_effectiveness(time_range: str = "7d") -> dict:
    """Audit AR effectiveness — did blocks actually stop alert traffic from the source?

    For each AR event that blocked an IP, count alerts from that IP AFTER the block.
    Zero = block worked; non-zero = the attacker got through anyway.
    """
    ar_body = {
        "size": 500,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {
                        "bool": {
                            "should": [
                                {"terms": {"rule.groups": AR_GROUPS}},
                                {"terms": {"rule.id": ["601", "651"]}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                    {"exists": {"field": "data.srcip"}},
                ]
            }
        },
        "_source": ["@timestamp", "data.srcip", "agent.name", "data.command"],
    }
    ar_res = await idx.search(ar_body)

    findings = []
    for h in ar_res["hits"]["hits"]:
        src = h["_source"]
        blocked_ip = src.get("data", {}).get("srcip")
        block_time = src.get("@timestamp")
        if not blocked_ip:
            continue
        post_query = {
            "bool": {
                "filter": [
                    {"term": {"data.srcip": blocked_ip}},
                    {"range": {"@timestamp": {"gt": block_time}}},
                ]
            }
        }
        post_count = await idx.count(post_query)
        findings.append({
            "blocked_ip": blocked_ip,
            "block_time": block_time,
            "agent": src.get("agent", {}).get("name"),
            "command": src.get("data", {}).get("command"),
            "alerts_after_block": post_count,
            "block_effective": post_count == 0,
        })

    ineffective = [f for f in findings if not f["block_effective"]]
    return {
        "time_range": time_range,
        "total_blocks": len(findings),
        "effective_blocks": len(findings) - len(ineffective),
        "ineffective_blocks": len(ineffective),
        "effectiveness_pct": (
            round((len(findings) - len(ineffective)) / len(findings) * 100, 1)
            if findings
            else None
        ),
        "ineffective_block_details": ineffective[:20],
    }


# ============================================================================
# File integrity monitoring (syscheck)
# ============================================================================

@mcp.tool()
async def get_recent_fim_changes(
    agent_id: str, limit: int = 50, event_type: str | None = None
) -> dict:
    """Recent file integrity events on an agent, newest first (from Manager API).

    event_type: optional filter — 'added', 'modified', or 'deleted'.
    Use this when the user asks 'what changed on agent X recently'.
    """
    path = f"/syscheck/{agent_id}?sort=-date&limit={limit}"
    if event_type:
        # Wazuh API uses ?type=... for added/modified/deleted
        path += f"&type={event_type}"
    return await wz.request("GET", path)


@mcp.tool()
async def search_fim_alerts(
    time_range: str = "24h",
    agent_id: str | None = None,
    file_path_substring: str | None = None,
    limit: int = 50,
) -> dict:
    """Search FIM alerts from the Indexer (alerts where rule.groups contains 'syscheck').

    file_path_substring: optional wildcard match against syscheck.path
                         (e.g. '/etc/' or 'shadow').
    """
    filters: list = [
        time_window(f"now-{time_range}"),
        {"term": {"rule.groups": "syscheck"}},
    ]
    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})
    if file_path_substring:
        filters.append({
            "wildcard": {"syscheck.path": f"*{file_path_substring}*"}
        })

    body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": filters}},
    }
    res = await idx.search(body)

    enriched = []
    for h in res["hits"]["hits"]:
        a = trim_alert(h)
        sc = h["_source"].get("syscheck", {})
        a["fim"] = {
            "path": sc.get("path"),
            "event": sc.get("event"),
            "mode": sc.get("mode"),
            "size_after": sc.get("size_after"),
            "sha256_after": sc.get("sha256_after"),
            "uname_after": sc.get("uname_after"),
            "perm_after": sc.get("perm_after"),
        }
        enriched.append(a)

    return {
        "total": res["hits"]["total"]["value"],
        "fim_alerts": enriched,
    }


@mcp.tool()
async def fim_summary(time_range: str = "24h") -> dict:
    """Aggregated FIM activity — by agent, file path, and event type.

    Call this BEFORE listing individual FIM events for broad questions like
    'where's the most file activity this week'.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    time_window(f"now-{time_range}"),
                    {"term": {"rule.groups": "syscheck"}},
                ]
            }
        },
        "aggs": {
            "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            "by_event": {"terms": {"field": "syscheck.event", "size": 10}},
            "top_paths": {"terms": {"field": "syscheck.path", "size": 25}},
        },
    }
    res = await idx.search(body)
    aggs = res["aggregations"]
    return {
        "time_range": time_range,
        "total_fim_events": res["hits"]["total"]["value"],
        "by_agent": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in aggs["by_agent"]["buckets"]
        ],
        "by_event_type": [
            {"event": b["key"], "count": b["doc_count"]}
            for b in aggs["by_event"]["buckets"]
        ],
        "most_changed_paths": [
            {"path": b["key"], "count": b["doc_count"]}
            for b in aggs["top_paths"]["buckets"]
        ],
    }


# Common high-value paths whose modification is almost always notable.
CRITICAL_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/etc/hosts", "/etc/cron", "/etc/systemd",
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/root/.ssh", "/.ssh/authorized_keys",
    # Windows
    "System32", "SysWOW64", "Registry",
]


@mcp.tool()
async def critical_file_changes(time_range: str = "7d", limit: int = 50) -> dict:
    """FIM changes on sensitive paths — auth files, cron, system binaries, ssh keys.

    Designed to surface the FIM events that warrant immediate attention regardless
    of which agent triggered them.
    """
    path_filters = [{"wildcard": {"syscheck.path": f"*{p}*"}} for p in CRITICAL_PATHS]
    body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    time_window(f"now-{time_range}"),
                    {"term": {"rule.groups": "syscheck"}},
                    {"bool": {"should": path_filters, "minimum_should_match": 1}},
                ]
            }
        },
    }
    res = await idx.search(body)
    enriched = []
    for h in res["hits"]["hits"]:
        a = trim_alert(h)
        sc = h["_source"].get("syscheck", {})
        a["fim_path"] = sc.get("path")
        a["fim_event"] = sc.get("event")
        a["sha256_after"] = sc.get("sha256_after")
        enriched.append(a)
    return {
        "total": res["hits"]["total"]["value"],
        "events": enriched,
    }


# ============================================================================
# Compliance aggregations (PCI, HIPAA, GDPR, NIST 800-53, TSC)
# ============================================================================

COMPLIANCE_FIELDS = {
    "pci_dss": "rule.pci_dss",
    "hipaa": "rule.hipaa",
    "gdpr": "rule.gdpr",
    "nist_800_53": "rule.nist_800_53",
    "tsc": "rule.tsc",
}


@mcp.tool()
async def compliance_summary(
    framework: str = "pci_dss", time_range: str = "30d", min_level: int = 5
) -> dict:
    """Aggregate alerts by compliance control for a given framework.

    framework: pci_dss | hipaa | gdpr | nist_800_53 | tsc
    Returns counts per control, plus top rules and top agents driving each.
    """
    field = COMPLIANCE_FIELDS.get(framework)
    if not field:
        return {
            "error": f"Unknown framework '{framework}'",
            "supported": list(COMPLIANCE_FIELDS),
        }
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    time_window(f"now-{time_range}"),
                    {"range": {"rule.level": {"gte": min_level}}},
                    {"exists": {"field": field}},
                ]
            }
        },
        "aggs": {
            "by_control": {
                "terms": {"field": field, "size": 30},
                "aggs": {
                    "top_rules": {"terms": {"field": "rule.id", "size": 3}},
                    "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                },
            }
        },
    }
    res = await idx.search(body)
    return {
        "framework": framework,
        "time_range": time_range,
        "total_alerts_with_control_mapping": res["hits"]["total"]["value"],
        "by_control": [
            {
                "control": b["key"],
                "count": b["doc_count"],
                "top_rules": [r["key"] for r in b["top_rules"]["buckets"]],
                "top_agents": [a["key"] for a in b["top_agents"]["buckets"]],
            }
            for b in res["aggregations"]["by_control"]["buckets"]
        ],
    }


@mcp.tool()
async def compliance_control_details(
    framework: str, control_id: str, time_range: str = "30d", limit: int = 50
) -> dict:
    """Drill into alerts mapped to one specific compliance control.

    Example: framework='pci_dss', control_id='10.2.4' returns alerts for failed
    authentication attempts (PCI control 10.2.4).
    """
    field = COMPLIANCE_FIELDS.get(framework)
    if not field:
        return {
            "error": f"Unknown framework '{framework}'",
            "supported": list(COMPLIANCE_FIELDS),
        }
    body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    time_window(f"now-{time_range}"),
                    {"term": {field: control_id}},
                ]
            }
        },
    }
    res = await idx.search(body)
    return {
        "framework": framework,
        "control": control_id,
        "total": res["hits"]["total"]["value"],
        "alerts": [trim_alert(h) for h in res["hits"]["hits"]],
    }


# ============================================================================
# Rule details
# ============================================================================

@mcp.tool()
async def get_rule_details(rule_id: str) -> dict:
    """Look up a Wazuh rule's full metadata by ID (description, level, groups,
    MITRE and compliance mappings).

    Useful after `alert_summary` surfaces a rule ID you don't recognize.
    """
    return await wz.request("GET", f"/rules?rule_ids={rule_id}")


# ============================================================================
# Group management
# ============================================================================

@mcp.tool()
async def list_groups(limit: int = 100) -> dict:
    """List Wazuh agent groups with their member counts and config status."""
    return await wz.request("GET", f"/groups?limit={limit}")


@mcp.tool()
async def get_group_agents(group_id: str, limit: int = 200) -> dict:
    """List agents that belong to a given group."""
    return await wz.request(
        "GET", f"/groups/{group_id}/agents?limit={limit}"
    )


@mcp.tool()
async def add_agent_to_group(agent_id: str, group_id: str) -> dict:
    """Assign an agent to a group. Destructive — requires WAZUH_ALLOW_WRITES=true."""
    blocked = _require_writes()
    if blocked:
        return blocked
    return await wz.request("PUT", f"/agents/{agent_id}/group/{group_id}")


# ============================================================================
# Anomaly comparison — current period vs baseline
# ============================================================================

@mcp.tool()
async def compare_alert_volume(
    current_range: str = "7d",
    baseline_offset: str = "7d",
    min_level: int = 7,
) -> dict:
    """Compare alert volume in the current window against the immediately preceding baseline.

    current_range='7d', baseline_offset='7d' compares the last 7 days against the 7 days
    before that (days 7..14 ago).

    Returns total counts and per-severity deltas. Negative delta is not always good — a
    silent SIEM often means a broken sensor, not a clean environment.
    """
    def make_body(time_filter: dict) -> dict:
        return {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_filter,
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "aggs": {"by_level": {"terms": {"field": "rule.level", "size": 20}}},
        }

    current_filter = time_window(f"now-{current_range}")
    baseline_filter = time_window(
        f"now-{current_range}-{baseline_offset}", f"now-{current_range}"
    )

    current_res = await idx.search(make_body(current_filter))
    baseline_res = await idx.search(make_body(baseline_filter))

    cur_total = current_res["hits"]["total"]["value"]
    base_total = baseline_res["hits"]["total"]["value"]

    def pct(cur: int, base: int) -> float | None:
        return None if base == 0 else round((cur - base) / base * 100, 1)

    cur_by_level = {
        b["key"]: b["doc_count"]
        for b in current_res["aggregations"]["by_level"]["buckets"]
    }
    base_by_level = {
        b["key"]: b["doc_count"]
        for b in baseline_res["aggregations"]["by_level"]["buckets"]
    }

    by_level_delta = []
    for lvl in sorted(set(cur_by_level) | set(base_by_level)):
        c = cur_by_level.get(lvl, 0)
        b = base_by_level.get(lvl, 0)
        by_level_delta.append({
            "level": lvl,
            "current": c,
            "baseline": b,
            "delta": c - b,
            "delta_pct": pct(c, b),
        })

    return {
        "current_range": current_range,
        "baseline_offset": baseline_offset,
        "current_total": cur_total,
        "baseline_total": base_total,
        "delta": cur_total - base_total,
        "delta_pct": pct(cur_total, base_total),
        "by_level": by_level_delta,
    }


@mcp.tool()
async def detect_rule_anomalies(
    current_range: str = "7d",
    baseline_offset: str = "7d",
    significance_threshold: float = 2.0,
    min_count: int = 10,
) -> dict:
    """Find rules whose firing frequency has significantly changed vs baseline.

    Buckets each rule into one of:
      - NEW: firing now, absent in baseline (new threat or new coverage)
      - SPIKE: current >= significance_threshold * baseline (potential active incident)
      - DROP: current * significance_threshold <= baseline (potential sensor failure!)
      - GONE: in baseline but absent now (could be remediated OR a broken pipeline)

    The DROP and GONE categories are the under-appreciated ones. A rule that used to fire
    1000 times/week and now fires zero is almost never 'we got better' — it's usually
    a misconfigured agent, a disabled rule, or a logging pipeline outage.

    min_count: ignore rules below this count in both periods.
    """
    def make_body(time_filter: dict) -> dict:
        return {
            "size": 0,
            "query": {"bool": {"filter": [time_filter]}},
            "aggs": {
                "by_rule": {
                    "terms": {"field": "rule.id", "size": 200},
                    "aggs": {
                        "detail": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description", "rule.level"],
                            }
                        }
                    },
                }
            },
        }

    current_filter = time_window(f"now-{current_range}")
    baseline_filter = time_window(
        f"now-{current_range}-{baseline_offset}", f"now-{current_range}"
    )

    cur = await idx.search(make_body(current_filter))
    base = await idx.search(make_body(baseline_filter))

    def bucketize(res: dict) -> dict:
        out = {}
        for b in res["aggregations"]["by_rule"]["buckets"]:
            top = b["detail"]["hits"]["hits"][0]["_source"]["rule"]
            out[b["key"]] = {
                "count": b["doc_count"],
                "description": top.get("description"),
                "level": top.get("level"),
            }
        return out

    cur_rules = bucketize(cur)
    base_rules = bucketize(base)

    new_rules, spikes, drops, gone = [], [], [], []
    all_ids = set(cur_rules) | set(base_rules)

    for rid in all_ids:
        c = cur_rules.get(rid, {}).get("count", 0)
        b = base_rules.get(rid, {}).get("count", 0)
        meta = cur_rules.get(rid) or base_rules.get(rid) or {}
        entry = {
            "rule_id": rid,
            "description": meta.get("description"),
            "level": meta.get("level"),
            "current": c,
            "baseline": b,
        }

        if b == 0 and c >= min_count:
            new_rules.append(entry)
        elif c == 0 and b >= min_count:
            gone.append(entry)
        elif b >= min_count and c >= min_count:
            ratio = c / b
            entry["ratio"] = round(ratio, 2)
            if ratio >= significance_threshold:
                spikes.append(entry)
            elif ratio <= 1 / significance_threshold:
                drops.append(entry)

    new_rules.sort(key=lambda x: x["current"], reverse=True)
    spikes.sort(key=lambda x: x["ratio"], reverse=True)
    drops.sort(key=lambda x: x["ratio"])
    gone.sort(key=lambda x: x["baseline"], reverse=True)

    return {
        "current_range": current_range,
        "baseline_offset": baseline_offset,
        "significance_threshold": significance_threshold,
        "min_count": min_count,
        "summary": {
            "new_rules": len(new_rules),
            "spikes": len(spikes),
            "drops": len(drops),
            "gone": len(gone),
        },
        "new_rules": new_rules[:20],
        "spikes": spikes[:20],
        "drops": drops[:20],
        "gone": gone[:20],
    }


# ============================================================================
# Inventory — per-agent (Manager API, works on all 4.x)
# ============================================================================

def _truncate(s: str | None, n: int = 300) -> str | None:
    """Cap long strings so process command lines don't blow up payloads."""
    if s is None:
        return None
    return s if len(s) <= n else s[:n] + "…"


@mcp.tool()
async def get_agent_packages(
    agent_id: str, search: str | None = None, limit: int = 50
) -> dict:
    """Installed packages on a single agent (from syscollector).

    search: optional substring match across package name/version/architecture
            (e.g. 'nginx', 'openssl', 'log4j').

    For fleet-wide 'who has package X' questions, use `fleet_find_package` instead.
    """
    path = f"/syscollector/{agent_id}/packages?limit={limit}"
    if search:
        path += f"&search={search}"
    return await wz.request("GET", path)


@mcp.tool()
async def get_agent_processes(
    agent_id: str, search: str | None = None, limit: int = 50
) -> dict:
    """Currently-tracked processes on a single agent (from syscollector).

    search: optional substring match across process name / command line / user.
    """
    path = f"/syscollector/{agent_id}/processes?limit={limit}"
    if search:
        path += f"&search={search}"
    return await wz.request("GET", path)


@mcp.tool()
async def get_agent_open_ports(agent_id: str, limit: int = 100) -> dict:
    """Listening / open ports on a single agent, with the bound process where available."""
    return await wz.request(
        "GET", f"/syscollector/{agent_id}/ports?limit={limit}"
    )


@mcp.tool()
async def get_agent_hardware_os(agent_id: str) -> dict:
    """Hardware (CPU, RAM, board) plus OS info for an agent — one consolidated call."""
    hw = await wz.request("GET", f"/syscollector/{agent_id}/hardware")
    osinfo = await wz.request("GET", f"/syscollector/{agent_id}/os")
    return {"hardware": hw, "os": osinfo}


# ============================================================================
# Inventory — fleet-wide (Indexer state indices, Wazuh 4.10+)
# ============================================================================

@mcp.tool()
async def fleet_find_package(
    package_name: str, version_substring: str | None = None, limit: int = 200
) -> dict:
    """Find every agent across the fleet that has a given package installed.

    package_name: exact-ish match (uses wildcard so 'openssl' finds openssl-libs too)
    version_substring: optional substring to narrow version (e.g. '1.0.2k')

    This is the CVE-response query: 'who has log4j 2.14?' — answers in one call.
    Requires Wazuh 4.10+ with the inventory state indices.
    """
    filters: list = [
        {"wildcard": {"package.name": f"*{package_name}*"}},
    ]
    if version_substring:
        filters.append({"wildcard": {"package.version": f"*{version_substring}*"}})

    body = {
        "size": limit,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "agent_count": {"cardinality": {"field": "agent.id"}},
            "by_version": {"terms": {"field": "package.version", "size": 20}},
        },
    }
    try:
        res = await idx.search(body, index=cfg.inventory_packages_index)
    except Exception as e:
        return {
            "error": f"Inventory index query failed: {e}. "
                     "fleet_find_package requires Wazuh 4.10+ inventory state indices.",
        }

    agents = []
    seen = set()
    for h in res["hits"]["hits"]:
        src = h["_source"]
        a = src.get("agent", {})
        p = src.get("package", {})
        key = (a.get("id"), p.get("version"))
        if key in seen:
            continue
        seen.add(key)
        agents.append({
            "agent_id": a.get("id"),
            "agent_name": a.get("name"),
            "package": p.get("name"),
            "version": p.get("version"),
            "architecture": p.get("architecture"),
        })

    return {
        "package_query": package_name,
        "version_query": version_substring,
        "total_matches": res["hits"]["total"]["value"],
        "unique_agents": res["aggregations"]["agent_count"]["value"],
        "versions_seen": [
            {"version": b["key"], "agents": b["doc_count"]}
            for b in res["aggregations"]["by_version"]["buckets"]
        ],
        "matches": agents,
    }


@mcp.tool()
async def fleet_find_process(process_name: str, limit: int = 200) -> dict:
    """Find every agent currently running a process matching `process_name`.

    Useful for IR ('who is running curl right now?') and asset queries
    ('which agents have nginx running?'). Requires Wazuh 4.10+.
    """
    body = {
        "size": limit,
        "query": {"wildcard": {"process.name": f"*{process_name}*"}},
        "aggs": {
            "agent_count": {"cardinality": {"field": "agent.id"}},
            "by_user": {"terms": {"field": "process.user.name", "size": 20}},
        },
    }
    try:
        res = await idx.search(body, index=cfg.inventory_processes_index)
    except Exception as e:
        return {
            "error": f"Inventory index query failed: {e}. "
                     "fleet_find_process requires Wazuh 4.10+ inventory state indices.",
        }

    rows = []
    for h in res["hits"]["hits"]:
        src = h["_source"]
        p = src.get("process", {})
        a = src.get("agent", {})
        rows.append({
            "agent_id": a.get("id"),
            "agent_name": a.get("name"),
            "process": p.get("name"),
            "pid": p.get("pid"),
            "ppid": p.get("ppid"),
            "user": (p.get("user") or {}).get("name"),
            "command_line": _truncate(p.get("command_line"), 300),
        })

    return {
        "process_query": process_name,
        "total_matches": res["hits"]["total"]["value"],
        "unique_agents": res["aggregations"]["agent_count"]["value"],
        "running_as": [
            {"user": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["by_user"]["buckets"]
        ],
        "matches": rows,
    }


@mcp.tool()
async def fleet_find_listening_port(port: int, limit: int = 200) -> dict:
    """Find every agent with the given port open / listening.

    Answers 'who exposes RDP/3389?', 'who has unauthenticated Redis on 6379?', etc.
    Requires Wazuh 4.10+.
    """
    body = {
        "size": limit,
        "query": {
            "bool": {
                "should": [
                    {"term": {"destination.port": port}},
                    {"term": {"source.port": port}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "agent_count": {"cardinality": {"field": "agent.id"}},
            "by_proto": {"terms": {"field": "network.protocol", "size": 10}},
        },
    }
    try:
        res = await idx.search(body, index=cfg.inventory_ports_index)
    except Exception as e:
        return {
            "error": f"Inventory index query failed: {e}. "
                     "fleet_find_listening_port requires Wazuh 4.10+ inventory state indices.",
        }

    rows = []
    for h in res["hits"]["hits"]:
        src = h["_source"]
        rows.append({
            "agent_id": (src.get("agent") or {}).get("id"),
            "agent_name": (src.get("agent") or {}).get("name"),
            "bound_process": (src.get("process") or {}).get("name"),
            "pid": (src.get("process") or {}).get("pid"),
            "local_ip": (src.get("destination") or {}).get("ip")
                        or (src.get("source") or {}).get("ip"),
            "protocol": (src.get("network") or {}).get("protocol"),
        })

    return {
        "port": port,
        "total_matches": res["hits"]["total"]["value"],
        "unique_agents": res["aggregations"]["agent_count"]["value"],
        "by_protocol": [
            {"protocol": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["by_proto"]["buckets"]
        ],
        "matches": rows,
    }


# ============================================================================
# Security Configuration Assessment (SCA / CIS benchmarks)
# ============================================================================

@mcp.tool()
async def get_agent_sca_policies(agent_id: str) -> dict:
    """List SCA policies running on an agent with pass/fail summary scores.

    Use this first to see WHICH benchmarks an agent runs (CIS Ubuntu, CIS Windows,
    custom policies, etc.) before drilling into failed checks for one policy.
    """
    return await wz.request("GET", f"/sca/{agent_id}")


@mcp.tool()
async def get_sca_failed_checks(
    agent_id: str, policy_id: str, limit: int = 100
) -> dict:
    """Failing checks for one SCA policy on one agent.

    policy_id: from `get_agent_sca_policies`, e.g. 'cis_ubuntu22-04', 'cis_win2019'

    Returns each failing check's title, rationale, remediation, and compliance mappings.
    """
    path = f"/sca/{agent_id}/checks/{policy_id}?result=failed&limit={limit}"
    return await wz.request("GET", path)


@mcp.tool()
async def sca_alerts_summary(time_range: str = "7d") -> dict:
    """Aggregated view of SCA alerts across the fleet from the indexer.

    Surfaces which checks are failing most across agents and which agents have the
    most SCA findings — broader view than per-agent `get_agent_sca_policies`.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    time_window(f"now-{time_range}"),
                    {"term": {"rule.groups": "sca"}},
                ]
            }
        },
        "aggs": {
            "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            "by_check": {
                "terms": {"field": "data.sca.check.title.keyword", "size": 20},
                "aggs": {
                    "agents_affected": {"cardinality": {"field": "agent.id"}}
                },
            },
            "by_result": {"terms": {"field": "data.sca.check.result", "size": 10}},
            "by_policy": {"terms": {"field": "data.sca.policy", "size": 10}},
        },
    }
    res = await idx.search(body)
    aggs = res["aggregations"]
    return {
        "time_range": time_range,
        "total_sca_alerts": res["hits"]["total"]["value"],
        "by_result": [
            {"result": b["key"], "count": b["doc_count"]}
            for b in aggs["by_result"]["buckets"]
        ],
        "policies_running": [
            {"policy": b["key"], "alerts": b["doc_count"]}
            for b in aggs["by_policy"]["buckets"]
        ],
        "noisiest_agents": [
            {"agent": b["key"], "alerts": b["doc_count"]}
            for b in aggs["by_agent"]["buckets"]
        ],
        "most_common_failures": [
            {
                "check": b["key"],
                "occurrences": b["doc_count"],
                "agents_affected": b["agents_affected"]["value"],
            }
            for b in aggs["by_check"]["buckets"]
        ],
    }


@mcp.tool()
async def fleet_sca_weakest_agents(limit: int = 20) -> dict:
    """Rank agents by their SCA configuration weakness — most failing checks first.

    Pulls per-agent SCA policy summaries from the Manager API. Use this to identify
    which hosts most urgently need configuration hardening.

    Note: makes N+1 API calls (list agents, then SCA per agent), so caps at `limit`.
    """
    # Step 1: list active agents
    agents_resp = await wz.request("GET", f"/agents?status=active&limit={limit}")
    agents = (agents_resp.get("data") or {}).get("affected_items", [])

    findings = []
    for ag in agents:
        agent_id = ag.get("id")
        if not agent_id:
            continue
        try:
            sca = await wz.request("GET", f"/sca/{agent_id}")
            policies = (sca.get("data") or {}).get("affected_items", [])
        except Exception:
            continue

        for p in policies:
            failed = p.get("fail", 0)
            passed = p.get("pass", 0)
            total = failed + passed
            score = p.get("score")  # Wazuh sometimes returns score directly
            if score is None and total:
                score = round(passed / total * 100, 1)
            findings.append({
                "agent_id": agent_id,
                "agent_name": ag.get("name"),
                "policy": p.get("name") or p.get("policy_id"),
                "passed": passed,
                "failed": failed,
                "score_pct": score,
            })

    findings.sort(key=lambda x: (x["failed"] or 0), reverse=True)
    return {
        "agents_scanned": len(agents),
        "weakest_first": findings[:limit],
    }



# ============================================================================
# CDB list management
# ============================================================================

@mcp.tool()
async def list_cdb_lists() -> dict:
    """List all CDB lookup lists configured in Wazuh (IP blocklists, domain lists, hash lists)."""
    return await wz.request("GET", "/lists?limit=100")


@mcp.tool()
async def get_cdb_list_contents(list_name: str) -> dict:
    """Get the full key:value contents of a CDB list file.

    list_name: as returned by list_cdb_lists, e.g. 'malicious-ips'
    """
    return await wz.request("GET", f"/lists/files/{list_name}?raw=true")


@mcp.tool()
async def add_to_cdb_list(list_name: str, key: str, value: str = "malicious") -> dict:
    """Add an IP, domain, or file hash to a CDB blocklist — takes effect immediately.

    Requires WAZUH_ALLOW_WRITES=true.
    list_name: e.g. 'malicious-ips'
    key: the IP/domain/hash to add
    value: label, e.g. 'c2-server', 'attacker', 'phishing'
    """
    blocked = _require_writes()
    if blocked:
        return blocked
    try:
        current = await wz.request("GET", f"/lists/files/{list_name}?raw=true")
        existing = (current.get("data") or {}).get("affected_items", [""])[0] or ""
    except Exception:
        existing = ""
    lines = [ln for ln in existing.splitlines() if ln.strip() and not ln.startswith(f"{key}:")]
    lines.append(f"{key}:{value}")
    new_content = "\n".join(lines) + "\n"
    result = await wz.request(
        "PUT", f"/lists/files/{list_name}",
        content=new_content.encode(),
        headers={"Content-Type": "application/octet-stream"},
    )
    return {"action": "added", "key": key, "value": value, "list": list_name, "api_result": result}


@mcp.tool()
async def remove_from_cdb_list(list_name: str, key: str) -> dict:
    """Remove an entry from a CDB list (unblock an IP, domain, or hash).

    Requires WAZUH_ALLOW_WRITES=true.
    """
    blocked = _require_writes()
    if blocked:
        return blocked
    current = await wz.request("GET", f"/lists/files/{list_name}?raw=true")
    existing = (current.get("data") or {}).get("affected_items", [""])[0] or ""
    filtered = "\n".join(
        ln for ln in existing.splitlines()
        if ln.strip() and not ln.startswith(f"{key}:")
    ) + "\n"
    result = await wz.request(
        "PUT", f"/lists/files/{list_name}",
        content=filtered.encode(),
        headers={"Content-Type": "application/octet-stream"},
    )
    return {"action": "removed", "key": key, "list": list_name, "api_result": result}


# ============================================================================
# Logtest — validate detection rules without real traffic
# ============================================================================

@mcp.tool()
async def test_log_against_rules(log_sample: str, log_format: str = "syslog") -> dict:
    """Test a raw log line against Wazuh decoder + rule engine.

    Returns which decoder fired, which rule matched, alert level and groups.
    Use to validate new detection rules or debug why a log is not triggering.

    log_format: syslog | json | audit | eventchannel | apache | nginx
    """
    body = {"event": log_sample, "log_format": log_format, "location": "test"}
    return await wz.request("PUT", "/logtest", json=body)


@mcp.tool()
async def test_rule_coverage(log_samples: list) -> dict:
    """Test up to 20 log samples and report what percentage your ruleset covers.

    Pass logs from an attack simulation to measure detection coverage.
    Returns per-sample rule details and overall coverage percentage.
    """
    results = []
    for raw_log in log_samples[:20]:
        try:
            r = await wz.request("PUT", "/logtest", json={
                "event": raw_log, "log_format": "syslog", "location": "test"
            })
            rule = (r.get("data") or {}).get("output", {}).get("rule", {})
            results.append({
                "log_snippet": str(raw_log)[:80],
                "rule_id": rule.get("id"),
                "description": rule.get("description"),
                "level": rule.get("level"),
                "groups": rule.get("groups", []),
                "covered": bool(rule.get("id")),
            })
        except Exception as e:
            results.append({"log_snippet": str(raw_log)[:80], "error": str(e), "covered": False})
    covered = sum(1 for r in results if r.get("covered"))
    return {
        "total_samples": len(results),
        "covered": covered,
        "not_covered": len(results) - covered,
        "coverage_pct": round(covered / len(results) * 100, 1) if results else 0,
        "details": results,
    }


# ============================================================================
# MITRE ATT&CK coverage analysis
# ============================================================================

@mcp.tool()
async def mitre_coverage_analysis() -> dict:
    """Analyse MITRE ATT&CK technique coverage across your Wazuh ruleset.

    Returns covered techniques with rule counts, tactics breakdown,
    and weakly-covered techniques (only 1 rule) that attackers could bypass.
    """
    rules_resp = await wz.request("GET", "/rules?limit=2000&status=enabled")
    rule_items = (rules_resp.get("data") or {}).get("affected_items", [])

    coverage: dict = {}
    for rule in rule_items:
        mitre = rule.get("mitre") or {}
        for technique in mitre.get("id", []):
            if technique not in coverage:
                coverage[technique] = {
                    "technique": technique,
                    "tactics": mitre.get("tactic", []),
                    "rule_count": 0,
                    "sample_rules": [],
                }
            coverage[technique]["rule_count"] += 1
            if len(coverage[technique]["sample_rules"]) < 3:
                coverage[technique]["sample_rules"].append({
                    "id": rule.get("id"),
                    "description": rule.get("description"),
                    "level": rule.get("level"),
                })

    by_coverage = sorted(coverage.values(), key=lambda x: x["rule_count"], reverse=True)
    tactics: dict = {}
    for v in coverage.values():
        for tactic in v.get("tactics", []):
            tactics[tactic] = tactics.get(tactic, 0) + 1

    return {
        "total_techniques_covered": len(coverage),
        "total_rules_with_mitre": len([r for r in rule_items if (r.get("mitre") or {}).get("id")]),
        "tactics_coverage": dict(sorted(tactics.items(), key=lambda x: x[1], reverse=True)),
        "top_10_covered": by_coverage[:10],
        "weakly_covered_1_rule": [t for t in by_coverage if t["rule_count"] == 1][:20],
    }


@mcp.tool()
async def get_mitre_gaps(time_range: str = "30d") -> dict:
    """Compare MITRE techniques seen in live alerts vs ruleset coverage.

    Surfaces techniques firing in real alerts but covered by only one rule —
    gaps attackers can exploit with slight payload variations.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    time_window(f"now-{time_range}"),
                    {"exists": {"field": "rule.mitre.id"}},
                ]
            }
        },
        "aggs": {"observed": {"terms": {"field": "rule.mitre.id", "size": 500}}},
    }
    observed_res = await idx.search(body)
    observed = {
        b["key"]: b["doc_count"]
        for b in observed_res["aggregations"]["observed"]["buckets"]
    }
    rules_resp = await wz.request("GET", "/rules?limit=2000&status=enabled")
    rule_items = (rules_resp.get("data") or {}).get("affected_items", [])
    technique_rule_count: dict = {}
    for rule in rule_items:
        for t in (rule.get("mitre") or {}).get("id", []):
            technique_rule_count[t] = technique_rule_count.get(t, 0) + 1

    gaps = []
    for technique, alert_count in observed.items():
        rule_count = technique_rule_count.get(technique, 0)
        if rule_count <= 1:
            gaps.append({
                "technique": technique,
                "alerts_in_period": alert_count,
                "rules_covering": rule_count,
                "risk": "HIGH" if alert_count > 50 else "MEDIUM",
            })
    gaps.sort(key=lambda x: x["alerts_in_period"], reverse=True)
    return {
        "time_range": time_range,
        "total_observed_techniques": len(observed),
        "thin_coverage_count": len(gaps),
        "gaps": gaps[:25],
    }


# ============================================================================
# Incident response — timeline and blast radius
# ============================================================================

@mcp.tool()
async def incident_timeline(
    start_time: str,
    end_time: str,
    agent_ids: list | None = None,
    min_level: int = 5,
    limit: int = 200,
) -> dict:
    """Reconstruct a full chronological event timeline within an incident window.

    start_time / end_time: ISO 8601, e.g. '2026-05-14T10:00:00'
    Returns events oldest-first for kill-chain reconstruction.
    """
    filters: list = [
        {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]
    if agent_ids:
        filters.append({"terms": {"agent.id": agent_ids}})

    body = {
        "size": limit,
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            "by_technique": {"terms": {"field": "rule.mitre.id", "size": 20}},
            "by_rule": {"terms": {"field": "rule.id", "size": 20}},
        },
    }
    res = await idx.search(body)
    aggs = res["aggregations"]
    return {
        "window": {"start": start_time, "end": end_time},
        "total_events": res["hits"]["total"]["value"],
        "agents_involved": [b["key"] for b in aggs["by_agent"]["buckets"]],
        "techniques_observed": [b["key"] for b in aggs["by_technique"]["buckets"]],
        "top_rules": [{"rule_id": b["key"], "count": b["doc_count"]} for b in aggs["by_rule"]["buckets"]],
        "timeline": [trim_alert(h) for h in res["hits"]["hits"]],
    }


@mcp.tool()
async def blast_radius_analysis(
    src_ip: str | None = None,
    agent_id: str | None = None,
    time_range: str = "2h",
) -> dict:
    """Determine the full scope of a potential compromise from an IP or agent.

    Returns agents contacted, source/dest IPs, MITRE techniques, activity
    histogram, and lateral movement assessment (3+ agents = suspected).
    """
    if not src_ip and not agent_id:
        return {"error": "Provide src_ip or agent_id"}

    filters: list = [time_window(f"now-{time_range}")]
    if src_ip:
        filters.append({
            "bool": {
                "should": [
                    {"term": {"data.srcip": src_ip}},
                    {"term": {"data.dstip": src_ip}},
                ],
                "minimum_should_match": 1,
            }
        })
    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})

    body = {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "agents_affected": {"terms": {"field": "agent.name", "size": 30}},
            "src_ips": {"terms": {"field": "data.srcip", "size": 20}},
            "dst_ips": {"terms": {"field": "data.dstip", "size": 20}},
            "techniques": {"terms": {"field": "rule.mitre.id", "size": 20}},
            "rules": {"terms": {"field": "rule.id", "size": 20}},
            "by_15min": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "15m",
                    "min_doc_count": 0,
                }
            },
        },
    }
    res = await idx.search(body)
    aggs = res["aggregations"]
    agents = aggs["agents_affected"]["buckets"]
    return {
        "indicator": {"src_ip": src_ip, "agent_id": agent_id},
        "time_range": time_range,
        "total_alerts": res["hits"]["total"]["value"],
        "lateral_movement_suspected": len(agents) >= 3,
        "agents_affected": [{"agent": b["key"], "count": b["doc_count"]} for b in agents],
        "source_ips": [b["key"] for b in aggs["src_ips"]["buckets"]],
        "destination_ips": [b["key"] for b in aggs["dst_ips"]["buckets"]],
        "techniques": [b["key"] for b in aggs["techniques"]["buckets"]],
        "top_rules": [{"rule_id": b["key"], "count": b["doc_count"]} for b in aggs["rules"]["buckets"][:10]],
        "activity_histogram": [
            {"time": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs["by_15min"]["buckets"]
        ],
    }


# ============================================================================
# External threat intelligence enrichment
# ============================================================================

async def _vt_get(path: str) -> dict | None:
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": vt_key},
            )
            return r.json() if r.status_code == 200 else None
    except Exception as e:
        log.warning("VirusTotal error: %s", e)
        return None


async def _abuse_get(ip: str) -> dict | None:
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if not abuse_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": abuse_key, "Accept": "application/json"},
            )
            return r.json().get("data") if r.status_code == 200 else None
    except Exception as e:
        log.warning("AbuseIPDB error: %s", e)
        return None


@mcp.tool()
async def enrich_ip(ip: str) -> dict:
    """Enrich a source IP with VirusTotal + AbuseIPDB reputation data.

    Returns malicious vote counts, abuse confidence, ASN, country, and a
    combined KNOWN MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN verdict.

    Requires VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY in .env.
    """
    vt_data, abuse_data = await asyncio.gather(
        _vt_get(f"ip_addresses/{ip}"),
        _abuse_get(ip),
        return_exceptions=False,
    )

    result: dict = {"ip": ip}

    if vt_data:
        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["virustotal"] = {
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "reputation": attrs.get("reputation"),
        }
    else:
        result["virustotal"] = {"status": "unavailable — set VIRUSTOTAL_API_KEY"}

    if abuse_data:
        result["abuseipdb"] = {
            "abuse_confidence_score": abuse_data.get("abuseConfidenceScore"),
            "total_reports": abuse_data.get("totalReports"),
            "country_code": abuse_data.get("countryCode"),
            "isp": abuse_data.get("isp"),
            "domain": abuse_data.get("domain"),
            "is_tor": abuse_data.get("isTor"),
            "last_reported_at": abuse_data.get("lastReportedAt"),
        }
    else:
        result["abuseipdb"] = {"status": "unavailable — set ABUSEIPDB_API_KEY"}

    vt_mal = (result.get("virustotal") or {}).get("malicious_votes") or 0
    abuse_score = (result.get("abuseipdb") or {}).get("abuse_confidence_score") or 0
    result["verdict"] = (
        "KNOWN MALICIOUS" if vt_mal > 5 or abuse_score > 50
        else "SUSPICIOUS" if vt_mal > 0 or abuse_score > 10
        else "CLEAN" if (vt_data or abuse_data)
        else "UNKNOWN — configure TI API keys"
    )
    return result


@mcp.tool()
async def enrich_file_hash(hash_value: str) -> dict:
    """Check a file hash (MD5, SHA1, or SHA256) against VirusTotal.

    Use after FIM alerts that flag unexpected binary changes.
    Requires VIRUSTOTAL_API_KEY in .env.
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}
    vt_data = await _vt_get(f"files/{hash_value}")
    if not vt_data:
        return {"hash": hash_value, "verdict": "NOT FOUND IN VIRUSTOTAL"}
    attrs = vt_data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    return {
        "hash": hash_value,
        "malicious_engines": malicious,
        "total_engines": total,
        "detection_ratio": f"{malicious}/{total}",
        "meaningful_name": attrs.get("meaningful_name"),
        "file_type": attrs.get("type_description"),
        "file_size": attrs.get("size"),
        "first_submission": attrs.get("first_submission_date"),
        "threat_label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "verdict": "MALICIOUS" if malicious > 3 else "SUSPICIOUS" if malicious > 0 else "CLEAN",
    }


# ============================================================================
# Archive log search
# ============================================================================

@mcp.tool()
async def search_archive_logs(
    query_string: str,
    time_range: str = "24h",
    agent_id: str | None = None,
    limit: int = 50,
) -> dict:
    """Search the full Wazuh archives index — all ingested logs, not just alerts.

    Use for forensic reconstruction when an attacker bypassed detection.
    query_string: Lucene syntax, e.g. 'data.srcip:198.51.100.42'
    Requires archiving enabled in ossec.conf. Set WAZUH_ARCHIVES_INDEX in .env if needed.
    """
    archives_index = os.getenv("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*")
    filters: list = [time_window(f"now-{time_range}")]
    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})
    body = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": filters,
                "must": [{"query_string": {"query": query_string, "default_field": "*"}}],
            }
        },
    }
    try:
        res = await idx.search(body, index=archives_index)
        return {
            "query": query_string,
            "total": res["hits"]["total"]["value"],
            "logs": [trim_alert(h) for h in res["hits"]["hits"]],
        }
    except Exception as e:
        return {
            "error": str(e),
            "hint": "Ensure archiving is enabled in ossec.conf and wazuh-archives-* indices exist.",
        }


# ============================================================================
# Cluster health monitoring
# ============================================================================

@mcp.tool()
async def get_cluster_health() -> dict:
    """Full health check of Wazuh cluster nodes and the Indexer (OpenSearch) cluster.

    Returns node sync state, Indexer cluster health, shard status, and doc counts.
    """
    cluster_status, cluster_nodes = await asyncio.gather(
        wz.request("GET", "/cluster/status"),
        wz.request("GET", "/cluster/nodes"),
        return_exceptions=True,
    )
    indexer_health: dict = {}
    try:
        async with httpx.AsyncClient(
            verify=cfg.verify_ssl,
            auth=(cfg.indexer_user, cfg.indexer_pass),
            timeout=15,
        ) as c:
            r_h = await c.get(f"{cfg.indexer_host}/_cluster/health")
            r_s = await c.get(
                f"{cfg.indexer_host}/_cluster/stats?"
                "filter_path=indices.count,indices.docs,indices.store,nodes.count"
            )
            if r_h.status_code == 200:
                indexer_health["health"] = r_h.json()
            if r_s.status_code == 200:
                indexer_health["stats"] = r_s.json()
    except Exception as e:
        indexer_health["error"] = str(e)
    return {
        "wazuh_cluster_status": cluster_status if not isinstance(cluster_status, Exception) else str(cluster_status),
        "wazuh_nodes": (
            (cluster_nodes.get("data") or {}).get("affected_items", [])
            if not isinstance(cluster_nodes, Exception) else str(cluster_nodes)
        ),
        "indexer": indexer_health,
    }


@mcp.tool()
async def check_event_queue_health() -> dict:
    """Check if Wazuh is silently dropping events due to queue pressure.

    Zero dropped events = healthy. Any nonzero value means events are being
    lost — the most dangerous and least visible SIEM failure mode.
    """
    try:
        stats = await wz.request("GET", "/manager/stats/analysisd")
        data = (stats.get("data") or {}).get("affected_items", [{}])[0]
        dropped = data.get("events_dropped_queue", 0) or 0
        return {
            "total_events_decoded": data.get("total_events_decoded"),
            "events_dropped": dropped,
            "health": "DEGRADED — events are being dropped!" if dropped > 0 else "OK",
            "raw_stats": data,
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Rule and decoder management
# ============================================================================

@mcp.tool()
async def search_rules(
    description_contains: str | None = None,
    group: str | None = None,
    level_min: int | None = None,
    mitre_technique: str | None = None,
    limit: int = 50,
) -> dict:
    """Search enabled Wazuh rules by description, group, minimum level, or MITRE technique."""
    path = f"/rules?limit={limit}&status=enabled"
    if description_contains:
        path += f"&search={description_contains}"
    if group:
        path += f"&group={group}"
    if level_min:
        path += f"&level={level_min}-16"
    if mitre_technique:
        path += f"&mitre_id={mitre_technique}"
    return await wz.request("GET", path)


@mcp.tool()
async def list_rule_files() -> dict:
    """List all rule files loaded by Wazuh — built-in and custom."""
    return await wz.request("GET", "/rules/files?limit=200")


@mcp.tool()
async def get_custom_rules() -> dict:
    """Get all rules from custom rule files (local_rules.xml and user-created files)."""
    return await wz.request("GET", "/rules/files?relative_dirname=etc/rules&limit=100")


@mcp.tool()
async def list_decoders() -> dict:
    """List all loaded decoders with their file sources."""
    return await wz.request("GET", "/decoders?limit=500")


# ============================================================================
# Shift handover report
# ============================================================================

@mcp.tool()
async def generate_shift_handover(
    shift_duration: str = "8h",
    analyst_name: str = "SOC Analyst",
) -> dict:
    """Generate a structured shift handover report covering the last N hours.

    Calls 6 tools in parallel and synthesises everything into a single structured
    response the incoming analyst can read in 2 minutes.

    shift_duration: '6h', '8h', '12h', '24h'
    """
    tasks = await asyncio.gather(
        alert_summary(time_range=shift_duration),
        search_authentication_failures(time_range=shift_duration, threshold=10),
        get_active_responses(time_range=shift_duration, limit=20),
        vulnerability_summary(min_severity="Critical"),
        compare_alert_volume(current_range=shift_duration, baseline_offset=shift_duration),
        detect_rule_anomalies(current_range=shift_duration, baseline_offset=shift_duration),
        return_exceptions=True,
    )
    s, authfail, ar, vuln, volume, rule_anom = tasks

    def safe(v: object) -> object:
        return str(v) if isinstance(v, Exception) else v

    attention: list = []
    if isinstance(rule_anom, dict):
        nr = len(rule_anom.get("new_rules", []))
        sp = len(rule_anom.get("spikes", []))
        if nr:
            attention.append(f"{nr} new rule(s) firing this shift — review rule_anomalies.new_rules")
        if sp:
            attention.append(f"{sp} rule spike(s) detected — review rule_anomalies.spikes")
    if isinstance(volume, dict):
        dp = volume.get("delta_pct")
        if isinstance(dp, (int, float)) and abs(dp) > 25:
            attention.append(f"Alert volume {dp:+.1f}% vs previous period — investigate cause")

    return {
        "shift_handover": {
            "analyst": analyst_name,
            "shift_duration": shift_duration,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "attention_items": attention or ["No significant anomalies — clean handover."],
        },
        "alert_overview": safe(s),
        "brute_force_activity": safe(authfail),
        "automated_responses": safe(ar),
        "critical_vulnerabilities": safe(vuln),
        "volume_vs_baseline": safe(volume),
        "rule_anomalies": safe(rule_anom),
    }


# ============================================================================
# MCP Prompts — one-click investigation workflows
# ============================================================================

@mcp.prompt()
def investigate_brute_force(time_range: str = "1h") -> str:
    """One-click brute force investigation."""
    return f"""Perform a complete brute force investigation for the last {time_range}:

1. search_authentication_failures(time_range="{time_range}", threshold=5) — find candidate IPs
2. For the top 3 IPs: search_by_source_ip to get full alert context
3. enrich_ip for each top IP — VirusTotal + AbuseIPDB reputation
4. correlate_alert_with_response for the highest-volume IP — did Wazuh block it?
5. If NOT blocked: blast_radius_analysis to assess lateral spread

Conclude with:
- What happened and which accounts/services were targeted
- Whether the attack is ongoing or was blocked
- Recommended action (block via add_to_cdb_list if ALLOW_WRITES=true, or escalate)"""


@mcp.prompt()
def weekly_soc_briefing() -> str:
    """Generate a complete weekly SOC executive briefing."""
    return """Generate the weekly SOC executive briefing by calling these tools in order:

1. compare_alert_volume(current_range="7d", baseline_offset="7d") — volume trend
2. detect_rule_anomalies(current_range="7d") — new/spiking/silent rules
3. vulnerability_summary(min_severity="Critical") — fleet CVE posture
4. prioritize_patches(top_n=5) — top patches by exposure * CVSS
5. active_response_effectiveness(time_range="7d") — block effectiveness rate
6. fleet_sca_weakest_agents(limit=5) — most misconfigured agents
7. mitre_coverage_analysis() — ATT&CK technique coverage stats

Format as an executive briefing with:
- Executive Summary (3 sentences)
- Key Metrics table
- Top 3 Risks this week
- Recommended Actions (owner + priority)"""


@mcp.prompt()
def triage_alert(alert_id: str) -> str:
    """Full structured triage for a single alert document ID."""
    return f"""Perform full triage on alert ID: {alert_id}

1. get_alert_by_id("{alert_id}") — full alert detail
2. get_rule_details(rule_id from alert) — what does this rule detect?
3. If alert has src_ip: search_by_source_ip(src_ip, time_range="24h")
4. enrich_ip(src_ip) — VirusTotal + AbuseIPDB verdict
5. correlate_alert_with_response(src_ip=src_ip) — automated response triggered?
6. blast_radius_analysis(src_ip=src_ip, time_range="2h") — scope of compromise
7. If alert involves file change: enrich_file_hash(sha256 from alert)

Produce a triage report:
- Classification: True Positive / False Positive / Needs Investigation
- Severity: Critical / High / Medium / Low
- Evidence summary (3 bullets)
- Recommended response
- Escalate: Yes/No — and to whom"""


@mcp.prompt()
def cve_emergency_response(cve_id: str) -> str:
    """Immediate CVE emergency response workflow."""
    return f"""Emergency response for {cve_id}:

1. search_cve("{cve_id}") — find every affected agent immediately
2. For top 5 affected agents: get_agent_vulnerabilities_detailed
3. prioritize_patches() — where does {cve_id} rank overall?
4. search_alerts(time_range="7d", rule_groups=["exploit","web_attack"]) — exploitation attempts?
5. fleet_find_package(package_name) — confirm package spread across fleet

Emergency response brief:
- Impact: agent count, environments affected
- Exploitation evidence: confirmed / suspected / not observed
- Immediate mitigations available
- Patch priority: P0 (now) / P1 (this week) / P2 (next cycle)
- Monitoring to add until patched"""



def main() -> None:
    import os as _os
    transport = _os.getenv("WAZUH_MCP_TRANSPORT", "stdio")
    host = _os.getenv("WAZUH_MCP_HOST", "0.0.0.0")
    port = int(_os.getenv("WAZUH_MCP_PORT", "8000"))

    log.info(
        "Starting Wazuh MCP server (transport=%s, host=%s, port=%s, writes=%s, manager=%s, indexer=%s)",
        transport, host, port, cfg.allow_writes, cfg.manager_host, cfg.indexer_host,
    )

    if transport == "http":
        # Use sse_app() + uvicorn directly — gives full host/port control.
        # run_sse_async reads host from self.settings (ignores env vars),
        # so we bypass it entirely and hand the ASGI app straight to uvicorn.
        #
        # mcp-remote URL:  http://<host>:<port>/sse  (GET stream)
        # messages path:   http://<host>:<port>/messages  (POST)
        import uvicorn
        from mcp.server.transport_security import TransportSecuritySettings
        # Disable DNS-rebinding protection so the server accepts requests
        # from non-localhost Host headers (e.g. 192.168.x.x, remote IPs).
        # The MCP SDK's TransportSecuritySettings defaults to localhost-only,
        # which causes HTTP 421 "Invalid Host header" for any remote client.
        # Safe to disable when the server is on a trusted private network;
        # for internet-facing deployments put the server behind a TLS reverse
        # proxy and restrict access at the network level instead.
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )
        asgi_app = mcp.sse_app()
        log.info("SSE routes: /sse (GET), /messages (POST)")
        uvicorn.run(asgi_app, host=host, port=port, log_level="warning")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
