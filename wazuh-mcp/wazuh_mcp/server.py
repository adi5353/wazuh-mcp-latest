"""Wazuh MCP Server — exposes Wazuh manager + indexer capabilities as MCP tools.

Logging note: in STDIO mode, never print() to stdout — it corrupts the JSON-RPC stream.
The logging module below is configured to write to stderr.

Enhanced edition — adds:
  • Incident management tools (create_incident_report, tag_alert, bulk_suppress_rule)
  • Threat hunting tools (hunt_lateral_movement, hunt_persistence_mechanisms, hunt_data_exfiltration)
  • CDB write helpers with dry-run safety (add_ip_to_blocklist, remove_ip_from_blocklist, preview_cdb_list_impact)
  • Archive tools (search_archive_logs_by_agent, get_agent_login_history)
  • Reporting tools (generate_weekly_summary, generate_compliance_report)
  • GeoIP enrichment (enrich_ip_geo)
  • Alert trend enrichment inline in alert_summary
  • 4 new MCP prompts (morning_briefing, incident_triage, shift_handover, threat_hunt_session)
  • /health HTTP endpoint
  • Optional API-key bearer-token middleware (WAZUH_MCP_API_KEY)
  • Structured JSON logging via structlog (falls back gracefully if not installed)
  • WAZUH_MAX_RESULTS_GLOBAL hard cap across all list tools
  • dry_run=True guard on restart_agent and run_active_response
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import logging
import os
import sys
import time

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx
from mcp.server.fastmcp import FastMCP

from .config import Config
from .helpers import trim_alert, trim_vuln, severities_at_or_above, time_window
from .wazuh_client import WazuhClient
from .wazuh_indexer import WazuhIndexer

# ── Structured logging (structlog optional, stdlib fallback) ──────────────────
try:
    import structlog

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    log = structlog.get_logger("wazuh-mcp")
    _structlog_available = True
except ImportError:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    log = logging.getLogger("wazuh-mcp")  # type: ignore[assignment]
    _structlog_available = False

# ── Global config ─────────────────────────────────────────────────────────────
cfg = Config.from_env()
wz = WazuhClient(cfg)
idx = WazuhIndexer(cfg)

MAX_RESULTS_GLOBAL = int(os.getenv("WAZUH_MAX_RESULTS_GLOBAL", "500"))
SERVER_START_TIME = time.time()

mcp = FastMCP("wazuh")


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _require_writes() -> dict | None:
    """Return an error dict if writes are disabled, else None."""
    if not cfg.allow_writes:
        return {
            "error": "Write operations are disabled. "
                     "Set WAZUH_ALLOW_WRITES=true to enable destructive tools."
        }
    return None


def _cap(n: int) -> int:
    """Clamp a requested limit to MAX_RESULTS_GLOBAL."""
    return min(n, MAX_RESULTS_GLOBAL)


def _truncate(s: str | None, n: int = 300) -> str | None:
    """Cap long strings so process command lines don't blow up payloads."""
    if s is None:
        return None
    return s if len(s) <= n else s[:n] + "…"


# ── Inline MITRE technique ID → name/tactic table (no network call needed) ───
_MITRE_MAP: dict[str, dict] = {
    "T1003": {"name": "OS Credential Dumping",              "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services",                    "tactic": "Lateral Movement"},
    "T1027": {"name": "Obfuscated Files or Information",    "tactic": "Defense Evasion"},
    "T1053": {"name": "Scheduled Task/Job",                 "tactic": "Persistence"},
    "T1055": {"name": "Process Injection",                  "tactic": "Defense Evasion"},
    "T1059": {"name": "Command and Scripting Interpreter",  "tactic": "Execution"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1071": {"name": "Application Layer Protocol",         "tactic": "Command and Control"},
    "T1078": {"name": "Valid Accounts",                     "tactic": "Persistence"},
    "T1082": {"name": "System Information Discovery",       "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery",       "tactic": "Discovery"},
    "T1098": {"name": "Account Manipulation",               "tactic": "Persistence"},
    "T1105": {"name": "Ingress Tool Transfer",              "tactic": "Command and Control"},
    "T1110": {"name": "Brute Force",                        "tactic": "Credential Access"},
    "T1112": {"name": "Modify Registry",                    "tactic": "Defense Evasion"},
    "T1190": {"name": "Exploit Public-Facing Application",  "tactic": "Initial Access"},
    "T1219": {"name": "Remote Access Software",             "tactic": "Command and Control"},
    "T1543": {"name": "Create or Modify System Process",    "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism",  "tactic": "Privilege Escalation"},
    "T1562": {"name": "Impair Defenses",                    "tactic": "Defense Evasion"},
    "T1569": {"name": "System Services",                    "tactic": "Execution"},
}


def _enrich_mitre_ids(technique_ids: list) -> list:
    enriched = []
    for tid in technique_ids:
        base_id = tid.split(".")[0]
        info = _MITRE_MAP.get(base_id, {})
        enriched.append({
            "id": tid,
            "name": info.get("name", "Unknown Technique"),
            "tactic": info.get("tactic", "Unknown"),
        })
    return enriched


def _incident_recommendations(techniques: list, severity: str, src_ips: list) -> list:
    recs: list[str] = []
    t = [x.lower() for x in techniques]
    if severity in ("CRITICAL", "HIGH"):
        recs.append("Isolate affected agents immediately and capture memory dumps if possible.")
    if any(k in x for x in t for k in ("brute", "credential", "password")):
        recs.append("Reset credentials for all accounts active on affected agents.")
        recs.append("Enable MFA if not already enforced.")
    if any(k in x for x in t for k in ("lateral", "remote")):
        recs.append("Review SMB/RDP/WinRM connections from affected agents to peer systems.")
    if any(k in x for x in t for k in ("persist", "scheduled", "registry")):
        recs.append("Audit startup items, scheduled tasks, and registry run keys on affected agents.")
    if src_ips:
        recs.append(f"Block source IPs via CDB list or firewall: {', '.join(src_ips[:5])}")
    if not recs:
        recs.append("Review alerts manually and escalate if activity continues.")
    return recs


async def _geoip_lookup(ip: str) -> dict:
    """Free GeoIP via ip-api.com — no key required, 45 req/min."""
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback:
            return {"ip": ip, "geo": "private/local"}
    except ValueError:
        return {"ip": ip, "geo": "invalid_ip"}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,city,isp,as"},
            )
            data = r.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "asn": data.get("as", ""),
                }
    except Exception:
        pass
    return {"ip": ip, "geo": "lookup_failed"}


# ============================================================================
# Manager API tools — agents and operational state
# ============================================================================

@mcp.tool()
async def list_agents(status: str = "active", limit: int = 50) -> dict:
    """List Wazuh agents filtered by status.

    status: active | disconnected | pending | never_connected
    """
    return await wz.request("GET", f"/agents?status={status}&limit={_cap(limit)}")


@mcp.tool()
async def get_agent(agent_id: str) -> dict:
    """Get detailed info for a single agent by its ID (e.g. '001')."""
    return await wz.request("GET", f"/agents?agents_list={agent_id}")


@mcp.tool()
async def restart_agent(agent_id: str, dry_run: bool = True) -> dict:
    """Restart a Wazuh agent.

    dry_run=True (default) — shows what would happen without executing.
    Set dry_run=False to actually restart. Requires WAZUH_ALLOW_WRITES=true.
    """
    if dry_run:
        return {
            "dry_run": True,
            "agent_id": agent_id,
            "message": "Set dry_run=False to restart the agent. Requires WAZUH_ALLOW_WRITES=true.",
        }
    blocked = _require_writes()
    if blocked:
        return blocked
    return await wz.request("PUT", f"/agents/{agent_id}/restart")


@mcp.tool()
async def run_active_response(
    agent_id: str,
    command: str,
    arguments: list | None = None,
    dry_run: bool = True,
) -> dict:
    """Trigger an active response command on an agent (e.g. firewall-drop).

    dry_run=True (default) — shows what would be sent without executing.
    Set dry_run=False to actually trigger. Requires WAZUH_ALLOW_WRITES=true.
    """
    if dry_run:
        return {
            "dry_run": True,
            "agent_id": agent_id,
            "command": command,
            "arguments": arguments or [],
            "message": "Set dry_run=False to execute. Requires WAZUH_ALLOW_WRITES=true.",
        }
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
    Now includes trend vs prior period and enriched MITRE technique names.
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
    current_total = res["hits"]["total"]["value"]

    # Trend vs prior same-length window
    prior_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {
                        "gte": f"now-{time_range}-{time_range}",
                        "lte": f"now-{time_range}",
                    }}},
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        },
    }
    try:
        prior_res = await idx.search(prior_body)
        prior_total = prior_res["hits"]["total"]["value"]
        trend_pct = (
            round((current_total - prior_total) / prior_total * 100, 1)
            if prior_total
            else None
        )
        trend_arrow = (
            "↑" if (trend_pct or 0) > 5
            else "↓" if (trend_pct or 0) < -5
            else "="
        )
    except Exception:
        prior_total = None
        trend_pct = None
        trend_arrow = "?"

    # Enrich MITRE technique IDs with names
    raw_techniques = [b["key"] for b in aggs["top_mitre"]["buckets"]]
    enriched_techniques = _enrich_mitre_ids(raw_techniques)
    # Merge counts back
    mitre_counts = {b["key"]: b["doc_count"] for b in aggs["top_mitre"]["buckets"]}
    for t in enriched_techniques:
        t["count"] = mitre_counts.get(t["id"], 0)

    return {
        "time_range": time_range,
        "total_alerts": current_total,
        "trend": {
            "prior_period_total": prior_total,
            "delta_pct": trend_pct,
            "direction": trend_arrow,
        },
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
        "top_mitre_techniques": enriched_techniques,
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
        "size": _cap(limit),
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
        "size": _cap(limit),
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
        "size": _cap(limit),
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
        "size": _cap(limit),
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
        "size": _cap(limit),
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
    path = f"/syscheck/{agent_id}?sort=-date&limit={_cap(limit)}"
    if event_type:
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
        "size": _cap(limit),
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


CRITICAL_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/etc/hosts", "/etc/cron", "/etc/systemd",
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/root/.ssh", "/.ssh/authorized_keys",
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
        "size": _cap(limit),
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
    """Drill into alerts mapped to one specific compliance control."""
    field = COMPLIANCE_FIELDS.get(framework)
    if not field:
        return {
            "error": f"Unknown framework '{framework}'",
            "supported": list(COMPLIANCE_FIELDS),
        }
    body = {
        "size": _cap(limit),
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
    return await wz.request("GET", f"/groups?limit={_cap(limit)}")


@mcp.tool()
async def get_group_agents(group_id: str, limit: int = 200) -> dict:
    """List agents that belong to a given group."""
    return await wz.request(
        "GET", f"/groups/{group_id}/agents?limit={_cap(limit)}"
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
    """Compare alert volume in the current window against the immediately preceding baseline."""
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

    Buckets each rule into NEW, SPIKE, DROP, or GONE.
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

@mcp.tool()
async def get_agent_packages(
    agent_id: str, search: str | None = None, limit: int = 50
) -> dict:
    """Installed packages on a single agent (from syscollector)."""
    path = f"/syscollector/{agent_id}/packages?limit={_cap(limit)}"
    if search:
        path += f"&search={search}"
    return await wz.request("GET", path)


@mcp.tool()
async def get_agent_processes(
    agent_id: str, search: str | None = None, limit: int = 50
) -> dict:
    """Currently-tracked processes on a single agent (from syscollector)."""
    path = f"/syscollector/{agent_id}/processes?limit={_cap(limit)}"
    if search:
        path += f"&search={search}"
    return await wz.request("GET", path)


@mcp.tool()
async def get_agent_open_ports(agent_id: str, limit: int = 100) -> dict:
    """Listening / open ports on a single agent, with the bound process where available."""
    return await wz.request(
        "GET", f"/syscollector/{agent_id}/ports?limit={_cap(limit)}"
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

    This is the CVE-response query: 'who has log4j 2.14?' — answers in one call.
    Requires Wazuh 4.10+ with the inventory state indices.
    """
    filters: list = [{"wildcard": {"package.name": f"*{package_name}*"}}]
    if version_substring:
        filters.append({"wildcard": {"package.version": f"*{version_substring}*"}})

    body = {
        "size": _cap(limit),
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
    seen: set = set()
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

    Requires Wazuh 4.10+.
    """
    body = {
        "size": _cap(limit),
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

    Requires Wazuh 4.10+.
    """
    body = {
        "size": _cap(limit),
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
    """List SCA policies running on an agent with pass/fail summary scores."""
    return await wz.request("GET", f"/sca/{agent_id}")


@mcp.tool()
async def get_sca_failed_checks(
    agent_id: str, policy_id: str, limit: int = 100
) -> dict:
    """Failing checks for one SCA policy on one agent."""
    path = f"/sca/{agent_id}/checks/{policy_id}?result=failed&limit={_cap(limit)}"
    return await wz.request("GET", path)


@mcp.tool()
async def sca_alerts_summary(time_range: str = "7d") -> dict:
    """Aggregated view of SCA alerts across the fleet from the indexer."""
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
    """Rank agents by their SCA configuration weakness — most failing checks first."""
    agents_resp = await wz.request("GET", f"/agents?status=active&limit={_cap(limit)}")
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
            score = p.get("score")
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
    """List all CDB lookup lists configured in Wazuh."""
    return await wz.request("GET", "/lists?limit=100")


@mcp.tool()
async def get_cdb_list_contents(list_name: str) -> dict:
    """Get the full key:value contents of a CDB list file."""
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
    """Remove an entry from a CDB list. Requires WAZUH_ALLOW_WRITES=true."""
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


# ── New CDB helpers ────────────────────────────────────────────────────────────

@mcp.tool()
async def preview_cdb_list_impact(ip: str, hours: int = 24) -> dict:
    """Show how many recent alerts came from this IP before adding it to a blocklist.

    Run this BEFORE add_to_cdb_list to understand noise-reduction impact.
    No writes performed — always safe.
    """
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"data.srcip": ip}},
                                {"term": {"data.src_ip": ip}},
                            ]
                        }
                    },
                ]
            }
        },
        "aggs": {
            "by_rule": {"terms": {"field": "rule.description", "size": 5}},
            "by_agent": {"terms": {"field": "agent.name", "size": 5}},
        },
        "size": 0,
    }
    res = await idx.search(query)
    total = res["hits"]["total"]["value"]
    return {
        "ip": ip,
        "alerts_last_n_hours": total,
        "hours_checked": hours,
        "top_triggered_rules": [
            {"rule": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["by_rule"]["buckets"]
        ],
        "top_targeted_agents": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["by_agent"]["buckets"]
        ],
        "recommendation": (
            f"Blocking this IP would suppress ~{total} alerts over {hours}h."
            if total > 0
            else "No recent alerts from this IP — blocking may have no immediate effect."
        ),
    }


# ============================================================================
# Logtest — validate detection rules without real traffic
# ============================================================================

@mcp.tool()
async def test_log_against_rules(log_sample: str, log_format: str = "syslog") -> dict:
    """Test a raw log line against Wazuh decoder + rule engine.

    Returns which decoder fired, which rule matched, alert level and groups.
    log_format: syslog | json | audit | eventchannel | apache | nginx
    """
    body = {"event": log_sample, "log_format": log_format, "location": "test"}
    return await wz.request("PUT", "/logtest", json=body)


@mcp.tool()
async def test_rule_coverage(log_samples: list) -> dict:
    """Test up to 20 log samples and report what percentage your ruleset covers."""
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
    """Analyse MITRE ATT&CK technique coverage across your Wazuh ruleset."""
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
    """Compare MITRE techniques seen in live alerts vs ruleset coverage."""
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
    """Reconstruct a full chronological event timeline within an incident window."""
    filters: list = [
        {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]
    if agent_ids:
        filters.append({"terms": {"agent.id": agent_ids}})

    body = {
        "size": _cap(limit),
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
    """Determine the full scope of a potential compromise from an IP or agent."""
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


@mcp.tool()
async def enrich_ip_geo(ips: list) -> dict:
    """Look up geolocation for up to 10 IP addresses.

    Returns country, city, ISP, and ASN for each. Uses ip-api.com — no API key required.
    Skips private/RFC1918 addresses automatically.
    """
    tasks = [_geoip_lookup(ip) for ip in ips[:10]]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return {"results": list(results)}


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
    Requires archiving enabled in ossec.conf.
    """
    archives_index = os.getenv("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*")
    filters: list = [time_window(f"now-{time_range}")]
    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})
    body = {
        "size": _cap(limit),
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


@mcp.tool()
async def search_archive_logs_by_agent(
    agent_name: str,
    time_range: str = "24h",
    query_string: str = "",
    limit: int = 50,
) -> dict:
    """Search the full archive index for a specific agent over a time range.

    Returns a chronological event timeline — useful for forensic investigation.
    All ingested logs, not just alerts. Requires archiving enabled in ossec.conf.
    """
    archives_index = os.getenv("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*")
    must_clauses: list = [
        {"term": {"agent.name": agent_name}},
        {"range": {"@timestamp": {"gte": f"now-{time_range}", "lte": "now"}}},
    ]
    if query_string:
        must_clauses.append({"query_string": {"query": query_string}})

    body = {
        "query": {"bool": {"must": must_clauses}},
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": _cap(limit),
        "_source": [
            "@timestamp", "rule.description", "rule.id", "rule.level",
            "rule.groups", "data", "full_log",
        ],
    }
    try:
        res = await idx.search(body, index=archives_index)
        total = res["hits"]["total"]["value"]
        hits = res["hits"]["hits"]
        return {
            "agent": agent_name,
            "time_range": time_range,
            "total_logs": total,
            "returned": len(hits),
            "events": [h.get("_source", {}) for h in hits],
        }
    except Exception as e:
        return {
            "error": str(e),
            "hint": "Ensure archiving is enabled in ossec.conf.",
        }


@mcp.tool()
async def get_agent_login_history(
    agent_name: str,
    time_range: str = "72h",
    include_failures: bool = True,
    include_successes: bool = True,
) -> dict:
    """Pull successful and/or failed login history for an agent.

    Groups by user and shows source IPs.
    Useful for account compromise investigation.
    """
    rule_filters: list = []
    if include_failures:
        rule_filters += ["5710", "5711", "5712", "2501", "2502", "60106"]
    if include_successes:
        rule_filters += ["5715", "5501", "5900", "2503", "60105"]

    if not rule_filters:
        return {"error": "At least one of include_failures or include_successes must be True."}

    body = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.name": agent_name}},
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"terms": {"rule.id": rule_filters}},
                ]
            }
        },
        "aggs": {
            "by_user": {
                "terms": {"field": "data.dstuser", "size": 20},
                "aggs": {
                    "by_src": {"terms": {"field": "data.srcip", "size": 5}},
                },
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 50,
        "_source": [
            "@timestamp", "rule.description", "rule.id",
            "data.srcip", "data.dstuser", "data.srcuser",
        ],
    }
    res = await idx.search(body)
    total = res["hits"]["total"]["value"]
    hits = res["hits"]["hits"]
    buckets = res["aggregations"]["by_user"]["buckets"]

    return {
        "agent": agent_name,
        "time_window": time_range,
        "total_login_events": total,
        "by_user": [
            {
                "user": b["key"],
                "event_count": b["doc_count"],
                "source_ips": [s["key"] for s in b.get("by_src", {}).get("buckets", [])],
            }
            for b in buckets
        ],
        "recent_events": [h.get("_source", {}) for h in hits[:20]],
    }


# ============================================================================
# Cluster health monitoring
# ============================================================================

@mcp.tool()
async def get_cluster_health() -> dict:
    """Full health check of Wazuh cluster nodes and the Indexer (OpenSearch) cluster."""
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
    """Check if Wazuh is silently dropping events due to queue pressure."""
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
    path = f"/rules?limit={_cap(limit)}&status=enabled"
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
# NEW — Incident management
# ============================================================================

@mcp.tool()
async def create_incident_report(
    alert_ids: list,
    title: str = "Security Incident",
    analyst: str = "SOC Analyst",
) -> dict:
    """Generate a structured incident report from a list of alert document IDs.

    Fetches each alert, builds a timeline, extracts affected agents, MITRE TTPs,
    and appends recommended actions. Returns a structured dict ready for ticketing.
    """
    alerts = []
    for aid in alert_ids[:20]:
        body = {"size": 1, "query": {"term": {"_id": aid}}}
        try:
            res = await idx.search(body)
            hits = res["hits"]["hits"]
            if hits:
                alerts.append(hits[0]["_source"])
        except Exception:
            pass

    if not alerts:
        return {"error": "No alerts found for provided IDs."}

    alerts.sort(key=lambda a: a.get("@timestamp", ""))

    agent_names = list({a.get("agent", {}).get("name", "unknown") for a in alerts})
    src_ips = list({
        a.get("data", {}).get("srcip", "") or a.get("data", {}).get("src_ip", "")
        for a in alerts
        if a.get("data", {}).get("srcip") or a.get("data", {}).get("src_ip")
    })
    raw_techniques = list({
        t
        for a in alerts
        for t in (a.get("rule", {}).get("mitre", {}).get("id", []) or [])
    })
    technique_names = _enrich_mitre_ids(raw_techniques)
    rule_names = list({a.get("rule", {}).get("description", "") for a in alerts if a.get("rule", {}).get("description")})
    max_level = max((a.get("rule", {}).get("level", 0) for a in alerts), default=0)
    sev = "CRITICAL" if max_level >= 12 else "HIGH" if max_level >= 8 else "MEDIUM" if max_level >= 5 else "LOW"

    return {
        "incident": {
            "title": title,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "analyst": analyst,
            "severity": sev,
            "alert_count": len(alerts),
            "time_range": {
                "first": alerts[0].get("@timestamp", ""),
                "last": alerts[-1].get("@timestamp", ""),
            },
        },
        "affected_assets": agent_names,
        "source_ips": src_ips,
        "mitre": {"techniques": technique_names},
        "top_rules": rule_names[:10],
        "timeline": [
            {
                "timestamp": a.get("@timestamp", ""),
                "agent": a.get("agent", {}).get("name", ""),
                "rule": a.get("rule", {}).get("description", ""),
                "level": a.get("rule", {}).get("level", 0),
            }
            for a in alerts
        ],
        "recommended_actions": _incident_recommendations(raw_techniques, sev, src_ips),
    }


@mcp.tool()
async def tag_alert(
    alert_id: str,
    tag: str,
    note: str = "",
) -> dict:
    """Write an analyst tag and optional note to an alert document in the Indexer.

    Suggested tags: investigated, false_positive, escalated, in_progress, resolved.
    Requires WAZUH_ALLOW_WRITES=true.
    """
    blocked = _require_writes()
    if blocked:
        return blocked

    update_url = (
        f"{cfg.indexer_host}/{os.getenv('WAZUH_ALERTS_INDEX', 'wazuh-alerts-*')}/_update/{alert_id}"
    )
    payload = {
        "doc": {
            "analyst_tag": tag,
            "analyst_note": note,
            "analyst_updated_at": datetime.datetime.utcnow().isoformat() + "Z",
        }
    }
    try:
        async with httpx.AsyncClient(
            verify=cfg.verify_ssl,
            auth=(cfg.indexer_user, cfg.indexer_pass),
            timeout=10,
        ) as client:
            r = await client.post(update_url, json=payload)
            return {"status": "tagged", "alert_id": alert_id, "tag": tag, "http_status": r.status_code}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def bulk_suppress_rule(
    rule_id: int,
    reason: str,
    hours: int = 24,
    dry_run: bool = True,
) -> dict:
    """Preview or tag all alerts from a rule as false_positive.

    dry_run=True (default): counts how many would be tagged — safe to run always.
    dry_run=False: applies the tag via update_by_query. Requires WAZUH_ALLOW_WRITES=true.
    """
    count_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"rule.id": str(rule_id)}},
                    {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                ]
            }
        },
        "size": 0,
    }
    count_res = await idx.search(count_query)
    count = count_res["hits"]["total"]["value"]

    if dry_run:
        return {
            "dry_run": True,
            "rule_id": rule_id,
            "alerts_that_would_be_tagged": count,
            "tag": "false_positive",
            "reason": reason,
            "message": "Set dry_run=False to apply. Requires WAZUH_ALLOW_WRITES=true.",
        }

    blocked = _require_writes()
    if blocked:
        return blocked

    alerts_index = os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-4.x-*")
    ubq_url = f"{cfg.indexer_host}/{alerts_index}/_update_by_query"
    ubq_body = {
        "query": count_query["query"],
        "script": {
            "source": (
                "ctx._source.analyst_tag = 'false_positive';"
                " ctx._source.suppression_reason = params.reason;"
                " ctx._source.suppressed_at = params.ts"
            ),
            "params": {
                "reason": reason,
                "ts": datetime.datetime.utcnow().isoformat() + "Z",
            },
        },
    }
    try:
        async with httpx.AsyncClient(
            verify=cfg.verify_ssl,
            auth=(cfg.indexer_user, cfg.indexer_pass),
            timeout=60,
        ) as client:
            r = await client.post(ubq_url, json=ubq_body)
            data = r.json()
            return {
                "status": "suppressed",
                "rule_id": rule_id,
                "updated": data.get("updated", 0),
                "failures": data.get("failures", []),
            }
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# NEW — Threat hunting
# ============================================================================

@mcp.tool()
async def hunt_lateral_movement(
    time_range: str = "24h",
    min_targets: int = 2,
) -> dict:
    """Hunt lateral movement: find agents showing auth failures + suspicious remote connections.

    Returns agents with lateral movement indicators ranked by unique source IP count.
    """
    lateral_rule_ids = ["5710", "5711", "5712", "18107", "18108", "60106", "60107"]
    lateral_rule_groups = ["authentication_failed", "win_ms-wef", "pam"]

    body = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}],
                "should": [
                    {"terms": {"rule.id": lateral_rule_ids}},
                    {"terms": {"rule.groups": lateral_rule_groups}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent.name", "size": 50},
                "aggs": {
                    "rule_ids": {"terms": {"field": "rule.id", "size": 20}},
                    "src_ips": {"terms": {"field": "data.srcip", "size": 10}},
                },
            }
        },
        "size": 0,
    }
    res = await idx.search(body)
    buckets = res.get("aggregations", {}).get("by_agent", {}).get("buckets", [])

    suspects = []
    for b in buckets:
        src_ips_seen = [s["key"] for s in b.get("src_ips", {}).get("buckets", [])]
        unique_src = len(src_ips_seen)
        count = b["doc_count"]
        if unique_src >= min_targets or count >= 10:
            suspects.append({
                "agent": b["key"],
                "alert_count": count,
                "unique_source_ips": unique_src,
                "source_ips": src_ips_seen[:5],
                "triggered_rule_ids": [r["key"] for r in b.get("rule_ids", {}).get("buckets", [])],
                "risk": "HIGH" if unique_src >= 3 or count >= 30 else "MEDIUM",
            })

    suspects.sort(key=lambda x: x["unique_source_ips"], reverse=True)
    return {
        "hunt": "lateral_movement",
        "time_window": time_range,
        "suspects": suspects,
        "total_suspects": len(suspects),
    }


@mcp.tool()
async def hunt_persistence_mechanisms(time_range: str = "48h") -> dict:
    """Hunt persistence: search for FIM changes to startup locations, cron,
    registry run keys, new services, and scheduled tasks across all agents.
    """
    persistence_paths = [
        "/etc/cron", "/var/spool/cron", "/etc/rc", "/etc/init",
        "CurrentVersion\\\\Run", "CurrentControlSet\\\\Services",
        "System32\\\\Tasks", "Startup",
    ]
    persistence_rule_ids = ["550", "554", "11", "12", "60103", "60104"]

    path_should = [
        {"match_phrase": {"syscheck.path": p}} for p in persistence_paths
    ]

    body = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}],
                "should": [
                    {"terms": {"rule.id": persistence_rule_ids}},
                    {
                        "bool": {
                            "must": [
                                {"term": {"rule.groups": "syscheck"}},
                                {"bool": {"should": path_should, "minimum_should_match": 1}},
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent.name", "size": 30},
                "aggs": {"by_path": {"terms": {"field": "syscheck.path", "size": 10}}},
            }
        },
        "size": 10,
        "_source": ["@timestamp", "agent.name", "rule.description", "syscheck.path", "rule.id"],
    }
    res = await idx.search(body)
    total = res["hits"]["total"]["value"]
    hits = res["hits"]["hits"]
    buckets = res.get("aggregations", {}).get("by_agent", {}).get("buckets", [])

    return {
        "hunt": "persistence_mechanisms",
        "time_window": time_range,
        "total_findings": total,
        "affected_agents": [
            {
                "agent": b["key"],
                "event_count": b["doc_count"],
                "paths": [p["key"] for p in b.get("by_path", {}).get("buckets", [])],
            }
            for b in buckets
        ],
        "sample_events": [h.get("_source", {}) for h in hits[:5]],
    }


@mcp.tool()
async def hunt_data_exfiltration(
    time_range: str = "24h",
    min_event_count: int = 100,
) -> dict:
    """Hunt data exfiltration: find agents with unusually high outbound network event counts.

    Looks for firewall/network/IDS alerts with high per-agent event volumes.
    min_event_count: flag agents above this threshold.
    """
    body = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}],
                "should": [
                    {"term": {"rule.groups": "firewall"}},
                    {"term": {"rule.groups": "ids"}},
                    {"term": {"rule.groups": "network"}},
                    {"match": {"rule.description": "outbound"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "by_agent": {
                "terms": {"field": "agent.name", "size": 20},
                "aggs": {
                    "dst_ips": {"terms": {"field": "data.dstip", "size": 10}},
                },
            }
        },
        "size": 0,
    }
    res = await idx.search(body)
    buckets = res.get("aggregations", {}).get("by_agent", {}).get("buckets", [])

    suspects = []
    for b in buckets:
        count = b["doc_count"]
        if count >= min_event_count:
            suspects.append({
                "agent": b["key"],
                "network_events": count,
                "destination_ips": [d["key"] for d in b.get("dst_ips", {}).get("buckets", [])],
                "risk": "HIGH" if count >= 500 else "MEDIUM",
            })

    suspects.sort(key=lambda x: x["network_events"], reverse=True)
    return {
        "hunt": "data_exfiltration",
        "time_window": time_range,
        "min_event_threshold": min_event_count,
        "suspects": suspects,
        "note": "High event counts may indicate exfiltration or noisy policy — correlate with FIM and auth events.",
    }


# ============================================================================
# NEW — Reporting
# ============================================================================

@mcp.tool()
async def generate_weekly_summary(week_offset: int = 0) -> dict:
    """Generate a weekly security summary with alert trend, top rules/agents/techniques.

    week_offset=0 = current week; week_offset=1 = last week.
    """
    # Current and prior window boundaries
    gte_current = f"now-{7 * (week_offset + 1)}d"
    lte_current = f"now-{7 * week_offset}d" if week_offset > 0 else "now"
    gte_prior = f"now-{7 * (week_offset + 2)}d"
    lte_prior = gte_current

    async def count_window(gte: str, lte: str) -> int:
        q = {"query": {"range": {"@timestamp": {"gte": gte, "lte": lte}}}, "size": 0}
        r = await idx.search(q)
        return r["hits"]["total"]["value"]

    current_count, prior_count = await asyncio.gather(
        count_window(gte_current, lte_current),
        count_window(gte_prior, lte_prior),
    )
    trend_pct = (
        round((current_count - prior_count) / prior_count * 100, 1)
        if prior_count else None
    )

    agg_body = {
        "query": {"range": {"@timestamp": {"gte": gte_current, "lte": lte_current}}},
        "aggs": {
            "top_rules": {"terms": {"field": "rule.description", "size": 5}},
            "top_agents": {"terms": {"field": "agent.name", "size": 5}},
            "by_level": {"terms": {"field": "rule.level", "size": 15}},
            "top_techniques": {"terms": {"field": "rule.mitre.id", "size": 5}},
        },
        "size": 0,
    }
    agg_res = await idx.search(agg_body)
    aggs = agg_res["aggregations"]
    raw_techniques = [b["key"] for b in aggs["top_techniques"]["buckets"]]

    return {
        "report_type": "weekly_summary",
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "alert_counts": {
            "this_week": current_count,
            "prior_week": prior_count,
            "trend_pct": trend_pct,
            "trend_direction": (
                "↑" if (trend_pct or 0) > 0 else "↓" if (trend_pct or 0) < 0 else "="
            ),
        },
        "top_rules": [
            {"rule": b["key"], "count": b["doc_count"]}
            for b in aggs["top_rules"]["buckets"]
        ],
        "top_agents": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in aggs["top_agents"]["buckets"]
        ],
        "top_mitre_techniques": _enrich_mitre_ids(raw_techniques),
        "by_severity_level": {
            str(b["key"]): b["doc_count"]
            for b in aggs["by_level"]["buckets"]
        },
    }


@mcp.tool()
async def generate_compliance_report(
    framework: str = "pci_dss",
    time_range: str = "168h",
) -> dict:
    """Generate a compliance posture report for a given framework.

    Supported: pci_dss, hipaa, gdpr, nist_800_53, tsc.
    Returns control coverage, failing controls, and alert counts per control.
    """
    field = COMPLIANCE_FIELDS.get(framework)
    if not field:
        return {
            "error": f"Unknown framework '{framework}'",
            "supported": list(COMPLIANCE_FIELDS),
        }
    body = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"exists": {"field": field}},
                ]
            }
        },
        "aggs": {
            "by_control": {
                "terms": {"field": field, "size": 50},
                "aggs": {
                    "by_level": {"terms": {"field": "rule.level", "size": 5}},
                    "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                },
            }
        },
        "size": 0,
    }
    res = await idx.search(body)
    buckets = res.get("aggregations", {}).get("by_control", {}).get("buckets", [])
    total = res["hits"]["total"]["value"]

    controls = []
    for b in buckets:
        levels = {str(lv["key"]): lv["doc_count"] for lv in b.get("by_level", {}).get("buckets", [])}
        critical_count = sum(v for k, v in levels.items() if int(k) >= 10)
        controls.append({
            "control": b["key"],
            "total_alerts": b["doc_count"],
            "critical_alerts": critical_count,
            "top_agents": [a["key"] for a in b.get("top_agents", {}).get("buckets", [])],
            "by_level": levels,
            "status": "FAILING" if critical_count > 0 else "WARNING" if b["doc_count"] > 10 else "OK",
        })

    controls.sort(key=lambda x: x["critical_alerts"], reverse=True)
    failing = [c for c in controls if c["status"] == "FAILING"]

    return {
        "report_type": "compliance_report",
        "framework": framework,
        "time_window": time_range,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_alerts": total,
        "controls_with_alerts": len(controls),
        "failing_controls_count": len(failing),
        "controls": controls,
    }


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
# Phase 1 — Alert suppression lifecycle
# Paste this block into server.py after the bulk_suppress_rule tool (~line 2660)
# Uses: idx, cfg, mcp, _require_writes(), datetime, httpx, os
# ============================================================================

@mcp.tool()
async def list_suppressed_rules(
    time_range: str = "7d",
    min_count: int = 1,
) -> dict:
    """List all rules currently tagged as false_positive with FP rate and tuning advice.

    Returns per-rule: FP count, total count, FP rate %, oldest/newest tag, and recommendation.
    time_range: look-back window e.g. '24h', '7d', '30d'
    min_count: minimum FP-tagged alerts to include (filters noise from results)
    """
    # Step 1: aggregate alerts tagged false_positive by rule_id
    fp_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"analyst_tag.keyword": "false_positive"}},
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.id", "size": 500, "min_doc_count": min_count},
                "aggs": {
                    "desc":   {"terms": {"field": "rule.description.keyword", "size": 1}},
                    "level":  {"terms": {"field": "rule.level", "size": 1}},
                    "oldest": {"min": {"field": "@timestamp"}},
                    "newest": {"max": {"field": "@timestamp"}},
                    "notes":  {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": {"order": "desc"}}],
                            "_source": ["analyst_note", "suppression_reason"],
                        }
                    },
                },
            }
        },
    }
    try:
        fp_res = await idx.search(fp_body)
    except Exception as e:
        return {"error": f"Indexer query failed: {e}"}

    fp_buckets = fp_res.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    if not fp_buckets:
        return {
            "time_range": time_range,
            "suppressed_rule_count": 0,
            "rules": [],
            "summary": f"No false_positive tagged alerts found in the last {time_range}.",
        }

    # Step 2: get total alert counts for the same rule IDs in the same window
    rule_ids = [b["key"] for b in fp_buckets]
    total_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"terms": {"rule.id": rule_ids}},
                ]
            }
        },
        "aggs": {"by_rule": {"terms": {"field": "rule.id", "size": 500}}},
    }
    try:
        total_res = await idx.search(total_body)
        total_by_rule = {
            b["key"]: b["doc_count"]
            for b in total_res.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
        }
    except Exception:
        total_by_rule = {}

    # Step 3: assemble output rows
    rules = []
    for b in fp_buckets:
        rule_id  = b["key"]
        fp_count = b["doc_count"]
        total    = total_by_rule.get(rule_id, fp_count)
        fp_rate  = round(fp_count / total * 100, 1) if total else 0.0

        desc_buckets = b.get("desc", {}).get("buckets", [])
        desc  = desc_buckets[0]["key"] if desc_buckets else "unknown"

        level_buckets = b.get("level", {}).get("buckets", [])
        level = level_buckets[0]["key"] if level_buckets else 0

        top_hit = b.get("notes", {}).get("hits", {}).get("hits", [{}])[0]
        note    = top_hit.get("_source", {}).get("analyst_note", "")
        reason  = top_hit.get("_source", {}).get("suppression_reason", "")

        # Recommendation logic
        if fp_rate >= 80:
            recommendation = "DISABLE or heavily tune — extremely high FP rate (>=80%)"
        elif fp_rate >= 50:
            recommendation = "TUNE urgently — majority of alerts are false positives"
        elif fp_rate >= 20:
            recommendation = "TUNE recommended — significant FP rate"
        elif fp_count >= 100:
            recommendation = "REVIEW — high absolute FP volume even if rate is acceptable"
        else:
            recommendation = "MONITOR — acceptable rate, continue observing"

        rules.append({
            "rule_id":           str(rule_id),
            "rule_description":  desc,
            "rule_level":        level,
            "fp_count":          fp_count,
            "total_count":       total,
            "fp_rate_pct":       fp_rate,
            "oldest_suppressed": b.get("oldest", {}).get("value_as_string", ""),
            "newest_suppressed": b.get("newest", {}).get("value_as_string", ""),
            "sample_note":       note,
            "suppression_reason": reason,
            "recommendation":    recommendation,
        })

    rules.sort(key=lambda x: x["fp_count"], reverse=True)
    top = rules[0]
    return {
        "time_range":            time_range,
        "suppressed_rule_count": len(rules),
        "rules":                 rules,
        "summary": (
            f"Found {len(rules)} rule(s) with false_positive tags in the last {time_range}. "
            f"Top offender: rule {top['rule_id']} "
            f"({top['fp_count']} FP tags, {top['fp_rate_pct']}% FP rate) — {top['recommendation']}."
        ),
    }


@mcp.tool()
async def expire_suppression(
    rule_id: int,
    older_than_hours: int = 24,
    dry_run: bool = True,
) -> dict:
    """Remove false_positive tags from a rule's alerts older than N hours.

    Use after a tuning cycle to re-open a rule for fresh evaluation.
    dry_run=True (default): previews count without making changes.
    dry_run=False: removes analyst_tag and suppression_reason fields.
    Requires WAZUH_ALLOW_WRITES=true.
    """
    if dry_run:
        # Just count what would be affected
        count_body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term":  {"rule.id": str(rule_id)}},
                        {"term":  {"analyst_tag.keyword": "false_positive"}},
                        {"range": {"@timestamp": {"lte": f"now-{older_than_hours}h"}}},
                    ]
                }
            },
        }
        try:
            res = await idx.search(count_body)
            affected = res["hits"]["total"]["value"]
        except Exception as e:
            return {"error": f"Count query failed: {e}"}
        return {
            "dry_run": True,
            "rule_id": rule_id,
            "older_than_hours": older_than_hours,
            "alerts_that_would_be_untagged": affected,
            "message": (
                f"DRY RUN: Would remove false_positive tag from {affected} alert(s) "
                f"for rule {rule_id} tagged more than {older_than_hours}h ago. "
                "Set dry_run=False to apply. Requires WAZUH_ALLOW_WRITES=true."
            ),
        }

    blocked = _require_writes()
    if blocked:
        return blocked

    alerts_index = os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-4.x-*")
    ubq_url = f"{cfg.indexer_host}/{alerts_index}/_update_by_query"
    ubq_body = {
        "query": {
            "bool": {
                "filter": [
                    {"term":  {"rule.id": str(rule_id)}},
                    {"term":  {"analyst_tag.keyword": "false_positive"}},
                    {"range": {"@timestamp": {"lte": f"now-{older_than_hours}h"}}},
                ]
            }
        },
        "script": {
            "source": (
                "ctx._source.remove('analyst_tag');"
                " ctx._source.remove('analyst_note');"
                " ctx._source.remove('suppression_reason');"
                " ctx._source.suppression_expired_at = params.ts"
            ),
            "params": {"ts": datetime.datetime.utcnow().isoformat() + "Z"},
        },
    }
    try:
        async with httpx.AsyncClient(
            verify=cfg.verify_ssl,
            auth=(cfg.indexer_user, cfg.indexer_pass),
            timeout=60,
        ) as client:
            r = await client.post(ubq_url, json=ubq_body)
            data = r.json()
            updated = data.get("updated", 0)
            log.info("expire_suppression: cleared %d tag(s) for rule %s", updated, rule_id)
            return {
                "status":           "ok",
                "rule_id":          rule_id,
                "older_than_hours": older_than_hours,
                "alerts_untagged":  updated,
                "failures":         data.get("failures", []),
                "message": (
                    f"Removed false_positive tag from {updated} alert(s) for rule {rule_id} "
                    f"(tagged more than {older_than_hours}h ago). "
                    "Rule is now active for fresh evaluation."
                ),
            }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def noise_score_rule(
    rule_id: int,
    time_range: str = "7d",
) -> dict:
    """Compute a 0-100 noise score for a rule to guide tuning decisions.

    Score factors: FP rate (60%), alert volume (25%), agent spread (15%).
    Returns noise_tier (LOW/MEDIUM/HIGH/CRITICAL) and a concrete tuning suggestion.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term":  {"rule.id": str(rule_id)}},
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                ]
            }
        },
        "aggs": {
            "fp_tagged":     {"filter": {"term": {"analyst_tag.keyword": "false_positive"}}},
            "unique_agents": {"cardinality": {"field": "agent.id"}},
            "unique_srcips": {"cardinality": {"field": "data.srcip.keyword"}},
            "rule_desc":     {"terms": {"field": "rule.description.keyword", "size": 1}},
            "rule_level":    {"terms": {"field": "rule.level", "size": 1}},
        },
    }
    try:
        res = await idx.search(body)
    except Exception as e:
        return {"error": f"Indexer query failed: {e}"}

    aggs      = res.get("aggregations", {})
    total     = res["hits"]["total"]["value"]
    fp_count  = aggs.get("fp_tagged", {}).get("doc_count", 0)
    agents    = aggs.get("unique_agents", {}).get("value", 0)
    src_ips   = aggs.get("unique_srcips", {}).get("value", 0)
    desc_b    = aggs.get("rule_desc", {}).get("buckets", [])
    desc      = desc_b[0]["key"] if desc_b else "unknown"
    level_b   = aggs.get("rule_level", {}).get("buckets", [])
    level     = level_b[0]["key"] if level_b else 0

    if total == 0:
        return {
            "rule_id":   rule_id,
            "time_range": time_range,
            "message":   f"No alerts found for rule {rule_id} in the last {time_range}.",
        }

    fp_rate = round(fp_count / total * 100, 1)

    # Noise score: FP rate 60% + volume 25% + agent spread 15%
    # Volume: 2000+ alerts/week → 100; Agent spread: 20+ agents → 100
    volume_score = min(100, total / 20)
    spread_score = min(100, agents / 20 * 100)
    noise_score  = round(fp_rate * 0.60 + volume_score * 0.25 + spread_score * 0.15)

    if noise_score >= 75:
        tier = "CRITICAL"
    elif noise_score >= 50:
        tier = "HIGH"
    elif noise_score >= 25:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    # Tuning suggestion
    if tier == "CRITICAL" and fp_rate >= 80:
        suggestion = (
            "Disable rule or raise threshold drastically. "
            "Over 80% of alerts are analyst-confirmed false positives."
        )
    elif tier == "CRITICAL":
        suggestion = (
            f"Immediate tuning required. Add agent/IP exclusions for the "
            f"{agents} agent(s) generating noise. Consider an overwrite rule with "
            "<same_source_ip> or <if_matched_sid> conditions."
        )
    elif tier == "HIGH":
        suggestion = (
            f"Add exclusion conditions for the {agents} agent(s) triggering this rule. "
            "Review ossec.conf <rule_ignore> or add an overwrite rule "
            "with narrower match conditions."
        )
    elif tier == "MEDIUM":
        suggestion = (
            "Monitor for 7 more days. If FP rate stays above 20%, "
            "add contextual conditions (e.g. restrict to non-business-hours or specific agents)."
        )
    else:
        suggestion = "Rule is performing well. Continue monitoring."

    return {
        "rule_id":           rule_id,
        "rule_description":  desc,
        "rule_level":        level,
        "time_range":        time_range,
        "alert_count":       total,
        "fp_count":          fp_count,
        "fp_rate_pct":       fp_rate,
        "unique_agents":     agents,
        "unique_source_ips": src_ips,
        "noise_score":       noise_score,
        "noise_tier":        tier,
        "tuning_suggestion": suggestion,
    }
# ============================================================================
# Phase 1 — SOAR / ticketing / notification tools
# Paste this block into server.py after the suppression tools block above.
# New env vars required (see .env.phase1.example):
#   JIRA_URL, JIRA_USER, JIRA_API_TOKEN, JIRA_PROJECT_KEY
#   THEHIVE_URL, THEHIVE_API_KEY
#   SLACK_WEBHOOK_URL  (or SLACK_BOT_TOKEN + SLACK_DEFAULT_CHANNEL)
# Uses: cfg, mcp, httpx, os, datetime, log
# ============================================================================

# ── SOAR config (read once at module level, same as other env vars in server.py) ──
_JIRA_URL        = os.getenv("JIRA_URL", "")
_JIRA_USER       = os.getenv("JIRA_USER", "")
_JIRA_TOKEN      = os.getenv("JIRA_API_TOKEN", "")
_JIRA_PROJECT    = os.getenv("JIRA_PROJECT_KEY", "SOC")
_THEHIVE_URL     = os.getenv("THEHIVE_URL", "")
_THEHIVE_KEY     = os.getenv("THEHIVE_API_KEY", "")
_SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL", "")
_SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
_SLACK_CHANNEL   = os.getenv("SLACK_DEFAULT_CHANNEL", "#soc-alerts")
_SOAR_TIMEOUT    = 15  # seconds


@mcp.tool()
async def create_jira_ticket(
    title: str,
    description: str,
    severity: str = "High",
    affected_agents: list | None = None,
    mitre_techniques: list | None = None,
    alert_ids: list | None = None,
    assignee: str | None = None,
    labels: list | None = None,
) -> dict:
    """Create a Jira issue in the SOC project from a Wazuh incident.

    Typically called right after create_incident_report — pass the report
    title and description directly.
    severity: Critical | High | Medium | Low
    assignee: Jira accountId (not email) — find in Jira user profile URL.
    Requires JIRA_URL, JIRA_USER, JIRA_API_TOKEN in .env.
    """
    if not _JIRA_URL or not _JIRA_TOKEN:
        return {
            "error": "Jira not configured. Add JIRA_URL, JIRA_USER, JIRA_API_TOKEN to .env."
        }

    priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}
    jira_priority = priority_map.get(severity.lower(), "High")

    body_lines = [description, ""]
    if affected_agents:
        body_lines.append("*Affected agents:* " + ", ".join(str(a) for a in affected_agents))
    if mitre_techniques:
        body_lines.append("*MITRE techniques:* " + ", ".join(mitre_techniques))
    if alert_ids:
        body_lines.append("*Wazuh alert IDs:* " + ", ".join(str(i) for i in alert_ids[:10]))
    body_lines.append(
        f"\n_Created by Wazuh MCP at "
        f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_"
    )

    all_labels = ["wazuh-mcp", f"severity-{severity.lower()}"] + (labels or [])

    payload: dict = {
        "fields": {
            "project":     {"key": _JIRA_PROJECT},
            "summary":     title,
            "description": "\n".join(body_lines),
            "issuetype":   {"name": "Bug"},
            "priority":    {"name": jira_priority},
            "labels":      all_labels,
        }
    }
    if assignee:
        payload["fields"]["assignee"] = {"accountId": assignee}

    try:
        async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
            r = await client.post(
                f"{_JIRA_URL.rstrip('/')}/rest/api/2/issue",
                json=payload,
                auth=(_JIRA_USER, _JIRA_TOKEN),
                headers={"Content-Type": "application/json"},
            )
        r.raise_for_status()
        data      = r.json()
        issue_key = data.get("key", "")
        issue_url = f"{_JIRA_URL.rstrip('/')}/browse/{issue_key}"
        log.info("Created Jira issue %s for: %s", issue_key, title)
        return {
            "status":    "ok",
            "issue_key": issue_key,
            "issue_url": issue_url,
            "priority":  jira_priority,
            "message":   f"Jira issue {issue_key} created: {issue_url}",
        }
    except httpx.HTTPStatusError as e:
        return {"error": f"Jira API {e.response.status_code}: {e.response.text[:300]}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def create_thehive_case(
    title: str,
    description: str,
    severity: str = "High",
    affected_agents: list | None = None,
    mitre_techniques: list | None = None,
    alert_ids: list | None = None,
    tags: list | None = None,
    tlp: int = 2,
    pap: int = 2,
) -> dict:
    """Open a TheHive 5 case from a Wazuh incident report.

    severity: Low | Medium | High | Critical
    tlp: 0=WHITE 1=GREEN 2=AMBER 3=RED (default AMBER)
    pap: 0=WHITE 1=GREEN 2=AMBER 3=RED (default AMBER)
    Requires THEHIVE_URL and THEHIVE_API_KEY in .env.
    """
    if not _THEHIVE_URL or not _THEHIVE_KEY:
        return {
            "error": "TheHive not configured. Add THEHIVE_URL, THEHIVE_API_KEY to .env."
        }

    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    hive_severity = severity_map.get(severity.lower(), 3)

    extra = []
    if affected_agents:
        extra.append(f"**Affected agents:** {', '.join(str(a) for a in affected_agents)}")
    if mitre_techniques:
        extra.append(f"**MITRE techniques:** {', '.join(mitre_techniques)}")
    if alert_ids:
        extra.append(f"**Wazuh alert IDs:** {', '.join(str(i) for i in alert_ids[:10])}")

    full_desc = description
    if extra:
        full_desc += "\n\n---\n" + "\n\n".join(extra)
    full_desc += (
        f"\n\n_Source: Wazuh MCP — "
        f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_"
    )

    all_tags = ["wazuh", "wazuh-mcp", f"severity:{severity.lower()}"]
    if mitre_techniques:
        all_tags += [f"mitre:{t}" for t in mitre_techniques]
    if tags:
        all_tags += tags

    payload = {
        "title":       title,
        "description": full_desc,
        "severity":    hive_severity,
        "tlp":         tlp,
        "pap":         pap,
        "tags":        all_tags,
        "flag":        False,
        "status":      "New",
    }
    try:
        async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
            r = await client.post(
                f"{_THEHIVE_URL.rstrip('/')}/api/v1/case",
                json=payload,
                headers={
                    "Authorization":  f"Bearer {_THEHIVE_KEY}",
                    "Content-Type":   "application/json",
                },
            )
        r.raise_for_status()
        data     = r.json()
        case_id  = data.get("_id", "")
        case_num = data.get("caseId", "")
        case_url = f"{_THEHIVE_URL.rstrip('/')}/cases/{case_id}"
        log.info("Created TheHive case #%s (%s) for: %s", case_num, case_id, title)
        return {
            "status":   "ok",
            "case_id":  case_id,
            "case_num": case_num,
            "case_url": case_url,
            "severity": hive_severity,
            "message":  f"TheHive case #{case_num} created: {case_url}",
        }
    except httpx.HTTPStatusError as e:
        return {"error": f"TheHive API {e.response.status_code}: {e.response.text[:300]}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def update_ticket_status(
    issue_key: str,
    new_status: str,
    comment: str | None = None,
    resolution: str | None = None,
) -> dict:
    """Transition a Jira issue to a new workflow status.

    Common values for new_status: 'In Progress', 'Done', 'Resolved', 'Closed'.
    resolution: e.g. 'Fixed', 'Won\\'t Fix', 'Duplicate' (used when closing).
    Requires JIRA_URL, JIRA_USER, JIRA_API_TOKEN in .env.
    """
    if not _JIRA_URL or not _JIRA_TOKEN:
        return {
            "error": "Jira not configured. Add JIRA_URL, JIRA_USER, JIRA_API_TOKEN to .env."
        }
    try:
        async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
            tr_r = await client.get(
                f"{_JIRA_URL.rstrip('/')}/rest/api/2/issue/{issue_key}/transitions",
                auth=(_JIRA_USER, _JIRA_TOKEN),
            )
            tr_r.raise_for_status()
            transitions = tr_r.json().get("transitions", [])

        match = next(
            (t for t in transitions if t["to"]["name"].lower() == new_status.lower()),
            None,
        )
        if not match:
            available = [t["to"]["name"] for t in transitions]
            return {
                "error": (
                    f"Transition '{new_status}' not found for {issue_key}. "
                    f"Available: {available}"
                )
            }

        tr_payload: dict = {"transition": {"id": match["id"]}}
        if resolution:
            tr_payload["fields"] = {"resolution": {"name": resolution}}
        if comment:
            tr_payload["update"] = {"comment": [{"add": {"body": comment}}]}

        async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
            do_r = await client.post(
                f"{_JIRA_URL.rstrip('/')}/rest/api/2/issue/{issue_key}/transitions",
                json=tr_payload,
                auth=(_JIRA_USER, _JIRA_TOKEN),
                headers={"Content-Type": "application/json"},
            )
        do_r.raise_for_status()
        log.info("Transitioned Jira %s → %s", issue_key, new_status)
        return {
            "status":     "ok",
            "issue_key":  issue_key,
            "new_status": new_status,
            "issue_url":  f"{_JIRA_URL.rstrip('/')}/browse/{issue_key}",
            "message":    f"{issue_key} transitioned to '{new_status}'.",
        }
    except httpx.HTTPStatusError as e:
        return {"error": f"Jira API {e.response.status_code}: {e.response.text[:300]}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def send_alert_to_slack(
    message: str,
    title: str | None = None,
    severity: str = "info",
    channel: str | None = None,
    fields: dict | None = None,
    ticket_url: str | None = None,
) -> dict:
    """Push a formatted message to a Slack channel.

    Use for ad-hoc notifications, critical alert escalations, or sharing reports.
    severity: info | warning | critical  (controls attachment colour)
    channel: override default channel (e.g. '#incident-response')
    fields: dict of key→value pairs shown as Slack attachment fields
    ticket_url: link to Jira/TheHive ticket if already created
    Requires SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN in .env.
    """
    if not _SLACK_WEBHOOK and not _SLACK_BOT_TOKEN:
        return {
            "error": "Slack not configured. Add SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN to .env."
        }

    color_map = {"critical": "#ff0000", "warning": "#ffaa00", "info": "#36a64f"}
    color = color_map.get(severity.lower(), "#36a64f")

    attachment: dict = {"color": color, "text": message, "mrkdwn_in": ["text", "fields"]}
    if title:
        attachment["title"] = title
    if ticket_url:
        attachment["title_link"] = ticket_url
        attachment["footer"] = "Wazuh MCP"
    if fields:
        attachment["fields"] = [
            {"title": k, "value": str(v), "short": len(str(v)) < 40}
            for k, v in fields.items()
        ]

    target_channel = channel or _SLACK_CHANNEL

    # Try webhook first (no OAuth scopes needed)
    if _SLACK_WEBHOOK:
        try:
            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                r = await client.post(_SLACK_WEBHOOK, json={"attachments": [attachment]})
            r.raise_for_status()
            log.info("Slack message sent via webhook severity=%s", severity)
            return {"status": "ok", "method": "webhook", "message": "Sent to Slack."}
        except Exception as e:
            return {"error": f"Slack webhook failed: {e}"}

    # Fallback: bot token
    try:
        async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
            r = await client.post(
                "https://slack.com/api/chat.postMessage",
                json={"channel": target_channel, "attachments": [attachment]},
                headers={
                    "Authorization": f"Bearer {_SLACK_BOT_TOKEN}",
                    "Content-Type":  "application/json",
                },
            )
        data = r.json()
        if not data.get("ok"):
            return {"error": f"Slack API error: {data.get('error')}"}
        log.info("Slack message sent via bot token to %s", target_channel)
        return {"status": "ok", "method": "bot_token", "channel": target_channel}
    except Exception as e:
        return {"error": str(e)}
# ============================================================================
# Phase 1 — Agent enrollment & onboarding workflow
# Paste this block into server.py after the SOAR tools block above.
# New env var (optional): WAZUH_REGISTRATION_PASSWORD
# Uses: wz, idx, cfg, mcp, _require_writes(), _cap(), datetime, os, log
# ============================================================================


@mcp.tool()
async def generate_enrollment_command(
    agent_name: str,
    os_type: str,
    group: str = "default",
    wazuh_manager_ip: str | None = None,
    registration_password: str | None = None,
) -> dict:
    """Generate the exact Wazuh agent installation command for a given OS.

    os_type: ubuntu | debian | centos | rhel | amazon_linux | windows | macos
    group: agent group to enroll into (default: 'default')
    wazuh_manager_ip: override the manager IP shown in the command
                      (defaults to WAZUH_HOST env var, protocol stripped)
    Supports Wazuh 4.x package URLs.
    """
    # Resolve manager IP — strip protocol and port from WAZUH_HOST
    raw_host = wazuh_manager_ip or cfg.manager_host
    manager_ip = raw_host.replace("https://", "").replace("http://", "").split(":")[0]

    reg_pass = registration_password or os.getenv("WAZUH_REGISTRATION_PASSWORD", "")

    # Try to get exact Wazuh version from manager API
    wazuh_ver = "4.7.5"
    try:
        ver_resp = await wz.request("GET", "/")
        wazuh_ver = (
            (ver_resp.get("data") or {}).get("api_version", wazuh_ver)
            or wazuh_ver
        )
    except Exception:
        pass  # use default version above

    os_norm = os_type.lower().replace("-", "_").replace(" ", "_")

    reg_env_linux = f'WAZUH_REGISTRATION_PASSWORD="{reg_pass}" \\\n     ' if reg_pass else ""
    reg_arg_win   = f'WAZUH_REGISTRATION_PASSWORD="{reg_pass}" `\n  ' if reg_pass else ""

    if os_norm in ("ubuntu", "debian"):
        pkg = f"wazuh-agent_{wazuh_ver}-1_amd64.deb"
        url = f"https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/{pkg}"
        command = (
            f"# 1. Download and install\n"
            f"curl -o /tmp/{pkg} \"{url}\"\n"
            f"sudo WAZUH_MANAGER=\"{manager_ip}\" \\\n"
            f"     WAZUH_AGENT_NAME=\"{agent_name}\" \\\n"
            f"     WAZUH_AGENT_GROUP=\"{group}\" \\\n"
            f"     {reg_env_linux}dpkg -i /tmp/{pkg}\n\n"
            f"# 2. Enable and start\n"
            f"sudo systemctl daemon-reload\n"
            f"sudo systemctl enable wazuh-agent\n"
            f"sudo systemctl start wazuh-agent\n\n"
            f"# 3. Verify\n"
            f"sudo systemctl status wazuh-agent"
        )
        notes = f"Package: {pkg}. Alternatively: add the Wazuh apt repo and run `sudo apt-get install wazuh-agent={wazuh_ver}-1`."

    elif os_norm in ("centos", "rhel", "amazon_linux", "fedora", "suse"):
        pkg = f"wazuh-agent-{wazuh_ver}-1.x86_64.rpm"
        url = f"https://packages.wazuh.com/4.x/yum/{pkg}"
        command = (
            f"# 1. Download and install\n"
            f"curl -o /tmp/{pkg} \"{url}\"\n"
            f"sudo WAZUH_MANAGER=\"{manager_ip}\" \\\n"
            f"     WAZUH_AGENT_NAME=\"{agent_name}\" \\\n"
            f"     WAZUH_AGENT_GROUP=\"{group}\" \\\n"
            f"     {reg_env_linux}rpm -ihv /tmp/{pkg}\n\n"
            f"# 2. Enable and start\n"
            f"sudo systemctl daemon-reload\n"
            f"sudo systemctl enable wazuh-agent\n"
            f"sudo systemctl start wazuh-agent\n\n"
            f"# 3. Verify\n"
            f"sudo systemctl status wazuh-agent"
        )
        notes = "Works on CentOS 7/8, RHEL 7/8/9, Amazon Linux 2, Fedora. For SUSE: add Wazuh zypper repo."

    elif os_norm == "windows":
        msi = f"wazuh-agent-{wazuh_ver}-1.msi"
        url = f"https://packages.wazuh.com/4.x/windows/{msi}"
        command = (
            f"# Run in PowerShell as Administrator\n\n"
            f"# 1. Download\n"
            f"Invoke-WebRequest -Uri \"{url}\" -OutFile \"$env:TEMP\\{msi}\"\n\n"
            f"# 2. Install silently\n"
            f"msiexec.exe /i \"$env:TEMP\\{msi}\" /q `\n"
            f"  WAZUH_MANAGER=\"{manager_ip}\" `\n"
            f"  WAZUH_AGENT_NAME=\"{agent_name}\" `\n"
            f"  WAZUH_AGENT_GROUP=\"{group}\" `\n"
            f"  {reg_arg_win}/l*v \"$env:TEMP\\wazuh-install.log\"\n\n"
            f"# 3. Start service\n"
            f"NET START WazuhSvc\n\n"
            f"# 4. Verify\n"
            f"Get-Service WazuhSvc"
        )
        notes = f"MSI: {msi}. Requires .NET 4.5+ and PowerShell 3.0+. Log at %TEMP%\\wazuh-install.log."

    elif os_norm == "macos":
        pkg = f"wazuh-agent-{wazuh_ver}-1.pkg"
        url = f"https://packages.wazuh.com/4.x/macos/{pkg}"
        reg_launchctl = (
            f"sudo launchctl setenv WAZUH_REGISTRATION_PASSWORD \"{reg_pass}\"\n"
            if reg_pass else ""
        )
        command = (
            f"# 1. Download\n"
            f"curl -o /tmp/{pkg} \"{url}\"\n\n"
            f"# 2. Set env vars\n"
            f"sudo launchctl setenv WAZUH_MANAGER \"{manager_ip}\"\n"
            f"sudo launchctl setenv WAZUH_AGENT_NAME \"{agent_name}\"\n"
            f"sudo launchctl setenv WAZUH_AGENT_GROUP \"{group}\"\n"
            f"{reg_launchctl}\n"
            f"# 3. Install\n"
            f"sudo installer -pkg /tmp/{pkg} -target /\n\n"
            f"# 4. Start\n"
            f"sudo /Library/Ossec/bin/wazuh-control start\n\n"
            f"# 5. Verify\n"
            f"sudo /Library/Ossec/bin/wazuh-control status"
        )
        notes = "Requires macOS 10.15+. On Sequoia+: approve extension in System Settings → Privacy & Security."

    else:
        return {
            "error": (
                f"Unsupported os_type: '{os_type}'. "
                "Supported: ubuntu, debian, centos, rhel, amazon_linux, windows, macos"
            )
        }

    return {
        "agent_name":      agent_name,
        "os_type":         os_type,
        "manager_ip":      manager_ip,
        "group":           group,
        "wazuh_version":   wazuh_ver,
        "install_command": command,
        "notes":           notes,
        "next_steps": [
            "Run the install_command above as root/Administrator on the target host.",
            f"Verify enrollment: list_agents(status='pending') — look for '{agent_name}'.",
            f"Confirm it comes online: agent_onboarding_checklist(agent_name='{agent_name}').",
        ],
    }


@mcp.tool()
async def list_never_connected_agents(limit: int = 50) -> dict:
    """List agents that enrolled in the manager but have never sent a heartbeat.

    Useful for finding failed deployments, stale enrollments, and debugging
    connectivity issues. Includes troubleshooting tips per agent.
    """
    try:
        result = await wz.request(
            "GET", f"/agents?status=never_connected&limit={_cap(limit)}&offset=0"
        )
    except Exception as e:
        return {"error": str(e)}

    items = (result.get("data") or {}).get("affected_items", [])
    total = (result.get("data") or {}).get("total_affected_items", 0)

    if not items:
        return {
            "count":   0,
            "total":   0,
            "agents":  [],
            "message": "No never_connected agents found. All enrolled agents have checked in.",
        }

    formatted = [
        {
            "agent_id":        a.get("id"),
            "agent_name":      a.get("name"),
            "os":              (a.get("os") or {}).get("name", "unknown"),
            "ip":              a.get("ip", "unknown"),
            "registered_date": a.get("dateAdd", "unknown"),
            "groups":          a.get("group", ["default"]),
        }
        for a in items
    ]

    return {
        "count":   len(formatted),
        "total":   total,
        "agents":  formatted,
        "message": (
            f"Found {total} never_connected agent(s). "
            "These enrolled but have not yet sent any events."
        ),
        "troubleshooting_checklist": [
            "1. Verify agent service is running: systemctl status wazuh-agent",
            "2. Check manager IP in /var/ossec/etc/ossec.conf → <server><address>",
            "3. Test connectivity: nc -zv <manager_ip> 1514 && nc -zv <manager_ip> 1515",
            "4. Check manager logs: tail -f /var/ossec/logs/ossec.log | grep <agent_name>",
            "5. Firewall: ensure outbound 1514/UDP (events) and 1515/TCP (registration) are open.",
        ],
    }


@mcp.tool()
async def agent_onboarding_checklist(
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict:
    """Run a 6-point health check on a newly enrolled agent.

    Checks: registered, active status, non-default group, sending events,
    SCA policy loaded, syscollector data available.
    Provide either agent_id (e.g. '005') or agent_name (e.g. 'webserver-01').
    """
    if not agent_id and not agent_name:
        return {"error": "Provide agent_id or agent_name."}

    checks: list[dict] = []
    overall_ok = True

    def _check(name: str, passed: bool, detail: str, warn_only: bool = False) -> dict:
        if passed:
            result = "pass"; icon = "✓"
        elif warn_only:
            result = "warn"; icon = "⚠"
        else:
            result = "fail"; icon = "✗"
        return {"check": name, "result": result, "icon": icon, "detail": detail}

    # ── Resolve agent_id from name if needed ─────────────────────────────────
    if not agent_id:
        try:
            r = await wz.request("GET", f"/agents?name={agent_name}&limit=1")
            items = (r.get("data") or {}).get("affected_items", [])
            if not items:
                return {"error": f"No agent found with name '{agent_name}'."}
            agent_id = items[0]["id"]
        except Exception as e:
            return {"error": f"Agent lookup failed: {e}"}

    # ── Check 1: Registered ───────────────────────────────────────────────────
    agent_data: dict = {}
    try:
        r = await wz.request("GET", f"/agents?agents_list={agent_id}")
        items = (r.get("data") or {}).get("affected_items", [])
        if items:
            agent_data = items[0]
            checks.append(_check(
                "Registered in manager", True,
                f"Agent ID: {agent_id}, Name: {agent_data.get('name')}",
            ))
        else:
            checks.append(_check("Registered in manager", False, "Agent not found."))
            overall_ok = False
    except Exception as e:
        checks.append(_check("Registered in manager", False, str(e)))
        overall_ok = False

    resolved_name = agent_data.get("name", agent_id)

    # ── Check 2: Active status ────────────────────────────────────────────────
    status = agent_data.get("status", "unknown")
    active = status == "active"
    if not active:
        overall_ok = False
    checks.append(_check(
        "Agent status is active", active,
        f"Status: {status}" + (
            " — connected and sending heartbeats." if active
            else " — not connected. Verify service is running and firewall allows port 1514."
        ),
    ))

    # ── Check 3: Non-default group ────────────────────────────────────────────
    groups = agent_data.get("group", [])
    in_custom_group = bool(groups) and groups != ["default"]
    checks.append(_check(
        "Assigned to a policy group", in_custom_group,
        f"Groups: {groups}",
        warn_only=True,  # Not a blocker, just good practice
    ))

    # ── Check 4: Sending events (last 30 min) ─────────────────────────────────
    try:
        event_body = {
            "size": 1,
            "query": {
                "bool": {
                    "filter": [
                        {"term":  {"agent.id": agent_id}},
                        {"range": {"@timestamp": {"gte": "now-30m"}}},
                    ]
                }
            },
        }
        er = await idx.search(event_body)
        event_count = er["hits"]["total"]["value"]
        has_events = event_count > 0
        if not has_events:
            overall_ok = False
        checks.append(_check(
            "Sending events (last 30 min)", has_events,
            f"{event_count} alert(s) in last 30 min." if has_events
            else "No events yet. Check ossec.conf <logall> or wait ~5 min after start.",
        ))
    except Exception as e:
        checks.append(_check("Sending events (last 30 min)", False, f"Indexer query failed: {e}"))
        overall_ok = False

    # ── Check 5: SCA policy loaded ────────────────────────────────────────────
    try:
        r = await wz.request("GET", f"/sca/{agent_id}?limit=5")
        policies = (r.get("data") or {}).get("affected_items", [])
        has_sca = len(policies) > 0
        if not has_sca:
            overall_ok = False
        checks.append(_check(
            "SCA policy loaded", has_sca,
            f"{len(policies)} policy(ies): " + ", ".join(p.get("name", "") for p in policies)
            if has_sca else "No SCA policies. Assign agent to a group with SCA configured.",
        ))
    except Exception as e:
        checks.append(_check("SCA policy loaded", False, f"SCA query failed: {e}"))

    # ── Check 6: Syscollector data present ────────────────────────────────────
    try:
        r = await wz.request("GET", f"/syscollector/{agent_id}/packages?limit=1")
        pkg_total = (r.get("data") or {}).get("total_affected_items", 0)
        has_syscollector = pkg_total > 0
        if not has_syscollector:
            overall_ok = False
        checks.append(_check(
            "Syscollector data available", has_syscollector,
            f"{pkg_total} packages indexed." if has_syscollector
            else "Syscollector hasn't run yet. Usually completes within 5 min of first start.",
        ))
    except Exception as e:
        checks.append(_check("Syscollector data available", False, f"Syscollector query failed: {e}"))

    passed   = sum(1 for c in checks if c["result"] == "pass")
    warnings = sum(1 for c in checks if c["result"] == "warn")
    failed   = sum(1 for c in checks if c["result"] == "fail")

    if overall_ok:
        overall = "READY"
    elif failed == 0:
        overall = "READY WITH WARNINGS"
    elif passed >= 4:
        overall = "PARTIAL"
    else:
        overall = "NOT READY"

    return {
        "agent_id":      agent_id,
        "agent_name":    resolved_name,
        "overall":       overall,
        "checks_passed": passed,
        "checks_warned": warnings,
        "checks_failed": failed,
        "checks":        checks,
        "summary": (
            f"Agent '{resolved_name}' onboarding: {passed}/{len(checks)} checks passed. "
            + ("Agent is fully operational." if overall_ok
               else f"{failed} issue(s) need attention.")
        ),
    }
# ============================================================================
# Phase 1 — Push report delivery (Slack + Email)
# Paste this block into server.py after the agent enrollment tools block above.
# New env vars required (see .env.phase1.example):
#   SLACK_SOC_CHANNEL, SLACK_MGMT_CHANNEL
#   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
#   REPORT_EMAIL_FROM, REPORT_EMAIL_TO
# Uses: cfg, mcp, httpx, os, datetime, log, smtplib (stdlib)
#       + calls existing tools: generate_shift_handover, generate_weekly_summary,
#         generate_compliance_report, alert_summary (already in server.py)
# ============================================================================

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

_SLACK_SOC_CHANNEL  = os.getenv("SLACK_SOC_CHANNEL",  os.getenv("SLACK_DEFAULT_CHANNEL", "#soc-handover"))
_SLACK_MGMT_CHANNEL = os.getenv("SLACK_MGMT_CHANNEL", "#security-mgmt")
_SMTP_HOST          = os.getenv("SMTP_HOST", "smtp.gmail.com")
_SMTP_PORT          = int(os.getenv("SMTP_PORT", "587"))
_SMTP_USER          = os.getenv("SMTP_USER", "")
_SMTP_PASS          = os.getenv("SMTP_PASS", "")
_EMAIL_FROM         = os.getenv("REPORT_EMAIL_FROM", _SMTP_USER)
_EMAIL_TO           = os.getenv("REPORT_EMAIL_TO", "")


async def _post_slack_blocks(channel: str, blocks: list, fallback: str) -> dict:
    """Internal: post Block Kit blocks to Slack via webhook or bot token."""
    # _SLACK_WEBHOOK and _SLACK_BOT_TOKEN are already defined in the SOAR block above
    if _SLACK_WEBHOOK:
        try:
            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                r = await client.post(
                    _SLACK_WEBHOOK,
                    json={"blocks": blocks, "text": fallback},
                )
            r.raise_for_status()
            return {"status": "ok", "method": "webhook"}
        except Exception as e:
            return {"error": str(e)}

    if _SLACK_BOT_TOKEN:
        try:
            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                r = await client.post(
                    "https://slack.com/api/chat.postMessage",
                    json={"channel": channel, "blocks": blocks, "text": fallback},
                    headers={
                        "Authorization": f"Bearer {_SLACK_BOT_TOKEN}",
                        "Content-Type":  "application/json",
                    },
                )
            data = r.json()
            if not data.get("ok"):
                return {"error": f"Slack: {data.get('error')}"}
            return {"status": "ok", "method": "bot_token", "ts": data.get("ts")}
        except Exception as e:
            return {"error": str(e)}

    return {"error": "Slack not configured. Add SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN to .env."}


@mcp.tool()
async def send_shift_handover_to_slack(
    analyst_name: str = "SOC Analyst",
    shift_duration: str = "8h",
    channel: str | None = None,
) -> dict:
    """Generate a shift handover report and push it to Slack immediately.

    Wraps the existing generate_shift_handover tool and delivers it to Slack
    in one call. Run at end of each shift.
    shift_duration: '6h', '8h', '12h', '24h'
    Requires SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN in .env.
    """
    if not _SLACK_WEBHOOK and not _SLACK_BOT_TOKEN:
        return {"error": "Slack not configured. Add SLACK_WEBHOOK_URL to .env."}

    report = await generate_shift_handover(
        shift_duration=shift_duration,
        analyst_name=analyst_name,
    )

    ts_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    target = channel or _SLACK_SOC_CHANNEL

    # Extract key numbers for the Slack summary
    overview = report.get("alert_overview") or {}
    total_alerts = overview.get("total_alerts", "N/A")
    trend = (overview.get("trend") or {}).get("direction", "?")

    attention_items = (report.get("shift_handover") or {}).get("attention_items", [])
    attention_text  = "\n".join(f"• {item}" for item in attention_items[:5])

    top_rules = overview.get("top_rules", [])[:5]
    rules_text = "\n".join(
        f"• Rule {r.get('rule_id')} — {r.get('count')} alerts ({r.get('description', '')[:50]})"
        for r in top_rules
    ) or "_No significant rules_"

    volume_data = report.get("volume_vs_baseline") or {}
    delta_pct   = volume_data.get("delta_pct")
    volume_text = f"{delta_pct:+.1f}% vs prior period" if isinstance(delta_pct, (int, float)) else "N/A"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔒 Wazuh Shift Handover — {ts_str}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Outgoing analyst:*\n{analyst_name}"},
                {"type": "mrkdwn", "text": f"*Shift:*\n{shift_duration}"},
                {"type": "mrkdwn", "text": f"*Total alerts:*\n{total_alerts} {trend}"},
                {"type": "mrkdwn", "text": f"*Volume vs baseline:*\n{volume_text}"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Attention items*\n{attention_text or '✓ Clean handover — no anomalies.'}",
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top rules this shift*\n{rules_text}"},
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Posted by Wazuh MCP"}],
        },
    ]

    result = await _post_slack_blocks(target, blocks, f"Wazuh Shift Handover — {ts_str}")
    return {**result, "channel": target, "analyst": analyst_name, "shift_duration": shift_duration}


@mcp.tool()
async def send_weekly_summary_to_slack(
    week_offset: int = 0,
    channel: str | None = None,
) -> dict:
    """Generate the weekly security summary and push it to Slack.

    week_offset: 0 = current week, 1 = last week.
    Requires SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN in .env.
    """
    if not _SLACK_WEBHOOK and not _SLACK_BOT_TOKEN:
        return {"error": "Slack not configured. Add SLACK_WEBHOOK_URL to .env."}

    report = await generate_weekly_summary(week_offset=week_offset)

    ts_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    label  = "This week" if week_offset == 0 else "Last week"
    target = channel or _SLACK_MGMT_CHANNEL

    total   = report.get("total_alerts", "N/A")
    trend   = (report.get("trend") or {}).get("direction", "?")
    delta   = (report.get("trend") or {}).get("delta_pct")
    delta_s = f"{delta:+.1f}%" if isinstance(delta, (int, float)) else "N/A"

    top_rules = report.get("top_rules", [])[:5]
    rules_text = "\n".join(
        f"• {r.get('rule')} — {r.get('count')} alerts" for r in top_rules
    ) or "_No significant rules_"

    top_mitre = report.get("top_mitre_techniques", [])[:3]
    mitre_text = "\n".join(
        f"• {t.get('id')} {t.get('name', '')} ({t.get('count', 0)})" for t in top_mitre
    ) or "_None observed_"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"📊 Weekly Security Summary — {label} ({ts_str})"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Total alerts:*\n{total} {trend}"},
                {"type": "mrkdwn", "text": f"*Week-on-week:*\n{delta_s}"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top rules*\n{rules_text}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top MITRE techniques*\n{mitre_text}"},
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Posted by Wazuh MCP"}],
        },
    ]

    result = await _post_slack_blocks(target, blocks, f"Wazuh Weekly Summary — {ts_str}")
    return {**result, "channel": target, "week_offset": week_offset}


@mcp.tool()
async def email_compliance_report(
    framework: str = "pci_dss",
    time_range: str = "168h",
    recipients: list | None = None,
) -> dict:
    """Generate a compliance report and email it as formatted HTML.

    framework: pci_dss | hipaa | gdpr | nist_800_53 | tsc
    time_range: reporting window (168h = 7 days)
    recipients: list of email addresses (overrides REPORT_EMAIL_TO env var)
    Requires SMTP_USER, SMTP_PASS, REPORT_EMAIL_TO in .env.
    """
    if not _SMTP_USER or not _SMTP_PASS:
        return {"error": "SMTP not configured. Add SMTP_USER and SMTP_PASS to .env."}

    to_addresses = recipients or [r.strip() for r in _EMAIL_TO.split(",") if r.strip()]
    if not to_addresses:
        return {
            "error": "No recipients. Set REPORT_EMAIL_TO in .env or pass recipients list."
        }

    report = await generate_compliance_report(framework=framework, time_range=time_range)
    if "error" in report:
        return report

    ts_str  = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    subject = f"[Wazuh SOC] {framework.upper()} Compliance Report — {ts_str}"

    # Build HTML
    controls    = report.get("controls", [])
    failing_cnt = report.get("failing_controls_count", 0)
    total_alerts = report.get("total_alerts", 0)

    rows_html = ""
    for ctrl in controls[:30]:
        color = "#d32f2f" if ctrl.get("status") == "FAILING" else (
                "#f57c00" if ctrl.get("status") == "WARNING" else "#388e3c")
        rows_html += (
            f"<tr>"
            f"<td style='padding:5px 8px;border-bottom:1px solid #eee'>{ctrl.get('control','')}</td>"
            f"<td style='padding:5px 8px;border-bottom:1px solid #eee'>{ctrl.get('total_alerts',0)}</td>"
            f"<td style='padding:5px 8px;border-bottom:1px solid #eee;color:{color};font-weight:bold'>"
            f"{ctrl.get('status','')}</td>"
            f"<td style='padding:5px 8px;border-bottom:1px solid #eee;font-size:12px'>"
            f"{', '.join(ctrl.get('top_agents',[])[:3])}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html><body style='font-family:Arial,sans-serif;color:#222;max-width:820px;margin:auto'>
<h2 style='background:#1a237e;color:#fff;padding:14px 18px;border-radius:4px;margin:0'>
  {framework.upper()} Compliance Report &mdash; {ts_str}
</h2>
<p style='color:#555;margin:12px 0'>
  Reporting window: <strong>{time_range}</strong> &nbsp;|&nbsp;
  Generated by: <strong>Wazuh MCP</strong>
</p>
<table style='width:100%;border-collapse:collapse;margin-bottom:20px'>
  <tr>
    <td style='background:#e8eaf6;padding:12px;border-radius:4px;text-align:center;width:33%'>
      <div style='font-size:26px;font-weight:bold'>{total_alerts}</div>
      <div style='color:#555;font-size:13px'>Total alerts</div>
    </td>
    <td style='width:2%'></td>
    <td style='background:#fce4ec;padding:12px;border-radius:4px;text-align:center;width:33%'>
      <div style='font-size:26px;font-weight:bold;color:#c62828'>{failing_cnt}</div>
      <div style='color:#555;font-size:13px'>Failing controls</div>
    </td>
    <td style='width:2%'></td>
    <td style='background:#e8f5e9;padding:12px;border-radius:4px;text-align:center;width:30%'>
      <div style='font-size:26px;font-weight:bold;color:#2e7d32'>
        {len(controls) - failing_cnt}
      </div>
      <div style='color:#555;font-size:13px'>Passing controls</div>
    </td>
  </tr>
</table>
<table style='width:100%;border-collapse:collapse;font-size:13px'>
  <tr style='background:#f5f5f5;font-weight:bold'>
    <th style='padding:6px 8px;text-align:left'>Control</th>
    <th style='padding:6px 8px;text-align:left'>Alerts</th>
    <th style='padding:6px 8px;text-align:left'>Status</th>
    <th style='padding:6px 8px;text-align:left'>Top agents</th>
  </tr>
  {rows_html}
</table>
<p style='color:#aaa;font-size:11px;margin-top:24px'>
  Auto-generated by Wazuh MCP. Do not reply to this email.
</p>
</body></html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = _EMAIL_FROM
        msg["To"]      = ", ".join(to_addresses)
        msg["Subject"] = subject
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(_SMTP_USER, _SMTP_PASS)
            smtp.sendmail(_EMAIL_FROM, to_addresses, msg.as_string())

        log.info("Compliance report emailed to %s", to_addresses)
        return {
            "status":     "ok",
            "framework":  framework,
            "recipients": to_addresses,
            "subject":    subject,
            "message":    f"{framework.upper()} report sent to {', '.join(to_addresses)}.",
        }
    except smtplib.SMTPException as e:
        return {"error": f"SMTP error: {e}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def send_critical_alert_notify(
    alert_id: str,
    rule_id: str,
    rule_description: str,
    agent_name: str,
    severity_level: int,
    source_ip: str | None = None,
    channel: str | None = None,
    ticket_url: str | None = None,
) -> dict:
    """Fire an instant Slack notification for a critical alert.

    severity_level >= 12 → CRITICAL (red), 9-11 → HIGH (orange), <9 → MEDIUM (yellow).
    ticket_url: link to Jira/TheHive ticket if already created.
    Requires SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN in .env.
    """
    if not _SLACK_WEBHOOK and not _SLACK_BOT_TOKEN:
        return {"error": "Slack not configured. Add SLACK_WEBHOOK_URL to .env."}

    ts_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    target = channel or _SLACK_SOC_CHANNEL

    if severity_level >= 12:
        tier = "CRITICAL"; emoji = "🚨"; color = "#ff0000"
    elif severity_level >= 9:
        tier = "HIGH";     emoji = "⚠️"; color = "#ff6600"
    else:
        tier = "MEDIUM";   emoji = "🔔"; color = "#ffaa00"

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {tier} Alert — {ts_str}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Rule:* `{rule_id}`"},
                {"type": "mrkdwn", "text": f"*Level:* {severity_level}"},
                {"type": "mrkdwn", "text": f"*Agent:* {agent_name}"},
                {"type": "mrkdwn", "text": f"*Source IP:* {source_ip or 'N/A'}"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{rule_description}*"},
        },
    ]

    if ticket_url:
        blocks.append({
            "type": "actions",
            "elements": [{
                "type":  "button",
                "text":  {"type": "plain_text", "text": "View Ticket"},
                "url":   ticket_url,
                "style": "danger",
            }],
        })

    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"Alert ID: `{alert_id}` | Wazuh MCP"},
        ],
    })

    result = await _post_slack_blocks(
        target, blocks,
        f"[{tier}] Rule {rule_id} on {agent_name}: {rule_description}",
    )
    return {**result, "channel": target, "severity_tier": tier, "alert_id": alert_id}

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
4. enrich_ip_geo for each top IP — geolocation context
5. correlate_alert_with_response for the highest-volume IP — did Wazuh block it?
6. If NOT blocked: blast_radius_analysis to assess lateral spread

Conclude with:
- What happened and which accounts/services were targeted
- Whether the attack is ongoing or was blocked
- Recommended action (add_to_cdb_list if ALLOW_WRITES=true, or escalate)"""


@mcp.prompt()
def weekly_soc_briefing() -> str:
    """Generate a complete weekly SOC executive briefing."""
    return """Generate the weekly SOC executive briefing by calling these tools in order:

1. compare_alert_volume(current_range="7d", baseline_offset="7d") — volume trend
2. detect_rule_anomalies(current_range="7d") — new/spiking/silent rules
3. generate_weekly_summary() — aggregated top rules, agents, MITRE
4. vulnerability_summary(min_severity="Critical") — fleet CVE posture
5. prioritize_patches(top_n=5) — top patches by exposure × CVSS
6. active_response_effectiveness(time_range="7d") — block effectiveness rate
7. fleet_sca_weakest_agents(limit=5) — most misconfigured agents
8. mitre_coverage_analysis() — ATT&CK technique coverage stats

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
5. enrich_ip_geo([src_ip]) — geolocation
6. correlate_alert_with_response(src_ip=src_ip) — automated response triggered?
7. blast_radius_analysis(src_ip=src_ip, time_range="2h") — scope of compromise
8. If alert involves file change: enrich_file_hash(sha256 from alert)

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


@mcp.prompt()
def morning_briefing() -> str:
    """Morning SOC shift briefing — run at the start of each shift."""
    return """Run a morning SOC briefing. Please:
1. alert_summary(time_range="24h") — overnight alert overview with trend
2. compare_alert_volume(current_range="24h", baseline_offset="24h") — vs yesterday
3. search_authentication_failures(time_range="24h", threshold=5) — overnight brute force
4. active_response_effectiveness(time_range="24h") — did overnight blocks work?
5. check_event_queue_health() — confirm the pipeline is healthy

Summarize findings as a shift handover with:
- Risk rating: LOW / MEDIUM / HIGH / CRITICAL
- 3 recommended actions for this shift
- Anything that needs immediate attention"""


@mcp.prompt()
def incident_triage_full(agent_name: str = "", src_ip: str = "") -> str:
    """Full incident triage for a specific agent or source IP."""
    target = f"agent '{agent_name}'" if agent_name else f"source IP '{src_ip}'"
    return f"""Run a full incident triage for {target}:
1. search_alerts(time_range="48h") filtered to the target
2. search_fim_alerts(time_range="48h") for the agent if known
3. get_agent_login_history(agent_name="{agent_name}") if agent known
4. correlate_alert_with_response(src_ip="{src_ip}") if IP known
5. enrich_ip_geo(["{src_ip}"]) if IP known — geolocation
6. blast_radius_analysis — assess lateral spread
7. create_incident_report from the top alert IDs found

End with:
- Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
- Recommended containment steps
- Whether to tag alerts as investigated or escalate"""


@mcp.prompt()
def threat_hunt_session() -> str:
    """Structured threat hunt across lateral movement, persistence, and exfiltration."""
    return """Run a full threat hunt session across the last 48 hours:
1. hunt_lateral_movement(time_range="48h") — auth patterns + multi-agent spread
2. hunt_persistence_mechanisms(time_range="48h") — startup/registry/cron changes
3. hunt_data_exfiltration(time_range="48h") — unusual outbound event volumes
4. For any agent flagged in 2+ hunts: get_agent_login_history and search_fim_alerts
5. Correlate findings — identify composite-risk agents (appear in multiple hunts)

Rate each finding LOW/MEDIUM/HIGH/CRITICAL.
Finish with a prioritised list of agents to investigate further."""


@mcp.prompt()
def end_of_shift_handover() -> str:
    """End-of-shift handover report."""
    return """Generate an end-of-shift handover report for the last 12 hours:
1. generate_shift_handover(shift_duration="12h")
2. generate_weekly_summary() for broader context
3. prioritize_patches(top_n=3) — top CVEs to patch
4. fleet_sca_weakest_agents(limit=5) — config posture
5. hunt_lateral_movement(time_range="12h") — any active threats?

Format as a handover document:
SUMMARY | OPEN INCIDENTS | PATCH QUEUE | CONFIG ISSUES | WATCH LIST"""


# ============================================================================
# Entry point — HTTP (SSE) or STDIO
# ============================================================================

def main() -> None:
    transport = os.getenv("WAZUH_MCP_TRANSPORT", "stdio")
    host = os.getenv("WAZUH_MCP_HOST", "0.0.0.0")
    port = int(os.getenv("WAZUH_MCP_PORT", "8000"))
    api_key = os.getenv("WAZUH_MCP_API_KEY", "")

    log.info(
        "Starting Wazuh MCP server — transport=%s host=%s port=%s writes=%s manager=%s indexer=%s",
        transport, host, port, cfg.allow_writes, cfg.manager_host, cfg.indexer_host,
    )

    if transport == "http":
        import uvicorn
        from starlette.applications import Starlette
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse, Response
        from starlette.routing import Mount, Route
        from mcp.server.transport_security import TransportSecuritySettings

        # ── /health endpoint ───────────────────────────────────────────────
        async def health_check(request):  # type: ignore[no-untyped-def]
            checks: dict = {}
            # Manager API ping
            try:
                await wz.request("GET", "/")
                checks["manager_api"] = "ok"
            except Exception as e:
                checks["manager_api"] = f"error: {str(e)[:80]}"
            # Indexer cluster health
            try:
                async with httpx.AsyncClient(
                    verify=cfg.verify_ssl,
                    auth=(cfg.indexer_user, cfg.indexer_pass),
                    timeout=5,
                ) as c:
                    r = await c.get(f"{cfg.indexer_host}/_cluster/health")
                    status = r.json().get("status", "unknown") if r.status_code == 200 else "unreachable"
                    checks["indexer"] = status
            except Exception as e:
                checks["indexer"] = f"error: {str(e)[:80]}"

            all_ok = all(
                v in ("ok", "green", "yellow") or "ok" in str(v)
                for v in checks.values()
            )
            return JSONResponse(
                {
                    "status": "healthy" if all_ok else "degraded",
                    "uptime_seconds": round(time.time() - SERVER_START_TIME, 1),
                    "checks": checks,
                    "max_results_global": MAX_RESULTS_GLOBAL,
                    "writes_enabled": cfg.allow_writes,
                },
                status_code=200 if all_ok else 503,
            )

        # ── Optional Bearer-token middleware ───────────────────────────────
        class APIKeyMiddleware(BaseHTTPMiddleware):
            def __init__(self, app, key: str) -> None:
                super().__init__(app)
                self._key = key

            async def dispatch(self, request, call_next):  # type: ignore[override]
                if self._key and request.url.path != "/health":
                    auth = request.headers.get("Authorization", "")
                    token = auth.removeprefix("Bearer ").strip()
                    if token != self._key:
                        return Response("Unauthorized", status_code=401)
                return await call_next(request)

        # ── Assemble ASGI app ──────────────────────────────────────────────
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )
        mcp_asgi = mcp.sse_app()

        app = Starlette(
            routes=[
                Route("/health", health_check),
                Mount("/", app=mcp_asgi),
            ]
        )

        if api_key:
            app = APIKeyMiddleware(app, key=api_key)  # type: ignore[assignment]
            log.info("API key authentication enabled")
        else:
            log.info("API key authentication disabled — set WAZUH_MCP_API_KEY to enable")

        log.info("SSE routes: /sse (GET), /messages (POST), /health (GET)")
        uvicorn.run(app, host=host, port=port, log_level="warning")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
