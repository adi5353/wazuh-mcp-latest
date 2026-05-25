"""Incident response tools — timeline, blast radius, report creation, and alert tagging."""
from __future__ import annotations

import datetime
import os

import httpx

from ..helpers import trim_alert, time_window


def register(mcp, wz, idx, cfg, _cap, _require_writes, _enrich_mitre_ids, _incident_recommendations):

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

        # Resolve the concrete index for this alert — wildcard indices don't support _update.
        resolve_body = {"size": 1, "query": {"term": {"_id": alert_id}}, "_source": False}
        try:
            resolved_res = await idx.search(resolve_body)
            hits = resolved_res.get("hits", {}).get("hits", [])
            if not hits:
                return {"error": f"Alert {alert_id} not found in index."}
            concrete_index = hits[0]["_index"]
        except Exception as e:
            return {"error": f"Failed to resolve alert index: {e}"}

        update_url = f"{cfg.indexer_host}/{concrete_index}/_update/{alert_id}"
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

        alerts_index = cfg.alerts_index
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
