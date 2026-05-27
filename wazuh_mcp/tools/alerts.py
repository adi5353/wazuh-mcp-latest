"""Alert search and summary tools — indexer queries for alert triage and investigation."""
from __future__ import annotations
from ..tool_context import ToolContext
import re

from ..helpers import trim_alert
from ..validators import safe_validate, validate_time_range, validate_min_level, validate_agent_id, validate_ip_address, validate_limit


def _double_time_range(time_range: str) -> str:
    """Return an ES date-math expression for 2× the given time range.

    '24h' → 'now-48h', '7d' → 'now-14d', '30m' → 'now-60m'.
    Falls back to 'now-{range}-{range}' only as a last resort (never valid ES).
    """
    m = re.match(r'^(\d+)([smhdwMy])$', time_range)
    if m:
        return f"now-{int(m.group(1)) * 2}{m.group(2)}"
    return f"now-{time_range}"


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _enrich_mitre_ids = ctx.enrich_mitre_ids

    @mcp.tool()
    async def alert_summary(time_range: str = "24h", min_level: int = 7) -> dict:
        """Aggregated summary of alerts over a time window — counts by rule, agent, MITRE.

        Call this BEFORE search_alerts for broad questions like 'what happened today'.
        Returns aggregations only, not raw alerts — much smaller payload.
        Includes trend vs prior period and enriched MITRE technique names.
        """
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        _, err = safe_validate(validate_min_level, min_level)
        if err:
            return err

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

        prior_body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {
                            "gte": _double_time_range(time_range),
                            "lte": f"now-{time_range}",
                        }}},
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
        }
        # Also aggregate per-rule counts for the prior period to compute per-rule delta
        prior_body["aggs"] = {
            "top_rules_prior": {"terms": {"field": "rule.id", "size": 10}},
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
            prior_rule_counts: dict[str, int] = {
                b["key"]: b["doc_count"]
                for b in prior_res.get("aggregations", {}).get("top_rules_prior", {}).get("buckets", [])
            }
        except Exception:
            prior_total = None
            trend_pct = None
            trend_arrow = "?"
            prior_rule_counts = {}

        raw_techniques = [b["key"] for b in aggs["top_mitre"]["buckets"]]
        enriched_techniques = _enrich_mitre_ids(raw_techniques)
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
                    "rule_id":     b["key"],
                    "count":       b["doc_count"],
                    "description": b["detail"]["hits"]["hits"][0]["_source"]["rule"]["description"],
                    "level":       b["detail"]["hits"]["hits"][0]["_source"]["rule"]["level"],
                    "delta_pct": (
                        round((b["doc_count"] - prior_rule_counts[b["key"]]) / prior_rule_counts[b["key"]] * 100, 1)
                        if prior_rule_counts.get(b["key"])
                        else None
                    ),
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
        agent_name: str | None = None,
        rule_groups: list | None = None,
        group_filter: str = "",
        limit: int = 50,
        page_token: str | None = None,
        sort_by: str = "timestamp_desc",
    ) -> dict:
        """Search Wazuh alerts in the Indexer.

        time_range:  relative time like '15m', '1h', '24h', '7d'
        min_level:   minimum rule level (default 7)
        agent_id:    optional filter by numeric agent ID (e.g. '001')
        agent_name:  optional filter by agent name string (e.g. 'web-server-01')
                     — prefer this over agent_id when you know the hostname
        rule_groups: optional rule-group filter (e.g. ['authentication_failed', 'ssh'])
        page_token:  opaque cursor from a previous response's next_page_token for pagination
        sort_by:     sort order — one of:
            'timestamp_desc'  (default) newest first
            'level_desc'      highest severity first
            'agent_name_asc'  alphabetical by agent name
        """
        import base64 as _b64, json as _json
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        _, err = safe_validate(validate_min_level, min_level)
        if err:
            return err
        if agent_id:
            _, err = safe_validate(validate_agent_id, agent_id)
            if err:
                return err
        if agent_name and (len(agent_name) > 64 or not agent_name.replace("-", "").replace("_", "").replace(".", "").isalnum()):
            return {"error": "agent_name must be a valid hostname (max 64 chars, alphanumeric/dash/underscore/dot)"}
        limit, err = safe_validate(validate_limit, limit)
        if err:
            return err

        filters = [
            {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]
        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})
        if agent_name:
            filters.append({"term": {"agent.name": agent_name}})
        if rule_groups:
            filters.append({"terms": {"rule.groups": rule_groups}})
        if group_filter:
            filters.append({"term": {"agent.groups": group_filter}})

        _SORT_MAP = {
            "timestamp_desc":  [{"@timestamp": "desc"}, {"_id": "asc"}],
            "level_desc":      [{"rule.level": "desc"}, {"@timestamp": "desc"}, {"_id": "asc"}],
            "agent_name_asc":  [{"agent.name": "asc"},  {"@timestamp": "desc"}, {"_id": "asc"}],
        }
        sort_clause = _SORT_MAP.get(sort_by, _SORT_MAP["timestamp_desc"])

        body: dict = {
            "size": _cap(limit),
            "sort": sort_clause,
            "query": {"bool": {"filter": filters}},
        }

        if page_token:
            try:
                search_after = _json.loads(_b64.b64decode(page_token).decode())
                body["search_after"] = search_after
            except Exception:
                return {"error": "Invalid page_token — use the next_page_token from a previous response."}

        res = await idx.search(body)
        hits = res["hits"]["hits"]
        next_token = None
        if len(hits) == _cap(limit):
            last_sort = hits[-1].get("sort")
            if last_sort:
                next_token = _b64.b64encode(_json.dumps(last_sort).encode()).decode()

        return {
            "total": res["hits"]["total"]["value"],
            "returned": len(hits),
            "alerts": [trim_alert(h) for h in hits],
            "next_page_token": next_token,
            "has_more": next_token is not None,
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
        _, err = safe_validate(validate_ip_address, src_ip, "src_ip")
        if err:
            return err
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
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

    @mcp.tool()
    async def get_recent_alerts_24h(
        limit: int = 10,
        min_level: int = 1,
    ) -> dict:
        """Fetch the most recent security alerts from the last 24 hours, ordered newest first.

        Uses the Wazuh Indexer exclusively — do not use this for infrastructure/agent queries.
        This is the recommended starting point for a SOC morning review or quick triage.

        Args:
            limit: Number of alerts to return (max 50, default 10).
            min_level: Minimum rule level to include (1-15, default 1 = all).
        """
        body = {
            "size": _cap(min(limit, 50)),
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": "now-24h"}}},
                    ],
                    "filter": [
                        {"range": {"rule.level": {"gte": min_level}}},
                    ],
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        try:
            res = await idx.search(body, index=cfg.alerts_index)
            hits = res["hits"]["hits"]
            alerts = [trim_alert(h) for h in hits]
            return {
                "window": "last 24 hours",
                "total_returned": len(alerts),
                "total_available": res["hits"]["total"]["value"],
                "min_level": min_level,
                "alerts": alerts,
            }
        except Exception as e:
            return {"error": str(e)}
