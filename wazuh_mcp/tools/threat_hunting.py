"""Threat hunting tools — lateral movement, persistence, and data exfiltration hunts."""
from __future__ import annotations
from ..tool_context import ToolContext
from ..rbac import ROLE
from ..validators import safe_validate, validate_time_range

REQUIRED_ROLE = ROLE.ANALYST


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg

    @mcp.tool()
    async def hunt_lateral_movement(
        time_range: str = "24h",
        min_targets: int = 2,
    ) -> dict:
        """Hunt lateral movement: find agents showing auth failures + suspicious remote connections.

        Returns agents with lateral movement indicators ranked by unique source IP count.
        """
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        if not isinstance(min_targets, int) or min_targets < 1:
            return {"error": "min_targets must be a positive integer."}
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
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
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
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        if not isinstance(min_event_count, int) or min_event_count < 1:
            return {"error": "min_event_count must be a positive integer."}
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
