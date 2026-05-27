"""MITRE ATT&CK tools — ruleset coverage analysis and gap detection."""
from __future__ import annotations
from ..tool_context import ToolContext

from ..helpers import time_window


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg

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
