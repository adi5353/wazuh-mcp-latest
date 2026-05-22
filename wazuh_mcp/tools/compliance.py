"""Compliance tools — framework summaries, control drill-down, and report generation."""
from __future__ import annotations

import datetime

from ..helpers import trim_alert, time_window

COMPLIANCE_FIELDS = {
    "pci_dss": "rule.pci_dss",
    "hipaa": "rule.hipaa",
    "gdpr": "rule.gdpr",
    "nist_800_53": "rule.nist_800_53",
    "tsc": "rule.tsc",
}


def register(mcp, wz, idx, cfg, _cap):

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

    return {"generate_compliance_report": generate_compliance_report}
