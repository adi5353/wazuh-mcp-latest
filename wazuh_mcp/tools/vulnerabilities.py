"""Vulnerability tools — fleet exposure, per-agent CVEs, patch prioritisation."""
from __future__ import annotations

from ..helpers import trim_vuln, severities_at_or_above


def register(mcp, wz, idx, cfg, _cap):

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
