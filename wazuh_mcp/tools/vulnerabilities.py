"""Vulnerability tools — fleet exposure, per-agent CVEs, patch prioritisation."""
from __future__ import annotations

import httpx

from ..helpers import trim_vuln, severities_at_or_above
from ..validators import safe_validate, validate_severity, validate_cve_id, validate_agent_id

_EPSS_API = "https://api.first.org/data/v1/epss"
_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_cache: dict = {}   # {cve_id: kev_entry}  — refreshed each call if stale
_kev_etag:  str  = ""


async def _fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Return {cve_id: {epss, percentile}} for the given CVE list (max 100)."""
    if not cve_ids:
        return {}
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(_EPSS_API, params={"cve": ",".join(cve_ids[:100])})
            r.raise_for_status()
            data = r.json().get("data", [])
            return {
                item["cve"]: {
                    "epss": round(float(item.get("epss", 0)), 4),
                    "percentile": round(float(item.get("percentile", 0)) * 100, 1),
                }
                for item in data
            }
    except Exception:
        return {}


async def _fetch_kev() -> dict[str, dict]:
    """Return {cve_id: kev_entry} for the full CISA KEV catalog (cached in-process)."""
    global _kev_cache, _kev_etag
    if _kev_cache:
        return _kev_cache
    try:
        headers = {"If-None-Match": _kev_etag} if _kev_etag else {}
        async with httpx.AsyncClient(timeout=12.0) as c:
            r = await c.get(_KEV_URL, headers=headers)
            if r.status_code == 304:
                return _kev_cache
            r.raise_for_status()
            _kev_etag = r.headers.get("ETag", "")
            vulns = r.json().get("vulnerabilities", [])
            _kev_cache = {v["cveID"]: v for v in vulns}
            return _kev_cache
    except Exception:
        return {}


def register(mcp, wz, idx, cfg, _cap):

    @mcp.tool()
    async def vulnerability_summary(min_severity: str = "High") -> dict:
        """Aggregated view of unpatched vulnerabilities across the fleet.

        Call this BEFORE listing specific CVEs for broad 'how exposed are we' questions.
        min_severity: Critical | High | Medium | Low
        """
        _, err = safe_validate(validate_severity, min_severity, "min_severity")
        if err:
            return err
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
        cve_id, err = safe_validate(validate_cve_id, cve_id)
        if err:
            return err
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

    @mcp.tool()
    async def enrich_cve_epss(cve_ids: list) -> dict:
        """Enrich a list of CVE IDs with EPSS exploit-probability scores.

        EPSS (Exploit Prediction Scoring System) gives the probability that a
        CVE will be exploited in the wild within 30 days. Scores range 0–1;
        anything above 0.1 (10%) deserves prioritised patching.

        cve_ids: list of CVE IDs, e.g. ['CVE-2021-44228', 'CVE-2024-3094']
        """
        if not cve_ids or not isinstance(cve_ids, list):
            return {"error": "cve_ids must be a non-empty list of CVE ID strings."}
        cleaned = [c.upper().strip() for c in cve_ids[:100] if isinstance(c, str)]
        epss_map = await _fetch_epss(cleaned)
        results = []
        for cve in cleaned:
            e = epss_map.get(cve, {})
            results.append({
                "cve": cve,
                "epss_score": e.get("epss"),
                "epss_percentile": e.get("percentile"),
                "risk_label": (
                    "CRITICAL" if (e.get("epss") or 0) >= 0.5
                    else "HIGH"   if (e.get("epss") or 0) >= 0.1
                    else "MEDIUM" if (e.get("epss") or 0) >= 0.01
                    else "LOW"    if e.get("epss") is not None
                    else "UNKNOWN"
                ),
                "note": (
                    "50%+ exploitation probability — treat as P0"
                    if (e.get("epss") or 0) >= 0.5 else
                    "High exploitation probability — patch this week"
                    if (e.get("epss") or 0) >= 0.1 else
                    "Low current exploitation activity"
                    if e.get("epss") is not None else
                    "CVE not found in EPSS dataset"
                ),
            })
        results.sort(key=lambda x: x.get("epss_score") or 0, reverse=True)
        return {
            "source": "FIRST.org EPSS API",
            "total": len(results),
            "results": results,
            "tip": "Combine with check_kev_exposure() to flag actively-exploited CVEs.",
        }

    @mcp.tool()
    async def check_kev_exposure(min_severity: str = "High") -> dict:
        """Cross-reference your fleet's unpatched CVEs against the CISA KEV catalog.

        KEV (Known Exploited Vulnerabilities) lists CVEs that threat actors are
        actively exploiting in the wild. Any KEV hit on your fleet is a P0 patch.

        Returns agents and packages affected by KEV CVEs, with CISA due dates.
        min_severity: Critical | High | Medium | Low
        """
        _, err = safe_validate(validate_severity, min_severity, "min_severity")
        if err:
            return err

        kev = await _fetch_kev()
        if not kev:
            return {"error": "Could not fetch CISA KEV catalog. Check network connectivity."}

        included = severities_at_or_above(min_severity)
        body = {
            "size": 0,
            "query": {"terms": {"vulnerability.severity": included}},
            "aggs": {
                "by_cve": {
                    "terms": {"field": "vulnerability.id", "size": 500},
                    "aggs": {
                        "agents": {"cardinality": {"field": "agent.id"}},
                        "sample": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["vulnerability.severity", "package.name", "agent.name"],
                            }
                        },
                    },
                }
            },
        }
        res = await idx.search(body, index=cfg.vuln_index)
        fleet_cves = {b["key"]: b for b in res["aggregations"]["by_cve"]["buckets"]}

        hits = []
        for cve_id, b in fleet_cves.items():
            if cve_id in kev:
                entry = kev[cve_id]
                sample_src = b["sample"]["hits"]["hits"][0]["_source"]
                hits.append({
                    "cve": cve_id,
                    "affected_agents": b["agents"]["value"],
                    "severity": sample_src["vulnerability"]["severity"],
                    "package": sample_src["package"]["name"],
                    "vendor_project": entry.get("vendorProject", ""),
                    "product": entry.get("product", ""),
                    "vulnerability_name": entry.get("vulnerabilityName", ""),
                    "date_added_to_kev": entry.get("dateAdded", ""),
                    "due_date": entry.get("dueDate", ""),
                    "known_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
                    "priority": "P0 — CISA KEV: actively exploited in the wild",
                })

        hits.sort(key=lambda x: x["affected_agents"], reverse=True)
        return {
            "source": "CISA Known Exploited Vulnerabilities Catalog",
            "kev_catalog_size": len(kev),
            "fleet_cves_scanned": len(fleet_cves),
            "kev_hits_on_fleet": len(hits),
            "critical_patches": hits,
            "message": (
                f"URGENT: {len(hits)} CVE(s) on your fleet are in the CISA KEV catalog — "
                "these are actively exploited. Patch immediately."
                if hits else
                f"No KEV CVEs found in fleet (scanned {len(fleet_cves)} CVEs at {min_severity}+ severity)."
            ),
        }

    @mcp.tool()
    async def prioritize_patches_with_epss(top_n: int = 20) -> dict:
        """Rank patches using CVSS × agent-count × EPSS + KEV flag — the most complete
        prioritisation available. Fetches live EPSS scores and CISA KEV status.

        Answers 'what should I patch first?' with exploitation probability factored in.
        """
        body = {
            "size": 0,
            "query": {"terms": {"vulnerability.severity": ["Critical", "High"]}},
            "aggs": {
                "by_cve": {
                    "terms": {"field": "vulnerability.id", "size": top_n * 5},
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
        buckets = res["aggregations"]["by_cve"]["buckets"]
        cve_ids = [b["key"] for b in buckets]

        epss_map, kev = await _fetch_epss(cve_ids), await _fetch_kev()

        items = []
        for b in buckets:
            cve  = b["key"]
            agents = b["agents"]["value"]
            cvss   = b["avg_cvss"]["value"] or 0
            epss   = (epss_map.get(cve) or {}).get("epss") or 0
            in_kev = cve in kev
            # Combined score: base CVSS*agents + EPSS bonus (0–10) + KEV bonus (10)
            combined = round(agents * cvss + epss * 10 + (10 if in_kev else 0), 2)
            items.append({
                "cve": cve,
                "affected_agents": agents,
                "cvss": round(cvss, 1),
                "epss_score": epss,
                "epss_percentile": (epss_map.get(cve) or {}).get("percentile"),
                "in_cisa_kev": in_kev,
                "severity": b["sample"]["hits"]["hits"][0]["_source"]["vulnerability"]["severity"],
                "package": b["sample"]["hits"]["hits"][0]["_source"]["package"]["name"],
                "combined_priority_score": combined,
                "patch_urgency": (
                    "P0 — PATCH NOW"      if in_kev or epss >= 0.5
                    else "P1 — this week" if epss >= 0.1 or cvss >= 9
                    else "P2 — this cycle"
                ),
            })

        items.sort(key=lambda x: x["combined_priority_score"], reverse=True)
        return {
            "scoring_method": "CVSS × agents + EPSS bonus + KEV bonus",
            "kev_cves_in_list": sum(1 for i in items if i["in_cisa_kev"]),
            "top_patches": items[:top_n],
        }
