"""Reporting tools — alert volume comparison, rule anomaly detection, weekly summary, shift handover."""
from __future__ import annotations

import asyncio
import datetime

from ..helpers import time_window


def register(mcp, wz, idx, cfg, _cap, _enrich_mitre_ids):

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

    @mcp.tool()
    async def generate_weekly_summary(week_offset: int = 0) -> dict:
        """Generate a weekly security summary with alert trend, top rules/agents/techniques.

        week_offset=0 = current week; week_offset=1 = last week.
        """
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
    async def generate_shift_handover(
        shift_duration: str = "8h",
        analyst_name: str = "SOC Analyst",
    ) -> dict:
        """Generate a structured shift handover report covering the last N hours.

        Calls parallel sub-queries and synthesises everything into a single structured
        response the incoming analyst can read in 2 minutes.

        shift_duration: '6h', '8h', '12h', '24h'
        """
        time_filter = {"range": {"@timestamp": {"gte": f"now-{shift_duration}"}}}

        async def _alert_overview() -> dict:
            body = {
                "size": 0,
                "query": {"bool": {"filter": [time_filter]}},
                "aggs": {
                    "top_rules": {
                        "terms": {"field": "rule.id", "size": 5},
                        "aggs": {"desc": {"terms": {"field": "rule.description.keyword", "size": 1}}},
                    },
                    "top_agents": {"terms": {"field": "agent.name", "size": 5}},
                    "by_level": {"terms": {"field": "rule.level", "size": 15}},
                },
            }
            res = await idx.search(body)
            aggs = res.get("aggregations", {})
            total = res["hits"]["total"]["value"]
            return {
                "total_alerts": total,
                "top_rules": [
                    {
                        "rule_id": b["key"],
                        "count": b["doc_count"],
                        "description": (b.get("desc", {}).get("buckets") or [{}])[0].get("key", ""),
                    }
                    for b in aggs.get("top_rules", {}).get("buckets", [])
                ],
                "top_agents": [
                    {"agent": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("top_agents", {}).get("buckets", [])
                ],
                "by_level": {
                    str(b["key"]): b["doc_count"]
                    for b in aggs.get("by_level", {}).get("buckets", [])
                },
            }

        async def _auth_failures() -> dict:
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [time_filter],
                        "should": [
                            {"terms": {"rule.groups": ["authentication_failed", "authentication_failures"]}},
                            {"range": {"rule.id": {"gte": "5700", "lte": "5800"}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "aggs": {"top_ips": {"terms": {"field": "data.srcip", "size": 5}}},
            }
            res = await idx.search(body)
            return {
                "total_failures": res["hits"]["total"]["value"],
                "top_source_ips": [b["key"] for b in res["aggregations"]["top_ips"]["buckets"]],
            }

        async def _active_responses() -> dict:
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [time_filter],
                        "should": [
                            {"terms": {"rule.groups": ["active_response", "ar"]}},
                            {"terms": {"rule.id": ["601", "602", "651", "652"]}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "aggs": {"by_type": {"terms": {"field": "rule.description.keyword", "size": 5}}},
            }
            res = await idx.search(body)
            return {
                "total_responses": res["hits"]["total"]["value"],
                "by_type": [
                    {"type": b["key"], "count": b["doc_count"]}
                    for b in res["aggregations"]["by_type"]["buckets"]
                ],
            }

        async def _critical_vulns() -> dict:
            try:
                res = await wz.request(
                    "GET",
                    "/vulnerability/agents?limit=1&severity=Critical&select=agent_id",
                )
                total = (res.get("data") or {}).get("total_affected_items", 0)
                return {"critical_vulnerabilities": total}
            except Exception as e:
                return {"error": str(e)}

        tasks = await asyncio.gather(
            _alert_overview(),
            _auth_failures(),
            _active_responses(),
            _critical_vulns(),
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

    return {
        "generate_shift_handover": generate_shift_handover,
        "generate_weekly_summary": generate_weekly_summary,
    }
