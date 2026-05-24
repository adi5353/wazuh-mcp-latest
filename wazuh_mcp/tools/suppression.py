"""Alert suppression and noise scoring tools — FP lifecycle management and rule tuning."""
from __future__ import annotations

import datetime
import logging
import os

import httpx

from ..rbac import responder_only

log = logging.getLogger("wazuh-mcp")


def register(mcp, wz, idx, cfg, _require_writes):

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
        Requires WAZUH_ALLOW_WRITES=true. Requires role: responder or above.
        """
        err = responder_only()
        if err:
            return err
        if dry_run:
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
                "rule_id":    rule_id,
                "time_range": time_range,
                "message":    f"No alerts found for rule {rule_id} in the last {time_range}.",
            }

        fp_rate = round(fp_count / total * 100, 1)

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
