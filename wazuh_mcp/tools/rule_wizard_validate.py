"""Rule Wizard — validation against rule engine.

Handles: validate_rule_xml, test_sigma_rule_against_archive, suggest_rule_tuning
"""
from __future__ import annotations
from ..tool_context import ToolContext

import defusedxml.ElementTree as ET


def _validate_rule_xml_impl(xml_content: str) -> dict:
    """Pure validation logic — callable from other modules without an MCP context."""
    if not xml_content or not xml_content.strip():
        return {"valid": False, "error": "XML content is empty."}

    try:
        root = ET.fromstring(xml_content.strip())
    except ET.ParseError as exc:
        return {"valid": False, "error": f"XML parse error: {exc}"}

    warnings = []
    rules_found = 0

    elements = list(root.iter("rule")) if root.tag != "rule" else [root]
    if not elements:
        return {"valid": False, "error": "No <rule> elements found in XML."}

    for rule_el in elements:
        rules_found += 1
        rule_id_str = rule_el.get("id", "")
        level_str = rule_el.get("level", "")

        if not rule_id_str:
            warnings.append("Rule is missing required 'id' attribute.")
        else:
            try:
                rid = int(rule_id_str)
                if rid < 100000 or rid > 199999:
                    warnings.append(
                        f"Rule ID {rid} is outside custom range 100000-199999. "
                        "Using system IDs may conflict with Wazuh built-in rules."
                    )
            except ValueError:
                warnings.append(f"Rule 'id' attribute is not a valid integer: {rule_id_str!r}")

        if not level_str:
            warnings.append("Rule is missing required 'level' attribute.")

        desc_el = rule_el.find("description")
        if desc_el is None or not (desc_el.text or "").strip():
            warnings.append(f"Rule {rule_id_str or '?'} is missing a <description> element.")

    return {
        "valid": True,
        "rules_found": rules_found,
        "warnings": warnings,
        "message": (
            "XML is syntactically valid."
            + (" Review warnings before pushing." if warnings else " Ready to push.")
        ),
    }


def register_validate(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg

    from .rule_wizard_generate import _extract_sigma_field_conditions

    @mcp.tool()
    async def validate_rule_xml(xml_content: str) -> dict:
        """Validate Wazuh rule XML syntax before pushing to the Manager.

        Checks:
          - Valid XML structure (parseable)
          - Presence of required attributes (id, level)
          - Presence of <description> element
          - rule_id in valid custom range (100000-199999)

        Returns valid=True/False, plus a list of warnings for best-practice issues.
        """
        return _validate_rule_xml_impl(xml_content)

    @mcp.tool()
    async def test_sigma_rule_against_archive(
        sigma_yaml: str,
        time_range: str = "30d",
        limit: int = 50,
        use_archive: bool = False,
    ) -> dict:
        """Backtest a Sigma rule against historical alert data to measure hit rate and FP signals.

        Converts the Sigma YAML to an OpenSearch query and runs it against the alerts
        index (or archive index if use_archive=True and archiving is enabled).
        Returns: match count, sample matches, false-positive signals, and a verdict.

        sigma_yaml:  Sigma rule in YAML format
        time_range:  Historical window to test against (default 30d)
        limit:       Max matching events to return (default 50)
        use_archive: If True, search archive index instead of alerts index (requires logall=yes)
        """
        from ..helpers import time_window as _tw, trim_alert

        try:
            import yaml as _yaml
            sigma = _yaml.safe_load(sigma_yaml)
        except ImportError:
            sigma = {}
            for line in sigma_yaml.splitlines():
                if ":" in line and not line.startswith(" "):
                    k, _, v = line.partition(":")
                    sigma[k.strip()] = v.strip().strip("'\"")
        except Exception as exc:
            return {"error": f"YAML parse error: {exc}"}

        if not isinstance(sigma, dict):
            return {"error": "Parsed YAML is not a valid Sigma rule dict."}

        detection  = sigma.get("detection",  {}) or {}
        conditions = _extract_sigma_field_conditions(detection)
        title      = sigma.get("title", "Unnamed Sigma Rule")

        if not conditions:
            return {
                "error": "No detection conditions could be extracted from this Sigma rule.",
                "tip":   "Ensure the 'detection' block has field: value mappings.",
            }

        should_clauses: list[dict] = []
        for field, pattern in conditions[:10]:
            if field == "full_log":
                should_clauses.append({"match_phrase": {"full_log": pattern}})
            else:
                should_clauses.append({"match_phrase": {field: pattern}})

        target_index = cfg.archives_index if use_archive else cfg.alerts_index
        query_body = {
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [_tw(f"now-{time_range}")],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            },
        }

        try:
            res  = await idx.search(query_body, index=target_index)
            hits = res["hits"]["hits"]
            total = res["hits"]["total"]["value"]
        except Exception as exc:
            return {"error": f"Search failed: {exc}"}

        fp_signals:  list[str] = []
        tp_signals:  list[str] = []
        level_counts: dict[int, int] = {}
        for h in hits:
            lvl = int(h.get("_source", {}).get("rule", {}).get("level", 0))
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        low_level_pct = sum(v for k, v in level_counts.items() if k < 5) / max(total, 1) * 100
        if low_level_pct > 60:
            fp_signals.append(f"{low_level_pct:.0f}% of matches are low-severity (level < 5)")
        if total > 500:
            fp_signals.append(f"Very high match count ({total}) — rule may be too broad")
        if total > 0 and total <= 20:
            tp_signals.append(f"Focused match count ({total}) — rule appears targeted")
        if any(k >= 10 for k in level_counts):
            tp_signals.append("Matches include high-severity (level >= 10) events")

        verdict = (
            "LIKELY_NOISY"    if total > 500 or low_level_pct > 60
            else "PROMISING"  if total > 0 and total <= 100
            else "NO_MATCHES" if total == 0
            else "REVIEW_NEEDED"
        )

        return {
            "sigma_title":    title,
            "time_range":     time_range,
            "index_searched": target_index,
            "total_matches":  total,
            "returned":       len(hits),
            "verdict":        verdict,
            "level_distribution": level_counts,
            "tp_signals":     tp_signals,
            "fp_signals":     fp_signals,
            "sample_matches": [trim_alert(h) for h in hits[:10]],
            "tip": (
                "PROMISING rules → use push_custom_rule to deploy. "
                "LIKELY_NOISY rules → add <field> restrictions or raise threshold before deploying. "
                "Set use_archive=True to test against all ingested logs (requires logall=yes in ossec.conf)."
            ),
        }

    @mcp.tool()
    async def suggest_rule_tuning(
        rule_id: int,
        time_range: str = "7d",
    ) -> dict:
        """Analyse a noisy Wazuh rule and suggest concrete tuning to reduce false positives.

        Looks at the last N days of alerts for this rule and identifies:
        - Fire frequency vs expected baseline
        - Time-of-day distribution (off-hours vs business hours)
        - Agent distribution (single noisy agent vs fleet-wide)
        - Common source IPs / users that appear legitimate
        - Groups that co-fire frequently (FP indicator)

        Returns: recommended XML tuning changes with rationale.

        rule_id:    Wazuh rule ID (e.g. 5710 for SSH authentication failures)
        time_range: How far back to analyse (default 7d)
        """
        from ..helpers import time_window as _tw

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        _tw(f"now-{time_range}"),
                        {"term": {"rule.id": str(rule_id)}},
                    ]
                }
            },
            "aggs": {
                "total":         {"value_count": {"field": "_id"}},
                "by_agent":      {"terms": {"field": "agent.name",    "size": 20}},
                "by_src_ip":     {"terms": {"field": "data.srcip",    "size": 20}},
                "by_user":       {"terms": {"field": "data.dstuser",  "size": 10}},
                "by_hour":       {"terms": {"field": "hour_of_day",   "size": 24}},
                "by_group":      {"terms": {"field": "rule.groups",   "size": 10}},
                "by_day": {
                    "date_histogram": {
                        "field": "@timestamp", "calendar_interval": "day", "min_doc_count": 0,
                    }
                },
            },
        }
        try:
            res  = await idx.search(body)
        except Exception as exc:
            return {"error": f"Rule query failed: {exc}"}

        aggs  = res.get("aggregations", {})
        total = res["hits"]["total"]["value"]

        if total == 0:
            return {
                "rule_id":    rule_id,
                "time_range": time_range,
                "status": "NO_ALERTS",
                "message": f"Rule {rule_id} has not fired in the last {time_range}.",
            }

        agent_bkts = aggs.get("by_agent", {}).get("buckets", [])
        top_agent  = agent_bkts[0] if agent_bkts else {}
        top_agent_pct = round(top_agent.get("doc_count", 0) / total * 100, 1) if total else 0

        src_bkts   = aggs.get("by_src_ip", {}).get("buckets", [])
        top_ips    = [b["key"] for b in src_bkts[:5]]

        user_bkts  = aggs.get("by_user", {}).get("buckets", [])
        top_users  = [b["key"] for b in user_bkts[:5] if b["key"] not in ("", None)]

        day_bkts   = aggs.get("by_day", {}).get("buckets", [])
        daily_avg  = total / max(len(day_bkts), 1)
        max_day_count = max((b["doc_count"] for b in day_bkts), default=0)
        spike_ratio   = round(max_day_count / daily_avg, 1) if daily_avg else 0

        grp_bkts = aggs.get("by_group", {}).get("buckets", [])
        top_groups = [b["key"] for b in grp_bkts[:5]]

        rule_description = f"Rule {rule_id}"
        try:
            r_resp = await wz.get(f"/rules?rule_ids={rule_id}&limit=1")
            items  = r_resp.get("data", {}).get("affected_items", [])
            if items:
                rule_description = items[0].get("description", rule_description)
        except Exception:
            pass

        suggestions: list[dict] = []

        if top_agent_pct > 70 and len(agent_bkts) > 1:
            suggestions.append({
                "type":        "AGENT_EXCLUSION",
                "priority":    "HIGH",
                "description": f"Agent '{top_agent.get('key')}' generates {top_agent_pct}% of alerts.",
                "xml_change":  '<list field="agent.name" lookup="not_match_key">agent-whitelist</list>',
                "rationale":   "Create a whitelist CDB list and exclude this agent if it is a known noisy host.",
            })

        if top_ips and src_bkts and src_bkts[0]["doc_count"] / total > 0.5:
            suggestions.append({
                "type":        "SOURCE_IP_FILTER",
                "priority":    "HIGH",
                "description": f"IP {top_ips[0]} drives {round(src_bkts[0]['doc_count']/total*100,1)}% of alerts.",
                "xml_change":  '<list field="data.srcip" lookup="not_match_key">ip-whitelist</list>',
                "rationale":   "Add this IP to a CDB whitelist if it is a scanner or monitoring tool.",
            })

        if total > 1000:
            suggestions.append({
                "type":        "THRESHOLD",
                "priority":    "HIGH",
                "description": f"Rule fired {total} times in {time_range} — extremely noisy.",
                "xml_change":  '<options>no_log</options>  <!-- or add <timeframe>60</timeframe><frequency>10</frequency> -->',
                "rationale":   "Add a frequency threshold so the rule only alerts after N events in a time window.",
            })
        elif total > 200:
            suggestions.append({
                "type":        "THRESHOLD",
                "priority":    "MEDIUM",
                "description": f"Rule fired {total} times in {time_range} — consider a frequency threshold.",
                "xml_change":  '<timeframe>300</timeframe>\n    <frequency>5</frequency>',
                "rationale":   "Alert only when rule fires 5+ times in 5 minutes rather than every event.",
            })

        if spike_ratio > 5:
            suggestions.append({
                "type":        "TIME_CORRELATION",
                "priority":    "MEDIUM",
                "description": f"Alert volume spikes {spike_ratio}x above daily average on peak days.",
                "xml_change":  "Consider scheduled suppression during maintenance windows.",
                "rationale":   "Recurring spikes often indicate scheduled jobs or backups triggering the rule.",
            })

        if top_users:
            suggestions.append({
                "type":        "USER_FILTER",
                "priority":    "LOW",
                "description": f"Top users triggering rule: {top_users}.",
                "xml_change":  '<list field="data.dstuser" lookup="not_match_key">user-whitelist</list>',
                "rationale":   "If these are service accounts, whitelist them to eliminate systematic FPs.",
            })

        noise_score = min(100, int(
            (total / 100) * 20 +
            (top_agent_pct / 100) * 30 +
            (1 if total > 1000 else 0) * 30 +
            (spike_ratio / 10) * 20
        ))

        return {
            "rule_id":          rule_id,
            "rule_description": rule_description,
            "time_range":       time_range,
            "stats": {
                "total_alerts":  total,
                "daily_average": round(daily_avg, 1),
                "peak_day_spike_ratio": spike_ratio,
                "top_agents":    [(b["key"], b["doc_count"]) for b in agent_bkts[:5]],
                "top_src_ips":   top_ips,
                "top_users":     top_users,
                "top_groups":    top_groups,
            },
            "noise_score":      noise_score,
            "noise_tier":       "CRITICAL" if noise_score > 75 else "HIGH" if noise_score > 50 else "MEDIUM" if noise_score > 25 else "LOW",
            "tuning_suggestions": suggestions,
            "next_steps": [
                f"noise_score_rule(rule_id='{rule_id}') — cross-check noise score",
                f"bulk_suppress_rule(rule_id={rule_id}, reason='tuning', dry_run=True) — preview suppression",
                "add_to_cdb_list('ip-whitelist', top_ip) — whitelist scanner IPs",
            ],
        }
