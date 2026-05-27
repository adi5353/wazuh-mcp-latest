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
                # Pivot: shared usernames indicate credential reuse / lateral movement
                "target_users": {"terms": {"field": "data.win.eventdata.targetUserName", "size": 20}},
                "dst_users":    {"terms": {"field": "data.dstuser", "size": 20}},
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

        # Merge Windows targetUserName + generic dstuser into one set
        pivot_users: list[str] = list({
            b["key"] for b in aggs.get("target_users", {}).get("buckets", [])
            if b["key"] not in ("", None)
        } | {
            b["key"] for b in aggs.get("dst_users", {}).get("buckets", [])
            if b["key"] not in ("", None)
        })

        # Lateral movement requires either 3+ agents touched OR the same user seen on
        # multiple distinct agents (credential reuse across the fleet)
        lateral_movement_suspected = len(agents) >= 3 or bool(pivot_users and len(agents) >= 2)

        # ── Optional attacker-IP enrichment ──────────────────────────────────
        # Enrich distinct source IPs via VirusTotal/AbuseIPDB if API key is set.
        attacker_ips = [b["key"] for b in aggs["src_ips"]["buckets"] if b["key"]]
        ip_enrichments: list[dict] = []
        vt_key = os.getenv("WAZUH_VT_API_KEY", "")
        if vt_key and attacker_ips:
            for _ip in attacker_ips[:5]:  # cap at 5 to avoid quota burn
                try:
                    async with httpx.AsyncClient(timeout=8) as _cli:
                        vtr = await _cli.get(
                            f"https://www.virustotal.com/api/v3/ip_addresses/{_ip}",
                            headers={"x-apikey": vt_key},
                        )
                    if vtr.status_code == 200:
                        vt = vtr.json().get("data", {}).get("attributes", {})
                        stats = vt.get("last_analysis_stats", {})
                        ip_enrichments.append({
                            "ip": _ip,
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "country": vt.get("country", ""),
                            "asn_owner": vt.get("as_owner", ""),
                            "reputation": vt.get("reputation", 0),
                        })
                except Exception:
                    pass

        return {
            "indicator": {"src_ip": src_ip, "agent_id": agent_id},
            "time_range": time_range,
            "total_alerts": res["hits"]["total"]["value"],
            "lateral_movement_suspected": lateral_movement_suspected,
            "agents_affected": [{"agent": b["key"], "count": b["doc_count"]} for b in agents],
            "source_ips": attacker_ips,
            "destination_ips": [b["key"] for b in aggs["dst_ips"]["buckets"]],
            "pivot_usernames": pivot_users[:10],
            "techniques": [b["key"] for b in aggs["techniques"]["buckets"]],
            "top_rules": [{"rule_id": b["key"], "count": b["doc_count"]} for b in aggs["rules"]["buckets"][:10]],
            "activity_histogram": [
                {"time": b["key_as_string"], "count": b["doc_count"]}
                for b in aggs["by_15min"]["buckets"]
            ],
            "attacker_ip_enrichment": ip_enrichments if ip_enrichments else None,
            "lateral_movement_tip": (
                f"Pivot username(s) {pivot_users[:3]} seen across multiple agents — "
                "investigate with get_user_activity_profile() and hunt_lateral_movement()."
            ) if pivot_users and len(agents) >= 2 else None,
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
    async def correlate_multi_agent_incident(
        time_range: str = "4h",
        seed_src_ip: str | None = None,
        seed_agent_id: str | None = None,
        seed_rule_id: str | None = None,
        seed_mitre_technique: str | None = None,
        min_level: int = 7,
        max_agents: int = 20,
    ) -> dict:
        """Correlate a security incident across multiple agents into a unified kill-chain.

        Starts from one or more seed indicators (src_ip, agent_id, rule_id, or MITRE
        technique) and expands outward through the fleet — finding every agent touched
        by the same attacker IP, shared usernames, lateral movement paths, and common
        MITRE techniques — then builds a causal timeline and confidence-scored kill-chain.

        This is the cross-fleet view that per-agent blast_radius_analysis cannot provide.

        time_range:           How far back to look (default 4h)
        seed_src_ip:          Starting attacker IP (most common seed for external attacks)
        seed_agent_id:        Starting compromised agent ID
        seed_rule_id:         Starting rule that fired — finds all agents it hit
        seed_mitre_technique: Starting ATT&CK technique ID (e.g. 'T1110')
        min_level:            Minimum alert level to include (default 7)
        max_agents:           Maximum agents to expand to (default 20, prevents runaway)
        """
        if not any([seed_src_ip, seed_agent_id, seed_rule_id, seed_mitre_technique]):
            return {"error": "Provide at least one seed: seed_src_ip, seed_agent_id, seed_rule_id, or seed_mitre_technique."}

        time_filter = time_window(f"now-{time_range}")

        # ── Phase 1: Gather seed alerts ──────────────────────────────────────────
        seed_filters: list[dict] = [time_filter, {"range": {"rule.level": {"gte": min_level}}}]
        if seed_src_ip:
            seed_filters.append({"term": {"data.srcip": seed_src_ip}})
        if seed_agent_id:
            seed_filters.append({"term": {"agent.id": seed_agent_id}})
        if seed_rule_id:
            seed_filters.append({"term": {"rule.id": seed_rule_id}})
        if seed_mitre_technique:
            seed_filters.append({"term": {"rule.mitre.id": seed_mitre_technique}})

        seed_body = {
            "size": 200,
            "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": seed_filters}},
            "aggs": {
                "involved_agents": {"terms": {"field": "agent.id",      "size": max_agents}},
                "src_ips":         {"terms": {"field": "data.srcip",    "size": 30}},
                "dst_ips":         {"terms": {"field": "data.dstip",    "size": 30}},
                "usernames":       {"terms": {"field": "data.dstuser",  "size": 20}},
                "techniques":      {"terms": {"field": "rule.mitre.id", "size": 20}},
                "top_rules":       {"terms": {"field": "rule.id",       "size": 10}},
            },
        }
        try:
            seed_res = await idx.search(seed_body)
        except Exception as exc:
            return {"error": f"Seed query failed: {exc}"}

        seed_hits  = seed_res["hits"]["hits"]
        seed_total = seed_res["hits"]["total"]["value"]
        seed_aggs  = seed_res.get("aggregations", {})

        if not seed_hits:
            return {
                "status": "NO_MATCH",
                "message": "No alerts matched the seed indicators in the given time range.",
                "seed": {"src_ip": seed_src_ip, "agent_id": seed_agent_id,
                         "rule_id": seed_rule_id, "mitre": seed_mitre_technique},
                "time_range": time_range,
            }

        involved_agent_ids: set[str] = {b["key"] for b in seed_aggs.get("involved_agents", {}).get("buckets", [])}
        attacker_ips:       set[str] = {b["key"] for b in seed_aggs.get("src_ips",          {}).get("buckets", [])} - {""}
        dst_ips:            set[str] = {b["key"] for b in seed_aggs.get("dst_ips",           {}).get("buckets", [])} - {""}
        usernames:          set[str] = {b["key"] for b in seed_aggs.get("usernames",         {}).get("buckets", [])} - {""}
        raw_techniques:     list     = [b["key"] for b in seed_aggs.get("techniques",        {}).get("buckets", [])]
        top_rules:          list     = [b["key"] for b in seed_aggs.get("top_rules",         {}).get("buckets", [])]

        # ── Phase 2: Expand to related agents via shared IPs / usernames ────────
        expansion_should = []
        if attacker_ips:
            expansion_should.append({"terms": {"data.srcip":   list(attacker_ips)[:10]}})
            expansion_should.append({"terms": {"data.dstip":   list(attacker_ips)[:10]}})
        if usernames:
            expansion_should.append({"terms": {"data.dstuser": list(usernames)[:10]}})
            expansion_should.append({"terms": {"data.srcuser": list(usernames)[:10]}})

        if expansion_should:
            expand_body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [time_filter, {"range": {"rule.level": {"gte": min_level}}}],
                        "should": expansion_should,
                        "minimum_should_match": 1,
                    }
                },
                "aggs": {
                    "new_agents": {"terms": {"field": "agent.id",      "size": max_agents}},
                    "new_ips":    {"terms": {"field": "data.srcip",    "size": 20}},
                    "techniques": {"terms": {"field": "rule.mitre.id", "size": 20}},
                },
            }
            try:
                expand_res = await idx.search(expand_body)
                exp_aggs   = expand_res.get("aggregations", {})
                for b in exp_aggs.get("new_agents", {}).get("buckets", []):
                    involved_agent_ids.add(b["key"])
                for b in exp_aggs.get("new_ips",    {}).get("buckets", []):
                    attacker_ips.add(b["key"])
                for b in exp_aggs.get("techniques", {}).get("buckets", []):
                    if b["key"] not in raw_techniques:
                        raw_techniques.append(b["key"])
            except Exception:
                pass

        involved_agent_ids = set(list(involved_agent_ids)[:max_agents])

        # ── Phase 3: Per-agent alert breakdown ────────────────────────────────
        agent_breakdown: list[dict] = []
        if involved_agent_ids:
            pa_body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            time_filter,
                            {"range": {"rule.level": {"gte": min_level}}},
                            {"terms": {"agent.id": list(involved_agent_ids)}},
                        ]
                    }
                },
                "aggs": {
                    "by_agent": {
                        "terms": {"field": "agent.id", "size": max_agents},
                        "aggs": {
                            "agent_name":  {"terms": {"field": "agent.name", "size": 1}},
                            "max_level":   {"max":   {"field": "rule.level"}},
                            "techniques":  {"terms": {"field": "rule.mitre.id", "size": 10}},
                            "top_rules":   {"terms": {"field": "rule.id",       "size": 5}},
                            "first_alert": {"min":   {"field": "@timestamp"}},
                            "last_alert":  {"max":   {"field": "@timestamp"}},
                        },
                    }
                },
            }
            try:
                pa_res = await idx.search(pa_body)
                for b in pa_res.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
                    name_bkts = b.get("agent_name", {}).get("buckets", [])
                    agent_breakdown.append({
                        "agent_id":    b["key"],
                        "agent_name":  name_bkts[0]["key"] if name_bkts else b["key"],
                        "alert_count": b["doc_count"],
                        "max_level":   int(b.get("max_level", {}).get("value") or 0),
                        "techniques":  [t["key"] for t in b.get("techniques", {}).get("buckets", [])],
                        "top_rules":   [r["key"] for r in b.get("top_rules",  {}).get("buckets", [])],
                        "first_seen":  b.get("first_alert", {}).get("value_as_string", ""),
                        "last_seen":   b.get("last_alert",  {}).get("value_as_string", ""),
                        "role": (
                            "PATIENT_ZERO"    if seed_agent_id and b["key"] == seed_agent_id
                            else "LATERAL_TARGET"
                        ),
                    })
            except Exception:
                pass

        agent_breakdown.sort(key=lambda x: x.get("first_seen", ""))
        # Mark the earliest-alert agent as INITIAL_TARGET if no seed_agent_id
        if agent_breakdown and not seed_agent_id:
            agent_breakdown[0]["role"] = "INITIAL_TARGET"

        # ── Phase 4: Kill-chain mapping ────────────────────────────────────────
        enriched_techniques = _enrich_mitre_ids(raw_techniques)
        PHASE_ORDER = {
            "Initial Access": 1, "Execution": 2, "Persistence": 3,
            "Privilege Escalation": 4, "Defense Evasion": 5, "Credential Access": 6,
            "Discovery": 7, "Lateral Movement": 8, "Collection": 9,
            "Command and Control": 10, "Exfiltration": 11, "Impact": 12,
        }
        kill_chain = sorted(enriched_techniques, key=lambda t: PHASE_ORDER.get(t.get("tactic", ""), 99))

        # ── Phase 5: Confidence scoring ────────────────────────────────────────
        confidence = 0
        confidence_factors: list[str] = []

        if len(involved_agent_ids) >= 3:
            confidence += 30
            confidence_factors.append(f"{len(involved_agent_ids)} agents involved — strong lateral movement signal")
        elif len(involved_agent_ids) == 2:
            confidence += 15
            confidence_factors.append("2 agents involved — possible lateral movement")

        if len(raw_techniques) >= 3:
            confidence += 25
            confidence_factors.append(f"{len(raw_techniques)} MITRE techniques mapped — multi-stage attack")
        elif raw_techniques:
            confidence += 10
            confidence_factors.append(f"{len(raw_techniques)} MITRE technique(s) detected")

        if any(t.get("tactic") == "Lateral Movement" for t in enriched_techniques):
            confidence += 25
            confidence_factors.append("Lateral Movement technique confirmed")
        if any(t.get("tactic") in ("Credential Access", "Privilege Escalation") for t in enriched_techniques):
            confidence += 15
            confidence_factors.append("Credential Access or Privilege Escalation detected")
        if attacker_ips:
            confidence += 5
            confidence_factors.append(f"Consistent attacker IP(s): {sorted(attacker_ips)[:3]}")

        confidence = min(confidence, 99)
        confidence_tier = "HIGH" if confidence >= 70 else "MEDIUM" if confidence >= 40 else "LOW"

        return {
            "correlation_summary": {
                "confidence":         confidence,
                "confidence_tier":    confidence_tier,
                "confidence_factors": confidence_factors,
                "total_seed_alerts":  seed_total,
                "agents_involved":    len(involved_agent_ids),
                "attacker_ips":       sorted(attacker_ips)[:10],
                "destination_ips":    sorted(dst_ips)[:10],
                "shared_usernames":   sorted(usernames)[:10],
                "time_range":         time_range,
            },
            "kill_chain":          kill_chain,
            "agent_timeline":      agent_breakdown,
            "top_rules_fired":     top_rules[:10],
            "recommended_actions": _incident_recommendations(raw_techniques, confidence_tier, list(attacker_ips)),
            "next_tools": [t for t in [
                f"blast_radius_analysis(src_ip='{sorted(attacker_ips)[0]}')" if attacker_ips else None,
                f"incident_timeline(start_time='now-{time_range}', agent_ids={list(involved_agent_ids)[:5]})",
                "create_incident_report(alert_ids=[...top alert IDs from timeline...])",
                f"bulk_enrich_iocs(iocs={sorted(attacker_ips)[:5]})" if attacker_ips else None,
            ] if t],
            "tip": (
                "Set seed_src_ip to expand from an attacker IP. "
                "Use incident_timeline() with the agent_ids from agent_timeline for a chronological view."
            ),
        }

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
