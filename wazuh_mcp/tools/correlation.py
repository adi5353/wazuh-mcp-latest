"""Lightweight alert correlation engine.

Groups related alerts by time window, source IP, agent, and MITRE tactic,
assigns a composite incident score, and detects multi-stage attack chains.
"""
from __future__ import annotations

import collections
from ..tool_context import ToolContext
from typing import Any

from ..helpers import time_window


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz  = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap

    @mcp.tool()
    async def correlate_alerts(
        time_range: str = "2h",
        min_score: int = 3,
        tactics: str = "",
    ) -> dict:
        """Group and score related alerts to surface candidate incidents.

        Clusters alerts by shared src_ip, agent, and MITRE tactic within the
        time window. Each cluster receives a composite score based on:
          +2 per unique MITRE tactic observed
          +2 for critical/high severity alerts in the cluster
          +1 per unique agent affected
          +1 per unique source IP

        Args:
            time_range:  Look-back window (e.g. "1h", "6h", "24h"). Default "2h".
            min_score:   Minimum score to include a cluster. Default 3.
            tactics:     Comma-separated MITRE tactic filter (e.g. "Lateral Movement,Persistence").
                         Empty = all tactics.
        """
        from ..rbac import require_role, ROLE
        err = require_role(ROLE.ANALYST)
        if err:
            return err

        gte, lte = time_window(time_range)
        tactic_filter = [t.strip() for t in tactics.split(",") if t.strip()]

        body: dict = {
            "size": 500,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
            ]}},
            "_source": [
                "@timestamp", "rule.id", "rule.description",
                "rule.level", "rule.mitre.id", "rule.mitre.tactic",
                "agent.id", "agent.name", "data.srcip",
            ],
            "sort": [{"@timestamp": {"order": "asc"}}],
        }

        try:
            resp = await idx.search(body)
        except Exception as exc:
            return {"error": f"Indexer query failed: {exc}"}

        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return {"clusters": [], "total_alerts_scanned": 0, "time_range": time_range}

        from ..mitre_data import enrich_mitre_ids

        # ── Build clusters keyed by (src_ip or agent_id) + tactic ────────────
        Cluster: Any = collections.defaultdict(lambda: {
            "alerts": [], "agents": set(), "src_ips": set(),
            "tactics": set(), "technique_ids": set(),
            "max_level": 0, "score": 0,
        })

        for hit in hits:
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            agent = src.get("agent", {})
            data = src.get("data", {})

            level = int(rule.get("level", 0))
            src_ip = data.get("srcip", "")
            agent_id = agent.get("id", "000")
            agent_name = agent.get("name", agent_id)
            mitre = rule.get("mitre", {})
            tids = mitre.get("id", [])
            if isinstance(tids, str):
                tids = [tids]
            raw_tactics = mitre.get("tactic", [])
            if isinstance(raw_tactics, str):
                raw_tactics = [raw_tactics]

            if tactic_filter and not any(t in raw_tactics for t in tactic_filter):
                continue

            # Cluster key: prefer src_ip grouping, fall back to agent
            cluster_key = src_ip if src_ip else agent_id

            c = Cluster[cluster_key]
            c["alerts"].append({
                "id": hit.get("_id"),
                "timestamp": src.get("@timestamp"),
                "rule_id": rule.get("id"),
                "description": rule.get("description", ""),
                "level": level,
            })
            c["agents"].add(agent_name)
            if src_ip:
                c["src_ips"].add(src_ip)
            c["tactics"].update(raw_tactics)
            c["technique_ids"].update(tids)
            c["max_level"] = max(c["max_level"], level)

        # ── Score each cluster ────────────────────────────────────────────────
        results = []
        for key, c in Cluster.items():
            score = 0
            score += len(c["tactics"]) * 2           # tactic diversity
            score += len(c["agents"])                 # agent spread
            score += len(c["src_ips"])                # source IP count
            if c["max_level"] >= 12:
                score += 3                            # critical severity
            elif c["max_level"] >= 9:
                score += 2                            # high severity
            if len(c["alerts"]) >= 10:
                score += 1                            # volume indicator

            if score < min_score:
                continue

            severity = (
                "CRITICAL" if c["max_level"] >= 12 else
                "HIGH"     if c["max_level"] >= 9  else
                "MEDIUM"   if c["max_level"] >= 6  else "LOW"
            )

            results.append({
                "cluster_key": key,
                "score": score,
                "severity": severity,
                "alert_count": len(c["alerts"]),
                "agents": sorted(c["agents"]),
                "src_ips": sorted(c["src_ips"]),
                "tactics": sorted(c["tactics"]),
                "techniques": enrich_mitre_ids(sorted(c["technique_ids"])),
                "max_rule_level": c["max_level"],
                "sample_alerts": c["alerts"][:5],
            })

        results.sort(key=lambda x: x["score"], reverse=True)

        return {
            "clusters": results[: _cap(50)],
            "total_clusters": len(results),
            "total_alerts_scanned": len(hits),
            "time_range": time_range,
            "min_score": min_score,
        }

    @mcp.tool()
    async def get_attack_chains(
        time_range: str = "24h",
        min_stages: int = 2,
    ) -> dict:
        """Detect multi-stage attack patterns by correlating MITRE tactic sequences.

        An "attack chain" is a sequence of distinct MITRE tactics observed on
        the same agent or from the same source IP within the time window.
        Chains with ≥ min_stages distinct tactics are returned, ordered by
        stage count descending.

        Args:
            time_range:  Look-back window (e.g. "6h", "24h", "48h"). Default "24h".
            min_stages:  Minimum distinct tactics to qualify as a chain. Default 2.
        """
        from ..rbac import require_role, ROLE
        err = require_role(ROLE.ANALYST)
        if err:
            return err

        gte, lte = time_window(time_range)

        body: dict = {
            "size": 1000,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
                {"exists": {"field": "rule.mitre.tactic"}},
            ]}},
            "_source": [
                "@timestamp", "rule.id", "rule.description", "rule.level",
                "rule.mitre.id", "rule.mitre.tactic",
                "agent.id", "agent.name", "data.srcip",
            ],
            "sort": [{"@timestamp": {"order": "asc"}}],
        }

        try:
            resp = await idx.search(body)
        except Exception as exc:
            return {"error": f"Indexer query failed: {exc}"}

        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return {"chains": [], "total_alerts_scanned": 0}

        # ── Build tactic timeline per pivot (agent or src_ip) ─────────────────
        # Maps pivot → ordered list of (timestamp, tactic, rule_desc, technique_ids)
        timeline: dict[str, list] = collections.defaultdict(list)

        for hit in hits:
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            agent = src.get("agent", {})
            data = src.get("data", {})

            tactics = rule.get("mitre", {}).get("tactic", [])
            if isinstance(tactics, str):
                tactics = [tactics]
            if not tactics:
                continue

            tids = rule.get("mitre", {}).get("id", [])
            if isinstance(tids, str):
                tids = [tids]

            pivot = data.get("srcip") or agent.get("name") or agent.get("id", "unknown")
            for tactic in tactics:
                timeline[pivot].append({
                    "timestamp": src.get("@timestamp"),
                    "tactic": tactic,
                    "rule_id": rule.get("id"),
                    "description": rule.get("description", "")[:120],
                    "level": rule.get("level", 0),
                    "technique_ids": tids,
                })

        # ── Identify chains with >= min_stages distinct tactics ───────────────
        # Standard kill-chain ordering for display
        _TACTIC_ORDER = [
            "Reconnaissance", "Resource Development", "Initial Access", "Execution",
            "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact",
        ]

        from ..mitre_data import enrich_mitre_ids

        chains = []
        for pivot, events in timeline.items():
            seen_tactics: dict[str, dict] = {}
            for ev in events:
                t = ev["tactic"]
                if t not in seen_tactics or ev["level"] > seen_tactics[t]["level"]:
                    seen_tactics[t] = ev

            if len(seen_tactics) < min_stages:
                continue

            ordered = sorted(
                seen_tactics.values(),
                key=lambda e: _TACTIC_ORDER.index(e["tactic"])
                if e["tactic"] in _TACTIC_ORDER else 99,
            )
            all_tids = list({tid for ev in ordered for tid in ev.get("technique_ids", [])})

            chains.append({
                "pivot": pivot,
                "stage_count": len(seen_tactics),
                "tactics_observed": [e["tactic"] for e in ordered],
                "techniques": enrich_mitre_ids(all_tids),
                "kill_chain": [
                    {
                        "tactic": e["tactic"],
                        "rule_id": e["rule_id"],
                        "description": e["description"],
                        "timestamp": e["timestamp"],
                        "level": e["level"],
                    }
                    for e in ordered
                ],
                "max_level": max(e["level"] for e in ordered),
            })

        chains.sort(key=lambda x: (x["stage_count"], x["max_level"]), reverse=True)

        return {
            "chains": chains[: _cap(20)],
            "total_chains": len(chains),
            "total_alerts_scanned": len(hits),
            "time_range": time_range,
            "min_stages": min_stages,
        }
