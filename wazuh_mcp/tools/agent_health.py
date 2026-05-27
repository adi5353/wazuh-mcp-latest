"""Agent health scoring — composite 0-100 health score per Wazuh agent.

Combines five dimensions into a single score:

  Dimension            Weight   Source
  ─────────────────────────────────────────────────────────────────────
  Connectivity          25 pts  Agent status (active = full marks)
  Event throughput      25 pts  Alert volume vs 7-day rolling average
  SCA pass rate         20 pts  Passed / (passed + failed) checks
  Vulnerability load    15 pts  Critical+High CVE count (inverted)
  FIM activity          15 pts  Recent critical file changes (inverted)

Score bands:
  90-100  HEALTHY
  70-89   WARNING
  50-69   DEGRADED
  0-49    CRITICAL
"""
from __future__ import annotations
from ..tool_context import ToolContext

import asyncio


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _agent_event_score(agent_name: str) -> tuple[int, dict]:
        """Compare last-24h event volume vs 7-day daily average. Returns (0-25, detail)."""
        try:
            base_body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": "now-7d", "lte": "now-1d"}}},
                            {"term": {"agent.name": agent_name}},
                        ]
                    }
                },
            }
            recent_body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": "now-24h"}}},
                            {"term": {"agent.name": agent_name}},
                        ]
                    }
                },
            }
            base_res, recent_res = await asyncio.gather(
                idx.search(base_body), idx.search(recent_body)
            )
            base_total = base_res["hits"]["total"]["value"]
            daily_avg = base_total / 6 if base_total else 0
            recent_count = recent_res["hits"]["total"]["value"]

            detail = {
                "events_last_24h": recent_count,
                "daily_avg_6d": round(daily_avg, 1),
            }

            if daily_avg == 0:
                # No baseline — neutral score
                return 15, {**detail, "note": "no_baseline"}

            ratio = recent_count / daily_avg
            if ratio >= 0.5:
                score = 25
            elif ratio >= 0.25:
                score = 18
            elif ratio >= 0.1:
                score = 10
            else:
                score = 0  # agent appears silent
            return score, detail
        except Exception as exc:
            return 15, {"error": str(exc)}

    async def _agent_sca_score(agent_id: str) -> tuple[int, dict]:
        """SCA pass rate → 0-20 pts."""
        try:
            res = await wz.request("GET", f"/sca/{agent_id}?limit=100")
            policies = (res.get("data") or {}).get("affected_items", [])
            if not policies:
                return 10, {"note": "no_sca_policies"}
            total_pass = sum(p.get("pass", 0) for p in policies)
            total_fail = sum(p.get("fail", 0) for p in policies)
            denominator = total_pass + total_fail
            pass_rate = (total_pass / denominator) if denominator else 0
            score = round(pass_rate * 20)
            return score, {
                "sca_pass": total_pass,
                "sca_fail": total_fail,
                "pass_rate_pct": round(pass_rate * 100, 1),
            }
        except Exception as exc:
            return 10, {"error": str(exc)}

    async def _agent_vuln_score(agent_name: str) -> tuple[int, dict]:
        """Invert CVE count → 0-15 pts. Penalises Critical + High findings."""
        try:
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"agent.name": agent_name}},
                            {"terms": {"vulnerability.severity": ["Critical", "High"]}},
                        ]
                    }
                },
            }
            res = await idx.search(body, index=cfg.vuln_index)
            count = res["hits"]["total"]["value"]
            if count == 0:
                score = 15
            elif count <= 5:
                score = 12
            elif count <= 20:
                score = 8
            elif count <= 50:
                score = 4
            else:
                score = 0
            return score, {"critical_high_cves": count}
        except Exception as exc:
            return 8, {"error": str(exc)}

    async def _agent_fim_score(agent_name: str) -> tuple[int, dict]:
        """Invert recent critical FIM changes → 0-15 pts."""
        try:
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": "now-24h"}}},
                            {"term": {"agent.name": agent_name}},
                            {"terms": {"rule.groups": ["syscheck"]}},
                            {"range": {"rule.level": {"gte": 10}}},
                        ]
                    }
                },
            }
            res = await idx.search(body)
            count = res["hits"]["total"]["value"]
            if count == 0:
                score = 15
            elif count <= 3:
                score = 12
            elif count <= 10:
                score = 8
            elif count <= 25:
                score = 4
            else:
                score = 0
            return score, {"critical_fim_changes_24h": count}
        except Exception as exc:
            return 10, {"error": str(exc)}

    def _connectivity_score(status: str) -> int:
        return {
            "active": 25,
            "pending": 10,
            "disconnected": 0,
            "never_connected": 0,
        }.get(status.lower(), 5)

    def _band(score: int) -> str:
        if score >= 90:
            return "HEALTHY"
        if score >= 70:
            return "WARNING"
        if score >= 50:
            return "DEGRADED"
        return "CRITICAL"

    # ── Exposed MCP tools ─────────────────────────────────────────────────────

    @mcp.tool()
    async def get_agent_health_score(agent_id: str) -> dict:
        """Compute a composite 0-100 health score for a single Wazuh agent.

        Combines connectivity (25pts), event throughput (25pts), SCA pass rate (20pts),
        vulnerability load (15pts), and FIM activity (15pts).

        Score bands: HEALTHY ≥90 | WARNING ≥70 | DEGRADED ≥50 | CRITICAL <50
        """
        from ..validators import safe_validate, validate_agent_id
        _, err = safe_validate(validate_agent_id, agent_id)
        if err:
            return err

        # Fetch basic agent info
        try:
            res = await wz.request("GET", f"/agents?agents_list={agent_id}")
            agent_info = (res.get("data") or {}).get("affected_items", [{}])[0]
        except Exception as exc:
            return {"error": f"Could not fetch agent info: {exc}"}

        status = agent_info.get("status", "unknown")
        agent_name = agent_info.get("name", agent_id)

        conn_score = _connectivity_score(status)

        # Run remaining dimension queries in parallel
        (evt_score, evt_detail), (sca_score, sca_detail), \
        (vuln_score, vuln_detail), (fim_score, fim_detail) = await asyncio.gather(
            _agent_event_score(agent_name),
            _agent_sca_score(agent_id),
            _agent_vuln_score(agent_name),
            _agent_fim_score(agent_name),
        )

        total = conn_score + evt_score + sca_score + vuln_score + fim_score

        return {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "status": status,
            "health_score": total,
            "band": _band(total),
            "dimensions": {
                "connectivity":   {"score": conn_score,  "max": 25, "status": status},
                "event_volume":   {"score": evt_score,   "max": 25, **evt_detail},
                "sca_compliance": {"score": sca_score,   "max": 20, **sca_detail},
                "vulnerability":  {"score": vuln_score,  "max": 15, **vuln_detail},
                "fim_activity":   {"score": fim_score,   "max": 15, **fim_detail},
            },
        }

    @mcp.tool()
    async def list_unhealthy_agents(
        band: str = "DEGRADED",
        limit: int = 20,
    ) -> dict:
        """List agents whose health score falls at or below the given band.

        band: CRITICAL | DEGRADED | WARNING (default DEGRADED — includes CRITICAL too)
        Returns agents sorted by health score ascending (worst first).
        """
        allowed_bands = {"CRITICAL", "DEGRADED", "WARNING"}
        if band.upper() not in allowed_bands:
            return {"error": f"Invalid band '{band}'. Choose from: {', '.join(sorted(allowed_bands))}"}
        band = band.upper()

        # Threshold scores per band
        thresholds = {"CRITICAL": 49, "DEGRADED": 69, "WARNING": 89}
        max_score = thresholds[band]

        try:
            res = await wz.request("GET", f"/agents?status=active,disconnected&limit={_cap(limit * 3)}")
            agents = (res.get("data") or {}).get("affected_items", [])
        except Exception as exc:
            return {"error": str(exc)}

        # Score each agent (bounded parallelism — up to limit*3 agents)
        async def _score_one(agent: dict) -> dict | None:
            aid = agent.get("id", "")
            aname = agent.get("name", aid)
            astatus = agent.get("status", "unknown")
            conn = _connectivity_score(astatus)
            evt_s, _ = await _agent_event_score(aname)
            sca_s, _ = await _agent_sca_score(aid)
            vuln_s, _ = await _agent_vuln_score(aname)
            fim_s, _ = await _agent_fim_score(aname)
            total = conn + evt_s + sca_s + vuln_s + fim_s
            if total <= max_score:
                return {"agent_id": aid, "agent_name": aname, "status": astatus, "health_score": total, "band": _band(total)}
            return None

        results_raw = await asyncio.gather(*[_score_one(a) for a in agents[:_cap(limit * 3)]])
        results = sorted(
            [r for r in results_raw if r is not None],
            key=lambda x: x["health_score"],
        )[:_cap(limit)]

        return {
            "filter_band": band,
            "max_score_included": max_score,
            "count": len(results),
            "agents": results,
        }

    @mcp.tool()
    async def get_health_breakdown(limit: int = 10) -> dict:
        """Fleet-wide health overview — score distribution and worst agents.

        Returns band distribution (HEALTHY/WARNING/DEGRADED/CRITICAL count)
        plus the bottom N agents by health score.
        """
        try:
            res = await wz.request("GET", f"/agents?status=active,disconnected&limit={_cap(100)}")
            agents = (res.get("data") or {}).get("affected_items", [])
        except Exception as exc:
            return {"error": str(exc)}

        async def _quick_score(agent: dict) -> dict:
            aid = agent.get("id", "")
            aname = agent.get("name", aid)
            astatus = agent.get("status", "unknown")
            conn = _connectivity_score(astatus)
            evt_s, _ = await _agent_event_score(aname)
            sca_s, _ = await _agent_sca_score(aid)
            vuln_s, _ = await _agent_vuln_score(aname)
            fim_s, _ = await _agent_fim_score(aname)
            total = conn + evt_s + sca_s + vuln_s + fim_s
            return {"agent_id": aid, "agent_name": aname, "health_score": total, "band": _band(total)}

        all_scores = await asyncio.gather(*[_quick_score(a) for a in agents])
        distribution: dict[str, int] = {"HEALTHY": 0, "WARNING": 0, "DEGRADED": 0, "CRITICAL": 0}
        for entry in all_scores:
            distribution[entry["band"]] = distribution.get(entry["band"], 0) + 1

        worst = sorted(all_scores, key=lambda x: x["health_score"])[:_cap(limit)]
        avg_score = round(sum(e["health_score"] for e in all_scores) / len(all_scores), 1) if all_scores else 0

        return {
            "total_agents_checked": len(all_scores),
            "average_health_score": avg_score,
            "distribution": distribution,
            "worst_agents": worst,
        }
