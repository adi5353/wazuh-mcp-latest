"""Security Configuration Assessment tools — policies, failed checks, fleet scoring."""
from __future__ import annotations
from ..tool_context import ToolContext

from ..helpers import time_window


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap

    @mcp.tool()
    async def get_agent_sca_policies(agent_id: str) -> dict:
        """List SCA policies running on an agent with pass/fail summary scores."""
        return await wz.request("GET", f"/sca/{agent_id}")

    @mcp.tool()
    async def get_sca_failed_checks(
        agent_id: str, policy_id: str, limit: int = 100
    ) -> dict:
        """Failing checks for one SCA policy on one agent."""
        path = f"/sca/{agent_id}/checks/{policy_id}?result=failed&limit={_cap(limit)}"
        return await wz.request("GET", path)

    @mcp.tool()
    async def sca_alerts_summary(time_range: str = "7d") -> dict:
        """Aggregated view of SCA alerts across the fleet from the indexer."""
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"term": {"rule.groups": "sca"}},
                    ]
                }
            },
            "aggs": {
                "by_agent": {"terms": {"field": "agent.name", "size": 20}},
                "by_check": {
                    "terms": {"field": "data.sca.check.title.keyword", "size": 20},
                    "aggs": {
                        "agents_affected": {"cardinality": {"field": "agent.id"}}
                    },
                },
                "by_result": {"terms": {"field": "data.sca.check.result", "size": 10}},
                "by_policy": {"terms": {"field": "data.sca.policy", "size": 10}},
            },
        }
        res = await idx.search(body)
        aggs = res["aggregations"]
        return {
            "time_range": time_range,
            "total_sca_alerts": res["hits"]["total"]["value"],
            "by_result": [
                {"result": b["key"], "count": b["doc_count"]}
                for b in aggs["by_result"]["buckets"]
            ],
            "policies_running": [
                {"policy": b["key"], "alerts": b["doc_count"]}
                for b in aggs["by_policy"]["buckets"]
            ],
            "noisiest_agents": [
                {"agent": b["key"], "alerts": b["doc_count"]}
                for b in aggs["by_agent"]["buckets"]
            ],
            "most_common_failures": [
                {
                    "check": b["key"],
                    "occurrences": b["doc_count"],
                    "agents_affected": b["agents_affected"]["value"],
                }
                for b in aggs["by_check"]["buckets"]
            ],
        }

    @mcp.tool()
    async def fleet_sca_weakest_agents(limit: int = 20) -> dict:
        """Rank agents by their SCA configuration weakness — most failing checks first."""
        agents_resp = await wz.request("GET", f"/agents?status=active&limit={_cap(limit)}")
        agents = (agents_resp.get("data") or {}).get("affected_items", [])

        findings = []
        for ag in agents:
            agent_id = ag.get("id")
            if not agent_id:
                continue
            try:
                sca = await wz.request("GET", f"/sca/{agent_id}")
                policies = (sca.get("data") or {}).get("affected_items", [])
            except Exception:
                continue

            for p in policies:
                failed = p.get("fail", 0)
                passed = p.get("pass", 0)
                total = failed + passed
                score = p.get("score")
                if score is None and total:
                    score = round(passed / total * 100, 1)
                findings.append({
                    "agent_id": agent_id,
                    "agent_name": ag.get("name"),
                    "policy": p.get("name") or p.get("policy_id"),
                    "passed": passed,
                    "failed": failed,
                    "score_pct": score,
                })

        findings.sort(key=lambda x: (x["failed"] or 0), reverse=True)
        return {
            "agents_scanned": len(agents),
            "weakest_first": findings[:limit],
        }
