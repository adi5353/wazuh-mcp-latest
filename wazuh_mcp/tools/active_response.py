"""Active response tools — list AR actions, correlate with alerts, audit effectiveness."""
from __future__ import annotations
from ..tool_context import ToolContext

from ..validators import safe_validate, validate_time_range

AR_RULE_IDS = ["601", "602", "603", "651", "652"]
AR_GROUPS = ["active_response", "ar"]


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap

    @mcp.tool()
    async def get_active_responses(time_range: str = "24h", limit: int = 50) -> dict:
        """List active-response actions Wazuh took recently, with triggering context."""
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        body = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                        {
                            "bool": {
                                "should": [
                                    {"terms": {"rule.groups": AR_GROUPS}},
                                    {"terms": {"rule.id": AR_RULE_IDS}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ]
                }
            },
        }
        res = await idx.search(body)
        responses = []
        for h in res["hits"]["hits"]:
            src = h["_source"]
            data = src.get("data", {})
            responses.append({
                "timestamp": src.get("@timestamp"),
                "agent": src.get("agent", {}).get("name"),
                "agent_id": src.get("agent", {}).get("id"),
                "command": data.get("command") or data.get("extra_data"),
                "src_ip_blocked": data.get("srcip"),
                "user_affected": data.get("dstuser") or data.get("srcuser"),
                "rule_description": src.get("rule", {}).get("description"),
                "rule_id": src.get("rule", {}).get("id"),
                "rule_level": src.get("rule", {}).get("level"),
                "log_snippet": (src.get("full_log") or "")[:300],
            })
        return {
            "time_range": time_range,
            "total": res["hits"]["total"]["value"],
            "responses": responses,
        }

    @mcp.tool()
    async def correlate_alert_with_response(
        src_ip: str | None = None,
        agent_id: str | None = None,
        time_range: str = "1h",
    ) -> dict:
        """Given a source IP or agent, return both the triggering alerts AND any AR taken."""
        if not src_ip and not agent_id:
            return {"error": "Provide src_ip or agent_id"}

        filters: list[dict] = [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}]
        if src_ip:
            filters.append({"term": {"data.srcip": src_ip}})
        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})

        body = {
            "size": 200,
            "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": filters}},
        }
        res = await idx.search(body)

        triggering, responses = [], []
        for h in res["hits"]["hits"]:
            src = h["_source"]
            groups = src.get("rule", {}).get("groups", [])
            rule_id = str(src.get("rule", {}).get("id", ""))
            is_ar = any(g in AR_GROUPS for g in groups) or rule_id in AR_RULE_IDS
            entry = {
                "timestamp": src.get("@timestamp"),
                "rule_id": rule_id,
                "rule_description": src.get("rule", {}).get("description"),
                "level": src.get("rule", {}).get("level"),
                "agent": src.get("agent", {}).get("name"),
            }
            if is_ar:
                entry["command"] = (src.get("data", {}).get("command")
                                    or src.get("data", {}).get("extra_data"))
                responses.append(entry)
            else:
                triggering.append(entry)

        return {
            "query": {"src_ip": src_ip, "agent_id": agent_id, "time_range": time_range},
            "response_taken": len(responses) > 0,
            "triggering_alerts_count": len(triggering),
            "response_actions_count": len(responses),
            "triggering_alerts": triggering[:30],
            "response_actions": responses,
            "verdict": (
                "Active response was triggered."
                if responses
                else "Alerts fired but no active response was executed in this window."
            ),
        }

    @mcp.tool()
    async def active_response_effectiveness(time_range: str = "7d") -> dict:
        """Audit AR effectiveness — did blocks actually stop alert traffic from the source?

        For each AR event that blocked an IP, count alerts from that IP AFTER the block.
        Zero = block worked; non-zero = the attacker got through anyway.
        """
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        ar_body = {
            "size": 500,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                        {
                            "bool": {
                                "should": [
                                    {"terms": {"rule.groups": AR_GROUPS}},
                                    {"terms": {"rule.id": ["601", "651"]}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        {"exists": {"field": "data.srcip"}},
                    ]
                }
            },
            "_source": ["@timestamp", "data.srcip", "agent.name", "data.command"],
        }
        ar_res = await idx.search(ar_body)

        findings = []
        for h in ar_res["hits"]["hits"]:
            src = h["_source"]
            blocked_ip = src.get("data", {}).get("srcip")
            block_time = src.get("@timestamp")
            if not blocked_ip:
                continue
            post_query = {
                "bool": {
                    "filter": [
                        {"term": {"data.srcip": blocked_ip}},
                        {"range": {"@timestamp": {"gt": block_time}}},
                    ]
                }
            }
            post_count = await idx.count(post_query)
            findings.append({
                "blocked_ip": blocked_ip,
                "block_time": block_time,
                "agent": src.get("agent", {}).get("name"),
                "command": src.get("data", {}).get("command"),
                "alerts_after_block": post_count,
                "block_effective": post_count == 0,
            })

        ineffective = [f for f in findings if not f["block_effective"]]
        return {
            "time_range": time_range,
            "total_blocks": len(findings),
            "effective_blocks": len(findings) - len(ineffective),
            "ineffective_blocks": len(ineffective),
            "effectiveness_pct": (
                round((len(findings) - len(ineffective)) / len(findings) * 100, 1)
                if findings
                else None
            ),
            "ineffective_block_details": ineffective[:20],
        }
