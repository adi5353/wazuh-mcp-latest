"""Active response tools — list AR actions, correlate with alerts, audit effectiveness,
and human-in-the-loop approval workflow for proposed active responses.
"""
from __future__ import annotations

import asyncio
import os

from ..tool_context import ToolContext
from ..rbac import ROLE
from ..validators import safe_validate, validate_time_range

# Minimum role required to see these tools (enforced at registration time by server.py)
REQUIRED_ROLE = ROLE.RESPONDER

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

    # ── Human-in-the-loop approval workflow ───────────────────────────────────

    @mcp.tool()
    async def propose_active_response(
        command: str,
        agent_id: str,
        src_ip: str | None = None,
    ) -> dict:
        """Propose an active response for human approval before execution.

        Instead of firing immediately, this tool creates an approval token and
        (if SLACK_WEBHOOK_URL is set) sends a Slack message to the SOC channel
        so a human can approve or deny.

        Workflow:
          1. Call propose_active_response(command, agent_id, src_ip)
             → returns a token and instructions
          2. Human reviews the proposal in Slack and calls:
             approve_response(token)  — executes the active response
             deny_response(token)     — cancels it
          3. Tokens expire after 5 minutes.

        Args:
            command:  Wazuh active-response command name (e.g. 'firewall-drop').
            agent_id: Target agent ID (e.g. '001').
            src_ip:   Source IP to block (passed as argument to the AR command).

        Requires ANALYST role or above.
        """
        from ..rbac import require_role, ROLE as _ROLE
        err = require_role(_ROLE.ANALYST)
        if err:
            return err

        from ..approval import approval_store

        params = {"command": command, "agent_id": agent_id, "src_ip": src_ip}
        token  = approval_store.create("run_active_response", params, ttl=300)

        # Auto-expire: schedule cleanup via asyncio (best-effort, approval_store
        # already tracks expire_at so approve() will reject stale tokens)
        loop = asyncio.get_event_loop()
        loop.call_later(300, approval_store.expire_stale)

        # Slack notification (best-effort — never fail the tool call if Slack is down)
        slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        slack_sent    = False
        if slack_webhook:
            import httpx as _httpx
            action_desc = f"`{command}` on agent `{agent_id}`"
            if src_ip:
                action_desc += f", blocking IP `{src_ip}`"
            msg = (
                f":bell: *Wazuh AI proposes active response*\n"
                f"Action: {action_desc}\n"
                f"Approval token: `{token}`\n"
                f"To proceed: call `approve_response('{token}')` in Wazuh MCP\n"
                f"To cancel:  call `deny_response('{token}')`\n"
                f"_Token expires in 5 minutes._"
            )
            try:
                async with _httpx.AsyncClient(timeout=10) as client:
                    r = await client.post(slack_webhook, json={"text": msg})
                slack_sent = r.status_code == 200
            except Exception:
                pass

        return {
            "status":       "pending_approval",
            "token":        token,
            "action":       "run_active_response",
            "params":       params,
            "slack_notified": slack_sent,
            "message": (
                f"Approval required. Token: {token}. "
                f"Call approve_response('{token}') to execute "
                f"or deny_response('{token}') to cancel. "
                f"Expires in 5 minutes."
            ),
        }

    @mcp.tool()
    async def approve_response(token: str) -> dict:
        """Approve a pending active response proposal and execute it immediately.

        Looks up the proposal by token, executes the stored active-response command
        against the Wazuh Manager, and returns the result.

        Args:
            token: The opaque token returned by propose_active_response.

        Requires RESPONDER role or above.
        """
        from ..rbac import require_role, ROLE as _ROLE
        err = require_role(_ROLE.RESPONDER)
        if err:
            return err

        from ..approval import approval_store
        entry = approval_store.approve(token)
        if entry is None:
            return {
                "error": (
                    f"Token '{token}' not found, already used, or expired. "
                    f"Call propose_active_response again to create a new proposal."
                )
            }

        params   = entry["params"]
        command  = params.get("command", "")
        agent_id = params.get("agent_id", "")
        src_ip   = params.get("src_ip")

        from ..validators import validate_active_response_target, validate_ar_command
        cmd_err = validate_ar_command(command)
        if cmd_err:
            return {"error": cmd_err, "blocked": True, "token": token}
        ip_err = validate_active_response_target(src_ip)
        if ip_err:
            return {"error": ip_err, "blocked": True, "token": token}

        ar_body: dict = {"command": command, "arguments": [src_ip] if src_ip else []}
        try:
            res = await wz.request(
                "PUT",
                f"/active-response?agents_list={agent_id}",
                json=ar_body,
            )
            return {
                "status":   "executed",
                "token":    token,
                "command":  command,
                "agent_id": agent_id,
                "src_ip":   src_ip,
                "result":   res,
            }
        except Exception as exc:
            return {"error": f"Active response execution failed: {exc}", "token": token}

    @mcp.tool()
    async def deny_response(token: str) -> dict:
        """Deny and cancel a pending active response proposal.

        Args:
            token: The opaque token returned by propose_active_response.

        Requires ANALYST role or above.
        """
        from ..rbac import require_role, ROLE as _ROLE
        err = require_role(_ROLE.ANALYST)
        if err:
            return err

        from ..approval import approval_store
        denied = approval_store.deny(token)
        if not denied:
            return {
                "error": (
                    f"Token '{token}' not found or already used. "
                    f"It may have expired or been approved/denied already."
                )
            }
        return {
            "status":  "denied",
            "token":   token,
            "message": "Active response proposal cancelled.",
        }
