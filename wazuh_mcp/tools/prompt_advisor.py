"""System prompt and routing advisor tools.

Ports the deterministic routing guardrails from the n8n + Groq PoC document
(WAI00001) into MCP-native tools. Provides the exact system prompt used in
the PoC, routing guidance, and a token-budget advisor to keep responses
within safe limits for any downstream LLM (Groq, OpenAI, local models).
"""
from __future__ import annotations
from ..tool_context import ToolContext

import json

# ── Exact system prompt from the n8n PoC document (WAI00001) ─────────────────
# Reproduced verbatim from the Confluence export. Used as the AI Agent
# system message that enforces deterministic Manager vs Indexer routing.
_POC_SYSTEM_PROMPT = """\
You are a Tier 1 security orchestrator. You have access to multiple tools \
grouped into two main categories:

1. Wazuh Manager Tools: Use these EXCLUSIVELY to manage the infrastructure, \
such as querying the list of deployed agents, their connection status, \
configurations, decoders, and base rules.

2. Wazuh Indexer Tools: Use these EXCLUSIVELY to search for security events, \
triggered alerts, raw logs, and filtering by severity levels.

STRICT RULES:
- NEVER attempt to search for alerts or incidents using the Manager tools. \
If the user asks about 'alerts', 'events', 'attacks', or 'levels', you must \
obligatorily look for the appropriate tool within the Indexer.
- If you cannot find the proper tool, reply that you do not have the \
capability instead of hallucinating or inventing data.

RESPONSE GUIDELINES:
- When asked for lists and counts, perform the action, then state the count \
clearly before providing the detailed list.
- Keep answers concise, technical, and professional.
- If an API returns a list, analyze the total number of items returned to \
answer 'how many' questions accurately.
- Always include the timestamp and the rule description from the tool's \
output when listing alerts so the user can verify the data.\
"""

# ── Tool routing table ─────────────────────────────────────────────────────────
# Maps intent keywords → recommended tool category and specific tools.
_ROUTING_TABLE = {
    "manager": {
        "keywords": [
            "agent", "agents", "status", "connection", "configuration",
            "config", "daemon", "decoder", "rule file", "active response",
            "restart", "upgrade", "rootcheck", "sca policy", "groups",
            "manager info", "manager logs", "manager status",
        ],
        "tools": [
            "list_agents", "get_agent", "get_manager_status", "get_manager_info",
            "get_manager_logs", "get_manager_config_section",
            "list_manager_config_sections", "get_agent_hardware_os",
            "get_agent_packages", "get_agent_processes", "get_agent_open_ports",
            "get_agent_sca_policies", "get_agent_rootcheck_results",
            "list_groups", "get_group_agents", "list_rule_files",
            "list_decoders", "get_custom_rules", "trigger_agent_upgrade",
            "list_agent_upgrades", "get_agent_upgrade_status",
        ],
    },
    "indexer": {
        "keywords": [
            "alert", "alerts", "event", "events", "attack", "level",
            "severity", "fim", "file integrity", "compliance", "vulnerability",
            "vulnerabilities", "cve", "log", "logs", "mitre", "tactic",
            "technique", "incident", "search", "query", "24h", "last",
            "recent", "history",
        ],
        "tools": [
            "search_alerts", "get_recent_alerts_24h", "search_fim_alerts",
            "get_recent_fim_changes", "critical_file_changes",
            "vulnerability_summary", "search_cve", "compliance_summary",
            "generate_compliance_report", "search_by_mitre",
            "hunt_lateral_movement", "hunt_persistence_mechanisms",
            "hunt_data_exfiltration", "get_agent_login_history",
            "search_authentication_failures", "search_archive_logs",
        ],
    },
}

# ── Approximate token costs per tool response ─────────────────────────────────
# Rough upper-bound estimates at default limits. Used by check_response_size.
_TOKEN_ESTIMATES: dict[str, int] = {
    "list_agents": 800,
    "search_alerts": 1200,
    "get_recent_alerts_24h": 1000,
    "vulnerability_summary": 1500,
    "search_cve": 900,
    "compliance_summary": 1100,
    "get_agent_packages": 2000,
    "fleet_batch_syscollector": 4000,
    "search_fim_alerts": 1000,
    "get_recent_fim_changes": 900,
    "hunt_lateral_movement": 1400,
    "hunt_persistence_mechanisms": 1400,
    "hunt_data_exfiltration": 1400,
    "generate_weekly_summary": 2000,
    "generate_compliance_report": 2500,
    "export_alerts_csv": 3000,
    "export_vulnerabilities_csv": 3000,
}

_DEFAULT_TOKEN_ESTIMATE = 600   # for any tool not in the table
_GROQ_TPM_LIMIT = 12_000        # Groq llama-3.3-70b free-tier limit


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _truncate = ctx.truncate

    @mcp.tool()
    async def get_recommended_system_prompt(
        include_routing_table: bool = False,
        model_tpm_limit: int = 12000,
    ) -> dict:
        """Return the deterministic routing system prompt from the n8n PoC document.

        This is the exact guardrail system message used in WAI00001 to enforce
        strict Manager vs Indexer routing in the Groq/n8n AI Security Analyst PoC.
        Paste it as the system message for any LLM integration (Claude, Groq,
        OpenAI) to prevent hallucination and ensure correct API routing.

        Args:
            include_routing_table: If True, also return keyword→tool mappings
                that explain which tools belong to Manager vs Indexer.
            model_tpm_limit: Your LLM's tokens-per-minute limit. Used to
                compute a safe per-response token budget. Defaults to 12 000
                (Groq llama-3.3-70b free tier).

        Returns:
            system_prompt: The verbatim guardrail prompt from the PoC.
            memory_guardrail: Recommended context window length setting (2-3 turns).
            token_budget: Safe per-response token budget given the TPM limit.
            indexer_query_template: The 24h alert query from the PoC doc.
            routing_table: (optional) keyword → tool category mappings.
        """
        # Safe per-call budget: assume 4 calls/min max, leave headroom
        safe_budget = max(500, model_tpm_limit // 6)

        result: dict = {
            "system_prompt": _POC_SYSTEM_PROMPT,
            "memory_guardrail": {
                "context_window_turns": 2,
                "rationale": (
                    "Constraining Simple Memory to 2-3 turns prevents historic "
                    "JSON arrays from compounding into the active context window, "
                    "stabilising transaction profiles within the TPM limit."
                ),
            },
            "token_budget": {
                "model_tpm_limit": model_tpm_limit,
                "recommended_per_response_limit": safe_budget,
                "recommended_tool_result_limit": min(10, _cap(10)),
                "rationale": (
                    f"With a {model_tpm_limit:,} TPM ceiling, cap each tool "
                    f"result to ~{safe_budget:,} tokens. Set global Limit on "
                    "list tools to 5-10 objects as described in the PoC doc."
                ),
            },
            "indexer_query_template": {
                "description": "24-hour alert query used in the PoC Wazuh Indexer node",
                "index": "wazuh-alerts-4.x-*",
                "query": {
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": "now-24h"}}}
                            ]
                        }
                    },
                    "sort": [{"@timestamp": {"order": "desc"}}],
                },
            },
            "routing_summary": {
                "manager_api": "Infrastructure queries — agents, config, daemons, rules",
                "indexer_api": "Security event queries — alerts, FIM, compliance, CVEs",
            },
        }

        if include_routing_table:
            result["routing_table"] = _ROUTING_TABLE

        return result

    @mcp.tool()
    async def check_response_size(
        tool_name: str,
        result_json: str,
        warn_threshold_tokens: int = 2000,
    ) -> dict:
        """Estimate the token cost of a tool result and warn if it's too large.

        Designed to help SOC operators stay within LLM context/TPM limits
        (especially Groq's 12,000 TPM ceiling). Pass the JSON-serialised
        result of any tool call to get a size estimate and actionable advice.

        Args:
            tool_name: The name of the tool that produced the result.
            result_json: The tool's JSON output serialised as a string.
            warn_threshold_tokens: Emit a warning when estimated tokens exceed
                this value (default 2 000).

        Returns:
            tool_name, char_count, estimated_tokens, status, advice.
        """
        char_count = len(result_json)
        # Rough heuristic: ~4 chars per token (GPT/Claude average)
        estimated_tokens = char_count // 4

        known_estimate = _TOKEN_ESTIMATES.get(tool_name, _DEFAULT_TOKEN_ESTIMATE)

        if estimated_tokens > warn_threshold_tokens:
            status = "warn"
            advice = (
                f"This response is ~{estimated_tokens:,} tokens — above the "
                f"{warn_threshold_tokens:,}-token threshold. Consider: "
                "(1) reducing the 'limit' parameter, "
                "(2) using a more specific filter, or "
                "(3) switching to a summarisation tool."
            )
        elif estimated_tokens > _GROQ_TPM_LIMIT * 0.5:
            status = "critical"
            advice = (
                f"This response alone (~{estimated_tokens:,} tokens) exceeds "
                f"50% of the Groq 12,000 TPM limit. Reduce limit to ≤10 or "
                "use export_*_csv tools for large data sets."
            )
        else:
            status = "ok"
            advice = f"Response size is within safe limits (~{estimated_tokens:,} tokens)."

        return {
            "tool_name": tool_name,
            "char_count": char_count,
            "estimated_tokens": estimated_tokens,
            "typical_tokens_for_tool": known_estimate,
            "warn_threshold": warn_threshold_tokens,
            "groq_tpm_limit": _GROQ_TPM_LIMIT,
            "status": status,
            "advice": advice,
        }

    @mcp.tool()
    async def get_routing_advice(query: str) -> dict:
        """Given a natural-language security query, recommend the correct API route.

        Applies the same deterministic routing rules from the n8n PoC to tell
        you whether to use a Manager tool or an Indexer tool, and which
        specific tool best matches the query.

        Args:
            query: A natural-language security question or task description.

        Returns:
            recommended_api, confidence, matched_keywords, suggested_tools, rationale.
        """
        query_lower = query.lower()

        manager_hits = [kw for kw in _ROUTING_TABLE["manager"]["keywords"] if kw in query_lower]
        indexer_hits = [kw for kw in _ROUTING_TABLE["indexer"]["keywords"] if kw in query_lower]

        if not manager_hits and not indexer_hits:
            return {
                "recommended_api": "unknown",
                "confidence": "low",
                "matched_keywords": [],
                "suggested_tools": [],
                "rationale": (
                    "No routing keywords matched. Per PoC guardrails: if the "
                    "correct tool cannot be identified, reply that you do not "
                    "have the capability rather than hallucinating data."
                ),
            }

        if len(indexer_hits) >= len(manager_hits):
            api = "indexer"
            hits = indexer_hits
            tools = _ROUTING_TABLE["indexer"]["tools"]
            rationale = (
                "Query contains Indexer keywords (alerts/events/logs/severity). "
                "Per PoC guardrails: use Indexer tools EXCLUSIVELY for security "
                "event search. Never use Manager tools for alert queries."
            )
        else:
            api = "manager"
            hits = manager_hits
            tools = _ROUTING_TABLE["manager"]["tools"]
            rationale = (
                "Query contains Manager keywords (agents/config/daemons). "
                "Per PoC guardrails: use Manager tools EXCLUSIVELY for "
                "infrastructure management."
            )

        confidence = "high" if len(hits) >= 2 else "medium"

        # Suggest the 3 most likely tools based on keyword overlap
        suggested = [t for t in tools if any(kw in t for kw in hits)][:3] or tools[:3]

        return {
            "recommended_api": api,
            "confidence": confidence,
            "matched_keywords": hits,
            "suggested_tools": suggested,
            "rationale": rationale,
        }
