"""MCP Resources — read-only structured data endpoints.

Resources let LLMs access stable reference data (agent list, rule set, MITRE
map, server health) without consuming a tool call slot. They appear in the
MCP client as browsable URIs prefixed with wazuh://.

Registered URIs:
  wazuh://agents                  — all connected agents (id, name, status, OS)
  wazuh://mitre/techniques        — full MITRE ATT&CK technique map (149 entries)
  wazuh://rules/summary           — top 50 most-triggered rules (last 7 days)
  wazuh://health                  — server + manager + indexer health snapshot
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

log = logging.getLogger("wazuh-mcp.resources")


def register(mcp: Any, wz: Any, idx: Any, cfg: Any) -> None:

    @mcp.resource(
        "wazuh://agents",
        name="wazuh-agents",
        description="Live list of all Wazuh agents — id, name, status, OS, last seen",
        mime_type="application/json",
    )
    async def agents_resource() -> str:
        """Return a JSON array of all agents (up to 500)."""
        try:
            resp = await wz.request(
                "GET", "/agents",
                params={"limit": 500, "select": "id,name,status,os.name,lastKeepAlive,group"},
            )
            items = resp.get("data", {}).get("affected_items", [])
            # ABAC: the Manager API isn't group-scoped, so a restricted session
            # must not enumerate the whole fleet via this resource. No-op unless
            # WAZUH_MCP_ALLOWED_GROUPS/AGENTS is configured.
            from .abac import filter_agents_by_abac
            items = filter_agents_by_abac(items)
            return json.dumps({
                "total": len(items),
                "agents": [
                    {
                        "id": a.get("id"),
                        "name": a.get("name"),
                        "status": a.get("status"),
                        "os": (a.get("os") or {}).get("name"),
                        "last_seen": a.get("lastKeepAlive"),
                        "group": (a.get("group") or ["(none)"])[0],
                    }
                    for a in items
                ],
            }, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @mcp.resource(
        "wazuh://mitre/techniques",
        name="mitre-techniques",
        description="Full MITRE ATT&CK Enterprise technique map — 149 techniques with tactic mapping",
        mime_type="application/json",
    )
    async def mitre_techniques_resource() -> str:
        """Return the complete MITRE ATT&CK technique map."""
        from .mitre_data import _MITRE_MAP
        return json.dumps(
            {tid: info for tid, info in sorted(_MITRE_MAP.items())},
            indent=2,
        )

    @mcp.resource(
        "wazuh://rules/summary",
        name="wazuh-rules-summary",
        description="Top 50 most-triggered Wazuh rules in the last 7 days with alert counts",
        mime_type="application/json",
    )
    async def rules_summary_resource() -> str:
        """Return the 50 highest-volume rules over the last 7 days."""
        try:
            body = {
                "size": 0,
                "query": {"range": {"timestamp": {"gte": "now-7d/d"}}},
                "aggs": {
                    "top_rules": {
                        "terms": {"field": "rule.id", "size": 50},
                        "aggs": {
                            "description": {"terms": {"field": "rule.description", "size": 1}},
                            "max_level": {"max": {"field": "rule.level"}},
                        },
                    }
                },
            }
            resp = await idx.search(body)
            buckets = resp.get("aggregations", {}).get("top_rules", {}).get("buckets", [])
            return json.dumps({
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "period": "last_7_days",
                "rules": [
                    {
                        "rule_id": b["key"],
                        "alert_count": b["doc_count"],
                        "description": (
                            (b.get("description", {}).get("buckets") or [{}])[0].get("key", "")
                        ),
                        "max_level": int(b.get("max_level", {}).get("value") or 0),
                    }
                    for b in buckets
                ],
            }, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @mcp.resource(
        "wazuh://health",
        name="wazuh-health",
        description="Real-time health snapshot: manager API status, indexer status, server uptime",
        mime_type="application/json",
    )
    async def health_resource() -> str:
        """Return current health of manager, indexer, and MCP server."""
        import httpx as _httpx

        checks: dict[str, Any] = {}

        try:
            info = await wz.request("GET", "/")
            checks["manager_api"] = "ok"
            checks["manager_version"] = (
                (info.get("data") or {}).get("api_version")
                or (info.get("data") or {}).get("version", "unknown")
            )
        except Exception as exc:
            log.warning("health_resource: manager check failed: %s", exc)
            checks["manager_api"] = "error: unreachable"

        try:
            async with _httpx.AsyncClient(
                verify=cfg.verify_ssl,
                auth=(cfg.indexer_user, cfg.indexer_pass),
                timeout=5,
            ) as client:
                r = await client.get(f"{cfg.indexer_host}/_cluster/health")
                body = r.json()
                checks["indexer"] = body.get("status", "unknown")
                checks["indexer_nodes"] = body.get("number_of_nodes", 0)
        except Exception as exc:
            log.warning("health_resource: indexer check failed: %s", exc)
            checks["indexer"] = "error: unreachable"

        return json.dumps({
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "checks": checks,
        }, indent=2)
