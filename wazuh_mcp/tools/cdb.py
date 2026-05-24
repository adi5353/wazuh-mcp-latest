"""CDB list management tools — list, read, add, remove, and preview blocklist impact."""
from __future__ import annotations

from ..rbac import responder_only


def register(mcp, wz, idx, cfg, _require_writes):

    @mcp.tool()
    async def list_cdb_lists() -> dict:
        """List all CDB lookup lists configured in Wazuh."""
        return await wz.request("GET", "/lists?limit=100")

    @mcp.tool()
    async def get_cdb_list_contents(list_name: str) -> dict:
        """Get the full key:value contents of a CDB list file."""
        return await wz.request("GET", f"/lists/files/{list_name}?raw=true")

    @mcp.tool()
    async def add_to_cdb_list(list_name: str, key: str, value: str = "malicious") -> dict:
        """Add an IP, domain, or file hash to a CDB blocklist — takes effect immediately.

        Requires WAZUH_ALLOW_WRITES=true. Requires role: responder or above.
        list_name: e.g. 'malicious-ips'
        key: the IP/domain/hash to add
        value: label, e.g. 'c2-server', 'attacker', 'phishing'
        """
        err = responder_only()
        if err:
            return err
        blocked = _require_writes()
        if blocked:
            return blocked
        try:
            current = await wz.request("GET", f"/lists/files/{list_name}?raw=true")
            existing = (current.get("data") or {}).get("affected_items", [""])[0] or ""
        except Exception:
            existing = ""
        lines = [ln for ln in existing.splitlines() if ln.strip() and not ln.startswith(f"{key}:")]
        lines.append(f"{key}:{value}")
        new_content = "\n".join(lines) + "\n"
        result = await wz.request(
            "PUT", f"/lists/files/{list_name}",
            content=new_content.encode(),
            headers={"Content-Type": "application/octet-stream"},
        )
        return {"action": "added", "key": key, "value": value, "list": list_name, "api_result": result}

    @mcp.tool()
    async def remove_from_cdb_list(list_name: str, key: str) -> dict:
        """Remove an entry from a CDB list. Requires WAZUH_ALLOW_WRITES=true.
        Requires role: responder or above.
        """
        err = responder_only()
        if err:
            return err
        blocked = _require_writes()
        if blocked:
            return blocked
        current = await wz.request("GET", f"/lists/files/{list_name}?raw=true")
        existing = (current.get("data") or {}).get("affected_items", [""])[0] or ""
        filtered = "\n".join(
            ln for ln in existing.splitlines()
            if ln.strip() and not ln.startswith(f"{key}:")
        ) + "\n"
        result = await wz.request(
            "PUT", f"/lists/files/{list_name}",
            content=filtered.encode(),
            headers={"Content-Type": "application/octet-stream"},
        )
        return {"action": "removed", "key": key, "list": list_name, "api_result": result}

    @mcp.tool()
    async def preview_cdb_list_impact(ip: str, hours: int = 24) -> dict:
        """Show how many recent alerts came from this IP before adding it to a blocklist.

        Run this BEFORE add_to_cdb_list to understand noise-reduction impact.
        No writes performed — always safe.
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                        {
                            "bool": {
                                "should": [
                                    {"term": {"data.srcip": ip}},
                                    {"term": {"data.src_ip": ip}},
                                ]
                            }
                        },
                    ]
                }
            },
            "aggs": {
                "by_rule": {"terms": {"field": "rule.description", "size": 5}},
                "by_agent": {"terms": {"field": "agent.name", "size": 5}},
            },
            "size": 0,
        }
        res = await idx.search(query)
        total = res["hits"]["total"]["value"]
        return {
            "ip": ip,
            "alerts_last_n_hours": total,
            "hours_checked": hours,
            "top_triggered_rules": [
                {"rule": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_rule"]["buckets"]
            ],
            "top_targeted_agents": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_agent"]["buckets"]
            ],
            "recommendation": (
                f"Blocking this IP would suppress ~{total} alerts over {hours}h."
                if total > 0
                else "No recent alerts from this IP — blocking may have no immediate effect."
            ),
        }
