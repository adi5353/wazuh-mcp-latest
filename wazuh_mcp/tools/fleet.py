"""Fleet inventory tools — per-agent and fleet-wide package/process/port/login queries."""
from __future__ import annotations
from ..tool_context import ToolContext

import asyncio
import os

_FLEET_BATCH_SIZE = int(os.getenv("WAZUH_MCP_FLEET_BATCH_SIZE", "10"))


async def _batch_gather(coros, batch_size: int = _FLEET_BATCH_SIZE) -> list:
    """Run coroutines in batches to avoid overwhelming the Wazuh API."""
    results = []
    for i in range(0, len(coros), batch_size):
        batch = coros[i: i + batch_size]
        results.extend(await asyncio.gather(*batch, return_exceptions=True))
    return results


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _truncate = ctx.truncate

    @mcp.tool()
    async def get_agent_packages(
        agent_id: str, search: str | None = None, limit: int = 50
    ) -> dict:
        """Installed packages on a single agent (from syscollector)."""
        path = f"/syscollector/{agent_id}/packages?limit={_cap(limit)}"
        if search:
            path += f"&search={search}"
        return await wz.request("GET", path)

    @mcp.tool()
    async def get_agent_processes(
        agent_id: str, search: str | None = None, limit: int = 50
    ) -> dict:
        """Currently-tracked processes on a single agent (from syscollector)."""
        path = f"/syscollector/{agent_id}/processes?limit={_cap(limit)}"
        if search:
            path += f"&search={search}"
        return await wz.request("GET", path)

    @mcp.tool()
    async def get_agent_open_ports(agent_id: str, limit: int = 100) -> dict:
        """Listening / open ports on a single agent, with the bound process where available."""
        return await wz.request(
            "GET", f"/syscollector/{agent_id}/ports?limit={_cap(limit)}"
        )

    @mcp.tool()
    async def get_agent_hardware_os(agent_id: str) -> dict:
        """Hardware (CPU, RAM, board) plus OS info for an agent — one consolidated call."""
        hw = await wz.request("GET", f"/syscollector/{agent_id}/hardware")
        osinfo = await wz.request("GET", f"/syscollector/{agent_id}/os")
        return {"hardware": hw, "os": osinfo}

    @mcp.tool()
    async def fleet_find_package(
        package_name: str, version_substring: str | None = None, limit: int = 200
    ) -> dict:
        """Find every agent across the fleet that has a given package installed.

        This is the CVE-response query: 'who has log4j 2.14?' — answers in one call.
        Requires Wazuh 4.10+ with the inventory state indices.
        """
        filters: list = [{"wildcard": {"package.name": f"*{package_name}*"}}]
        if version_substring:
            filters.append({"wildcard": {"package.version": f"*{version_substring}*"}})

        body = {
            "size": _cap(limit),
            "query": {"bool": {"filter": filters}},
            "aggs": {
                "agent_count": {"cardinality": {"field": "agent.id"}},
                "by_version": {"terms": {"field": "package.version", "size": 20}},
            },
        }
        try:
            res = await idx.search(body, index=cfg.inventory_packages_index)
        except Exception as e:
            return {
                "error": f"Inventory index query failed: {e}. "
                         "fleet_find_package requires Wazuh 4.10+ inventory state indices.",
            }

        agents = []
        seen: set = set()
        for h in res["hits"]["hits"]:
            src = h["_source"]
            a = src.get("agent", {})
            p = src.get("package", {})
            key = (a.get("id"), p.get("version"))
            if key in seen:
                continue
            seen.add(key)
            agents.append({
                "agent_id": a.get("id"),
                "agent_name": a.get("name"),
                "package": p.get("name"),
                "version": p.get("version"),
                "architecture": p.get("architecture"),
            })

        return {
            "package_query": package_name,
            "version_query": version_substring,
            "total_matches": res["hits"]["total"]["value"],
            "unique_agents": res["aggregations"]["agent_count"]["value"],
            "versions_seen": [
                {"version": b["key"], "agents": b["doc_count"]}
                for b in res["aggregations"]["by_version"]["buckets"]
            ],
            "matches": agents,
        }

    @mcp.tool()
    async def fleet_find_process(process_name: str, limit: int = 200) -> dict:
        """Find every agent currently running a process matching `process_name`.

        Requires Wazuh 4.10+.
        """
        body = {
            "size": _cap(limit),
            "query": {"wildcard": {"process.name": f"*{process_name}*"}},
            "aggs": {
                "agent_count": {"cardinality": {"field": "agent.id"}},
                "by_user": {"terms": {"field": "process.user.name", "size": 20}},
            },
        }
        try:
            res = await idx.search(body, index=cfg.inventory_processes_index)
        except Exception as e:
            return {
                "error": f"Inventory index query failed: {e}. "
                         "fleet_find_process requires Wazuh 4.10+ inventory state indices.",
            }

        rows = []
        for h in res["hits"]["hits"]:
            src = h["_source"]
            p = src.get("process", {})
            a = src.get("agent", {})
            rows.append({
                "agent_id": a.get("id"),
                "agent_name": a.get("name"),
                "process": p.get("name"),
                "pid": p.get("pid"),
                "ppid": p.get("ppid"),
                "user": (p.get("user") or {}).get("name"),
                "command_line": _truncate(p.get("command_line"), 300),
            })

        return {
            "process_query": process_name,
            "total_matches": res["hits"]["total"]["value"],
            "unique_agents": res["aggregations"]["agent_count"]["value"],
            "running_as": [
                {"user": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_user"]["buckets"]
            ],
            "matches": rows,
        }

    @mcp.tool()
    async def fleet_find_listening_port(port: int, limit: int = 200) -> dict:
        """Find every agent with the given port open / listening.

        Requires Wazuh 4.10+.
        """
        body = {
            "size": _cap(limit),
            "query": {
                "bool": {
                    "should": [
                        {"term": {"destination.port": port}},
                        {"term": {"source.port": port}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "aggs": {
                "agent_count": {"cardinality": {"field": "agent.id"}},
                "by_proto": {"terms": {"field": "network.protocol", "size": 10}},
            },
        }
        try:
            res = await idx.search(body, index=cfg.inventory_ports_index)
        except Exception as e:
            return {
                "error": f"Inventory index query failed: {e}. "
                         "fleet_find_listening_port requires Wazuh 4.10+ inventory state indices.",
            }

        rows = []
        for h in res["hits"]["hits"]:
            src = h["_source"]
            rows.append({
                "agent_id": (src.get("agent") or {}).get("id"),
                "agent_name": (src.get("agent") or {}).get("name"),
                "bound_process": (src.get("process") or {}).get("name"),
                "pid": (src.get("process") or {}).get("pid"),
                "local_ip": (src.get("destination") or {}).get("ip")
                            or (src.get("source") or {}).get("ip"),
                "protocol": (src.get("network") or {}).get("protocol"),
            })

        return {
            "port": port,
            "total_matches": res["hits"]["total"]["value"],
            "unique_agents": res["aggregations"]["agent_count"]["value"],
            "by_protocol": [
                {"protocol": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_proto"]["buckets"]
            ],
            "matches": rows,
        }

    @mcp.tool()
    async def fleet_batch_syscollector(
        agent_ids: list[str],
        resource: str = "packages",
        limit_per_agent: int = 20,
    ) -> dict:
        """Query syscollector data for multiple agents in parallel batches.

        Fetches packages, processes, or ports for a list of agents concurrently
        instead of sequentially, using WAZUH_MCP_FLEET_BATCH_SIZE (default 10)
        to avoid overwhelming the Wazuh Manager API.

        Args:
            agent_ids: List of agent IDs to query.
            resource: 'packages', 'processes', or 'ports'.
            limit_per_agent: Max items to return per agent.
        """
        if resource not in ("packages", "processes", "ports"):
            return {"error": "resource must be 'packages', 'processes', or 'ports'."}
        if not agent_ids:
            return {"error": "agent_ids must not be empty."}
        if len(agent_ids) > 100:
            return {"error": "Maximum 100 agent_ids per batch call."}

        async def fetch_one(agent_id: str):
            path = f"/syscollector/{agent_id}/{resource}?limit={_cap(limit_per_agent)}"
            try:
                data = await wz.request("GET", path)
                return {
                    "agent_id": agent_id,
                    "items": (data.get("data") or {}).get("affected_items", []),
                    "total": (data.get("data") or {}).get("total_affected_items", 0),
                }
            except Exception as e:
                return {"agent_id": agent_id, "error": str(e)}

        coros = [fetch_one(aid) for aid in agent_ids]
        results = await _batch_gather(coros, _FLEET_BATCH_SIZE)

        success = [r for r in results if isinstance(r, dict) and "error" not in r]
        errors  = [r for r in results if isinstance(r, dict) and "error" in r]
        return {
            "resource": resource,
            "agents_queried": len(agent_ids),
            "agents_succeeded": len(success),
            "agents_failed": len(errors),
            "batch_size": _FLEET_BATCH_SIZE,
            "results": success,
            "errors": errors,
        }

    @mcp.tool()
    async def get_agent_login_history(
        agent_name: str,
        time_range: str = "72h",
        include_failures: bool = True,
        include_successes: bool = True,
    ) -> dict:
        """Pull successful and/or failed login history for an agent.

        Groups by user and shows source IPs.
        Useful for account compromise investigation.
        """
        rule_filters: list = []
        if include_failures:
            rule_filters += ["5710", "5711", "5712", "2501", "2502", "60106"]
        if include_successes:
            rule_filters += ["5715", "5501", "5900", "2503", "60105"]

        if not rule_filters:
            return {"error": "At least one of include_failures or include_successes must be True."}

        body = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.name": agent_name}},
                        {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                        {"terms": {"rule.id": rule_filters}},
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "data.dstuser", "size": 20},
                    "aggs": {
                        "by_src": {"terms": {"field": "data.srcip", "size": 5}},
                    },
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 50,
            "_source": [
                "@timestamp", "rule.description", "rule.id",
                "data.srcip", "data.dstuser", "data.srcuser",
            ],
        }
        res = await idx.search(body)
        total = res["hits"]["total"]["value"]
        hits = res["hits"]["hits"]
        buckets = res["aggregations"]["by_user"]["buckets"]

        return {
            "agent": agent_name,
            "time_window": time_range,
            "total_login_events": total,
            "by_user": [
                {
                    "user": b["key"],
                    "event_count": b["doc_count"],
                    "source_ips": [s["key"] for s in b.get("by_src", {}).get("buckets", [])],
                }
                for b in buckets
            ],
            "recent_events": [h.get("_source", {}) for h in hits[:20]],
        }
