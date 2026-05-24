"""Network topology mapping — F1.

Builds a live network map from Wazuh agent inventory: agents grouped by
subnet, exposed ports per node, and peer communications from alert data.

Tools: get_network_topology, get_agent_neighbors, map_subnet_exposure
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

log = logging.getLogger("wazuh-mcp")


def _subnet_key(ip: str, prefix: int = 24) -> str:
    try:
        return str(ipaddress.ip_interface(f"{ip}/{prefix}").network)
    except ValueError:
        return "unknown"


async def _get_agent_ports(wz, agent_id: str) -> list[dict]:
    try:
        raw = await wz.request("GET", f"/syscollector/{agent_id}/ports?limit=50")
        return (raw.get("data") or {}).get("affected_items") or []
    except Exception:
        return []


def register(mcp, wz, idx, cfg, _cap):

    @mcp.tool()
    async def get_network_topology(subnet_prefix: int = 24) -> dict:
        """Build a live network topology map from Wazuh agent inventory.

        Groups all agents by their IP subnet, lists exposed ports per agent,
        and shows connectivity status. Useful for lateral movement investigations.

        subnet_prefix: CIDR prefix length for grouping (default /24)
        """
        try:
            raw = await wz.request("GET", "/agents?limit=500&select=id,name,ip,status,groups")
        except Exception as exc:
            return {"error": "Failed to fetch agents: " + str(exc)}

        agents_raw = (raw.get("data") or {}).get("affected_items") or []
        subnets: dict[str, list[dict]] = defaultdict(list)

        for ag in agents_raw:
            ip = ag.get("ip") or ""
            subnet = _subnet_key(ip, subnet_prefix) if ip else "unknown"
            subnets[subnet].append({
                "agent_id": ag.get("id", ""),
                "name": ag.get("name", ""),
                "ip": ip,
                "status": ag.get("status", ""),
                "groups": ag.get("groups") or [],
                "subnet": subnet,
            })

        active = [a for a in agents_raw if a.get("status") == "active"][:20]
        port_results = await asyncio.gather(
            *[_get_agent_ports(wz, a.get("id", "")) for a in active],
            return_exceptions=True,
        )
        port_map = {
            a.get("id", ""): (r if not isinstance(r, Exception) else [])
            for a, r in zip(active, port_results)
        }

        topology = []
        for subnet, nodes in sorted(subnets.items()):
            topology.append({
                "subnet": subnet,
                "agent_count": len(nodes),
                "active_count": sum(1 for n in nodes if n["status"] == "active"),
                "agents": [
                    {**n, "exposed_ports": port_map.get(n["agent_id"], [])[:20]}
                    for n in nodes
                ],
            })

        return {
            "topology": topology,
            "subnet_count": len(topology),
            "total_agents": len(agents_raw),
            "active_agents": sum(1 for a in agents_raw if a.get("status") == "active"),
            "subnet_prefix": subnet_prefix,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    @mcp.tool()
    async def get_agent_neighbors(agent_id: str, hours: int = 24) -> dict:
        """Find agents that communicated with a given agent based on alert data.

        Searches network alerts to find peer IPs, then maps them to known agents.
        agent_id: Wazuh agent ID to investigate
        hours: look-back window (default 24h)
        """
        try:
            ag_raw = await wz.request(
                "GET", f"/agents?agents_list={agent_id}&select=id,name,ip"
            )
        except Exception as exc:
            return {"error": "Agent lookup failed: " + str(exc)}

        items = (ag_raw.get("data") or {}).get("affected_items") or []
        if not items:
            return {"error": f"Agent {agent_id} not found"}
        agent = items[0]
        agent_ip = agent.get("ip", "")

        now = datetime.now(timezone.utc)
        gte = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": gte}}},
                        {"term": {"agent.id": agent_id}},
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "srcips": {"terms": {"field": "data.srcip", "size": 50}},
                "dstips": {"terms": {"field": "data.dstip", "size": 50}},
            },
        }
        try:
            raw = await idx.search(query, index="wazuh-alerts-*")
        except Exception as exc:
            return {"error": "Indexer query failed: " + str(exc)}

        aggs = raw.get("aggregations") or {}
        peer_ips: set[str] = set()
        for b in (aggs.get("srcips") or {}).get("buckets", []) + \
                 (aggs.get("dstips") or {}).get("buckets", []):
            ip = b.get("key", "")
            if ip and ip != agent_ip:
                peer_ips.add(ip)

        known_agents = []
        external_ips = list(peer_ips)[:30]
        if peer_ips:
            try:
                all_raw = await wz.request("GET", "/agents?limit=500&select=id,name,ip,status")
                for ag in (all_raw.get("data") or {}).get("affected_items") or []:
                    if ag.get("ip") in peer_ips:
                        known_agents.append({
                            "agent_id": ag.get("id"),
                            "name": ag.get("name"),
                            "ip": ag.get("ip"),
                            "status": ag.get("status"),
                        })
                        peer_ips.discard(ag.get("ip", ""))
                external_ips = list(peer_ips)[:30]
            except Exception:
                pass

        return {
            "agent_id": agent_id,
            "agent_name": agent.get("name"),
            "agent_ip": agent_ip,
            "time_window_hours": hours,
            "known_agent_neighbors": known_agents,
            "external_ip_contacts": external_ips,
            "total_peer_ips_found": len(known_agents) + len(external_ips),
            "tip": "Use enrich_ip_extended on external IPs for threat intel.",
        }

    @mcp.tool()
    async def map_subnet_exposure(subnet: str) -> dict:
        """List all agents in a subnet and their exposed ports/services.

        subnet: CIDR notation, e.g. '10.0.1.0/24' or '192.168.0.0/16'
        """
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            return {"error": f"Invalid subnet '{subnet}': {exc}"}

        try:
            raw = await wz.request("GET", "/agents?limit=500&select=id,name,ip,status,groups")
        except Exception as exc:
            return {"error": "Failed to fetch agents: " + str(exc)}

        all_agents = (raw.get("data") or {}).get("affected_items") or []
        in_subnet = []
        for ag in all_agents:
            try:
                if ipaddress.ip_address(ag.get("ip") or "") in network:
                    in_subnet.append(ag)
            except ValueError:
                pass

        port_results = await asyncio.gather(
            *[_get_agent_ports(wz, ag.get("id", "")) for ag in in_subnet[:20]],
            return_exceptions=True,
        )

        all_ports: dict[int, int] = defaultdict(int)
        nodes = []
        for ag, ports in zip(in_subnet, port_results):
            port_list = ports if not isinstance(ports, Exception) else []
            for p in port_list:
                port_num = p.get("local_port") or p.get("port") or 0
                if port_num:
                    all_ports[int(port_num)] += 1
            nodes.append({
                "agent_id": ag.get("id"),
                "name": ag.get("name"),
                "ip": ag.get("ip"),
                "status": ag.get("status"),
                "groups": ag.get("groups") or [],
                "exposed_ports": port_list[:20],
                "port_count": len(port_list),
            })

        top_ports = sorted(all_ports.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "subnet": str(network),
            "agents_in_subnet": len(in_subnet),
            "nodes": nodes,
            "most_common_ports": [{"port": p, "agent_count": c} for p, c in top_ports],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
