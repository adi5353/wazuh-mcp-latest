"""Cluster health tools — Wazuh cluster status and event queue monitoring."""
from __future__ import annotations

import httpx


def register(mcp, wz, idx, cfg):

    @mcp.tool()
    async def get_cluster_health() -> dict:
        """Full health check of Wazuh cluster nodes and the Indexer (OpenSearch) cluster."""
        import asyncio
        cluster_status, cluster_nodes = await asyncio.gather(
            wz.request("GET", "/cluster/status"),
            wz.request("GET", "/cluster/nodes"),
            return_exceptions=True,
        )
        indexer_health: dict = {}
        try:
            async with httpx.AsyncClient(
                verify=cfg.verify_ssl,
                auth=(cfg.indexer_user, cfg.indexer_pass),
                timeout=15,
            ) as c:
                r_h = await c.get(f"{cfg.indexer_host}/_cluster/health")
                r_s = await c.get(
                    f"{cfg.indexer_host}/_cluster/stats?"
                    "filter_path=indices.count,indices.docs,indices.store,nodes.count"
                )
                if r_h.status_code == 200:
                    indexer_health["health"] = r_h.json()
                if r_s.status_code == 200:
                    indexer_health["stats"] = r_s.json()
        except Exception as e:
            indexer_health["error"] = str(e)
        return {
            "wazuh_cluster_status": cluster_status if not isinstance(cluster_status, Exception) else str(cluster_status),
            "wazuh_nodes": (
                (cluster_nodes.get("data") or {}).get("affected_items", [])
                if not isinstance(cluster_nodes, Exception) else str(cluster_nodes)
            ),
            "indexer": indexer_health,
        }

    @mcp.tool()
    async def check_event_queue_health() -> dict:
        """Check if Wazuh is silently dropping events due to queue pressure."""
        try:
            stats = await wz.request("GET", "/manager/stats/analysisd")
            data = (stats.get("data") or {}).get("affected_items", [{}])[0]
            dropped = data.get("events_dropped_queue", 0) or 0
            return {
                "total_events_decoded": data.get("total_events_decoded"),
                "events_dropped": dropped,
                "health": "DEGRADED — events are being dropped!" if dropped > 0 else "OK",
                "raw_stats": data,
            }
        except Exception as e:
            return {"error": str(e)}
