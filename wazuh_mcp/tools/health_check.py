"""Unified Wazuh API health check tool.

Single-call liveness probe for both the Wazuh Manager API and the
Wazuh Indexer (OpenSearch), with latency measurements and a clear
overall status. Ideal as the first tool to run in any SOC session.
"""
from __future__ import annotations

import asyncio
import time


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def get_wazuh_api_health() -> dict:
        """Check liveness and latency of both the Wazuh Manager API and Wazuh Indexer.

        Runs both probes concurrently and returns an overall status of
        'healthy', 'degraded' (one component down), or 'critical' (both down).

        Returns:
            overall_status: 'healthy' | 'degraded' | 'critical'
            manager: status, latency_ms, version, daemons_running
            indexer: status, latency_ms, cluster_status, nodes
            checked_at: ISO-8601 timestamp
        """
        import datetime

        async def _probe_manager() -> dict:
            t0 = time.monotonic()
            try:
                info = await wz.request("GET", "/manager/info")
                status_resp = await wz.request("GET", "/manager/status")
                latency_ms = round((time.monotonic() - t0) * 1000)
                data = (info.get("data") or {}).get("affected_items", [{}])
                item = data[0] if data else {}
                # Count running daemons
                daemon_data = (status_resp.get("data") or {}).get("affected_items", [{}])
                daemon_item = daemon_data[0] if daemon_data else {}
                running = sum(1 for v in daemon_item.values() if v == "running")
                total = len(daemon_item)
                return {
                    "status": "up",
                    "latency_ms": latency_ms,
                    "version": item.get("version", "unknown"),
                    "daemons_running": f"{running}/{total}",
                }
            except Exception as e:
                latency_ms = round((time.monotonic() - t0) * 1000)
                return {
                    "status": "down",
                    "latency_ms": latency_ms,
                    "error": str(e),
                }

        async def _probe_indexer() -> dict:
            t0 = time.monotonic()
            try:
                health = await idx.request("GET", "/_cluster/health")
                latency_ms = round((time.monotonic() - t0) * 1000)
                return {
                    "status": "up",
                    "latency_ms": latency_ms,
                    "cluster_status": health.get("status", "unknown"),
                    "nodes": health.get("number_of_nodes", 0),
                    "active_shards": health.get("active_shards", 0),
                    "unassigned_shards": health.get("unassigned_shards", 0),
                }
            except Exception as e:
                latency_ms = round((time.monotonic() - t0) * 1000)
                return {
                    "status": "down",
                    "latency_ms": latency_ms,
                    "error": str(e),
                }

        manager_result, indexer_result = await asyncio.gather(
            _probe_manager(), _probe_indexer()
        )

        manager_up = manager_result["status"] == "up"
        indexer_up = indexer_result["status"] == "up"

        if manager_up and indexer_up:
            overall = "healthy"
        elif manager_up or indexer_up:
            overall = "degraded"
        else:
            overall = "critical"

        return {
            "overall_status": overall,
            "manager": manager_result,
            "indexer": indexer_result,
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        }
