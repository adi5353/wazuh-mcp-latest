"""Wazuh Indexer (OpenSearch) index lifecycle management tools.

Query index health, statistics, aliases, and ISM policies.
"""
from __future__ import annotations
from ..tool_context import ToolContext
from ..rbac import ROLE

REQUIRED_ROLE = ROLE.ADMIN


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _truncate = ctx.truncate

    @mcp.tool()
    async def get_index_stats(index_pattern: str = "wazuh-alerts-*") -> dict:
        """Get document counts and storage stats for an index pattern.

        Args:
            index_pattern: OpenSearch index pattern (e.g. 'wazuh-alerts-*').
        """
        from ..validators import validate_index_pattern
        try:
            index_pattern = validate_index_pattern(index_pattern)
        except ValueError as e:
            return {"error": str(e)}

        try:
            result = await idx.request("GET", f"/{index_pattern}/_stats/docs,store")
            indices = result.get("indices", {})
            summary = []
            for name, stats in indices.items():
                primaries = stats.get("primaries", {})
                summary.append({
                    "index": name,
                    "doc_count": (primaries.get("docs") or {}).get("count", 0),
                    "size_bytes": (primaries.get("store") or {}).get("size_in_bytes", 0),
                    "deleted_docs": (primaries.get("docs") or {}).get("deleted", 0),
                })
            summary.sort(key=lambda x: x["doc_count"], reverse=True)
            total_docs = sum(s["doc_count"] for s in summary)
            total_size = sum(s["size_bytes"] for s in summary)
            return {
                "index_pattern": index_pattern,
                "total_indices": len(summary),
                "total_documents": total_docs,
                "total_size_bytes": total_size,
                "indices": summary[:50],
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def list_index_aliases() -> dict:
        """List all OpenSearch index aliases and the indices they point to."""
        try:
            result = await idx.request("GET", "/_aliases")
            aliases: dict[str, list] = {}
            for index_name, index_data in result.items():
                for alias_name in (index_data.get("aliases") or {}).keys():
                    aliases.setdefault(alias_name, []).append(index_name)
            return {
                "total_aliases": len(aliases),
                "aliases": [
                    {"alias": k, "indices": v} for k, v in sorted(aliases.items())
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_index_settings(index_pattern: str = "wazuh-alerts-*") -> dict:
        """Retrieve settings (shard count, replicas, refresh interval) for an index pattern."""
        from ..validators import validate_index_pattern
        try:
            index_pattern = validate_index_pattern(index_pattern)
        except ValueError as e:
            return {"error": str(e)}

        try:
            result = await idx.request(
                "GET", f"/{index_pattern}/_settings?filter_path=**.settings.index"
            )
            summaries = []
            for name, data in result.items():
                s = (data.get("settings") or {}).get("index") or {}
                summaries.append({
                    "index": name,
                    "number_of_shards": s.get("number_of_shards"),
                    "number_of_replicas": s.get("number_of_replicas"),
                    "refresh_interval": s.get("refresh_interval"),
                    "creation_date_ms": s.get("creation_date"),
                })
            return {"index_pattern": index_pattern, "indices": summaries[:50]}
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def list_index_policies() -> dict:
        """List ISM (Index State Management) policies configured in OpenSearch."""
        try:
            result = await idx.request("GET", "/_plugins/_ism/policies")
            policies = result.get("policies", [])
            return {
                "total_policies": result.get("total_policies", len(policies)),
                "policies": [
                    {
                        "id": p.get("_id"),
                        "description": (p.get("policy") or {}).get("description", ""),
                        "states": len((p.get("policy") or {}).get("states", [])),
                    }
                    for p in policies
                ],
            }
        except Exception as e:
            return {
                "error": str(e),
                "note": "ISM plugin may not be enabled on this cluster.",
            }

    @mcp.tool()
    async def get_cluster_index_health() -> dict:
        """Get health status (green/yellow/red) for all Wazuh indices."""
        try:
            result = await idx.request(
                "GET", "/_cluster/health/wazuh-*?level=indices"
            )
            indices = result.get("indices", {})
            by_status: dict[str, list] = {"red": [], "yellow": [], "green": []}
            for name, health in indices.items():
                status = health.get("status", "unknown")
                by_status.setdefault(status, []).append({
                    "index": name,
                    "active_shards": health.get("active_shards"),
                    "unassigned_shards": health.get("unassigned_shards"),
                })
            return {
                "cluster_status": result.get("status"),
                "red_indices": by_status.get("red", []),
                "yellow_indices": by_status.get("yellow", []),
                "green_count": len(by_status.get("green", [])),
            }
        except Exception as e:
            return {"error": str(e)}
