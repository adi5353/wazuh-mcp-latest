"""Archive log search tools — forensic reconstruction from full Wazuh archives index."""
from __future__ import annotations

import os

from ..helpers import trim_alert, time_window


def register(mcp, wz, idx, cfg, _cap):

    @mcp.tool()
    async def search_archive_logs(
        query_string: str,
        time_range: str = "24h",
        agent_id: str | None = None,
        limit: int = 50,
    ) -> dict:
        """Search the full Wazuh archives index — all ingested logs, not just alerts.

        Use for forensic reconstruction when an attacker bypassed detection.
        query_string: Lucene syntax, e.g. 'data.srcip:198.51.100.42'
        Requires archiving enabled in ossec.conf.
        """
        archives_index = os.getenv("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*")
        filters: list = [time_window(f"now-{time_range}")]
        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})
        body = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": filters,
                    "must": [{"query_string": {"query": query_string, "default_field": "*"}}],
                }
            },
        }
        try:
            res = await idx.search(body, index=archives_index)
            return {
                "query": query_string,
                "total": res["hits"]["total"]["value"],
                "logs": [trim_alert(h) for h in res["hits"]["hits"]],
            }
        except Exception as e:
            return {
                "error": str(e),
                "hint": "Ensure archiving is enabled in ossec.conf and wazuh-archives-* indices exist.",
            }

    @mcp.tool()
    async def search_archive_logs_by_agent(
        agent_name: str,
        time_range: str = "24h",
        query_string: str = "",
        limit: int = 50,
    ) -> dict:
        """Search the full archive index for a specific agent over a time range.

        Returns a chronological event timeline — useful for forensic investigation.
        All ingested logs, not just alerts. Requires archiving enabled in ossec.conf.
        """
        archives_index = os.getenv("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*")
        must_clauses: list = [
            {"term": {"agent.name": agent_name}},
            {"range": {"@timestamp": {"gte": f"now-{time_range}", "lte": "now"}}},
        ]
        if query_string:
            must_clauses.append({"query_string": {"query": query_string}})

        body = {
            "query": {"bool": {"must": must_clauses}},
            "sort": [{"@timestamp": {"order": "asc"}}],
            "size": _cap(limit),
            "_source": [
                "@timestamp", "rule.description", "rule.id", "rule.level",
                "rule.groups", "data", "full_log",
            ],
        }
        try:
            res = await idx.search(body, index=archives_index)
            total = res["hits"]["total"]["value"]
            hits = res["hits"]["hits"]
            return {
                "agent": agent_name,
                "time_range": time_range,
                "total_logs": total,
                "returned": len(hits),
                "events": [h.get("_source", {}) for h in hits],
            }
        except Exception as e:
            return {
                "error": str(e),
                "hint": "Ensure archiving is enabled in ossec.conf.",
            }
