"""File Integrity Monitoring tools — recent changes, FIM alerts, summaries, critical paths."""
from __future__ import annotations
from ..tool_context import ToolContext

from ..helpers import trim_alert, time_window
from ..validators import safe_validate, validate_time_range

CRITICAL_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/etc/hosts", "/etc/cron", "/etc/systemd",
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/root/.ssh", "/.ssh/authorized_keys",
    "System32", "SysWOW64", "Registry",
]


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap

    @mcp.tool()
    async def get_recent_fim_changes(
        agent_id: str, limit: int = 50, event_type: str | None = None
    ) -> dict:
        """Recent file integrity events on an agent, newest first (from Manager API).

        event_type: optional filter — 'added', 'modified', or 'deleted'.
        Use this when the user asks 'what changed on agent X recently'.
        """
        path = f"/syscheck/{agent_id}?sort=-date&limit={_cap(limit)}"
        if event_type:
            path += f"&type={event_type}"
        return await wz.request("GET", path)

    @mcp.tool()
    async def search_fim_alerts(
        time_range: str = "24h",
        agent_id: str | None = None,
        file_path_substring: str | None = None,
        limit: int = 50,
    ) -> dict:
        """Search FIM alerts from the Indexer (alerts where rule.groups contains 'syscheck').

        file_path_substring: optional wildcard match against syscheck.path
                             (e.g. '/etc/' or 'shadow').
        """
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        filters: list = [
            time_window(f"now-{time_range}"),
            {"term": {"rule.groups": "syscheck"}},
        ]
        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})
        if file_path_substring:
            filters.append({"wildcard": {"syscheck.path": f"*{file_path_substring}*"}})

        body = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": filters}},
        }
        res = await idx.search(body)

        enriched = []
        for h in res["hits"]["hits"]:
            a = trim_alert(h)
            sc = h["_source"].get("syscheck", {})
            a["fim"] = {
                "path": sc.get("path"),
                "event": sc.get("event"),
                "mode": sc.get("mode"),
                "size_after": sc.get("size_after"),
                "sha256_after": sc.get("sha256_after"),
                "uname_after": sc.get("uname_after"),
                "perm_after": sc.get("perm_after"),
            }
            enriched.append(a)

        return {
            "total": res["hits"]["total"]["value"],
            "fim_alerts": enriched,
        }

    @mcp.tool()
    async def fim_summary(time_range: str = "24h") -> dict:
        """Aggregated FIM activity — by agent, file path, and event type.

        Call this BEFORE listing individual FIM events for broad questions like
        'where's the most file activity this week'.
        """
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"term": {"rule.groups": "syscheck"}},
                    ]
                }
            },
            "aggs": {
                "by_agent": {"terms": {"field": "agent.name", "size": 20}},
                "by_event": {"terms": {"field": "syscheck.event", "size": 10}},
                "top_paths": {"terms": {"field": "syscheck.path", "size": 25}},
            },
        }
        res = await idx.search(body)
        aggs = res["aggregations"]
        return {
            "time_range": time_range,
            "total_fim_events": res["hits"]["total"]["value"],
            "by_agent": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in aggs["by_agent"]["buckets"]
            ],
            "by_event_type": [
                {"event": b["key"], "count": b["doc_count"]}
                for b in aggs["by_event"]["buckets"]
            ],
            "most_changed_paths": [
                {"path": b["key"], "count": b["doc_count"]}
                for b in aggs["top_paths"]["buckets"]
            ],
        }

    @mcp.tool()
    async def critical_file_changes(time_range: str = "7d", limit: int = 50) -> dict:
        """FIM changes on sensitive paths — auth files, cron, system binaries, ssh keys.

        Designed to surface the FIM events that warrant immediate attention regardless
        of which agent triggered them.
        """
        _, err = safe_validate(validate_time_range, time_range)
        if err:
            return err
        path_filters = [{"wildcard": {"syscheck.path": f"*{p}*"}} for p in CRITICAL_PATHS]
        body = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"term": {"rule.groups": "syscheck"}},
                        {"bool": {"should": path_filters, "minimum_should_match": 1}},
                    ]
                }
            },
        }
        res = await idx.search(body)
        enriched = []
        for h in res["hits"]["hits"]:
            a = trim_alert(h)
            sc = h["_source"].get("syscheck", {})
            a["fim_path"] = sc.get("path")
            a["fim_event"] = sc.get("event")
            a["sha256_after"] = sc.get("sha256_after")
            enriched.append(a)
        return {
            "total": res["hits"]["total"]["value"],
            "events": enriched,
        }
