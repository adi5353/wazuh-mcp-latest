"""MCP server self-monitoring tools — Prometheus metrics, tool usage stats, slow query detection."""
from __future__ import annotations

import os
import time
import logging
from collections import defaultdict

log = logging.getLogger("wazuh-mcp")

# In-process tool call tracker (populated by the sanitizing tool decorator via roi_tracker)
# We shadow-track here too so these tools remain independent of the ROI module.
_call_counts:    dict[str, int]   = defaultdict(int)
_call_errors:    dict[str, int]   = defaultdict(int)
_call_durations: dict[str, list]  = defaultdict(list)   # tool → [elapsed_seconds, ...]
_SERVER_START    = time.monotonic()

# Max samples kept per tool (ring-buffer style to avoid unbounded growth)
_MAX_SAMPLES = 200


def record_tool_call(tool_name: str, elapsed: float, had_error: bool = False) -> None:
    """Called by server middleware to record each tool invocation."""
    _call_counts[tool_name] += 1
    if had_error:
        _call_errors[tool_name] += 1
    buf = _call_durations[tool_name]
    buf.append(elapsed)
    if len(buf) > _MAX_SAMPLES:
        _call_durations[tool_name] = buf[-_MAX_SAMPLES:]


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def get_mcp_server_metrics() -> dict:
        """Return Prometheus-style metrics for the MCP server itself.

        Reports: uptime, total tool calls, per-tool call counts, error rates,
        p50/p95/p99 latency percentiles, and active circuit breaker states.

        Use this to monitor server health, detect performance regressions,
        and identify tools that are being called most frequently.
        """
        import statistics

        uptime_seconds = time.monotonic() - _SERVER_START
        uptime_h = uptime_seconds / 3600

        total_calls  = sum(_call_counts.values())
        total_errors = sum(_call_errors.values())

        # Per-tool latency stats
        tool_stats: list[dict] = []
        for tool, count in sorted(_call_counts.items(), key=lambda x: -x[1]):
            durations = _call_durations.get(tool, [])
            errors    = _call_errors.get(tool, 0)
            if durations:
                sorted_d = sorted(durations)
                n = len(sorted_d)
                p50 = sorted_d[int(n * 0.50)]
                p95 = sorted_d[min(int(n * 0.95), n - 1)]
                p99 = sorted_d[min(int(n * 0.99), n - 1)]
                avg = statistics.mean(sorted_d)
            else:
                p50 = p95 = p99 = avg = 0.0

            tool_stats.append({
                "tool":       tool,
                "calls":      count,
                "errors":     errors,
                "error_rate": f"{errors / count * 100:.1f}%" if count else "0%",
                "avg_ms":     round(avg * 1000, 1),
                "p50_ms":     round(p50 * 1000, 1),
                "p95_ms":     round(p95 * 1000, 1),
                "p99_ms":     round(p99 * 1000, 1),
            })

        # Circuit breaker states
        try:
            from ..circuit_breaker import breaker
            circuit_status = breaker.status()
        except Exception:
            circuit_status = {"error": "circuit breaker unavailable"}

        # Prometheus text format (for /metrics scraping)
        prom_lines = [
            f"# HELP wazuh_mcp_uptime_seconds MCP server uptime",
            f"# TYPE wazuh_mcp_uptime_seconds gauge",
            f"wazuh_mcp_uptime_seconds {uptime_seconds:.1f}",
            f"# HELP wazuh_mcp_tool_calls_total Total tool invocations",
            f"# TYPE wazuh_mcp_tool_calls_total counter",
        ]
        for tool, count in _call_counts.items():
            safe = tool.replace("-", "_")
            prom_lines.append(f'wazuh_mcp_tool_calls_total{{tool="{safe}"}} {count}')

        return {
            "uptime_seconds":  round(uptime_seconds),
            "uptime_human":    f"{uptime_h:.1f}h",
            "total_calls":     total_calls,
            "total_errors":    total_errors,
            "overall_error_rate": f"{total_errors / total_calls * 100:.1f}%" if total_calls else "0%",
            "calls_per_hour":  round(total_calls / uptime_h, 1) if uptime_h > 0 else 0,
            "tool_stats":      tool_stats,
            "circuit_breakers": circuit_status,
            "prometheus_text": "\n".join(prom_lines),
            "note": "prometheus_text can be scraped directly — also available at GET /metrics",
        }

    @mcp.tool()
    async def get_tool_usage_stats(
        top_n: int = 20,
        sort_by: str = "calls",
    ) -> dict:
        """Show which MCP tools are called most, least, and have the highest error rates.

        Useful for understanding analyst workflows, identifying noisy integrations,
        and prioritising which tools need performance improvement.

        top_n:   Number of tools to return (default 20)
        sort_by: 'calls' | 'errors' | 'latency' | 'error_rate'
        """
        top_n = min(top_n, 100)
        sort_by = sort_by.lower()

        rows: list[dict] = []
        all_tools = set(_call_counts) | set(_call_errors)
        for tool in all_tools:
            count = _call_counts.get(tool, 0)
            errs  = _call_errors.get(tool, 0)
            durs  = _call_durations.get(tool, [])
            avg_ms = round(sum(durs) / len(durs) * 1000, 1) if durs else 0.0
            rows.append({
                "tool":       tool,
                "calls":      count,
                "errors":     errs,
                "error_rate_pct": round(errs / count * 100, 1) if count else 0.0,
                "avg_latency_ms": avg_ms,
            })

        key_map = {
            "calls":      lambda r: -r["calls"],
            "errors":     lambda r: -r["errors"],
            "latency":    lambda r: -r["avg_latency_ms"],
            "error_rate": lambda r: -r["error_rate_pct"],
        }
        rows.sort(key=key_map.get(sort_by, key_map["calls"]))

        total_calls  = sum(_call_counts.values())
        never_called = [t for t in _list_all_registered_tools() if t not in _call_counts]

        return {
            "sort_by":       sort_by,
            "total_calls":   total_calls,
            "total_tools_called": len(rows),
            "never_called_tools": never_called[:30],
            "top_tools": rows[:top_n],
        }

    @mcp.tool()
    async def get_slow_queries(
        threshold_ms: float = 2000.0,
        top_n: int = 10,
    ) -> dict:
        """Identify MCP tools with consistently high latency (potential performance issues).

        Returns tools where the p95 latency exceeds threshold_ms, sorted by p95 descending.
        Use this to diagnose which tools are slow and may need optimization or caching.

        threshold_ms: p95 threshold in milliseconds (default 2000 = 2 seconds)
        top_n:        max results (default 10)
        """
        import statistics

        slow: list[dict] = []
        for tool, durations in _call_durations.items():
            if len(durations) < 3:
                continue  # not enough samples
            sorted_d = sorted(durations)
            n = len(sorted_d)
            p95_ms = round(sorted_d[min(int(n * 0.95), n - 1)] * 1000, 1)
            p99_ms = round(sorted_d[min(int(n * 0.99), n - 1)] * 1000, 1)
            avg_ms = round(statistics.mean(sorted_d) * 1000, 1)
            if p95_ms >= threshold_ms:
                slow.append({
                    "tool":     tool,
                    "samples":  n,
                    "avg_ms":   avg_ms,
                    "p95_ms":   p95_ms,
                    "p99_ms":   p99_ms,
                    "calls":    _call_counts.get(tool, 0),
                    "recommendation": (
                        "Consider adding caching (cache.py) or reducing query window"
                        if p95_ms > 5000 else
                        "Review external API calls or increase timeout in circuit_breaker.py"
                    ),
                })

        slow.sort(key=lambda x: -x["p95_ms"])
        return {
            "threshold_ms": threshold_ms,
            "slow_tools_count": len(slow),
            "slow_tools": slow[:top_n],
            "message": (
                f"Found {len(slow)} tool(s) with p95 latency ≥ {threshold_ms}ms."
                if slow else
                f"All tools are within the {threshold_ms}ms p95 threshold."
            ),
        }


def _list_all_registered_tools() -> list[str]:
    """Best-effort list of known tool names for 'never called' reporting."""
    return [
        "alert_summary", "search_alerts", "search_by_mitre", "search_by_source_ip",
        "search_authentication_failures", "alert_timeline", "get_alert_by_id",
        "compare_alert_volume", "detect_rule_anomalies", "get_recent_alerts_24h",
        "get_recent_alerts_7d", "get_recent_alerts_30d", "deduplicate_alerts",
        "vulnerability_summary", "get_agent_vulnerabilities_detailed", "search_cve",
        "prioritize_patches", "list_agents", "get_agent", "restart_agent",
        "enrich_ip", "enrich_domain", "enrich_url", "enrich_file_hash", "bulk_enrich_iocs",
        "enrich_ip_geo", "enrich_ip_extended", "classify_ip_infrastructure",
        "compliance_summary", "compliance_control_details", "generate_compliance_report",
        "iso27001_compliance_summary", "nist_csf2_compliance_summary", "soc2_compliance_summary",
        "export_alerts_csv", "export_alerts_json", "export_alerts_ndjson", "export_report_html",
        "export_vulnerabilities_csv", "export_compliance_csv",
        "send_alert_to_slack", "send_alert_to_teams", "send_critical_alert_to_teams",
        "send_weekly_summary_to_slack", "send_weekly_summary_to_teams",
        "send_critical_alert_notify", "email_compliance_report",
        "get_mcp_server_metrics", "get_tool_usage_stats", "get_slow_queries",
        "hunt_lateral_movement", "hunt_persistence_mechanisms", "hunt_data_exfiltration",
        "mitre_coverage_analysis", "get_mitre_gaps",
        "create_jira_ticket", "create_thehive_case", "update_ticket_status",
        "auto_triage_alert", "batch_auto_triage", "nl_to_opensearch_query",
    ]
