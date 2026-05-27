"""Bulk data export tools — CSV export of alerts, vulnerabilities, compliance.

Returns file content as a string. For large exports, combine with the
workspace tools to save to a file.
"""
from __future__ import annotations

import csv
import io


def _to_csv(rows: list[dict], fieldnames: list[str] | None = None) -> str:
    if not rows:
        return ""
    if fieldnames is None:
        seen: dict = {}
        for r in rows:
            seen.update(r)
        fieldnames = list(seen.keys())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def export_alerts_csv(
        time_range: str = "24h",
        min_level: int = 7,
        limit: int = 500,
        stream: bool = False,
    ) -> str:
        """Export alerts as CSV text for download or offline analysis.

        Returns a CSV string with columns: timestamp, agent_id, agent_name,
        rule_id, rule_level, rule_description, srcip, mitre_tactics.

        Args:
            time_range: Lookback window (e.g. '24h', '7d').
            min_level:  Minimum Wazuh rule level (1-15, default 7).
            limit:      Maximum rows to export (max 500 in normal mode;
                        ignored in stream mode — all matching rows are fetched).
            stream:     If True, use search_after cursor pagination to export ALL
                        matching alerts without memory-buffering a single large page.
                        Use for exports > 500 rows or when the server reports truncation.
        """
        from ..validators import validate_time_range, validate_min_level
        try:
            time_range = validate_time_range(time_range)
            min_level = validate_min_level(min_level)
        except ValueError as e:
            return f"ERROR: {e}"

        from ..helpers import time_window, trim_alert

        query = {
            "bool": {
                "filter": [
                    time_window(f"now-{time_range}"),
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        }

        _CSV_FIELDS = ["timestamp", "agent_id", "agent_name", "rule_id",
                       "rule_level", "rule_description", "srcip", "mitre_tactics"]

        def _hit_to_row(h: dict) -> dict:
            a = trim_alert(h)
            return {
                "timestamp":       a.get("timestamp", ""),
                "agent_id":        a.get("agent_id", ""),
                "agent_name":      a.get("agent_name", ""),
                "rule_id":         a.get("rule_id", ""),
                "rule_level":      a.get("rule_level", ""),
                "rule_description": a.get("rule_description", ""),
                "srcip":           a.get("srcip", ""),
                "mitre_tactics":   ",".join((a.get("mitre") or {}).get("tactic", [])),
            }

        if not stream:
            # ── Normal (single-page) mode ─────────────────────────────────────
            body = {
                "size": _cap(limit),
                "sort": [{"@timestamp": "desc"}, {"_id": "asc"}],
                "query": query,
            }
            try:
                res = await idx.search(body, index=cfg.alerts_index)
                rows = [_hit_to_row(h) for h in res["hits"]["hits"]]
                return _to_csv(rows, _CSV_FIELDS) or "No alerts found for the specified criteria."
            except Exception as e:
                return f"ERROR: {e}"

        # ── Streaming (search_after cursor) mode ─────────────────────────────
        # Iterates pages of 500 until no more results, then assembles one CSV.
        PAGE_SIZE = 500
        rows: list[dict] = []
        search_after: list | None = None
        page = 0

        try:
            while True:
                body = {
                    "size": PAGE_SIZE,
                    "sort": [{"@timestamp": "desc"}, {"_id": "asc"}],
                    "query": query,
                }
                if search_after:
                    body["search_after"] = search_after

                res = await idx.search(body, index=cfg.alerts_index)
                hits = res["hits"]["hits"]
                if not hits:
                    break

                rows.extend(_hit_to_row(h) for h in hits)
                page += 1

                if len(hits) < PAGE_SIZE:
                    break  # last page

                last_sort = hits[-1].get("sort")
                if not last_sort:
                    break
                search_after = last_sort

            if not rows:
                return "No alerts found for the specified criteria."

            csv_content = _to_csv(rows, _CSV_FIELDS)
            # Prepend a metadata comment line for transparency
            meta = f"# wazuh-mcp export | time_range={time_range} | min_level={min_level} | rows={len(rows)} | pages={page}\n"
            return meta + csv_content
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    async def export_vulnerabilities_csv(
        min_severity: str = "High",
        limit: int = 500,
    ) -> str:
        """Export vulnerability findings as CSV for patch tracking.

        Returns CSV with columns: agent_id, agent_name, cve, severity,
        cvss_score, package, installed_version, published, detected.
        """
        from ..validators import validate_severity
        try:
            min_severity = validate_severity(min_severity)
        except ValueError as e:
            return f"ERROR: {e}"

        from ..helpers import trim_vuln, severities_at_or_above
        severities = severities_at_or_above(min_severity)
        body = {
            "size": _cap(limit),
            "query": {"terms": {"vulnerability.severity": severities}},
            "sort": [{"vulnerability.score.base": "desc"}],
        }
        try:
            res = await idx.search(body, index=cfg.vuln_index)
            rows = []
            for h in res["hits"]["hits"]:
                v = trim_vuln(h)
                rows.append({
                    "agent_id": v.get("agent_id", ""),
                    "agent_name": v.get("agent_name", ""),
                    "cve": v.get("cve", ""),
                    "severity": v.get("severity", ""),
                    "cvss_score": v.get("cvss_score", ""),
                    "package": v.get("package", ""),
                    "installed_version": v.get("installed_version", ""),
                    "published": v.get("published", ""),
                    "detected": v.get("detected", ""),
                })
            return _to_csv(rows) or "No vulnerabilities found."
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    async def export_compliance_csv(
        framework: str = "pci_dss",
        time_range: str = "7d",
        limit: int = 500,
    ) -> str:
        """Export compliance alert data as CSV for auditor review.

        Returns CSV with columns: timestamp, agent_id, agent_name,
        rule_id, rule_description, compliance_requirement.
        """
        from ..validators import validate_framework, validate_time_range
        try:
            framework = validate_framework(framework)
            time_range = validate_time_range(time_range)
        except ValueError as e:
            return f"ERROR: {e}"

        from ..helpers import time_window, trim_alert
        body = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"exists": {"field": f"rule.{framework}"}},
                    ]
                }
            },
        }
        try:
            res = await idx.search(body, index=cfg.alerts_index)
            rows = []
            for h in res["hits"]["hits"]:
                src = h.get("_source", {})
                rule = src.get("rule", {})
                agent = src.get("agent", {})
                req = rule.get(framework, "")
                if isinstance(req, list):
                    req = ",".join(req)
                rows.append({
                    "timestamp": src.get("@timestamp", ""),
                    "agent_id": agent.get("id", ""),
                    "agent_name": agent.get("name", ""),
                    "rule_id": rule.get("id", ""),
                    "rule_description": rule.get("description", ""),
                    "compliance_requirement": req,
                })
            return _to_csv(rows) or f"No {framework} alerts found."
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    async def export_alerts_json(
        time_range: str = "24h",
        min_level: int = 7,
        limit: int = 500,
        pretty: bool = False,
    ) -> str:
        """Export alerts as JSON for programmatic processing or SIEM ingestion.

        Returns a JSON array string. Each element contains the same fields
        as export_alerts_csv plus the raw mitre object.

        Args:
            time_range: Lookback window (e.g. '24h', '7d').
            min_level:  Minimum Wazuh rule level (1-15, default 7).
            limit:      Maximum rows to export (max 500).
            pretty:     If True, indent JSON for human readability.
        """
        import json as _json
        from ..validators import validate_time_range, validate_min_level
        try:
            time_range = validate_time_range(time_range)
            min_level = validate_min_level(min_level)
        except ValueError as e:
            return f"ERROR: {e}"

        from ..helpers import time_window, trim_alert
        body = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
        }
        try:
            res = await idx.search(body, index=cfg.alerts_index)
            hits = res["hits"]["hits"]
            rows = []
            for h in hits:
                a = trim_alert(h)
                rows.append({
                    "timestamp":        a.get("timestamp", ""),
                    "agent_id":         a.get("agent_id", ""),
                    "agent_name":       a.get("agent_name", ""),
                    "rule_id":          a.get("rule_id", ""),
                    "rule_level":       a.get("rule_level", ""),
                    "rule_description": a.get("rule_description", ""),
                    "srcip":            a.get("srcip", ""),
                    "mitre":            a.get("mitre") or {},
                })
            indent = 2 if pretty else None
            return _json.dumps(rows, indent=indent) if rows else "[]"
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    async def export_alerts_ndjson(
        time_range: str = "24h",
        min_level: int = 7,
        limit: int = 500,
    ) -> str:
        """Export alerts as NDJSON (newline-delimited JSON) for log pipeline ingestion.

        Each line is a self-contained JSON object. Compatible with Logstash,
        Fluent Bit, Vector, and most SIEM bulk-import APIs.

        Args:
            time_range: Lookback window (e.g. '24h', '7d').
            min_level:  Minimum Wazuh rule level (1-15, default 7).
            limit:      Maximum rows to export (max 500).
        """
        import json as _json
        from ..validators import validate_time_range, validate_min_level
        try:
            time_range = validate_time_range(time_range)
            min_level = validate_min_level(min_level)
        except ValueError as e:
            return f"ERROR: {e}"

        from ..helpers import time_window, trim_alert
        body = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
        }
        try:
            res = await idx.search(body, index=cfg.alerts_index)
            hits = res["hits"]["hits"]
            lines = []
            for h in hits:
                a = trim_alert(h)
                lines.append(_json.dumps({
                    "timestamp":        a.get("timestamp", ""),
                    "agent_id":         a.get("agent_id", ""),
                    "agent_name":       a.get("agent_name", ""),
                    "rule_id":          a.get("rule_id", ""),
                    "rule_level":       a.get("rule_level", ""),
                    "rule_description": a.get("rule_description", ""),
                    "srcip":            a.get("srcip", ""),
                    "mitre":            a.get("mitre") or {},
                }))
            return "\n".join(lines) if lines else ""
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    async def export_report_html(
        report_type: str = "compliance",
        framework: str = "pci_dss",
        time_range: str = "7d",
        include_style: bool = True,
    ) -> str:
        """Generate a print-ready HTML report for compliance or vulnerability data.

        The returned HTML is self-contained with inline CSS and print media queries,
        so it can be opened in any browser and printed to PDF via Ctrl+P.

        report_type: 'compliance' | 'vulnerabilities'
        framework:   pci_dss | hipaa | gdpr | nist_800_53 | tsc  (compliance only)
        time_range:  lookback window (default 7d)
        include_style: embed CSS (default True; set False for raw table HTML)
        """
        import datetime as _dt
        import html as _html

        STYLE = """
        <style>
          body { font-family: Arial, sans-serif; color: #222; max-width: 900px; margin: 40px auto; padding: 0 20px; }
          h1 { background: #1a237e; color: #fff; padding: 14px 20px; border-radius: 4px; font-size: 20px; }
          h2 { color: #1a237e; border-bottom: 2px solid #e8eaf6; padding-bottom: 6px; font-size: 15px; }
          .meta { color: #666; font-size: 13px; margin: 6px 0 20px; }
          .kpi-row { display: flex; gap: 16px; margin: 16px 0; }
          .kpi { flex: 1; border-radius: 4px; padding: 14px; text-align: center; }
          .kpi .num { font-size: 28px; font-weight: bold; }
          .kpi .lbl { font-size: 12px; color: #555; }
          .kpi-blue  { background: #e8eaf6; }
          .kpi-red   { background: #fce4ec; }  .kpi-red .num { color: #c62828; }
          .kpi-green { background: #e8f5e9; }  .kpi-green .num { color: #2e7d32; }
          table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 12px; }
          th { background: #f5f5f5; padding: 7px 10px; text-align: left; font-size: 12px; }
          td { padding: 6px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
          tr:hover td { background: #fafafa; }
          .status-FAILING { color: #c62828; font-weight: bold; }
          .status-WARNING { color: #e65100; font-weight: bold; }
          .status-OK      { color: #2e7d32; }
          .status-Critical { color: #c62828; font-weight: bold; }
          .status-High     { color: #e65100; font-weight: bold; }
          .status-Medium   { color: #f9a825; }
          .status-Low      { color: #388e3c; }
          footer { margin-top: 30px; font-size: 11px; color: #aaa; text-align: center; }
          @media print {
            body { margin: 0; padding: 0; max-width: 100%; }
            .kpi-row { page-break-inside: avoid; }
            table { page-break-inside: auto; }
            tr { page-break-inside: avoid; page-break-after: auto; }
          }
        </style>
        """

        ts_str = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        if report_type == "compliance":
            from ..validators import validate_framework, validate_time_range
            try:
                framework = validate_framework(framework)
                time_range = validate_time_range(time_range)
            except ValueError as e:
                return f"ERROR: {e}"

            from ..helpers import time_window
            from ..tools.compliance import COMPLIANCE_FIELDS
            field = COMPLIANCE_FIELDS.get(framework)
            if not field:
                return f"ERROR: Unknown framework '{framework}'"

            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            time_window(f"now-{time_range}"),
                            {"exists": {"field": field}},
                        ]
                    }
                },
                "aggs": {
                    "by_control": {
                        "terms": {"field": field, "size": 50},
                        "aggs": {
                            "critical": {"filter": {"range": {"rule.level": {"gte": 10}}}},
                            "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                        },
                    }
                },
            }
            try:
                res = await idx.search(body, index=cfg.alerts_index)
            except Exception as e:
                return f"ERROR: {e}"

            buckets = res.get("aggregations", {}).get("by_control", {}).get("buckets", [])
            total = res["hits"]["total"]["value"]
            controls = []
            for b in buckets:
                crit = b["critical"]["doc_count"]
                status = "FAILING" if crit > 0 else "WARNING" if b["doc_count"] > 10 else "OK"
                controls.append({
                    "control": b["key"],
                    "total": b["doc_count"],
                    "critical": crit,
                    "agents": ", ".join(a["key"] for a in b["top_agents"]["buckets"][:3]),
                    "status": status,
                })
            controls.sort(key=lambda x: x["critical"], reverse=True)
            failing = sum(1 for c in controls if c["status"] == "FAILING")

            rows_html = "".join(
                f"<tr>"
                f"<td>{_html.escape(str(c['control']))}</td>"
                f"<td>{c['total']}</td>"
                f"<td>{c['critical']}</td>"
                "<td class='status-" + c["status"] + "'>" + c["status"] + "</td>"
                f"<td>{_html.escape(c['agents'])}</td>"
                f"</tr>"
                for c in controls
            )

            content = f"""
            <div class='kpi-row'>
              <div class='kpi kpi-blue'><div class='num'>{total}</div><div class='lbl'>Total alerts</div></div>
              <div class='kpi kpi-red'><div class='num'>{failing}</div><div class='lbl'>Failing controls</div></div>
              <div class='kpi kpi-green'><div class='num'>{len(controls) - failing}</div><div class='lbl'>Passing controls</div></div>
            </div>
            <h2>Control breakdown</h2>
            <table>
              <tr><th>Control</th><th>Alerts</th><th>Critical</th><th>Status</th><th>Top agents</th></tr>
              {rows_html}
            </table>"""
            title = f"{framework.upper()} Compliance Report"

        elif report_type == "vulnerabilities":
            from ..helpers import severities_at_or_above, trim_vuln
            severities = severities_at_or_above("High")
            body = {
                "size": _cap(200),
                "query": {"terms": {"vulnerability.severity": severities}},
                "sort": [{"vulnerability.score.base": "desc"}],
            }
            try:
                res = await idx.search(body, index=cfg.vuln_index)
            except Exception as e:
                return f"ERROR: {e}"

            vulns = [trim_vuln(h) for h in res["hits"]["hits"]]
            total_v = res["hits"]["total"]["value"]
            critical_v = sum(1 for v in vulns if v.get("severity") == "Critical")
            high_v = sum(1 for v in vulns if v.get("severity") == "High")

            rows_html = "".join(
                f"<tr>"
                f"<td>{_html.escape(str(v.get('agent_name', '')))}</td>"
                f"<td>{_html.escape(str(v.get('cve', '')))}</td>"
                "<td class='status-" + v.get("severity", "Low") + "'>" + v.get("severity", "") + "</td>"
                f"<td>{v.get('cvss_score', '')}</td>"
                f"<td>{_html.escape(str(v.get('package', '')))}</td>"
                f"<td>{_html.escape(str(v.get('installed_version', '')))}</td>"
                f"</tr>"
                for v in vulns[:200]
            )

            content = f"""
            <div class='kpi-row'>
              <div class='kpi kpi-blue'><div class='num'>{total_v}</div><div class='lbl'>Total (High+)</div></div>
              <div class='kpi kpi-red'><div class='num'>{critical_v}</div><div class='lbl'>Critical</div></div>
              <div class='kpi kpi-green'><div class='num'>{high_v}</div><div class='lbl'>High</div></div>
            </div>
            <h2>Vulnerability findings (High and above)</h2>
            <table>
              <tr><th>Agent</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Version</th></tr>
              {rows_html}
            </table>"""
            title = "Vulnerability Report (High+)"
        else:
            return f"ERROR: report_type must be 'compliance' or 'vulnerabilities', got '{report_type}'"

        style_block = STYLE if include_style else ""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_html.escape(title)}</title>
  {style_block}
</head>
<body>
  <h1>{_html.escape(title)}</h1>
  <div class="meta">
    Generated: {ts_str} &nbsp;|&nbsp; Time range: {time_range} &nbsp;|&nbsp; Wazuh MCP
  </div>
  {content}
  <footer>Auto-generated by Wazuh MCP &mdash; open in browser &rarr; Ctrl+P &rarr; Save as PDF</footer>
</body>
</html>"""
