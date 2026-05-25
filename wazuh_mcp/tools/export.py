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
    ) -> str:
        """Export alerts as CSV text for download or offline analysis.

        Returns a CSV string with columns: timestamp, agent_id, agent_name,
        rule_id, rule_level, rule_description, srcip, mitre_tactics.

        Args:
            time_range: Lookback window (e.g. '24h', '7d').
            min_level: Minimum Wazuh rule level (1-15, default 7).
            limit: Maximum rows to export (max 500).
        """
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
                    "timestamp": a.get("timestamp", ""),
                    "agent_id": a.get("agent_id", ""),
                    "agent_name": a.get("agent_name", ""),
                    "rule_id": a.get("rule_id", ""),
                    "rule_level": a.get("rule_level", ""),
                    "rule_description": a.get("rule_description", ""),
                    "srcip": a.get("srcip", ""),
                    "mitre_tactics": ",".join(
                        (a.get("mitre") or {}).get("tactic", [])
                    ),
                })
            return _to_csv(rows) or "No alerts found for the specified criteria."
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
