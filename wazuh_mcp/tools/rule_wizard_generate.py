"""Rule Wizard — XML generation logic (pure functions, no I/O).

Handles: generate_rule_xml, convert_sigma_rule, sigma_coverage_gap
"""
from __future__ import annotations
from ..tool_context import ToolContext

import re

# Sigma log source → Wazuh parent rule IDs (best-effort heuristic mapping)
_SIGMA_LOGSOURCE_TO_PARENT: dict[str, int] = {
    "windows": 60000,
    "sysmon":  61000,
    "linux":   5500,
    "apache":  30100,
    "nginx":   31100,
    "aws":     80200,
    "azure":   87700,
    "gcp":     65000,
    "network": 40100,
}

_SIGMA_MITRE_LEVELS: dict[str, int] = {
    "initial-access": 10, "execution": 8, "persistence": 10,
    "privilege-escalation": 12, "defense-evasion": 8, "credential-access": 12,
    "discovery": 5, "lateral-movement": 12, "collection": 8,
    "exfiltration": 12, "command-and-control": 10, "impact": 12,
}

_RULE_TEMPLATE = """\
<group name="local,syslog,">
  <rule id="{rule_id}" level="{level}">
{conditions}    <description>{description}</description>
{mitre}  </rule>
</group>"""


def _sigma_to_wazuh_level(sigma_level: str) -> int:
    mapping = {"critical": 14, "high": 12, "medium": 8, "low": 5, "informational": 3}
    return mapping.get((sigma_level or "medium").lower(), 8)


def _extract_sigma_field_conditions(detection: dict) -> list[tuple[str, str]]:
    """Walk Sigma detection dict and return [(field_name, pattern), ...]."""
    pairs: list[tuple[str, str]] = []
    for key, value in detection.items():
        if key in ("condition", "keywords"):
            continue
        if isinstance(value, dict):
            for field, pattern in value.items():
                field_wazuh = field.lower().replace("commandline", "data.win.eventdata.commandLine") \
                                          .replace("image", "data.win.eventdata.image") \
                                          .replace("parentimage", "data.win.eventdata.parentImage") \
                                          .replace("eventid", "data.win.system.eventID") \
                                          .replace("user", "data.dstuser") \
                                          .replace("destinationip", "data.destip") \
                                          .replace("sourceip", "data.srcip")
                if isinstance(pattern, list):
                    for p in pattern:
                        pairs.append((field_wazuh, str(p)))
                else:
                    pairs.append((field_wazuh, str(pattern)))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    pairs.append(("full_log", item))
    return pairs


def register_generate(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg

    @mcp.tool()
    async def generate_rule_xml(
        description: str,
        rule_id: int = 100001,
        level: int = 5,
        parent_rule_id: int | None = None,
        match_pattern: str = "",
        field_name: str = "",
        field_pattern: str = "",
        mitre_id: str = "",
    ) -> dict:
        """Generate Wazuh XML rule syntax from a description.

        Produces a ready-to-use XML rule snippet. Review and adjust before pushing.

        description:    Natural language description of what the rule detects.
        rule_id:        Custom rule ID (must be 100000-199999).
        level:          Severity level 1-15 (default 5 = notice).
        parent_rule_id: If set, add <if_sid> to chain from a parent rule.
        match_pattern:  Regex for <match> field (matches log message).
        field_name:     Field name for <field> matching (e.g. "srcip").
        field_pattern:  Regex for the named field.
        mitre_id:       MITRE ATT&CK technique ID (e.g. "T1110").
        """
        if not description or not description.strip():
            return {"error": "description must not be empty."}
        if len(description) > 1000:
            return {"error": "description is too long (max 1000 characters)."}
        if rule_id < 100000 or rule_id > 199999:
            return {"error": "rule_id must be between 100000 and 199999 (custom rule range)."}
        if level < 1 or level > 15:
            return {"error": "level must be between 1 and 15."}

        safe_desc = description.replace("<", "&lt;").replace(">", "&gt;")

        conditions = ""
        if parent_rule_id:
            conditions += f"    <if_sid>{parent_rule_id}</if_sid>\n"
        if match_pattern:
            safe_pat = match_pattern.replace("<", "&lt;").replace(">", "&gt;")
            conditions += f"    <match>{safe_pat}</match>\n"
        if field_name and field_pattern:
            safe_fp = field_pattern.replace("<", "&lt;").replace(">", "&gt;")
            conditions += f"    <field name=\"{field_name}\">{safe_fp}</field>\n"

        mitre_block = ""
        if mitre_id:
            mitre_block = f"    <mitre>\n      <id>{mitre_id.upper()}</id>\n    </mitre>\n"

        xml_out = _RULE_TEMPLATE.format(
            rule_id=rule_id,
            level=level,
            conditions=conditions,
            description=safe_desc,
            mitre=mitre_block,
        )

        return {
            "xml": xml_out,
            "rule_id": rule_id,
            "level": level,
            "tip": (
                "Review the XML, then use validate_rule_xml to check syntax, "
                "and push_custom_rule to upload to the Wazuh Manager."
            ),
        }

    @mcp.tool()
    async def convert_sigma_rule(
        sigma_yaml: str,
        rule_id: int = 100100,
        dry_run: bool = True,
    ) -> dict:
        """Convert a Sigma detection rule (YAML) to a Wazuh XML rule.

        Sigma is the industry standard for portable detection rules. This tool
        translates the detection logic, severity level, MITRE tags, and title
        into a ready-to-use Wazuh XML rule snippet.

        sigma_yaml: Full Sigma rule as a YAML string.
        rule_id:    Wazuh custom rule ID to assign (100000-199999).
        dry_run:    If True (default), return XML only — don't push to Manager.

        After conversion, use validate_rule_xml to check, then push_custom_rule to deploy.
        """
        try:
            import yaml as _yaml  # type: ignore[import]
        except ImportError:
            _yaml = None

        if not sigma_yaml or not sigma_yaml.strip():
            return {"error": "sigma_yaml must not be empty."}

        try:
            if _yaml:
                sigma = _yaml.safe_load(sigma_yaml)
            else:
                def _ry(key: str) -> str:
                    m = re.search(rf'^{key}:\s*(.+)$', sigma_yaml, re.MULTILINE)
                    return m.group(1).strip().strip("'\"") if m else ""
                sigma = {
                    "title": _ry("title"),
                    "description": _ry("description"),
                    "level": _ry("level"),
                    "logsource": {},
                    "detection": {},
                    "tags": [],
                }
        except Exception as exc:
            return {"error": f"Failed to parse YAML: {exc}"}

        if not isinstance(sigma, dict):
            return {"error": "Parsed YAML is not a mapping. Check Sigma rule structure."}

        title       = sigma.get("title", "Converted Sigma Rule")[:200]
        description = sigma.get("description", title)[:500]
        level_str   = sigma.get("level", "medium")
        wazuh_level = _sigma_to_wazuh_level(level_str)
        tags        = sigma.get("tags", []) or []
        logsource   = sigma.get("logsource", {}) or {}
        detection   = sigma.get("detection", {}) or {}

        if rule_id < 100000 or rule_id > 199999:
            return {"error": "rule_id must be between 100000 and 199999."}

        product   = str(logsource.get("product", "")).lower()
        category  = str(logsource.get("category", "")).lower()
        service   = str(logsource.get("service", "")).lower()
        source_key = product or category or service or "linux"
        parent_id = _SIGMA_LOGSOURCE_TO_PARENT.get(source_key, 0)

        mitre_ids = [t.replace("attack.", "").upper() for t in tags
                     if isinstance(t, str) and t.startswith("attack.t")]

        for tag in tags:
            if isinstance(tag, str) and tag.startswith("attack.") and not tag.startswith("attack.t"):
                tactic = tag.replace("attack.", "").lower()
                boost = _SIGMA_MITRE_LEVELS.get(tactic, 0)
                wazuh_level = max(wazuh_level, boost)

        conditions = _extract_sigma_field_conditions(detection)

        safe_title = title.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")
        safe_desc  = description.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")

        lines = ['<group name="local,sigma,">',
                 f'  <rule id="{rule_id}" level="{wazuh_level}">']
        if parent_id:
            lines.append(f'    <if_sid>{parent_id}</if_sid>')

        match_patterns = [p for f, p in conditions if f == "full_log"]
        field_pairs    = [(f, p) for f, p in conditions if f != "full_log"]

        if match_patterns:
            escaped = match_patterns[0].replace("<", "&lt;").replace(">", "&gt;")
            lines.append(f'    <match>{escaped}</match>')
        for fname, fpattern in field_pairs[:3]:
            escaped = fpattern.replace("<", "&lt;").replace(">", "&gt;")
            lines.append(f'    <field name="{fname}" type="pcre2">{escaped}</field>')

        if mitre_ids:
            lines.append('    <mitre>')
            for mid in mitre_ids[:5]:
                lines.append(f'      <id>{mid}</id>')
            lines.append('    </mitre>')

        lines.append(f'    <description>{safe_title}</description>')
        lines.append(f'    <info type="text">{safe_desc[:300]}</info>')
        lines.append('  </rule>')
        lines.append('</group>')
        xml_out = "\n".join(lines)

        warnings = []
        if not conditions:
            warnings.append(
                "No detection conditions were extracted. The rule will match all events from "
                "the parent rule — review and add <match> or <field> conditions manually."
            )
        if not parent_id:
            warnings.append(
                f"Unknown log source '{source_key}'. No <if_sid> parent was set — "
                "add one manually to scope the rule correctly."
            )
        if len(conditions) > 3:
            warnings.append(
                f"Sigma rule has {len(conditions)} conditions; only the first 3 field conditions "
                "were included. Complex AND/OR logic requires manual adjustment."
            )

        result = {
            "xml": xml_out,
            "rule_id": rule_id,
            "wazuh_level": wazuh_level,
            "sigma_level": level_str,
            "title": title,
            "mitre_ids": mitre_ids,
            "parent_rule_id": parent_id or None,
            "conditions_extracted": len(conditions),
            "warnings": warnings,
            "next_steps": [
                "validate_rule_xml(xml) — check syntax",
                f"push_custom_rule(xml, dry_run=False) — deploy to Manager" if not dry_run
                else "Set dry_run=False and call push_custom_rule to deploy",
            ],
        }

        if not dry_run:
            from .rule_wizard_validate import _validate_rule_xml_impl
            validation = _validate_rule_xml_impl(xml_out)
            if not validation.get("valid"):
                result["push_error"] = "XML validation failed — push skipped."
                result["validation"] = validation
            else:
                try:
                    push_res = await wz.upload_xml_file(
                        f"/rules/files/sigma_{rule_id}.xml", xml_out, overwrite=True
                    )
                    result["pushed"] = True
                    result["manager_response"] = push_res
                except Exception as exc:
                    result["push_error"] = str(exc)

        return result

    @mcp.tool()
    async def sigma_coverage_gap(
        time_range: str = "30d",
    ) -> dict:
        """Compare your deployed Sigma/custom rules against observed MITRE ATT&CK techniques.

        Queries the Wazuh Indexer for every MITRE technique seen in real alerts,
        then checks which of those techniques have at least one custom/Sigma rule.
        Returns: covered techniques, gap techniques (seen in alerts but no custom rule),
        and blind-spot techniques (no alert AND no rule — silent gaps).

        Use this to prioritise which Sigma rules to import next.
        """
        from ..helpers import time_window as _tw

        alert_body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        _tw(f"now-{time_range}"),
                        {"exists": {"field": "rule.mitre.id"}},
                    ]
                }
            },
            "aggs": {
                "by_technique": {
                    "terms": {"field": "rule.mitre.id", "size": 200},
                    "aggs": {"alert_count": {"value_count": {"field": "_id"}}},
                }
            },
        }
        try:
            alert_res    = await idx.search(alert_body)
            observed_map = {
                b["key"]: b["doc_count"]
                for b in alert_res.get("aggregations", {}).get("by_technique", {}).get("buckets", [])
            }
        except Exception as exc:
            return {"error": f"Alert query failed: {exc}"}

        covered_techniques: set[str] = set()
        custom_rule_techniques: set[str] = set()
        try:
            rules_resp = await wz.get("/rules?limit=500&offset=0&q=status=enabled")
            for rule in (rules_resp.get("data", {}).get("affected_items") or []):
                for tid in (rule.get("mitre", {}).get("id") or []):
                    covered_techniques.add(tid.upper())
            custom_resp = await wz.get("/rules?limit=500&offset=0&q=status=enabled&filename=0local*,0sigma*,custom*")
            for rule in (custom_resp.get("data", {}).get("affected_items") or []):
                for tid in (rule.get("mitre", {}).get("id") or []):
                    custom_rule_techniques.add(tid.upper())
        except Exception:
            pass

        observed_set  = {t.upper() for t in observed_map}
        gap_set       = observed_set - covered_techniques
        sigma_covered = observed_set & custom_rule_techniques
        wazuh_covered = (observed_set & covered_techniques) - custom_rule_techniques

        gap_prioritised = sorted(
            [{"technique": t, "alert_count": observed_map.get(t, 0)} for t in gap_set],
            key=lambda x: -x["alert_count"],
        )

        return {
            "time_range": time_range,
            "summary": {
                "observed_techniques":       len(observed_set),
                "covered_by_any_rule":       len(observed_set & covered_techniques),
                "covered_by_sigma_custom":   len(sigma_covered),
                "covered_by_wazuh_builtins": len(wazuh_covered),
                "gap_count":                 len(gap_set),
                "coverage_pct":              round((len(observed_set & covered_techniques) / len(observed_set) * 100) if observed_set else 0, 1),
            },
            "gap_techniques": gap_prioritised[:30],
            "sigma_covered":  sorted(sigma_covered)[:30],
            "wazuh_covered":  sorted(wazuh_covered)[:30],
            "tip": (
                "Import Sigma rules from https://github.com/SigmaHQ/sigma for the gap_techniques "
                "using sigma_bulk_import(). Prioritise by alert_count — these are actively firing TTPs "
                "without dedicated detection rules."
            ),
        }
