"""F7: Custom Detection Rules Wizard.

AI-assisted tool for creating, validating, and pushing Wazuh XML detection rules.

Tools:
    generate_rule_xml     — generate Wazuh XML rule from a natural language description
    validate_rule_xml     — parse and validate rule XML before upload
    push_custom_rule      — push validated rule XML to Manager's custom_rules.xml
    convert_sigma_rule    — convert a Sigma rule (YAML) to Wazuh XML

Wazuh rule ID ranges:
    100000-109999       — local/custom rules (safe to use)
    200000+             — reserved for decoders
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import textwrap
import re
from ..rbac import admin_only

# Sigma log source → Wazuh parent rule IDs (best-effort heuristic mapping)
_SIGMA_LOGSOURCE_TO_PARENT: dict[str, int] = {
    "windows": 60000,       # Windows EventLog parent
    "sysmon":  61000,       # Sysmon events
    "linux":   5500,        # Linux syslog
    "apache":  30100,       # Apache access log
    "nginx":   31100,       # Nginx
    "aws":     80200,       # AWS CloudTrail
    "azure":   87700,       # Azure AD
    "gcp":     65000,       # GCP audit
    "network": 40100,       # Generic network
}

# Sigma condition operators we can translate to Wazuh <match> / <field>
_SIGMA_MITRE_LEVELS: dict[str, int] = {
    "initial-access": 10, "execution": 8, "persistence": 10,
    "privilege-escalation": 12, "defense-evasion": 8, "credential-access": 12,
    "discovery": 5, "lateral-movement": 12, "collection": 8,
    "exfiltration": 12, "command-and-control": 10, "impact": 12,
}


def _sigma_to_wazuh_level(sigma_level: str) -> int:
    mapping = {"critical": 14, "high": 12, "medium": 8, "low": 5, "informational": 3}
    return mapping.get((sigma_level or "medium").lower(), 8)


def _extract_sigma_field_conditions(detection: dict) -> list[tuple[str, str]]:
    """Walk Sigma detection dict and return [(field_name, pattern), …]."""
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


_RULE_TEMPLATE = """\
<group name="local,syslog,">
  <rule id="{rule_id}" level="{level}">
{conditions}    <description>{description}</description>
{mitre}  </rule>
</group>"""


def register(mcp, wz, cfg):
    from ..validators import safe_validate, validate_free_text

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
        rule_id:        Custom rule ID (must be 100000–199999).
        level:          Severity level 1–15 (default 5 = notice).
        parent_rule_id: If set, add <if_sid> to chain from a parent rule.
        match_pattern:  Regex for <match> field (matches log message).
        field_name:     Field name for <field> matching (e.g. "srcip").
        field_pattern:  Regex for the named field.
        mitre_id:       MITRE ATT&CK technique ID (e.g. "T1110").
        """
        # Validate inputs
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
    async def validate_rule_xml(xml_content: str) -> dict:
        """Validate Wazuh rule XML syntax before pushing to the Manager.

        Checks:
          - Valid XML structure (parseable)
          - Presence of required attributes (id, level)
          - Presence of <description> element
          - rule_id in valid custom range (100000-199999)

        Returns valid=True/False, plus a list of warnings for best-practice issues.
        """
        if not xml_content or not xml_content.strip():
            return {"valid": False, "error": "XML content is empty."}

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as exc:
            return {"valid": False, "error": f"XML parse error: {exc}"}

        warnings = []
        rules_found = 0

        # Walk all <rule> elements (could be nested under <group>)
        elements = list(root.iter("rule")) if root.tag != "rule" else [root]
        if not elements:
            return {"valid": False, "error": "No <rule> elements found in XML."}

        for rule_el in elements:
            rules_found += 1
            rule_id_str = rule_el.get("id", "")
            level_str = rule_el.get("level", "")

            if not rule_id_str:
                warnings.append("Rule is missing required 'id' attribute.")
            else:
                try:
                    rid = int(rule_id_str)
                    if rid < 100000 or rid > 199999:
                        warnings.append(
                            f"Rule ID {rid} is outside custom range 100000-199999. "
                            "Using system IDs may conflict with Wazuh built-in rules."
                        )
                except ValueError:
                    warnings.append(f"Rule 'id' attribute is not a valid integer: {rule_id_str!r}")

            if not level_str:
                warnings.append("Rule is missing required 'level' attribute.")

            desc_el = rule_el.find("description")
            if desc_el is None or not (desc_el.text or "").strip():
                warnings.append(f"Rule {rule_id_str or '?'} is missing a <description> element.")

        return {
            "valid": True,
            "rules_found": rules_found,
            "warnings": warnings,
            "message": (
                "XML is syntactically valid."
                + (" Review warnings before pushing." if warnings else " Ready to push.")
            ),
        }

    @mcp.tool()
    async def push_custom_rule(
        xml_content: str,
        filename: str = "custom_rules.xml",
        dry_run: bool = True,
    ) -> dict:
        """Push validated rule XML to the Wazuh Manager's custom rules file.

        Validates the XML locally first. If valid, uploads to
        /var/ossec/etc/rules/<filename> via Manager API (PUT with overwrite=true).

        xml_content: Complete XML rule group (must include <group> wrapper).
        filename:    Target filename under etc/rules/ (default: custom_rules.xml).
        dry_run=True (default): validate only, do not push.
        Requires role: admin. Requires WAZUH_ALLOW_WRITES=true.
        """
        err = admin_only()
        if err:
            return err

        # Sanitise filename — only alphanumeric, hyphens, underscores, dots
        import re as _re
        if not _re.match(r'^[\w\-\.]+\.xml$', filename):
            return {"error": "filename must be a simple .xml filename with no path separators."}

        # Validate first
        validation = await validate_rule_xml(xml_content)
        if not validation.get("valid"):
            return {
                "error": "XML validation failed — fix errors before pushing.",
                "details": validation,
            }

        if dry_run:
            return {
                "dry_run": True,
                "valid": True,
                "warnings": validation.get("warnings", []),
                "rules_found": validation.get("rules_found", 0),
                "target_file": filename,
                "message": (
                    f"DRY RUN: XML is valid. Set dry_run=False to push to "
                    f"etc/rules/{filename} on the Wazuh Manager."
                ),
            }

        # Push to Manager using dedicated file-upload method
        try:
            result = await wz.upload_xml_file(
                f"/rules/files/{filename}",
                xml_content,
                overwrite=True,
            )
        except Exception as exc:
            return {"error": f"Failed to push rule to Manager: {exc}"}

        return {
            "success": True,
            "target_file": filename,
            "warnings": validation.get("warnings", []),
            "rules_found": validation.get("rules_found", 0),
            "manager_response": result,
            "next_step": (
                "The rule is now active. Use search_rules or test_rule_coverage to verify detection."
            ),
        }

    @mcp.tool()
    async def push_custom_decoder(
        xml_content: str,
        filename: str = "custom_decoders.xml",
        dry_run: bool = True,
    ) -> dict:
        """Push a custom decoder XML file to the Wazuh Manager.

        Validates the XML locally first. If valid, uploads to
        /var/ossec/etc/decoders/<filename> via Manager API (PUT with overwrite=true).

        xml_content: Complete XML decoder group (must include <decoder> elements).
        filename:    Target filename under etc/decoders/ (default: custom_decoders.xml).
        dry_run=True (default): validate only, do not push.
        Requires role: admin. Requires WAZUH_ALLOW_WRITES=true.

        Decoder XML example:
            <decoder name="my-app">
              <prematch>^MyApp </prematch>
            </decoder>
            <decoder name="my-app-fields">
              <parent>my-app</parent>
              <regex>user=(\\S+) action=(\\S+)</regex>
              <order>user, action</order>
            </decoder>
        """
        err = admin_only()
        if err:
            return err

        import re as _re
        if not _re.match(r'^[\w\-\.]+\.xml$', filename):
            return {"error": "filename must be a simple .xml filename with no path separators."}

        if not xml_content or not xml_content.strip():
            return {"error": "xml_content must not be empty."}

        # Validate XML structure
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as exc:
            return {"valid": False, "error": f"XML parse error: {exc}"}

        # Check for <decoder> elements
        decoders = list(root.iter("decoder")) if root.tag != "decoder" else [root]
        if not decoders:
            return {
                "error": "No <decoder> elements found in XML. "
                         "Decoder XML must contain at least one <decoder name='...'> element."
            }

        warnings = []
        for d in decoders:
            if not d.get("name"):
                warnings.append("A <decoder> element is missing the required 'name' attribute.")

        if dry_run:
            return {
                "dry_run": True,
                "valid": True,
                "decoders_found": len(decoders),
                "warnings": warnings,
                "target_file": filename,
                "message": (
                    f"DRY RUN: XML is valid ({len(decoders)} decoder(s) found). "
                    f"Set dry_run=False to push to etc/decoders/{filename}."
                ),
            }

        try:
            result = await wz.upload_xml_file(
                f"/decoders/files/{filename}",
                xml_content,
                overwrite=True,
            )
        except Exception as exc:
            return {"error": f"Failed to push decoder to Manager: {exc}"}

        return {
            "success": True,
            "target_file": filename,
            "decoders_found": len(decoders),
            "warnings": warnings,
            "manager_response": result,
            "next_step": (
                "The decoder is now active. Use test_log_against_rules to verify it parses logs correctly."
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
            # Minimal YAML parser fallback for simple Sigma rules
            _yaml = None

        if not sigma_yaml or not sigma_yaml.strip():
            return {"error": "sigma_yaml must not be empty."}

        # Parse YAML
        try:
            if _yaml:
                sigma = _yaml.safe_load(sigma_yaml)
            else:
                # Basic fallback: extract key fields with regex
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

        # Rule ID range check
        if rule_id < 100000 or rule_id > 199999:
            return {"error": "rule_id must be between 100000 and 199999."}

        # Determine parent rule from log source
        product   = str(logsource.get("product", "")).lower()
        category  = str(logsource.get("category", "")).lower()
        service   = str(logsource.get("service", "")).lower()
        source_key = product or category or service or "linux"
        parent_id = _SIGMA_LOGSOURCE_TO_PARENT.get(source_key, 0)

        # Extract MITRE technique IDs from tags
        mitre_ids = [t.replace("attack.", "").upper() for t in tags
                     if isinstance(t, str) and t.startswith("attack.t")]

        # Determine level boost from MITRE tactics
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("attack.") and not tag.startswith("attack.t"):
                tactic = tag.replace("attack.", "").lower()
                boost = _SIGMA_MITRE_LEVELS.get(tactic, 0)
                wazuh_level = max(wazuh_level, boost)

        # Extract field conditions from detection block
        conditions = _extract_sigma_field_conditions(detection)

        # Build XML
        safe_title = title.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")
        safe_desc  = description.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")

        lines = ['<group name="local,sigma,">',
                 f'  <rule id="{rule_id}" level="{wazuh_level}">']
        if parent_id:
            lines.append(f'    <if_sid>{parent_id}</if_sid>')

        # Add field conditions (first match= for full_log, then field elements)
        match_patterns = [p for f, p in conditions if f == "full_log"]
        field_pairs    = [(f, p) for f, p in conditions if f != "full_log"]

        if match_patterns:
            escaped = match_patterns[0].replace("<", "&lt;").replace(">", "&gt;")
            lines.append(f'    <match>{escaped}</match>')
        for fname, fpattern in field_pairs[:3]:  # cap at 3 field conditions
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
            # Validate then push
            validation = await validate_rule_xml(xml_out)
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
