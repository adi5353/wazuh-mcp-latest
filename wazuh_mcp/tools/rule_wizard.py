"""F7: Custom Detection Rules Wizard.

AI-assisted tool for creating, validating, and pushing Wazuh XML detection rules.

Tools:
    generate_rule_xml   — generate Wazuh XML rule from a natural language description
    validate_rule_xml   — parse and validate rule XML before upload
    push_custom_rule    — push validated rule XML to Manager's custom_rules.xml

Wazuh rule ID ranges:
    100000-109999       — local/custom rules (safe to use)
    200000+             — reserved for decoders
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import textwrap
from ..rbac import admin_only


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
