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
from ..tool_context import ToolContext

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


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg

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

        # Save current content as backup before overwriting (enables rollback_custom_rule)
        # Persisted to state_store so backups survive server restarts.
        from ..state_store import save_kv as _save_kv
        backup_saved = False
        try:
            existing = await wz.request("GET", f"/rules/files/{filename}?raw=true")
            if isinstance(existing, str) and existing.strip():
                import time as _time
                _save_kv(f"rule_backup_{filename}", {
                    "content": existing,
                    "filename": filename,
                    "backed_up_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                })
                backup_saved = True
        except Exception:
            pass  # No existing file to back up — first push

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
            "backup_saved": backup_saved,
            "warnings": validation.get("warnings", []),
            "rules_found": validation.get("rules_found", 0),
            "manager_response": result,
            "next_step": (
                "The rule is now active. Use search_rules or test_rule_coverage to verify detection. "
                "Use rollback_custom_rule() to restore the previous version if needed."
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

    @mcp.tool()
    async def sigma_bulk_import(
        sigma_rules_yaml: str,
        start_rule_id: int = 100200,
        dry_run: bool = True,
        push_all: bool = False,
    ) -> dict:
        """Convert and optionally deploy multiple Sigma rules in one call.

        Accepts a single YAML string containing one or more Sigma rules separated
        by '---' document separators (standard YAML multi-doc format). Each rule
        is converted to Wazuh XML, validated, and optionally pushed to the Manager.

        sigma_rules_yaml: One or more Sigma rules as a YAML string (--- separated)
        start_rule_id:    First custom rule ID to assign; subsequent rules increment by 1
        dry_run:          True (default) — convert and validate only, don't push
        push_all:         True — push all valid rules to Manager (requires admin + writes)

        Returns per-rule results + summary of successes/failures/warnings.
        """
        try:
            import yaml as _yaml
            docs = list(_yaml.safe_load_all(sigma_rules_yaml))
        except ImportError:
            # Minimal fallback: split by --- and parse each block
            docs = []
            for block in sigma_rules_yaml.split("---"):
                block = block.strip()
                if not block:
                    continue
                rule: dict = {}
                for line in block.splitlines():
                    if ":" in line and not line.startswith(" "):
                        k, _, v = line.partition(":")
                        rule[k.strip()] = v.strip().strip("'\"")
                if rule:
                    docs.append(rule)
        except Exception as exc:
            return {"error": f"YAML parse error: {exc}"}

        docs = [d for d in docs if isinstance(d, dict)]
        if not docs:
            return {"error": "No valid Sigma rule documents found in input."}
        if len(docs) > 50:
            return {"error": "Maximum 50 rules per bulk import call."}

        results: list[dict] = []
        successes = failures = warnings_total = 0

        for i, sigma in enumerate(docs):
            rule_id = start_rule_id + i
            title   = str(sigma.get("title", f"Rule {rule_id}"))[:200]

            # Reuse convert_sigma_rule logic inline
            try:
                level_str   = sigma.get("level", "medium")
                wazuh_level = _sigma_to_wazuh_level(str(level_str))
                tags        = sigma.get("tags", []) or []
                logsource   = sigma.get("logsource", {}) or {}
                detection   = sigma.get("detection", {}) or {}

                product    = str(logsource.get("product",  "")).lower()
                category   = str(logsource.get("category", "")).lower()
                service    = str(logsource.get("service",  "")).lower()
                src_key    = product or category or service or "linux"
                parent_id  = _SIGMA_LOGSOURCE_TO_PARENT.get(src_key, 0)

                mitre_ids  = [t.replace("attack.", "").upper() for t in tags
                              if isinstance(t, str) and t.startswith("attack.t")]
                for tag in tags:
                    if isinstance(tag, str) and tag.startswith("attack.") and not tag.startswith("attack.t"):
                        tactic    = tag.replace("attack.", "").lower()
                        wazuh_level = max(wazuh_level, _SIGMA_MITRE_LEVELS.get(tactic, 0))

                conditions = _extract_sigma_field_conditions(detection)
                safe_title = title.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")

                lines = ['<group name="local,sigma,">',
                         f'  <rule id="{rule_id}" level="{wazuh_level}">']
                if parent_id:
                    lines.append(f'    <if_sid>{parent_id}</if_sid>')

                match_pats  = [p for f, p in conditions if f == "full_log"]
                field_pairs = [(f, p) for f, p in conditions if f != "full_log"]

                if match_pats:
                    escaped = match_pats[0].replace("<", "&lt;").replace(">", "&gt;")
                    lines.append(f'    <match>{escaped}</match>')
                for fname, fpat in field_pairs[:3]:
                    escaped = fpat.replace("<", "&lt;").replace(">", "&gt;")
                    lines.append(f'    <field name="{fname}" type="pcre2">{escaped}</field>')

                if mitre_ids:
                    lines.append('    <mitre>')
                    for mid in mitre_ids[:5]:
                        lines.append(f'      <id>{mid}</id>')
                    lines.append('    </mitre>')

                lines.append(f'    <description>{safe_title}</description>')
                lines.append('  </rule>')
                lines.append('</group>')
                xml_out = "\n".join(lines)

                rule_warnings: list[str] = []
                if not conditions:
                    rule_warnings.append("No detection conditions extracted — rule will match all parent events")
                if not parent_id:
                    rule_warnings.append(f"Unknown log source '{src_key}' — no <if_sid> set")
                if len(conditions) > 3:
                    rule_warnings.append(f"{len(conditions)} conditions found; only first 3 used")

                pushed = False
                push_error = None
                if push_all and not dry_run:
                    err = admin_only()
                    if err:
                        push_error = "Insufficient role for push"
                    else:
                        try:
                            fname_safe = f"sigma_{rule_id}.xml"
                            await wz.upload_xml_file(f"/rules/files/{fname_safe}", xml_out, overwrite=True)
                            pushed = True
                        except Exception as exc:
                            push_error = str(exc)

                results.append({
                    "index":       i,
                    "rule_id":     rule_id,
                    "title":       title,
                    "sigma_level": level_str,
                    "wazuh_level": wazuh_level,
                    "mitre_ids":   mitre_ids,
                    "log_source":  src_key,
                    "conditions_extracted": len(conditions),
                    "xml":         xml_out,
                    "warnings":    rule_warnings,
                    "status":      "pushed" if pushed else ("push_error" if push_error else "converted"),
                    "push_error":  push_error,
                })
                successes += 1
                warnings_total += len(rule_warnings)

            except Exception as exc:
                results.append({
                    "index":  i,
                    "title":  title,
                    "status": "error",
                    "error":  str(exc),
                })
                failures += 1

        return {
            "summary": {
                "total":    len(docs),
                "success":  successes,
                "failed":   failures,
                "warnings": warnings_total,
                "dry_run":  dry_run,
                "pushed":   push_all and not dry_run,
                "rule_id_range": f"{start_rule_id}–{start_rule_id + len(docs) - 1}",
            },
            "rules": results,
            "tip": (
                "Set dry_run=False and push_all=True to deploy all valid rules. "
                "Each rule gets its own file: sigma_<rule_id>.xml. "
                "Use test_rule_coverage to verify detection after deployment."
            ),
        }

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

        # Step 1: Techniques observed in alerts (Indexer)
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

        # Step 2: Techniques covered by existing rules (Manager API)
        covered_techniques: set[str] = set()
        custom_rule_techniques: set[str] = set()
        try:
            rules_resp = await wz.get("/rules?limit=500&offset=0&q=status=enabled")
            for rule in (rules_resp.get("data", {}).get("affected_items") or []):
                for tid in (rule.get("mitre", {}).get("id") or []):
                    covered_techniques.add(tid.upper())
            # Separate custom rules (ID >= 100000)
            custom_resp = await wz.get("/rules?limit=500&offset=0&q=status=enabled&filename=0local*,0sigma*,custom*")
            for rule in (custom_resp.get("data", {}).get("affected_items") or []):
                for tid in (rule.get("mitre", {}).get("id") or []):
                    custom_rule_techniques.add(tid.upper())
        except Exception:
            pass  # degrade gracefully — observed data is still useful

        observed_set  = {t.upper() for t in observed_map}
        gap_set       = observed_set - covered_techniques   # seen in alerts but no rule at all
        sigma_covered = observed_set & custom_rule_techniques
        wazuh_covered = (observed_set & covered_techniques) - custom_rule_techniques

        # Priority score: gap techniques with highest alert counts are highest priority
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

    @mcp.tool()
    async def test_sigma_rule_against_archive(
        sigma_yaml: str,
        time_range: str = "30d",
        limit: int = 50,
        use_archive: bool = False,
    ) -> dict:
        """Backtest a Sigma rule against historical alert data to measure hit rate and FP signals.

        Converts the Sigma YAML to an OpenSearch query and runs it against the alerts
        index (or archive index if use_archive=True and archiving is enabled).
        Returns: match count, sample matches, false-positive signals, and a verdict.

        sigma_yaml:  Sigma rule in YAML format
        time_range:  Historical window to test against (default 30d)
        limit:       Max matching events to return (default 50)
        use_archive: If True, search archive index instead of alerts index (requires logall=yes)
        """
        from ..helpers import time_window as _tw, trim_alert

        # Parse YAML
        try:
            import yaml as _yaml
            sigma = _yaml.safe_load(sigma_yaml)
        except ImportError:
            sigma = {}
            for line in sigma_yaml.splitlines():
                if ":" in line and not line.startswith(" "):
                    k, _, v = line.partition(":")
                    sigma[k.strip()] = v.strip().strip("'\"")
        except Exception as exc:
            return {"error": f"YAML parse error: {exc}"}

        if not isinstance(sigma, dict):
            return {"error": "Parsed YAML is not a valid Sigma rule dict."}

        # Extract detection fields
        detection  = sigma.get("detection",  {}) or {}
        logsource  = sigma.get("logsource",  {}) or {}
        conditions = _extract_sigma_field_conditions(detection)
        title      = sigma.get("title", "Unnamed Sigma Rule")

        if not conditions:
            return {
                "error": "No detection conditions could be extracted from this Sigma rule.",
                "tip":   "Ensure the 'detection' block has field: value mappings.",
            }

        # Build OpenSearch filters from Sigma conditions
        should_clauses: list[dict] = []
        for field, pattern in conditions[:10]:
            if field == "full_log":
                should_clauses.append({"match_phrase": {"full_log": pattern}})
            else:
                should_clauses.append({"match_phrase": {field: pattern}})

        target_index = cfg.archives_index if use_archive else cfg.alerts_index
        query_body = {
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [_tw(f"now-{time_range}")],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            },
        }

        try:
            res  = await idx.search(query_body, index=target_index)
            hits = res["hits"]["hits"]
            total = res["hits"]["total"]["value"]
        except Exception as exc:
            return {"error": f"Search failed: {exc}"}

        # FP signal analysis
        fp_signals:  list[str] = []
        tp_signals:  list[str] = []
        level_counts: dict[int, int] = {}
        for h in hits:
            lvl = int(h.get("_source", {}).get("rule", {}).get("level", 0))
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        low_level_pct = sum(v for k, v in level_counts.items() if k < 5) / max(total, 1) * 100
        if low_level_pct > 60:
            fp_signals.append(f"{low_level_pct:.0f}% of matches are low-severity (level < 5)")
        if total > 500:
            fp_signals.append(f"Very high match count ({total}) — rule may be too broad")
        if total > 0 and total <= 20:
            tp_signals.append(f"Focused match count ({total}) — rule appears targeted")
        if any(k >= 10 for k in level_counts):
            tp_signals.append("Matches include high-severity (level ≥ 10) events")

        verdict = (
            "LIKELY_NOISY"    if total > 500 or low_level_pct > 60
            else "PROMISING"  if total > 0 and total <= 100
            else "NO_MATCHES" if total == 0
            else "REVIEW_NEEDED"
        )

        return {
            "sigma_title":    title,
            "time_range":     time_range,
            "index_searched": target_index,
            "total_matches":  total,
            "returned":       len(hits),
            "verdict":        verdict,
            "level_distribution": level_counts,
            "tp_signals":     tp_signals,
            "fp_signals":     fp_signals,
            "sample_matches": [trim_alert(h) for h in hits[:10]],
            "tip": (
                "PROMISING rules → use push_custom_rule to deploy. "
                "LIKELY_NOISY rules → add <field> restrictions or raise threshold before deploying. "
                "Set use_archive=True to test against all ingested logs (requires logall=yes in ossec.conf)."
            ),
        }

    @mcp.tool()
    async def suggest_rule_tuning(
        rule_id: int,
        time_range: str = "7d",
    ) -> dict:
        """Analyse a noisy Wazuh rule and suggest concrete tuning to reduce false positives.

        Looks at the last N days of alerts for this rule and identifies:
        - Fire frequency vs expected baseline
        - Time-of-day distribution (off-hours vs business hours)
        - Agent distribution (single noisy agent vs fleet-wide)
        - Common source IPs / users that appear legitimate
        - Groups that co-fire frequently (FP indicator)

        Returns: recommended XML tuning changes with rationale.

        rule_id:    Wazuh rule ID (e.g. 5710 for SSH authentication failures)
        time_range: How far back to analyse (default 7d)
        """
        from ..helpers import time_window as _tw, trim_alert

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        _tw(f"now-{time_range}"),
                        {"term": {"rule.id": str(rule_id)}},
                    ]
                }
            },
            "aggs": {
                "total":         {"value_count": {"field": "_id"}},
                "by_agent":      {"terms": {"field": "agent.name",    "size": 20}},
                "by_src_ip":     {"terms": {"field": "data.srcip",    "size": 20}},
                "by_user":       {"terms": {"field": "data.dstuser",  "size": 10}},
                "by_hour":       {"terms": {"field": "hour_of_day",   "size": 24}},
                "by_group":      {"terms": {"field": "rule.groups",   "size": 10}},
                "by_day": {
                    "date_histogram": {
                        "field": "@timestamp", "calendar_interval": "day", "min_doc_count": 0,
                    }
                },
            },
        }
        try:
            res  = await idx.search(body)
        except Exception as exc:
            return {"error": f"Rule query failed: {exc}"}

        aggs  = res.get("aggregations", {})
        total = res["hits"]["total"]["value"]

        if total == 0:
            return {
                "rule_id":   rule_id,
                "time_range": time_range,
                "status": "NO_ALERTS",
                "message": f"Rule {rule_id} has not fired in the last {time_range}.",
            }

        # Agent concentration
        agent_bkts = aggs.get("by_agent", {}).get("buckets", [])
        top_agent  = agent_bkts[0] if agent_bkts else {}
        top_agent_pct = round(top_agent.get("doc_count", 0) / total * 100, 1) if total else 0

        # Source IP analysis
        src_bkts   = aggs.get("by_src_ip", {}).get("buckets", [])
        top_ips    = [b["key"] for b in src_bkts[:5]]

        # User analysis
        user_bkts  = aggs.get("by_user", {}).get("buckets", [])
        top_users  = [b["key"] for b in user_bkts[:5] if b["key"] not in ("", None)]

        # Day-of-week distribution from date histogram
        day_bkts   = aggs.get("by_day", {}).get("buckets", [])
        daily_avg  = total / max(len(day_bkts), 1)
        max_day_count = max((b["doc_count"] for b in day_bkts), default=0)
        spike_ratio   = round(max_day_count / daily_avg, 1) if daily_avg else 0

        # Groups
        grp_bkts = aggs.get("by_group", {}).get("buckets", [])
        top_groups = [b["key"] for b in grp_bkts[:5]]

        # Fetch rule description from Manager
        rule_description = f"Rule {rule_id}"
        try:
            r_resp = await wz.get(f"/rules?rule_ids={rule_id}&limit=1")
            items  = r_resp.get("data", {}).get("affected_items", [])
            if items:
                rule_description = items[0].get("description", rule_description)
        except Exception:
            pass

        # ── Tuning recommendations ────────────────────────────────────────────
        suggestions: list[dict] = []

        if top_agent_pct > 70 and len(agent_bkts) > 1:
            suggestions.append({
                "type":        "AGENT_EXCLUSION",
                "priority":    "HIGH",
                "description": f"Agent '{top_agent.get('key')}' generates {top_agent_pct}% of alerts.",
                "xml_change":  f'<list field="agent.name" lookup="not_match_key">agent-whitelist</list>',
                "rationale":   "Create a whitelist CDB list and exclude this agent if it is a known noisy host.",
            })

        if top_ips and src_bkts and src_bkts[0]["doc_count"] / total > 0.5:
            suggestions.append({
                "type":        "SOURCE_IP_FILTER",
                "priority":    "HIGH",
                "description": f"IP {top_ips[0]} drives {round(src_bkts[0]['doc_count']/total*100,1)}% of alerts.",
                "xml_change":  f'<list field="data.srcip" lookup="not_match_key">ip-whitelist</list>',
                "rationale":   "Add this IP to a CDB whitelist if it is a scanner or monitoring tool.",
            })

        if total > 1000:
            suggestions.append({
                "type":        "THRESHOLD",
                "priority":    "HIGH",
                "description": f"Rule fired {total} times in {time_range} — extremely noisy.",
                "xml_change":  f'<options>no_log</options>  <!-- or add <timeframe>60</timeframe><frequency>10</frequency> -->',
                "rationale":   "Add a frequency threshold so the rule only alerts after N events in a time window.",
            })
        elif total > 200:
            suggestions.append({
                "type":        "THRESHOLD",
                "priority":    "MEDIUM",
                "description": f"Rule fired {total} times in {time_range} — consider a frequency threshold.",
                "xml_change":  '<timeframe>300</timeframe>\n    <frequency>5</frequency>',
                "rationale":   "Alert only when rule fires 5+ times in 5 minutes rather than every event.",
            })

        if spike_ratio > 5:
            suggestions.append({
                "type":        "TIME_CORRELATION",
                "priority":    "MEDIUM",
                "description": f"Alert volume spikes {spike_ratio}x above daily average on peak days.",
                "xml_change":  "Consider scheduled suppression during maintenance windows.",
                "rationale":   "Recurring spikes often indicate scheduled jobs or backups triggering the rule.",
            })

        if top_users:
            suggestions.append({
                "type":        "USER_FILTER",
                "priority":    "LOW",
                "description": f"Top users triggering rule: {top_users}.",
                "xml_change":  f'<list field="data.dstuser" lookup="not_match_key">user-whitelist</list>',
                "rationale":   "If these are service accounts, whitelist them to eliminate systematic FPs.",
            })

        noise_score = min(100, int(
            (total / 100) * 20 +
            (top_agent_pct / 100) * 30 +
            (1 if total > 1000 else 0) * 30 +
            (spike_ratio / 10) * 20
        ))

        return {
            "rule_id":          rule_id,
            "rule_description": rule_description,
            "time_range":       time_range,
            "stats": {
                "total_alerts":  total,
                "daily_average": round(daily_avg, 1),
                "peak_day_spike_ratio": spike_ratio,
                "top_agents":    [(b["key"], b["doc_count"]) for b in agent_bkts[:5]],
                "top_src_ips":   top_ips,
                "top_users":     top_users,
                "top_groups":    top_groups,
            },
            "noise_score":      noise_score,
            "noise_tier":       "CRITICAL" if noise_score > 75 else "HIGH" if noise_score > 50 else "MEDIUM" if noise_score > 25 else "LOW",
            "tuning_suggestions": suggestions,
            "next_steps": [
                f"noise_score_rule(rule_id='{rule_id}') — cross-check noise score",
                f"bulk_suppress_rule(rule_id={rule_id}, reason='tuning', dry_run=True) — preview suppression",
                "add_to_cdb_list('ip-whitelist', top_ip) — whitelist scanner IPs",
            ],
        }
