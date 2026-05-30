"""Rule Wizard — upload_xml_file calls + rollback state management.

Handles: push_custom_rule, push_custom_decoder, sigma_bulk_import
"""
from __future__ import annotations
from ..tool_context import ToolContext

from ..rbac import admin_only


def register_deploy(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz

    from .rule_wizard_generate import _sigma_to_wazuh_level, _extract_sigma_field_conditions, _SIGMA_LOGSOURCE_TO_PARENT, _SIGMA_MITRE_LEVELS
    from .rule_wizard_validate import _validate_rule_xml_impl

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

        import re as _re
        if not _re.match(r'^[\w\-\.]+\.xml$', filename):
            return {"error": "filename must be a simple .xml filename with no path separators."}

        validation = _validate_rule_xml_impl(xml_content)
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
            pass

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

        import defusedxml.ElementTree as ET
        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as exc:
            return {"valid": False, "error": f"XML parse error: {exc}"}

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
                "rule_id_range": f"{start_rule_id}-{start_rule_id + len(docs) - 1}",
            },
            "rules": results,
            "tip": (
                "Set dry_run=False and push_all=True to deploy all valid rules. "
                "Each rule gets its own file: sigma_<rule_id>.xml. "
                "Use test_rule_coverage to verify detection after deployment."
            ),
        }
