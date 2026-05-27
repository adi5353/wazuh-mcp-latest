"""Rules and decoder tools — lookup, search, logtest, coverage analysis, rollback, and decoder test."""
from __future__ import annotations
import json as _json

from ..rbac import analyst_only, admin_only


# In-memory rule backup store: filename → previous XML content
_rule_backups: dict[str, str] = {}


def register(mcp, wz, idx, cfg, _cap):

    @mcp.tool()
    async def get_rule_details(rule_id: str) -> dict:
        """Look up a Wazuh rule's full metadata by ID (description, level, groups,
        MITRE and compliance mappings).

        Useful after `alert_summary` surfaces a rule ID you don't recognize.
        """
        return await wz.request("GET", f"/rules?rule_ids={rule_id}")

    @mcp.tool()
    async def search_rules(
        description_contains: str | None = None,
        group: str | None = None,
        level_min: int | None = None,
        mitre_technique: str | None = None,
        limit: int = 50,
    ) -> dict:
        """Search enabled Wazuh rules by description, group, minimum level, or MITRE technique."""
        path = f"/rules?limit={_cap(limit)}&status=enabled"
        if description_contains:
            path += f"&search={description_contains}"
        if group:
            path += f"&group={group}"
        if level_min:
            path += f"&level={level_min}-16"
        if mitre_technique:
            path += f"&mitre_id={mitre_technique}"
        return await wz.request("GET", path)

    @mcp.tool()
    async def list_rule_files() -> dict:
        """List all rule files loaded by Wazuh — built-in and custom."""
        return await wz.request("GET", "/rules/files?limit=200")

    @mcp.tool()
    async def get_custom_rules() -> dict:
        """Get all rules from custom rule files (local_rules.xml and user-created files)."""
        return await wz.request("GET", "/rules/files?relative_dirname=etc/rules&limit=100")

    @mcp.tool()
    async def list_decoders() -> dict:
        """List all loaded decoders with their file sources."""
        return await wz.request("GET", "/decoders?limit=500")

    @mcp.tool()
    async def test_log_against_rules(
        log_sample: str,
        log_format: str = "syslog",
        log_samples: list | None = None,
    ) -> dict:
        """Test one or more raw log lines against Wazuh decoder + rule engine.

        Single mode:  pass log_sample (one line).
        Batch mode:   pass log_samples (list of strings, max 20).
        Returns which decoder fired, which rule matched, alert level and groups.
        log_format: syslog | json | audit | eventchannel | apache | nginx
        Requires role: analyst.
        """
        err = analyst_only()
        if err:
            return err

        # Batch mode
        if log_samples:
            results = []
            for raw in log_samples[:20]:
                try:
                    r = await wz.request("PUT", "/logtest", json={
                        "event": str(raw), "log_format": log_format, "location": "test"
                    })
                    out = (r.get("data") or {}).get("output", {})
                    rule = out.get("rule", {})
                    results.append({
                        "log_snippet": str(raw)[:120],
                        "decoder": out.get("decoder", {}).get("name"),
                        "rule_id": rule.get("id"),
                        "description": rule.get("description"),
                        "level": rule.get("level"),
                        "groups": rule.get("groups", []),
                        "matched": bool(rule.get("id")),
                    })
                except Exception as exc:
                    results.append({"log_snippet": str(raw)[:120], "error": str(exc), "matched": False})
            matched = sum(1 for r in results if r.get("matched"))
            return {
                "mode": "batch",
                "total": len(results),
                "matched": matched,
                "unmatched": len(results) - matched,
                "coverage_pct": round(matched / len(results) * 100, 1) if results else 0,
                "results": results,
            }

        # Single mode
        body = {"event": log_sample, "log_format": log_format, "location": "test"}
        return await wz.request("PUT", "/logtest", json=body)

    @mcp.tool()
    async def test_rule_coverage(log_samples: list) -> dict:
        """Test up to 20 log samples and report what percentage your ruleset covers.
        Requires role: analyst.
        """
        err = analyst_only()
        if err:
            return err
        results = []
        for raw_log in log_samples[:20]:
            try:
                r = await wz.request("PUT", "/logtest", json={
                    "event": raw_log, "log_format": "syslog", "location": "test"
                })
                rule = (r.get("data") or {}).get("output", {}).get("rule", {})
                results.append({
                    "log_snippet": str(raw_log)[:80],
                    "rule_id": rule.get("id"),
                    "description": rule.get("description"),
                    "level": rule.get("level"),
                    "groups": rule.get("groups", []),
                    "covered": bool(rule.get("id")),
                })
            except Exception as e:
                results.append({"log_snippet": str(raw_log)[:80], "error": str(e), "covered": False})
        covered = sum(1 for r in results if r.get("covered"))
        return {
            "total_samples": len(results),
            "covered": covered,
            "not_covered": len(results) - covered,
            "coverage_pct": round(covered / len(results) * 100, 1) if results else 0,
            "details": results,
        }

    @mcp.tool()
    async def rollback_custom_rule(
        filename: str = "custom_rules.xml",
    ) -> dict:
        """Restore the previous version of a custom rule file from the in-memory backup.

        push_custom_rule automatically saves the existing content before overwriting.
        This tool restores that saved version — useful when a pushed rule causes issues.

        filename: rule filename under etc/rules/ that was previously pushed.
        Requires role: admin.
        """
        err = admin_only()
        if err:
            return err

        backup = _rule_backups.get(filename)
        if not backup:
            return {
                "error": f"No backup found for '{filename}'.",
                "tip": "Backups are saved in memory when push_custom_rule is called. They are lost on server restart.",
            }

        try:
            result = await wz.upload_xml_file(f"/rules/files/{filename}", backup, overwrite=True)
        except Exception as exc:
            return {"error": f"Rollback push failed: {exc}"}

        # Clear backup after successful restore
        del _rule_backups[filename]
        return {
            "success": True,
            "rolled_back_file": filename,
            "manager_response": result,
            "message": f"'{filename}' has been restored to its previous version.",
        }

    @mcp.tool()
    async def test_decoder(
        log_sample: str,
        decoder_name: str | None = None,
    ) -> dict:
        """Test a log line against Wazuh's decoder engine and return field extraction results.

        Shows exactly which decoder fired, what parent decoder chain was used,
        and every field extracted from the log sample — essential for writing
        custom decoders or debugging field-not-found issues.

        log_sample:    Raw log line to test.
        decoder_name:  Optional — if provided, checks whether this decoder matched.
        Requires role: analyst.
        """
        err = analyst_only()
        if err:
            return err

        body = {"event": log_sample, "log_format": "syslog", "location": "test"}
        try:
            r = await wz.request("PUT", "/logtest", json=body)
        except Exception as exc:
            return {"error": f"Logtest request failed: {exc}"}

        output = (r.get("data") or {}).get("output", {})
        decoder = output.get("decoder", {})
        fields  = {
            k: v for k, v in output.items()
            if k not in ("decoder", "rule", "agent", "manager", "id", "cluster", "@timestamp", "location")
        }
        rule = output.get("rule", {})

        result = {
            "log_snippet": log_sample[:200],
            "decoder_name": decoder.get("name"),
            "decoder_parent": decoder.get("parent"),
            "fields_extracted": fields,
            "rule_triggered": {
                "rule_id":     rule.get("id"),
                "description": rule.get("description"),
                "level":       rule.get("level"),
                "groups":      rule.get("groups", []),
            } if rule.get("id") else None,
        }

        if decoder_name:
            matched = decoder.get("name") == decoder_name
            result["decoder_name_check"] = {
                "expected": decoder_name,
                "matched":  matched,
                "actual":   decoder.get("name"),
            }
            if not matched:
                result["tip"] = (
                    f"Expected decoder '{decoder_name}' but got '{decoder.get('name')}'. "
                    "Check the prematch/program_name patterns in your decoder definition."
                )

        return result
