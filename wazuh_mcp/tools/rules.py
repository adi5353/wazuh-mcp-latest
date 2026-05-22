"""Rules and decoder tools — lookup, search, logtest, and coverage analysis."""
from __future__ import annotations


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
    async def test_log_against_rules(log_sample: str, log_format: str = "syslog") -> dict:
        """Test a raw log line against Wazuh decoder + rule engine.

        Returns which decoder fired, which rule matched, alert level and groups.
        log_format: syslog | json | audit | eventchannel | apache | nginx
        """
        body = {"event": log_sample, "log_format": log_format, "location": "test"}
        return await wz.request("PUT", "/logtest", json=body)

    @mcp.tool()
    async def test_rule_coverage(log_samples: list) -> dict:
        """Test up to 20 log samples and report what percentage your ruleset covers."""
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
