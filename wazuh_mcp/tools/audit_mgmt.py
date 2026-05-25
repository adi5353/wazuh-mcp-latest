"""MCP audit log management tools.

Query and verify the integrity of the Wazuh MCP audit log.
Requires ADMIN role.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def get_audit_log_stats() -> dict:
        """Return statistics about the MCP audit log file.

        Requires ADMIN role.
        """
        from ..rbac import admin_only
        err = admin_only()
        if err:
            return err

        log_path = Path(os.getenv("WAZUH_AUDIT_LOG", "logs/audit.jsonl"))
        if not log_path.exists():
            return {"error": "Audit log file not found.", "path": str(log_path)}

        try:
            stat = log_path.stat()
            lines = 0
            errors = 0
            first_ts = None
            last_ts = None
            with log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    lines += 1
                    try:
                        record = json.loads(line)
                        ts = record.get("ts")
                        if ts:
                            if first_ts is None:
                                first_ts = ts
                            last_ts = ts
                    except json.JSONDecodeError:
                        errors += 1
            return {
                "path": str(log_path),
                "size_bytes": stat.st_size,
                "total_records": lines,
                "parse_errors": errors,
                "first_record_ts": first_ts,
                "last_record_ts": last_ts,
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def search_audit_log(
        tool_name: str | None = None,
        identity: str | None = None,
        result_code: str | None = None,
        limit: int = 50,
    ) -> dict:
        """Search the MCP audit log for specific tool calls or identities.

        Args:
            tool_name: Filter by tool name (e.g. 'run_active_response').
            identity: Filter by identity hash prefix.
            result_code: Filter by result code ('ok' or 'error').
            limit: Maximum records to return.

        Requires ADMIN role.
        """
        from ..rbac import admin_only
        err = admin_only()
        if err:
            return err

        log_path = Path(os.getenv("WAZUH_AUDIT_LOG", "logs/audit.jsonl"))
        if not log_path.exists():
            return {"error": "Audit log not found.", "path": str(log_path)}

        results = []
        try:
            with log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if tool_name and record.get("tool") != tool_name:
                        continue
                    if identity and not record.get("identity", "").startswith(identity):
                        continue
                    if result_code and record.get("result_code") != result_code:
                        continue
                    results.append(record)

            results = results[-_cap(limit):]
            return {
                "total_matching": len(results),
                "records": results,
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def verify_audit_log_integrity() -> dict:
        """Verify HMAC signatures on audit log records (if signing is enabled).

        Checks every record's 'hmac' field against WAZUH_AUDIT_LOG_SIGNING_KEY.
        Returns a summary of valid, invalid, and unsigned records.

        Requires ADMIN role.
        """
        from ..rbac import admin_only
        err = admin_only()
        if err:
            return err

        import hashlib
        import hmac as hmac_mod

        signing_key = os.getenv("WAZUH_AUDIT_LOG_SIGNING_KEY", "")
        log_path = Path(os.getenv("WAZUH_AUDIT_LOG", "logs/audit.jsonl"))

        if not log_path.exists():
            return {"error": "Audit log not found."}

        if not signing_key:
            return {
                "signing_enabled": False,
                "note": "Set WAZUH_AUDIT_LOG_SIGNING_KEY to enable integrity verification.",
            }

        valid = invalid = unsigned = 0
        tampered_records = []

        with log_path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                stored_hmac = record.pop("hmac", None)
                if stored_hmac is None:
                    unsigned += 1
                    continue

                canonical = json.dumps(record, sort_keys=True, default=str)
                expected = hmac_mod.new(
                    signing_key.encode(), canonical.encode(), hashlib.sha256
                ).hexdigest()

                if hmac_mod.compare_digest(stored_hmac, expected):
                    valid += 1
                else:
                    invalid += 1
                    tampered_records.append({
                        "line": line_no,
                        "ts": record.get("ts"),
                        "tool": record.get("tool"),
                    })

        return {
            "signing_enabled": True,
            "valid_records": valid,
            "invalid_records": invalid,
            "unsigned_records": unsigned,
            "tampered": tampered_records[:20],
            "integrity": "ok" if invalid == 0 else "COMPROMISED",
        }
