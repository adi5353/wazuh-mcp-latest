"""CDB list management tools — list, read, add, remove, preview blocklist impact,
and backup/restore CDB lists for disaster recovery.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ..rbac import responder_only, admin_only


def register(mcp, wz, idx, cfg, _require_writes):

    @mcp.tool()
    async def list_cdb_lists() -> dict:
        """List all CDB lookup lists configured in Wazuh."""
        return await wz.request("GET", "/lists?limit=100")

    @mcp.tool()
    async def get_cdb_list_contents(list_name: str) -> dict:
        """Get the full key:value contents of a CDB list file."""
        return await wz.request("GET", f"/lists/files/{list_name}?raw=true")

    @mcp.tool()
    async def add_to_cdb_list(list_name: str, key: str, value: str = "malicious") -> dict:
        """Add an IP, domain, or file hash to a CDB blocklist — takes effect immediately.

        Requires WAZUH_ALLOW_WRITES=true. Requires role: responder or above.
        list_name: e.g. 'malicious-ips'
        key: the IP/domain/hash to add
        value: label, e.g. 'c2-server', 'attacker', 'phishing'
        """
        err = responder_only()
        if err:
            return err
        blocked = _require_writes()
        if blocked:
            return blocked
        try:
            current = await wz.request("GET", f"/lists/files/{list_name}?raw=true")
            existing = (current.get("data") or {}).get("affected_items", [""])[0] or ""
        except Exception:
            existing = ""
        lines = [ln for ln in existing.splitlines() if ln.strip() and not ln.startswith(f"{key}:")]
        lines.append(f"{key}:{value}")
        new_content = "\n".join(lines) + "\n"
        result = await wz.request(
            "PUT", f"/lists/files/{list_name}",
            content=new_content.encode(),
            headers={"Content-Type": "application/octet-stream"},
        )
        return {"action": "added", "key": key, "value": value, "list": list_name, "api_result": result}

    @mcp.tool()
    async def remove_from_cdb_list(list_name: str, key: str) -> dict:
        """Remove an entry from a CDB list. Requires WAZUH_ALLOW_WRITES=true.
        Requires role: responder or above.
        """
        err = responder_only()
        if err:
            return err
        blocked = _require_writes()
        if blocked:
            return blocked
        current = await wz.request("GET", f"/lists/files/{list_name}?raw=true")
        existing = (current.get("data") or {}).get("affected_items", [""])[0] or ""
        filtered = "\n".join(
            ln for ln in existing.splitlines()
            if ln.strip() and not ln.startswith(f"{key}:")
        ) + "\n"
        result = await wz.request(
            "PUT", f"/lists/files/{list_name}",
            content=filtered.encode(),
            headers={"Content-Type": "application/octet-stream"},
        )
        return {"action": "removed", "key": key, "list": list_name, "api_result": result}

    @mcp.tool()
    async def preview_cdb_list_impact(ip: str, hours: int = 24) -> dict:
        """Show how many recent alerts came from this IP before adding it to a blocklist.

        Run this BEFORE add_to_cdb_list to understand noise-reduction impact.
        No writes performed — always safe.
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                        {
                            "bool": {
                                "should": [
                                    {"term": {"data.srcip": ip}},
                                    {"term": {"data.src_ip": ip}},
                                ]
                            }
                        },
                    ]
                }
            },
            "aggs": {
                "by_rule": {"terms": {"field": "rule.description", "size": 5}},
                "by_agent": {"terms": {"field": "agent.name", "size": 5}},
            },
            "size": 0,
        }
        res = await idx.search(query)
        total = res["hits"]["total"]["value"]
        return {
            "ip": ip,
            "alerts_last_n_hours": total,
            "hours_checked": hours,
            "top_triggered_rules": [
                {"rule": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_rule"]["buckets"]
            ],
            "top_targeted_agents": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in res["aggregations"]["by_agent"]["buckets"]
            ],
            "recommendation": (
                f"Blocking this IP would suppress ~{total} alerts over {hours}h."
                if total > 0
                else "No recent alerts from this IP — blocking may have no immediate effect."
            ),
        }

    @mcp.tool()
    async def export_cdb_backup(list_names: list | None = None) -> dict:
        """Export CDB lists to a JSON backup file for disaster recovery.

        Exports all CDB lists (or a specified subset) to the workspace backup
        directory. Run this before upgrades or bulk changes.

        list_names: specific list names to export, or null/[] to export ALL lists.

        Returns the backup file path and a summary of exported entries.
        """
        err = admin_only()
        if err:
            return err

        # Discover available lists
        try:
            all_lists_resp = await wz.request("GET", "/lists?limit=100")
            all_items = (all_lists_resp.get("data") or {}).get("affected_items") or []
            available = [item.get("filename", "") for item in all_items if item.get("filename")]
        except Exception as exc:
            return {"error": f"Failed to list CDB lists: {exc}"}

        to_export = list_names if list_names else available
        if not to_export:
            return {"error": "No CDB lists found to export."}

        backup: dict[str, list] = {}
        errors: list[str] = []

        for list_name in to_export:
            try:
                resp = await wz.request("GET", f"/lists/files/{list_name}?raw=true")
                content = (resp.get("data") or {}).get("affected_items", [""])[0] or ""
                entries = []
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if ":" in line:
                        k, _, v = line.partition(":")
                        entries.append({"key": k, "value": v})
                    else:
                        entries.append({"key": line, "value": ""})
                backup[list_name] = entries
            except Exception as exc:
                errors.append(f"{list_name}: {exc}")

        # Write backup file
        backup_dir = Path(os.getenv("WAZUH_WORKSPACE_DIR", "/app/workspaces")) / "backups" / "cdb"
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_file = backup_dir / f"cdb_backup_{ts}.json"

        metadata = {
            "_backup_metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "lists_exported": list(backup.keys()),
                "total_entries": sum(len(v) for v in backup.values()),
                "errors": errors,
            }
        }
        try:
            backup_file.write_text(json.dumps({**metadata, **backup}, indent=2))
        except Exception as exc:
            return {"error": f"Failed to write backup file: {exc}"}

        return {
            "backup_file": str(backup_file),
            "lists_exported": list(backup.keys()),
            "total_entries": sum(len(v) for v in backup.values()),
            "errors": errors,
            "message": (
                f"CDB backup written to {backup_file}. "
                "Use import_cdb_backup(backup_file=...) to restore."
            ),
        }

    @mcp.tool()
    async def import_cdb_backup(backup_file: str, dry_run: bool = True) -> dict:
        """Restore CDB lists from a backup file created by export_cdb_backup.

        dry_run=True (default): show what would be restored without writing.
        dry_run=False: restore all list entries. Existing entries are overwritten.

        backup_file: absolute path to the JSON backup file.
        Requires role: admin. Requires WAZUH_ALLOW_WRITES=true.
        """
        err = admin_only()
        if err:
            return err

        blocked = _require_writes()
        if blocked and not dry_run:
            return blocked

        # Validate path — only allow files within the workspace backup directory
        allowed_base = Path(os.getenv("WAZUH_WORKSPACE_DIR", "/app/workspaces")) / "backups" / "cdb"
        try:
            resolved = Path(backup_file).resolve()
            allowed_base.resolve()
            if not str(resolved).startswith(str(allowed_base.resolve())):
                return {"error": "backup_file must be inside the CDB backup directory."}
        except Exception as exc:
            return {"error": f"Invalid backup_file path: {exc}"}

        try:
            data = json.loads(resolved.read_text())
        except Exception as exc:
            return {"error": f"Failed to read backup file: {exc}"}

        metadata = data.pop("_backup_metadata", {})
        lists_to_restore = list(data.keys())

        if dry_run:
            preview = []
            for list_name, entries in data.items():
                preview.append({
                    "list_name": list_name,
                    "entry_count": len(entries),
                    "sample": entries[:3],
                })
            return {
                "dry_run": True,
                "backup_created_at": metadata.get("created_at"),
                "lists_to_restore": lists_to_restore,
                "preview": preview,
                "message": "Dry run only. Set dry_run=False to restore.",
            }

        restored = []
        errors = []
        for list_name, entries in data.items():
            if not entries:
                continue
            content = "\n".join(
                f"{e['key']}:{e['value']}" if e.get("value") else e["key"]
                for e in entries
            ) + "\n"
            try:
                await wz.request(
                    "PUT", f"/lists/files/{list_name}",
                    content=content.encode(),
                    headers={"Content-Type": "application/octet-stream"},
                )
                restored.append({"list_name": list_name, "entries_written": len(entries)})
            except Exception as exc:
                errors.append(f"{list_name}: {exc}")

        return {
            "dry_run": False,
            "restored": restored,
            "errors": errors,
            "message": (
                f"Restored {len(restored)} CDB list(s) from backup. "
                + (f"{len(errors)} error(s)." if errors else "")
            ),
        }
