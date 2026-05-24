"""F6: CVE Watchlist & Patch Tracking.

Maintains a persistent watchlist of CVEs the SOC cares about, stored in a
Wazuh CDB list ("cve-watchlist"). Auto-alerts when a watched CVE appears in
the fleet's vulnerability data.

CDB list entry format:
    key   = CVE ID (e.g. "CVE-2024-1234")
    value = "<status>|<note>"   where status = "active" | "patched" | "monitoring"

Tools:
    add_cve_to_watchlist    — add a CVE to track
    list_cve_watchlist      — list all watched CVEs with status
    mark_patched            — mark a CVE as patched across the fleet
    get_watchlist_exposure  — count affected agents per active CVE
"""
from __future__ import annotations

import re

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CDB_LIST = "cve-watchlist"


def register(mcp, wz, idx, cfg):
    from ..validators import safe_validate, validate_cve_id, validate_free_text, safe_validate

    @mcp.tool()
    async def add_cve_to_watchlist(cve_id: str, note: str = "") -> dict:
        """Add a CVE to the SOC watchlist for continuous monitoring.

        cve_id: CVE identifier in CVE-YYYY-NNNN format.
        note:   Optional annotation (e.g. affected software, severity context).

        The CVE is stored in the Wazuh CDB list 'cve-watchlist' with status 'active'.
        Use get_watchlist_exposure to check how many agents are affected.
        """
        _, err = safe_validate(validate_cve_id, cve_id)
        if err:
            return err

        cve_id = cve_id.upper()
        if note:
            _, err = safe_validate(validate_free_text, note, "note", max_len=200)
            if err:
                return err

        value = f"active|{note}"
        try:
            await wz.request(
                "PUT",
                f"/lists/files/{_CDB_LIST}",
                json={cve_id: value},
            )
        except Exception as exc:
            return {"error": f"Failed to add CVE to watchlist: {exc}"}

        return {
            "added": cve_id,
            "status": "active",
            "note": note,
            "message": (
                f"'{cve_id}' added to watchlist. "
                "Use get_watchlist_exposure to check affected agents."
            ),
        }

    @mcp.tool()
    async def list_cve_watchlist() -> dict:
        """List all CVEs on the SOC watchlist with their status and notes.

        Returns CVE IDs, status (active/patched/monitoring), notes, and counts.
        Status values:
          active     — being tracked, may have affected agents
          monitoring — acknowledged but not yet patched
          patched    — remediation confirmed
        """
        try:
            resp = await wz.request("GET", f"/lists/files/{_CDB_LIST}?raw=true")
            items = (resp.get("data") or {}).get("affected_items") or []
        except Exception as exc:
            return {"error": f"Failed to read watchlist: {exc}"}

        watchlist = []
        for entry in items:
            key = entry.get("key", "")
            val = entry.get("value", "")
            if not _CVE_RE.match(key):
                continue
            parts = val.split("|", 1)
            status = parts[0] if parts else "active"
            note = parts[1] if len(parts) > 1 else ""
            watchlist.append({"cve_id": key, "status": status, "note": note})

        by_status: dict[str, int] = {}
        for w in watchlist:
            by_status[w["status"]] = by_status.get(w["status"], 0) + 1

        return {
            "total": len(watchlist),
            "by_status": by_status,
            "watchlist": watchlist,
        }

    @mcp.tool()
    async def mark_patched(cve_id: str, note: str = "") -> dict:
        """Mark a watched CVE as patched across the fleet.

        Updates the CVE's status in the watchlist from 'active'/'monitoring'
        to 'patched'. The entry is preserved for audit purposes.

        cve_id: CVE identifier to mark as patched.
        note:   Optional remediation note (e.g. patch version applied).
        """
        _, err = safe_validate(validate_cve_id, cve_id)
        if err:
            return err

        cve_id = cve_id.upper()
        if note:
            _, err = safe_validate(validate_free_text, note, "note", max_len=200)
            if err:
                return err

        value = f"patched|{note}"
        try:
            await wz.request(
                "PUT",
                f"/lists/files/{_CDB_LIST}",
                json={cve_id: value},
            )
        except Exception as exc:
            return {"error": f"Failed to update watchlist: {exc}"}

        return {
            "cve_id": cve_id,
            "status": "patched",
            "note": note,
            "message": f"'{cve_id}' marked as patched in the watchlist.",
        }

    @mcp.tool()
    async def get_watchlist_exposure() -> dict:
        """Check how many agents are affected by each active CVE in the watchlist.

        Queries the Wazuh vulnerability index to count affected agents per CVE.
        Only 'active' and 'monitoring' CVEs are checked (patched are skipped).

        Returns per-CVE agent counts and a list of affected agent names.
        """
        # Get active CVEs
        try:
            resp = await wz.request("GET", f"/lists/files/{_CDB_LIST}?raw=true")
            items = (resp.get("data") or {}).get("affected_items") or []
        except Exception as exc:
            return {"error": f"Failed to read watchlist: {exc}"}

        active_cves = []
        for entry in items:
            key = entry.get("key", "")
            val = entry.get("value", "")
            if not _CVE_RE.match(key):
                continue
            status = val.split("|", 1)[0]
            if status in ("active", "monitoring"):
                active_cves.append(key)

        if not active_cves:
            return {
                "message": "No active CVEs in watchlist.",
                "exposure": [],
            }

        exposure = []
        for cve in active_cves:
            try:
                result = await idx.search(
                    index="wazuh-states-vulnerabilities-*",
                    body={
                        "query": {
                            "bool": {
                                "must": [{"term": {"vulnerability.id": cve}}]
                            }
                        },
                        "aggs": {
                            "agents": {
                                "terms": {"field": "agent.id", "size": 50}
                            }
                        },
                        "size": 0,
                    },
                )
                total = (result.get("hits") or {}).get("total", {}).get("value", 0)
                buckets = (result.get("aggregations") or {}).get("agents", {}).get("buckets", [])
                agent_ids = [b["key"] for b in buckets]
                exposure.append({
                    "cve_id": cve,
                    "affected_agents": total,
                    "agent_ids": agent_ids[:20],
                })
            except Exception as exc:
                exposure.append({"cve_id": cve, "error": str(exc)})

        total_affected = sum(e.get("affected_agents", 0) for e in exposure)
        return {
            "active_cves_checked": len(active_cves),
            "total_agent_exposures": total_affected,
            "exposure": exposure,
        }
