"""F6: CVE Watchlist & Patch Tracking.

Maintains a persistent watchlist of CVEs the SOC cares about, stored in a
Wazuh CDB list ("cve-watchlist"). Auto-alerts when a watched CVE appears in
the fleet's vulnerability data.

CDB list entry format:
    key   = CVE ID (e.g. "CVE-2024-1234")
    value = "<status>|<note>|<cvss>|<sla_days>|<added_at>"

Tools:
    add_cve_to_watchlist    — add a CVE to track (with optional CVSS + SLA)
    list_cve_watchlist      — list all watched CVEs with status + SLA countdown
    mark_patched            — mark a CVE as patched across the fleet
    get_watchlist_exposure  — count affected agents per active CVE
    prioritize_cve_risk     — rank active CVEs by composite risk score
    check_sla_breaches      — list CVEs that have breached their patch SLA
"""
from __future__ import annotations
from ..tool_context import ToolContext

import re
from datetime import datetime, timedelta, timezone

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CDB_LIST = "cve-watchlist"


def _parse_entry(key: str, val: str) -> dict:
    """Parse a CDB watchlist value into structured fields."""
    parts = val.split("|")
    status    = parts[0] if len(parts) > 0 else "active"
    note      = parts[1] if len(parts) > 1 else ""
    cvss      = float(parts[2]) if len(parts) > 2 and parts[2] else 0.0
    sla_days  = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
    added_at  = parts[4] if len(parts) > 4 else ""
    return {
        "cve_id": key,
        "status": status,
        "note": note,
        "cvss_score": cvss,
        "sla_days": sla_days,
        "added_at": added_at,
    }


def _sla_status(entry: dict) -> dict:
    """Return SLA deadline + breach info for a watchlist entry."""
    sla_days = entry.get("sla_days", 0)
    added_at = entry.get("added_at", "")
    if not sla_days or not added_at:
        return {"sla_deadline": None, "sla_breached": False, "days_remaining": None}
    try:
        added = datetime.fromisoformat(added_at.replace("Z", "+00:00"))
        deadline = added + timedelta(days=sla_days)
        now = datetime.now(timezone.utc)
        days_remaining = (deadline - now).days
        return {
            "sla_deadline": deadline.strftime("%Y-%m-%d"),
            "sla_breached": now > deadline,
            "days_remaining": days_remaining,
        }
    except Exception:
        return {"sla_deadline": None, "sla_breached": False, "days_remaining": None}


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg

    from ..validators import safe_validate, validate_cve_id, validate_free_text, safe_validate

    @mcp.tool()
    async def add_cve_to_watchlist(
        cve_id: str,
        note: str = "",
        cvss_score: float = 0.0,
        sla_days: int = 0,
    ) -> dict:
        """Add a CVE to the SOC watchlist for continuous monitoring.

        cve_id:     CVE identifier in CVE-YYYY-NNNN format.
        note:       Optional annotation (e.g. affected software, severity context).
        cvss_score: CVSS base score (0.0–10.0) for risk scoring. Set for accurate
                    prioritize_cve_risk() output.
        sla_days:   Days to patch deadline from today (0 = no SLA). Triggers
                    check_sla_breaches() alerts when expired.

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

        if not (0.0 <= cvss_score <= 10.0):
            return {"error": "cvss_score must be between 0.0 and 10.0"}
        if sla_days < 0:
            return {"error": "sla_days must be 0 or positive"}

        added_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        value = f"active|{note}|{cvss_score}|{sla_days}|{added_at}"
        try:
            await wz.request(
                "PUT",
                f"/lists/files/{_CDB_LIST}",
                json={cve_id: value},
            )
        except Exception as exc:
            return {"error": f"Failed to add CVE to watchlist: {exc}"}

        result = {
            "added": cve_id,
            "status": "active",
            "note": note,
            "cvss_score": cvss_score,
            "message": (
                f"'{cve_id}' added to watchlist. "
                "Use get_watchlist_exposure to check affected agents."
            ),
        }
        if sla_days:
            deadline = datetime.now(timezone.utc) + timedelta(days=sla_days)
            result["sla_deadline"] = deadline.strftime("%Y-%m-%d")
            result["message"] = str(result["message"]) + f" Patch SLA: {sla_days} days (by {result['sla_deadline']})."
        return result

    @mcp.tool()
    async def list_cve_watchlist() -> dict:
        """List all CVEs on the SOC watchlist with their status, SLA, and notes.

        Returns CVE IDs, status (active/patched/monitoring), CVSS score,
        SLA deadline, days remaining, and notes.
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
        sla_breached = []
        for entry in items:
            key = entry.get("key", "")
            val = entry.get("value", "")
            if not _CVE_RE.match(key):
                continue
            parsed = _parse_entry(key, val)
            sla = _sla_status(parsed)
            parsed.update(sla)
            watchlist.append(parsed)
            if sla["sla_breached"] and parsed["status"] != "patched":
                sla_breached.append(key)

        by_status: dict[str, int] = {}
        for w in watchlist:
            by_status[w["status"]] = by_status.get(w["status"], 0) + 1

        return {
            "total": len(watchlist),
            "by_status": by_status,
            "sla_breached_count": len(sla_breached),
            "sla_breached_cves": sla_breached,
            "watchlist": watchlist,
        }

    @mcp.tool()
    async def mark_patched(cve_id: str, note: str = "") -> dict:
        """Mark a watched CVE as patched across the fleet.

        Updates the CVE's status in the watchlist from 'active'/'monitoring'
        to 'patched'. The entry is preserved for audit purposes. CVSS and SLA
        fields are preserved from the original entry.

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

        # Preserve existing CVSS + SLA + added_at fields
        try:
            resp = await wz.request("GET", f"/lists/files/{_CDB_LIST}?raw=true")
            items = (resp.get("data") or {}).get("affected_items") or []
            existing_entry = next((e for e in items if e.get("key") == cve_id), None)
        except Exception:
            existing_entry = None

        if existing_entry:
            parsed = _parse_entry(cve_id, existing_entry.get("value", ""))
            value = f"patched|{note}|{parsed['cvss_score']}|{parsed['sla_days']}|{parsed['added_at']}"
        else:
            value = f"patched|{note}|||"

        try:
            await wz.request(
                "PUT",
                f"/lists/files/{_CDB_LIST}",
                json={cve_id: value},
            )
        except Exception as exc:
            return {"error": f"Failed to update watchlist: {exc}"}

        patched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "cve_id": cve_id,
            "status": "patched",
            "note": note,
            "patched_at": patched_at,
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

    @mcp.tool()
    async def prioritize_cve_risk(top_n: int = 10) -> dict:
        """Rank active CVEs by composite risk score: CVSS × affected_agents.

        Higher score = patch first. CVEs without CVSS scores use a default of 5.0.
        Only 'active' and 'monitoring' CVEs are ranked (patched are excluded).

        top_n: number of top CVEs to return (default 10).
        """
        # Get watchlist
        try:
            resp = await wz.request("GET", f"/lists/files/{_CDB_LIST}?raw=true")
            items = (resp.get("data") or {}).get("affected_items") or []
        except Exception as exc:
            return {"error": f"Failed to read watchlist: {exc}"}

        active_entries = []
        for entry in items:
            key = entry.get("key", "")
            if not _CVE_RE.match(key):
                continue
            parsed = _parse_entry(key, entry.get("value", ""))
            if parsed["status"] in ("active", "monitoring"):
                active_entries.append(parsed)

        if not active_entries:
            return {"message": "No active CVEs in watchlist to prioritize.", "ranked": []}

        # Query affected agent counts for each CVE in parallel
        import asyncio as _asyncio

        async def _count_agents(cve_id: str) -> int:
            try:
                result = await idx.search(
                    index="wazuh-states-vulnerabilities-*",
                    body={
                        "query": {"bool": {"must": [{"term": {"vulnerability.id": cve_id}}]}},
                        "aggs": {"agents": {"cardinality": {"field": "agent.id"}}},
                        "size": 0,
                    },
                )
                return (result.get("aggregations") or {}).get("agents", {}).get("value", 0)
            except Exception:
                return 0

        counts = await _asyncio.gather(*[_count_agents(e["cve_id"]) for e in active_entries])

        ranked = []
        for entry, agent_count in zip(active_entries, counts):
            cvss = entry["cvss_score"] or 5.0  # default CVSS if unknown
            risk_score = round(cvss * max(agent_count, 1), 2)
            sla = _sla_status(entry)
            ranked.append({
                "cve_id": entry["cve_id"],
                "cvss_score": cvss,
                "affected_agents": agent_count,
                "risk_score": risk_score,
                "status": entry["status"],
                "note": entry["note"],
                **sla,
            })

        ranked.sort(key=lambda x: x["risk_score"], reverse=True)
        ranked = ranked[:top_n]

        return {
            "total_active_cves": len(active_entries),
            "ranked": ranked,
            "tip": (
                "Risk score = CVSS × affected_agents. "
                "Patch the highest-scored CVEs first. "
                "Add CVSS scores via add_cve_to_watchlist(cvss_score=...) for accurate ranking."
            ),
        }

    @mcp.tool()
    async def check_sla_breaches() -> dict:
        """List active CVEs that have breached their patch SLA deadline.

        Returns CVEs where the patch deadline has passed and status is not 'patched'.
        Use mark_patched() to resolve breaches or add_cve_to_watchlist() with
        a new sla_days to extend the deadline.
        """
        try:
            resp = await wz.request("GET", f"/lists/files/{_CDB_LIST}?raw=true")
            items = (resp.get("data") or {}).get("affected_items") or []
        except Exception as exc:
            return {"error": f"Failed to read watchlist: {exc}"}

        breached = []
        upcoming = []
        now = datetime.now(timezone.utc)

        for entry in items:
            key = entry.get("key", "")
            if not _CVE_RE.match(key):
                continue
            parsed = _parse_entry(key, entry.get("value", ""))
            if parsed["status"] == "patched":
                continue
            sla = _sla_status(parsed)
            if not sla["sla_deadline"]:
                continue

            record = {
                "cve_id": key,
                "status": parsed["status"],
                "cvss_score": parsed["cvss_score"],
                "note": parsed["note"],
                **sla,
            }
            if sla["sla_breached"]:
                breached.append(record)
            elif sla["days_remaining"] is not None and sla["days_remaining"] <= 7:
                upcoming.append(record)

        breached.sort(key=lambda x: x.get("days_remaining") or 0)
        upcoming.sort(key=lambda x: x.get("days_remaining") or 999)

        return {
            "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "breached_count": len(breached),
            "expiring_soon_count": len(upcoming),
            "breached": breached,
            "expiring_within_7_days": upcoming,
            "severity": (
                "critical" if breached else
                "high" if upcoming else
                "none"
            ),
        }
