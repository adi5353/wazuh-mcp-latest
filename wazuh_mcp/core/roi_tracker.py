"""ROI tracker — measures time saved per session vs. manual analyst baseline.

Tracks per-session tool calls, durations, and produces ROI reports that can
be used in sales conversations ("This week Claude saved 14 analyst hours").

Design: in-process singleton. State is kept in memory and periodically flushed
to a JSON file next to the audit log so it survives server restarts.
"""
from __future__ import annotations

import json
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Baseline analyst time-per-task (minutes) ─────────────────────────────────
# Conservative estimates from published SOC efficiency studies.
BASELINE_MINUTES: dict[str, float] = {
    # Alert triage / investigation
    "get_alert_by_id":                 2.0,
    "search_alerts":                   4.0,
    "alert_summary":                   5.0,
    "explain_alert":                   3.0,
    "explain_recent_alerts":           4.0,
    "triage_alert":                    8.0,
    # Threat intel enrichment
    "enrich_ip":                       5.0,
    "enrich_ip_extended":              6.0,
    "enrich_file_hash":                4.0,
    "enrich_ip_geo":                   2.0,
    "classify_ip_infrastructure":      3.0,
    # Threat hunting
    "hunt_lateral_movement":          20.0,
    "hunt_persistence_mechanisms":    20.0,
    "hunt_data_exfiltration":         15.0,
    "search_authentication_failures":  8.0,
    # Vulnerability management
    "vulnerability_summary":           10.0,
    "get_agent_vulnerabilities_detailed": 8.0,
    "prioritize_patches":              15.0,
    "search_cve":                       5.0,
    # Compliance
    "compliance_summary":             20.0,
    "compliance_control_details":     25.0,
    "generate_compliance_report":     45.0,
    "export_compliance_csv":          10.0,
    # Incident management
    "create_incident_report":         20.0,
    "incident_timeline":              15.0,
    "blast_radius_analysis":          15.0,
    # Reporting
    "generate_weekly_summary":        60.0,
    "generate_shift_handover":        30.0,
    # Fleet & agent ops
    "fleet_find_package":             10.0,
    "fleet_find_process":             10.0,
    "fleet_find_listening_port":      10.0,
    "fleet_batch_syscollector":       15.0,
    "get_agent_vulnerabilities_detailed": 8.0,
    # MITRE
    "mitre_coverage_analysis":        30.0,
    "get_mitre_gaps":                  20.0,
    # Default for anything not listed
    "__default__":                      5.0,
}

_STATE_PATH = Path("/tmp/wazuh_mcp_roi.json")
_lock = threading.Lock()

_state: dict[str, Any] = {
    "sessions": [],           # list of completed session dicts
    "current_session": None,  # active session dict or None
    "total_calls": 0,
    "total_saved_minutes": 0.0,
    "total_actual_seconds": 0.0,
    "started_at": datetime.now(timezone.utc).isoformat(),
}


def _load() -> None:
    global _state
    if _STATE_PATH.exists():
        try:
            loaded = json.loads(_STATE_PATH.read_text())
            _state.update(loaded)
        except Exception:
            pass


def _save() -> None:
    try:
        _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        serialisable = {
            k: v for k, v in _state.items() if k != "current_session"
        }
        serialisable["current_session"] = None  # don't persist mid-session state
        _STATE_PATH.write_text(json.dumps(serialisable, default=str))
    except Exception:
        pass


_load()


def session_start(session_id: str) -> None:
    with _lock:
        _state["current_session"] = {
            "session_id": session_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "calls": [],
            "saved_minutes": 0.0,
            "actual_seconds": 0.0,
        }


def record_call(tool_name: str, duration_seconds: float) -> None:
    baseline = BASELINE_MINUTES.get(tool_name, BASELINE_MINUTES["__default__"])
    saved = baseline - (duration_seconds / 60)
    saved = max(saved, 0.0)  # floor at 0 — we don't penalise fast baseline

    with _lock:
        entry = {
            "tool": tool_name,
            "duration_s": round(duration_seconds, 2),
            "baseline_min": baseline,
            "saved_min": round(saved, 2),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        _state["total_calls"] += 1
        _state["total_saved_minutes"] += saved
        _state["total_actual_seconds"] += duration_seconds

        sess = _state.get("current_session")
        if sess:
            sess["calls"].append(entry)
            sess["saved_minutes"] = round(sess["saved_minutes"] + saved, 2)
            sess["actual_seconds"] = round(sess["actual_seconds"] + duration_seconds, 2)

    # Periodic save (every 10 calls)
    if _state["total_calls"] % 10 == 0:
        _save()


def session_end() -> dict | None:
    with _lock:
        sess = _state.get("current_session")
        if not sess:
            return None
        sess["ended_at"] = datetime.now(timezone.utc).isoformat()
        sess["call_count"] = len(sess["calls"])
        _state["sessions"].append(sess)
        if len(_state["sessions"]) > 200:
            _state["sessions"] = _state["sessions"][-200:]
        _state["current_session"] = None
    _save()
    return sess


def get_roi_summary(days: int = 7) -> dict:
    """Return aggregated ROI metrics for the last N days."""
    cutoff_ts = datetime.now(timezone.utc).timestamp() - (days * 86400)

    with _lock:
        recent = [
            s for s in _state["sessions"]
            if _ts_to_epoch(s.get("started_at", "")) >= cutoff_ts
        ]

    total_sessions = len(recent)
    total_calls = sum(s.get("call_count", len(s.get("calls", []))) for s in recent)
    saved_minutes = sum(s.get("saved_minutes", 0.0) for s in recent)
    actual_seconds = sum(s.get("actual_seconds", 0.0) for s in recent)

    # Tool-level breakdown
    tool_counts: dict[str, int] = {}
    tool_saved: dict[str, float] = {}
    for sess in recent:
        for call in sess.get("calls", []):
            t = call["tool"]
            tool_counts[t] = tool_counts.get(t, 0) + 1
            tool_saved[t] = tool_saved.get(t, 0.0) + call.get("saved_min", 0.0)

    top_tools = sorted(tool_counts.items(), key=lambda x: -x[1])[:10]

    return {
        "period_days": days,
        "sessions": total_sessions,
        "tool_calls": total_calls,
        "time_saved_minutes": round(saved_minutes, 1),
        "time_saved_hours": round(saved_minutes / 60, 1),
        "actual_time_seconds": round(actual_seconds, 1),
        "efficiency_ratio": (
            round(saved_minutes * 60 / actual_seconds, 1)
            if actual_seconds > 0 else 0.0
        ),
        "analyst_hours_equivalent": round(saved_minutes / 60, 1),
        "top_tools": [
            {
                "tool": t,
                "calls": c,
                "saved_minutes": round(tool_saved.get(t, 0.0), 1),
            }
            for t, c in top_tools
        ],
        "lifetime_calls": _state["total_calls"],
        "lifetime_saved_minutes": round(_state["total_saved_minutes"], 1),
    }


def _ts_to_epoch(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0
