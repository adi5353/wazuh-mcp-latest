"""Persistent state store for playbook runs and autonomous monitor state (Gap 2).

Uses JSON files in WAZUH_WORKSPACE_DIR (same dir as workspaces) — no extra deps.
Each playbook run is stored as runs/{run_id}.json.
Monitor state is stored as monitor_state.json.

Upgrade path: swap _read/_write for aiosqlite calls when query needs arise.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any  # noqa: F401 – re-exported for kv helpers

log = logging.getLogger("wazuh-mcp")


def _state_dir() -> Path:
    base = Path(os.getenv("WAZUH_WORKSPACE_DIR", "/app/workspaces"))
    d = base / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _runs_dir() -> Path:
    d = _state_dir() / "runs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_id(run_id: str) -> str:
    return "".join(c for c in run_id if c.isalnum() or c == "-")


# ── Playbook run persistence ──────────────────────────────────────────────────

def save_run(run_id: str, data: dict) -> None:
    p = _runs_dir() / f"{_safe_id(run_id)}.json"
    try:
        p.write_text(json.dumps(data, indent=2, default=str))
    except Exception as exc:
        log.warning("state_store: failed to save run %s: %s", run_id, exc)


def load_run(run_id: str) -> dict | None:
    p = _runs_dir() / f"{_safe_id(run_id)}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception as exc:
        log.warning("state_store: failed to load run %s: %s", run_id, exc)
        return None


def list_recent_runs(n: int = 20) -> list[dict]:
    try:
        files = sorted(_runs_dir().glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
        result = []
        for f in files[:n]:
            try:
                data = json.loads(f.read_text())
                result.append({
                    "run_id": data.get("run_id", f.stem),
                    "playbook": data.get("playbook", ""),
                    "status": data.get("status", ""),
                    "started_at": data.get("started_at", ""),
                })
            except Exception:
                pass
        return result
    except Exception:
        return []


# ── Autonomous monitor state persistence ──────────────────────────────────────

def _monitor_state_path() -> Path:
    return _state_dir() / "monitor_state.json"


def save_monitor_state(state: dict) -> None:
    p = _monitor_state_path()
    try:
        serializable = {k: v for k, v in state.items() if k != "task"}
        serializable["saved_at"] = datetime.now(timezone.utc).isoformat()
        p.write_text(json.dumps(serializable, indent=2, default=str))
    except Exception as exc:
        log.warning("state_store: failed to save monitor state: %s", exc)


def load_monitor_state() -> dict | None:
    p = _monitor_state_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception as exc:
        log.warning("state_store: failed to load monitor state: %s", exc)
        return None


def clear_monitor_state() -> None:
    p = _monitor_state_path()
    try:
        if p.exists():
            p.unlink()
    except Exception:
        pass


# ── Generic key-value persistence ─────────────────────────────────────────────

def _kv_dir() -> Path:
    d = _state_dir() / "kv"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_key(key: str) -> str:
    """Sanitize an arbitrary key to a safe filename (alphanumeric + dash/underscore)."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in key)


def save_kv(key: str, data: Any) -> None:
    """Persist an arbitrary JSON-serialisable value under the given key.

    Survives server restarts. Used by compliance_drift for baselines and
    rule_wizard for pre-push rule backups.
    """
    p = _kv_dir() / f"{_safe_key(key)}.json"
    try:
        p.write_text(json.dumps(data, indent=2, default=str))
    except Exception as exc:
        log.warning("state_store: failed to save kv '%s': %s", key, exc)


def load_kv(key: str) -> Any | None:
    """Load a previously saved key-value entry.  Returns None if not found."""
    p = _kv_dir() / f"{_safe_key(key)}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception as exc:
        log.warning("state_store: failed to load kv '%s': %s", key, exc)
        return None


def delete_kv(key: str) -> bool:
    """Delete a stored key-value entry. Returns True if it existed."""
    p = _kv_dir() / f"{_safe_key(key)}.json"
    try:
        if p.exists():
            p.unlink()
            return True
    except Exception:
        pass
    return False


def list_kv(prefix: str = "") -> list[str]:
    """Return all stored key names, optionally filtered by prefix.

    The returned names are the original logical key names (without the .json
    suffix) sorted alphabetically.  Use this instead of globbing _kv_dir()
    directly — it keeps callers decoupled from the storage layout.

    Examples:
        list_kv()                        # all keys
        list_kv("agent_baseline_")       # all per-agent baselines
        list_kv("compliance_baseline_")  # all compliance drift baselines
        list_kv("rule_backup_")          # all rule pre-push backups
    """
    safe_prefix = _safe_key(prefix) if prefix else ""
    try:
        pattern = f"{safe_prefix}*.json" if safe_prefix else "*.json"
        return sorted(
            f.stem  # filename without .json == the safe key name
            for f in _kv_dir().glob(pattern)
            if f.is_file()
        )
    except Exception:
        return []
