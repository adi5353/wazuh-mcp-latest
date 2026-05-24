"""F12: Investigation Workspaces.

Named investigation sessions that persist context across Claude conversations.
Stored as JSON files on the server disk (path configurable via WAZUH_WORKSPACE_DIR).

Each workspace holds:
  - metadata (name, analyst, created_at, updated_at)
  - items: list of typed evidence entries (note, alert_id, agent_id, artifact, timeline)

Tools:
    create_workspace    — start a new named investigation workspace
    add_to_workspace    — add a note, alert ID, or artifact to a workspace
    get_workspace       — retrieve workspace contents
    export_workspace    — export workspace as JSON or Markdown
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path


def _workspace_dir() -> Path:
    d = Path(os.getenv("WAZUH_WORKSPACE_DIR", "/app/workspaces"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ws_path(workspace_id: str) -> Path:
    # Sanitise ID to prevent path traversal
    safe_id = "".join(c for c in workspace_id if c.isalnum() or c == "-")
    return _workspace_dir() / f"{safe_id}.json"


def _load_ws(workspace_id: str) -> dict | None:
    p = _ws_path(workspace_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _save_ws(ws: dict) -> None:
    p = _ws_path(ws["workspace_id"])
    p.write_text(json.dumps(ws, indent=2))


_VALID_TYPES = {"note", "alert_id", "agent_id", "artifact", "timeline", "cve", "ip"}


def register(mcp, cfg):
    from ..validators import safe_validate, validate_free_text

    @mcp.tool()
    async def create_workspace(name: str, analyst: str = "") -> dict:
        """Create a new investigation workspace.

        name:    Short descriptive name for the investigation (e.g. "Ransomware 2025-05").
        analyst: Optional analyst identifier for the workspace header.

        Returns a workspace_id to use in subsequent add_to_workspace calls.
        The workspace persists on disk at WAZUH_WORKSPACE_DIR (default /app/workspaces).
        """
        if not name or not name.strip():
            return {"error": "name must not be empty."}
        _, err = safe_validate(validate_free_text, name, "name", max_len=200)
        if err:
            return err

        ws_id = str(uuid.uuid4())[:8]
        ws = {
            "workspace_id": ws_id,
            "name": name.strip(),
            "analyst": analyst.strip(),
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "items": [],
        }
        _save_ws(ws)

        return {
            "workspace_id": ws_id,
            "name": ws["name"],
            "created_at": ws["created_at"],
            "message": (
                f"Workspace '{name}' created (ID: {ws_id}). "
                "Use add_to_workspace to add notes, alert IDs, and artifacts."
            ),
        }

    @mcp.tool()
    async def add_to_workspace(
        workspace_id: str,
        item_type: str,
        content: str,
        label: str = "",
    ) -> dict:
        """Add an evidence item to an investigation workspace.

        workspace_id: Workspace ID returned by create_workspace.
        item_type:    One of: note, alert_id, agent_id, artifact, timeline, cve, ip.
        content:      The evidence content (note text, alert ID, agent ID, etc.).
        label:        Optional short label for the item (e.g. "Initial access vector").
        """
        ws = _load_ws(workspace_id)
        if ws is None:
            return {"error": f"Workspace '{workspace_id}' not found."}

        if item_type not in _VALID_TYPES:
            return {
                "error": f"item_type must be one of: {', '.join(sorted(_VALID_TYPES))}",
            }
        if not content or not content.strip():
            return {"error": "content must not be empty."}
        _, err = safe_validate(validate_free_text, content, "content", max_len=5000)
        if err:
            return err

        item = {
            "type": item_type,
            "content": content.strip(),
            "label": label.strip(),
            "added_at": int(time.time()),
        }
        ws["items"].append(item)
        ws["updated_at"] = int(time.time())
        _save_ws(ws)

        return {
            "added": True,
            "workspace_id": workspace_id,
            "item_type": item_type,
            "total_items": len(ws["items"]),
        }

    @mcp.tool()
    async def get_workspace(workspace_id: str) -> dict:
        """Retrieve the full contents of an investigation workspace.

        workspace_id: Workspace ID to retrieve.

        Returns all stored items with their types, content, and timestamps.
        """
        ws = _load_ws(workspace_id)
        if ws is None:
            return {"error": f"Workspace '{workspace_id}' not found."}

        return {
            "workspace_id": ws["workspace_id"],
            "name": ws["name"],
            "analyst": ws.get("analyst", ""),
            "created_at": ws["created_at"],
            "updated_at": ws["updated_at"],
            "item_count": len(ws["items"]),
            "items": ws["items"],
        }

    @mcp.tool()
    async def export_workspace(workspace_id: str, fmt: str = "json") -> dict:
        """Export an investigation workspace as JSON or Markdown.

        workspace_id: Workspace ID to export.
        fmt:          Export format — "json" (default) or "markdown".

        The export can be saved to a file or included in an incident report.
        """
        ws = _load_ws(workspace_id)
        if ws is None:
            return {"error": f"Workspace '{workspace_id}' not found."}

        if fmt == "json":
            return {
                "format": "json",
                "workspace_id": workspace_id,
                "export": json.dumps(ws, indent=2),
            }

        if fmt == "markdown":
            lines = [
                f"# Investigation Workspace: {ws['name']}",
                f"**ID:** {ws['workspace_id']}  ",
                f"**Analyst:** {ws.get('analyst') or 'N/A'}  ",
                f"**Created:** {_fmt_ts(ws['created_at'])}  ",
                f"**Last Updated:** {_fmt_ts(ws['updated_at'])}  ",
                "",
                f"## Evidence Items ({len(ws['items'])})",
                "",
            ]
            for i, item in enumerate(ws["items"], 1):
                label = f" — {item['label']}" if item.get("label") else ""
                lines.append(f"### {i}. [{item['type'].upper()}]{label}")
                lines.append(f"*Added: {_fmt_ts(item['added_at'])}*")
                lines.append("")
                lines.append(item["content"])
                lines.append("")
            return {
                "format": "markdown",
                "workspace_id": workspace_id,
                "export": "\n".join(lines),
            }

        return {"error": f"Unknown format '{fmt}'. Use 'json' or 'markdown'."}


def _fmt_ts(ts: int) -> str:
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC")
