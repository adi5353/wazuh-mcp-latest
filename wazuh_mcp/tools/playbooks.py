"""Automated playbook execution — F4.

Pre-defined YAML playbooks that chain multiple Wazuh MCP tools in sequence
with approval gates. Reduces MTTR and enforces consistent response procedures.

Tools: list_playbooks, run_playbook, get_playbook_status
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("wazuh-mcp")

_BUILTIN_PLAYBOOKS = [
    {
        "id": "isolate-compromised-host",
        "name": "Isolate Compromised Host",
        "description": "Gather forensic data from a suspected compromised agent.",
        "required_params": ["agent_id"],
        "severity": "critical",
        "steps": [
            {"name": "Get agent info", "tool": "get_agent", "params": {"agent_id": "{agent_id}"}},
            {"name": "List running processes", "tool": "get_agent_processes", "params": {"agent_id": "{agent_id}"}},
            {"name": "List open ports", "tool": "get_agent_open_ports", "params": {"agent_id": "{agent_id}"}},
            {"name": "Recent FIM changes", "tool": "get_recent_fim_changes", "params": {"agent_id": "{agent_id}"}},
            {"name": "Login history", "tool": "get_agent_login_history", "params": {"agent_id": "{agent_id}"}},
            {"name": "Health score", "tool": "get_agent_health_score", "params": {"agent_id": "{agent_id}"}},
        ],
        "approval_before_step": None,
    },
    {
        "id": "brute-force-response",
        "name": "Brute Force IP Response",
        "description": "Enrich a brute-forcing IP and block it via CDB list.",
        "required_params": ["ip"],
        "severity": "high",
        "steps": [
            {"name": "Enrich IP reputation", "tool": "enrich_ip", "params": {"ip": "{ip}"}},
            {"name": "Extended geo/ASN info", "tool": "enrich_ip_extended", "params": {"ip": "{ip}"}},
            {"name": "Search alerts by IP", "tool": "search_by_source_ip", "params": {"ip": "{ip}", "hours": 24}},
            {"name": "Add to blocklist", "tool": "add_to_cdb_list",
             "params": {"list_name": "malicious-ips", "key": "{ip}", "value": "brute-force"}},
        ],
        "approval_before_step": 3,
    },
    {
        "id": "cve-triage",
        "name": "CVE Triage Workflow",
        "description": "Find all agents affected by a CVE and prioritize patching.",
        "required_params": ["cve_id"],
        "severity": "high",
        "steps": [
            {"name": "Search CVE details", "tool": "search_cve", "params": {"cve_id": "{cve_id}"}},
            {"name": "Find affected agents", "tool": "get_watchlist_exposure", "params": {"cve_id": "{cve_id}"}},
            {"name": "Prioritize patches", "tool": "prioritize_patches", "params": {"agent_id": "000"}},
        ],
        "approval_before_step": None,
    },
    {
        "id": "incident-response",
        "name": "Full Incident Response",
        "description": "Create incident report and Slack notification for an alert.",
        "required_params": ["alert_id"],
        "severity": "high",
        "steps": [
            {"name": "Fetch alert", "tool": "get_alert_by_id", "params": {"alert_id": "{alert_id}"}},
            {"name": "Create incident report", "tool": "create_incident_report",
             "params": {"alert_id": "{alert_id}", "severity": "high"}},
            {"name": "Send Slack notification", "tool": "send_critical_alert_notify",
             "params": {"alert_id": "{alert_id}"}},
        ],
        "approval_before_step": None,
    },
]

from ..state_store import save_run, load_run, list_recent_runs

# In-memory cache — persisted to disk via state_store on every write
_RUN_HISTORY: dict[str, dict] = {}


def _resolve_params(params: dict, variables: dict) -> dict:
    resolved = {}
    for k, v in params.items():
        if isinstance(v, str):
            for var_name, var_val in variables.items():
                v = v.replace("{" + var_name + "}", str(var_val))
        resolved[k] = v
    return resolved


def _save(record: dict) -> None:
    _RUN_HISTORY[record["run_id"]] = record
    save_run(record["run_id"], record)


def _load(run_id: str) -> dict | None:
    if run_id in _RUN_HISTORY:
        return _RUN_HISTORY[run_id]
    return load_run(run_id)


def register(mcp, wz, idx, cfg, tool_registry: dict | None = None):

    def _get_playbook(playbook_id: str) -> dict | None:
        for pb in _BUILTIN_PLAYBOOKS:
            if pb["id"] == playbook_id:
                return pb
        pb_dir = getattr(cfg, "playbooks_dir", None) or "/app/playbooks"
        if os.path.isdir(pb_dir):
            try:
                import yaml  # type: ignore[import]
                for fname in os.listdir(pb_dir):
                    if fname.endswith((".yaml", ".yml")):
                        with open(os.path.join(pb_dir, fname)) as f:
                            data = yaml.safe_load(f)
                            if isinstance(data, dict) and data.get("id") == playbook_id:
                                return data
            except Exception:
                pass
        return None

    @mcp.tool()
    async def list_playbooks() -> dict:
        """List all available playbooks with descriptions and required parameters."""
        return {
            "playbooks": [
                {
                    "id": pb["id"],
                    "name": pb["name"],
                    "description": pb["description"],
                    "required_params": pb["required_params"],
                    "severity": pb["severity"],
                    "step_count": len(pb["steps"]),
                    "has_approval_gate": pb.get("approval_before_step") is not None,
                }
                for pb in _BUILTIN_PLAYBOOKS
            ],
            "total": len(_BUILTIN_PLAYBOOKS),
            "tip": "Run run_playbook(playbook_id, dry_run=True, **params) to preview steps.",
        }

    @mcp.tool()
    async def run_playbook(
        playbook_id: str,
        dry_run: bool = True,
        agent_id: str = "",
        ip: str = "",
        cve_id: str = "",
        alert_id: str = "",
    ) -> dict:
        """Execute a named playbook, chaining tool calls in sequence.

        dry_run=True (default): preview steps without executing.
        dry_run=False: run each step and collect results.
        Approval gates pause execution for human review.

        playbook_id: 'isolate-compromised-host', 'brute-force-response',
                     'cve-triage', or 'incident-response'
        """
        pb = _get_playbook(playbook_id)
        if pb is None:
            return {"error": f"Playbook '{playbook_id}' not found. Use list_playbooks()."}

        variables = {"agent_id": agent_id, "ip": ip, "cve_id": cve_id, "alert_id": alert_id}
        missing = [p for p in pb["required_params"] if not variables.get(p)]
        if missing:
            return {"error": f"Missing required parameters: {missing}",
                    "required_params": pb["required_params"]}

        if dry_run:
            run_id = str(uuid.uuid4())[:8]
            preview = {
                "run_id": run_id,
                "playbook": playbook_id,
                "name": pb["name"],
                "status": "dry_run_preview",
                "dry_run": True,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "variables": variables,
                "steps": [
                    {
                        "step": i + 1,
                        "name": step["name"],
                        "tool": step["tool"],
                        "params": _resolve_params(step["params"], variables),
                        "approval_gate": (pb.get("approval_before_step") == i),
                        "status": "preview",
                    }
                    for i, step in enumerate(pb["steps"])
                ],
                "message": (
                    "Dry run only — no actions taken. "
                    "Set dry_run=False to execute with real tool chaining."
                ),
            }
            _save(preview)
            return preview

        run_id = str(uuid.uuid4())[:8]
        run_record: dict[str, Any] = {
            "run_id": run_id,
            "playbook": playbook_id,
            "name": pb["name"],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "variables": variables,
            "status": "running",
            "steps": [],
        }
        _save(run_record)

        approval_gate = pb.get("approval_before_step")
        registry = tool_registry or {}

        for i, step in enumerate(pb["steps"]):
            if approval_gate is not None and i == approval_gate:
                run_record["status"] = "awaiting_approval"
                run_record["paused_at_step"] = i
                run_record["message"] = (
                    f"Paused at step {i+1} '{step['name']}' (approval gate). "
                    "Review results above then call resume_playbook(run_id, approved=True) to continue."
                )
                _save(run_record)
                return run_record

            resolved = _resolve_params(step["params"], variables)
            step_result: dict[str, Any] = {
                "step": i + 1,
                "name": step["name"],
                "tool": step["tool"],
                "params": resolved,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }

            fn = registry.get(step["tool"])
            if fn is None:
                step_result["status"] = "skipped"
                step_result["note"] = f"Tool '{step['tool']}' not in registry — call manually."
            else:
                try:
                    output = await asyncio.wait_for(fn(**resolved), timeout=30)
                    step_result["status"] = "completed"
                    step_result["output"] = output
                    # Stop playbook if a step returns an error to prevent destructive follow-on steps
                    if isinstance(output, dict) and "error" in output:
                        step_result["status"] = "failed"
                        run_record["steps"].append(step_result)
                        run_record["status"] = "failed"
                        run_record["failed_at_step"] = i + 1
                        run_record["error"] = output["error"]
                        _save(run_record)
                        return run_record
                except asyncio.TimeoutError:
                    step_result["status"] = "timeout"
                    step_result["error"] = f"Tool '{step['tool']}' timed out after 30s"
                    run_record["steps"].append(step_result)
                    run_record["status"] = "failed"
                    run_record["failed_at_step"] = i + 1
                    _save(run_record)
                    return run_record
                except Exception as exc:
                    step_result["status"] = "failed"
                    step_result["error"] = str(exc)
                    run_record["steps"].append(step_result)
                    run_record["status"] = "failed"
                    run_record["failed_at_step"] = i + 1
                    _save(run_record)
                    return run_record

            run_record["steps"].append(step_result)

        if run_record["status"] == "running":
            run_record["status"] = "completed"
            run_record["completed_at"] = datetime.now(timezone.utc).isoformat()

        _save(run_record)
        return run_record

    @mcp.tool()
    async def get_playbook_status(run_id: str) -> dict:
        """Get current status and step results for a playbook run.

        run_id: returned by run_playbook (both dry_run=True and dry_run=False).
        Dry-run records have status='dry_run_preview'.
        """
        record = _load(run_id)
        if not record:
            recent = list_recent_runs(5)
            return {
                "error": f"Run ID '{run_id}' not found.",
                "recent_runs": recent,
            }
        return record

    @mcp.tool()
    async def resume_playbook(run_id: str, approved: bool = False) -> dict:
        """Resume a playbook that is paused at an approval gate.

        run_id: the run ID from run_playbook.
        approved=True: continue execution past the gate.
        approved=False: abort the playbook.
        """
        record = _load(run_id)
        if not record:
            return {"error": f"Run ID '{run_id}' not found."}
        if record.get("status") != "awaiting_approval":
            return {
                "error": f"Playbook '{run_id}' is not awaiting approval.",
                "current_status": record.get("status"),
            }
        if not approved:
            record["status"] = "aborted"
            record["aborted_at"] = datetime.now(timezone.utc).isoformat()
            _save(record)
            return {"status": "aborted", "run_id": run_id}

        pb = _get_playbook(record["playbook"])
        if pb is None:
            return {"error": f"Playbook definition for '{record['playbook']}' not found."}

        registry = tool_registry or {}
        paused_at = record.get("paused_at_step", len(record["steps"]))
        variables = record.get("variables", {})
        record["status"] = "running"
        record.pop("message", None)
        record.pop("paused_at_step", None)

        for i, step in enumerate(pb["steps"]):
            if i <= paused_at - 1:
                continue  # already completed
            resolved = _resolve_params(step["params"], variables)
            step_result: dict[str, Any] = {
                "step": i + 1,
                "name": step["name"],
                "tool": step["tool"],
                "params": resolved,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
            fn = registry.get(step["tool"])
            if fn is None:
                step_result["status"] = "skipped"
                step_result["note"] = f"Tool '{step['tool']}' not in registry."
            else:
                try:
                    output = await asyncio.wait_for(fn(**resolved), timeout=30)
                    step_result["status"] = "completed"
                    step_result["output"] = output
                    if isinstance(output, dict) and "error" in output:
                        step_result["status"] = "failed"
                        record["steps"].append(step_result)
                        record["status"] = "failed"
                        record["error"] = output["error"]
                        _save(record)
                        return record
                except Exception as exc:
                    step_result["status"] = "failed"
                    step_result["error"] = str(exc)
                    record["steps"].append(step_result)
                    record["status"] = "failed"
                    _save(record)
                    return record
            record["steps"].append(step_result)

        record["status"] = "completed"
        record["completed_at"] = datetime.now(timezone.utc).isoformat()
        _save(record)
        return record
