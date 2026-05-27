"""Azure DevOps integration tools.

Create and update work items in Azure Boards from Wazuh security findings.

Configuration:
    AZURE_DEVOPS_ORG      — organisation name (e.g. 'myorg')
    AZURE_DEVOPS_PROJECT  — project name (e.g. 'Security')
    AZURE_DEVOPS_TOKEN    — Personal Access Token with Work Items (Read & Write) scope
"""
from __future__ import annotations
from ..tool_context import ToolContext

import os
import base64


def _headers() -> tuple[dict | None, str | None]:
    token = os.getenv("AZURE_DEVOPS_TOKEN", "")
    if not token:
        return None, "AZURE_DEVOPS_TOKEN not configured."
    encoded = base64.b64encode(f":{token}".encode()).decode()
    return {
        "Authorization": f"Basic {encoded}",
        "Content-Type": "application/json-patch+json",
    }, None


def _base_url() -> str:
    org = os.getenv("AZURE_DEVOPS_ORG", "")
    project = os.getenv("AZURE_DEVOPS_PROJECT", "")
    return f"https://dev.azure.com/{org}/{project}/_apis"


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _truncate = ctx.truncate

    @mcp.tool()
    async def create_azure_devops_work_item(
        title: str,
        description: str,
        work_item_type: str = "Bug",
        priority: int = 2,
        tags: str | None = None,
        area_path: str | None = None,
    ) -> dict:
        """Create an Azure DevOps work item from a Wazuh security finding.

        Args:
            title: Work item title.
            description: Detailed description (HTML supported).
            work_item_type: 'Bug', 'Task', 'Issue', or custom type.
            priority: 1 (Critical) to 4 (Low).
            tags: Semicolon-separated tags (e.g. 'security;wazuh').
            area_path: Optional area path override.
        """
        import httpx
        headers, err = _headers()
        if err:
            return {"error": err}
        if not os.getenv("AZURE_DEVOPS_ORG") or not os.getenv("AZURE_DEVOPS_PROJECT"):
            return {"error": "AZURE_DEVOPS_ORG and AZURE_DEVOPS_PROJECT must be set."}

        patch_doc = [
            {"op": "add", "path": "/fields/System.Title", "value": title[:255]},
            {"op": "add", "path": "/fields/System.Description", "value": description[:32000]},
            {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Priority", "value": priority},
        ]
        if tags:
            patch_doc.append({"op": "add", "path": "/fields/System.Tags", "value": tags})
        if area_path:
            patch_doc.append({"op": "add", "path": "/fields/System.AreaPath", "value": area_path})

        url = f"{_base_url()}/wit/workitems/${work_item_type}?api-version=7.1"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(url, json=patch_doc, headers=headers)
                r.raise_for_status()
                data = r.json()
                fields = data.get("fields", {})
                return {
                    "created": True,
                    "id": data.get("id"),
                    "url": data.get("_links", {}).get("html", {}).get("href"),
                    "title": fields.get("System.Title"),
                    "state": fields.get("System.State"),
                    "type": fields.get("System.WorkItemType"),
                }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_azure_devops_work_item(work_item_id: int) -> dict:
        """Retrieve an Azure DevOps work item by ID."""
        import httpx
        headers, err = _headers()
        if err:
            return {"error": err}

        url = f"{_base_url()}/wit/workitems/{work_item_id}?api-version=7.1"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()
                fields = data.get("fields", {})
                return {
                    "id": data.get("id"),
                    "title": fields.get("System.Title"),
                    "state": fields.get("System.State"),
                    "type": fields.get("System.WorkItemType"),
                    "priority": fields.get("Microsoft.VSTS.Common.Priority"),
                    "assigned_to": (fields.get("System.AssignedTo") or {}).get("displayName"),
                    "created": fields.get("System.CreatedDate"),
                    "changed": fields.get("System.ChangedDate"),
                }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def update_azure_devops_work_item(
        work_item_id: int,
        state: str | None = None,
        comment: str | None = None,
    ) -> dict:
        """Update state or add a comment to an Azure DevOps work item.

        Args:
            work_item_id: Numeric work item ID.
            state: New state (e.g. 'Active', 'Resolved', 'Closed').
            comment: Comment text to append to the discussion.
        """
        import httpx
        headers, err = _headers()
        if err:
            return {"error": err}

        patch_doc = []
        if state:
            patch_doc.append({"op": "add", "path": "/fields/System.State", "value": state})
        if comment:
            patch_doc.append({"op": "add", "path": "/fields/System.History", "value": comment})

        if not patch_doc:
            return {"error": "No update fields provided."}

        url = f"{_base_url()}/wit/workitems/{work_item_id}?api-version=7.1"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.patch(url, json=patch_doc, headers=headers)
                r.raise_for_status()
                data = r.json()
                return {
                    "updated": True,
                    "id": data.get("id"),
                    "state": (data.get("fields") or {}).get("System.State"),
                }
        except Exception as e:
            return {"error": str(e)}
