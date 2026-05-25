"""Wazuh Manager configuration management tools.

Reads ossec.conf sections via the Manager REST API.
"""
from __future__ import annotations

_COMMON_SECTIONS = [
    "global", "alerts", "logging", "remote", "rootcheck", "syscheck",
    "active-response", "command", "email_notification", "syslog_output",
    "integration", "cluster", "vulnerability-detection", "indexer",
]


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def list_manager_config_sections() -> dict:
        """List all available ossec.conf configuration sections."""
        return {
            "known_sections": _COMMON_SECTIONS,
            "note": "Use get_manager_config_section(section) to read a specific section.",
        }

    @mcp.tool()
    async def get_manager_config_section(section: str) -> dict:
        """Read a specific ossec.conf section from the Wazuh Manager.

        Examples: 'global', 'alerts', 'syscheck', 'remote', 'active-response'.
        """
        if section not in _COMMON_SECTIONS:
            return {
                "warning": f"'{section}' is not a recognised section name.",
                "known_sections": _COMMON_SECTIONS,
            }
        try:
            result = await wz.request(
                "GET", f"/manager/configuration?section={section}"
            )
            return result
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_manager_status() -> dict:
        """Get the running status of all Wazuh Manager daemons.

        Returns health of: analysisd, remoted, logcollector, modulesd,
        integratord, monitord, clusterd, and others.
        """
        try:
            result = await wz.request("GET", "/manager/status")
            return result
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_manager_info() -> dict:
        """Get Wazuh Manager version, compilation info, and runtime details."""
        try:
            result = await wz.request("GET", "/manager/info")
            return result
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def get_manager_logs(
        level: str = "error",
        tag: str | None = None,
        limit: int = 50,
    ) -> dict:
        """Retrieve recent Manager log entries filtered by level and optional tag.

        Args:
            level: Log level filter — 'error', 'warning', 'info', 'debug'.
            tag: Optional daemon tag filter (e.g. 'wazuh-analysisd').
            limit: Maximum entries to return (max 500).
        """
        path = f"/manager/logs?limit={_cap(limit)}&level={level}"
        if tag:
            path += f"&tag={tag}"
        try:
            result = await wz.request("GET", path)
            return result
        except Exception as e:
            return {"error": str(e)}
