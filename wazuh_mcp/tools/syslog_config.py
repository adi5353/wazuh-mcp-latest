"""Syslog output configuration management tools.

Read and test syslog output destinations configured in ossec.conf.
"""
from __future__ import annotations
import socket


def register(mcp, wz, idx, cfg, _cap, _truncate):

    @mcp.tool()
    async def list_syslog_outputs() -> dict:
        """List configured syslog_output destinations from ossec.conf."""
        try:
            result = await wz.request(
                "GET", "/manager/configuration?section=syslog_output"
            )
            section = (result.get("data") or {}).get("affected_items", [{}])
            config = section[0].get("syslog_output", []) if section else []
            if isinstance(config, dict):
                config = [config]
            return {
                "syslog_outputs": [
                    {
                        "server": entry.get("server"),
                        "port": entry.get("port", 514),
                        "format": entry.get("format", "default"),
                        "level": entry.get("level"),
                    }
                    for entry in config
                ],
                "total": len(config),
            }
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def test_syslog_connection(server: str, port: int = 514) -> dict:
        """Test TCP/UDP reachability to a syslog server.

        Args:
            server: Hostname or IP of the syslog destination.
            port: UDP/TCP port (default 514).
        """
        results: dict = {"server": server, "port": port}
        try:
            sock = socket.create_connection((server, port), timeout=3)
            sock.close()
            results["tcp"] = "reachable"
        except OSError as e:
            results["tcp"] = f"unreachable ({e})"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b"<14>test", (server, port))
            sock.close()
            results["udp"] = "sent"
        except OSError as e:
            results["udp"] = f"error ({e})"
        return results

    @mcp.tool()
    async def get_syslog_config_section() -> dict:
        """Return the full syslog_output section from the Manager configuration."""
        try:
            return await wz.request(
                "GET", "/manager/configuration?section=syslog_output"
            )
        except Exception as e:
            return {"error": str(e)}
