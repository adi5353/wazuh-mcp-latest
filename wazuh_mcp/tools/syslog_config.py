"""Syslog output configuration management tools.

Read and test syslog output destinations configured in ossec.conf.
"""
from __future__ import annotations

import asyncio


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

        Uses non-blocking async I/O — safe to call from within the MCP event loop.

        Args:
            server: Hostname or IP of the syslog destination.
            port: UDP/TCP port (default 514).
        """
        results: dict = {"server": server, "port": port}

        # ── TCP probe (async, non-blocking) ──────────────────────────────────
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(server, port), timeout=3.0
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            results["tcp"] = "reachable"
        except asyncio.TimeoutError:
            results["tcp"] = "unreachable (timeout)"
        except OSError as e:
            results["tcp"] = f"unreachable ({e})"

        # ── UDP probe (best-effort via executor — sendto is synchronous) ──────
        def _udp_probe():
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b"<14>wazuh-mcp syslog test", (server, port))
                sock.close()
                return "sent"
            except OSError as e:
                return f"error ({e})"

        loop = asyncio.get_event_loop()
        results["udp"] = await loop.run_in_executor(None, _udp_probe)
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
