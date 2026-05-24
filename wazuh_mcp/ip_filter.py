"""IP allowlist / blocklist ASGI middleware.

Reads comma-separated CIDR lists from environment variables and rejects
connections from untrusted IP addresses before authentication or processing.

Environment variables:
    WAZUH_MCP_ALLOWED_IPS  — comma-separated CIDRs (e.g. "10.0.0.0/8,192.168.1.0/24")
                             If set, ONLY these IPs are allowed. Empty = allow all.
    WAZUH_MCP_BLOCKED_IPS  — comma-separated CIDRs. Evaluated after allowlist. Empty = block none.

Usage in server.py::

    from .ip_filter import IPFilterMiddleware
    app = IPFilterMiddleware(app)
"""
from __future__ import annotations

import ipaddress
import json
import os
from typing import Union

_IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _parse_cidr_list(env_var: str) -> list[_IPNetwork]:
    raw = os.getenv(env_var, "").strip()
    if not raw:
        return []
    networks: list[_IPNetwork] = []
    for cidr in raw.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass  # skip malformed entries silently
    return networks


def _matches_any(addr: str, networks: list[_IPNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in networks)
    except ValueError:
        return False


def _client_ip(scope: dict) -> str:
    client = scope.get("client")
    return client[0] if client else "unknown"


class IPFilterMiddleware:
    """Pure ASGI middleware — runs before auth, rate limiting, and body reading."""

    def __init__(self, app) -> None:
        self._app = app
        self._allowed = _parse_cidr_list("WAZUH_MCP_ALLOWED_IPS")
        self._blocked = _parse_cidr_list("WAZUH_MCP_BLOCKED_IPS")

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        ip = _client_ip(scope)

        if self._blocked and _matches_any(ip, self._blocked):
            await self._deny(send)
            return

        if self._allowed and not _matches_any(ip, self._allowed):
            await self._deny(send)
            return

        await self._app(scope, receive, send)

    @staticmethod
    async def _deny(send) -> None:
        body = json.dumps({"error": "Access denied"}).encode()
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body, "more_body": False})
