"""In-process sliding-window rate limiter for the MCP HTTP endpoint.

Tracks requests per identity token (SHA-256 fingerprint of the
Authorization header) within a rolling 60-second window.

Configuration (env vars):
    WAZUH_MCP_RATE_LIMIT_RPM   — max requests per minute per identity (default 60)
    WAZUH_MCP_RATE_LIMIT_BURST — burst allowance above RPM before throttling (default 10)

When the limit is exceeded the middleware returns HTTP 429 with a
Retry-After header indicating when the window resets.

Usage in server.py::

    from .rate_limit import RateLimitMiddleware
    app = RateLimitMiddleware(app)
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import time
from typing import Deque


def _rpm() -> int:
    return int(os.getenv("WAZUH_MCP_RATE_LIMIT_RPM", "60"))


def _burst() -> int:
    return int(os.getenv("WAZUH_MCP_RATE_LIMIT_BURST", "10"))


def _writes_rpm() -> int:
    return int(os.getenv("WAZUH_MCP_RATE_LIMIT_WRITES_RPM", "5"))


def _admin_rpm() -> int:
    return int(os.getenv("WAZUH_MCP_RATE_LIMIT_ADMIN_RPM", "2"))


# Tools that trigger active-response, CDB writes, or credential operations
_WRITE_TOOLS = frozenset({
    "run_active_response", "add_to_cdb_list", "remove_from_cdb_list",
    "trigger_agent_upgrade", "rollback_agent_upgrade",
    "rotate_wazuh_api_password", "push_custom_rule", "push_custom_decoder",
    "clear_rootcheck_results", "restart_agent",
})

# Tools that affect system configuration or user management
_ADMIN_TOOLS = frozenset({
    "rotate_wazuh_api_password", "push_custom_rule", "push_custom_decoder",
    "rollback_agent_upgrade", "clear_rootcheck_results", "restart_agent",
    "delete_report_schedule",
})

# Per-tool windows (separate buckets from global)
_write_windows: dict[str, Deque[float]] = collections.defaultdict(collections.deque)
_admin_windows: dict[str, Deque[float]] = collections.defaultdict(collections.deque)


# Per-identity sliding window: deque of request timestamps (float, epoch seconds)
_windows: dict[str, Deque[float]] = collections.defaultdict(collections.deque)

_WINDOW_SECONDS = 60.0


def _identity_from_scope(scope: dict) -> str:
    """Derive a stable, opaque identity from the Authorization header in ASGI scope."""
    headers = dict(scope.get("headers", []))
    auth = headers.get(b"authorization", b"anonymous").decode("utf-8", errors="replace")
    return hashlib.sha256(auth.encode()).hexdigest()[:16]


def _tool_name_from_scope(scope: dict) -> str | None:
    """Best-effort extraction of MCP tool name from ASGI scope query string."""
    # The tool name is embedded in the JSON-RPC body, not the scope.
    # We expose it via a scope extension set by AuditMiddleware in server.py.
    return scope.get("wazuh_mcp_tool_name")


def _is_throttled(identity: str) -> tuple[bool, int]:
    """
    Returns (throttled, retry_after_seconds).
    Advances the sliding window, evicts stale entries, then checks the limit.
    """
    now = time.monotonic()
    dq = _windows[identity]

    # Evict entries outside the rolling window
    cutoff = now - _WINDOW_SECONDS
    while dq and dq[0] < cutoff:
        dq.popleft()

    limit = _rpm() + _burst()
    if len(dq) >= limit:
        # Retry after the oldest entry leaves the window
        retry_after = max(1, int(_WINDOW_SECONDS - (now - dq[0])) + 1)
        return True, retry_after

    dq.append(now)
    return False, 0


def _is_tool_throttled(identity: str, tool_name: str) -> tuple[bool, int]:
    """Per-tool rate limit check for write and admin operations."""
    now = time.monotonic()
    cutoff = now - _WINDOW_SECONDS

    if tool_name in _ADMIN_TOOLS:
        dq = _admin_windows[identity]
        while dq and dq[0] < cutoff:
            dq.popleft()
        limit = _admin_rpm()
        if len(dq) >= limit:
            retry_after = max(1, int(_WINDOW_SECONDS - (now - dq[0])) + 1)
            return True, retry_after
        dq.append(now)
        return False, 0

    if tool_name in _WRITE_TOOLS:
        dq = _write_windows[identity]
        while dq and dq[0] < cutoff:
            dq.popleft()
        limit = _writes_rpm()
        if len(dq) >= limit:
            retry_after = max(1, int(_WINDOW_SECONDS - (now - dq[0])) + 1)
            return True, retry_after
        dq.append(now)
        return False, 0

    return False, 0


class RateLimitMiddleware:
    """/health is always exempt — only MCP tool paths are rate-limited.

    Implemented as a pure ASGI middleware (not BaseHTTPMiddleware) so it
    never touches the request body stream — no interference with MCP tool calls.
    """

    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == "/health":
            await self._app(scope, receive, send)
            return

        identity = _identity_from_scope(scope)

        # Global per-identity limit
        throttled, retry_after = _is_throttled(identity)
        if throttled:
            await self._send_429(send, retry_after, "global")
            return

        # Per-tool limits for write/admin tools (parse tool name from path/body lazily)
        # Tool name inspection is best-effort: only works for JSON-RPC /messages POST
        tool_name = _tool_name_from_scope(scope)
        if tool_name:
            throttled, retry_after = _is_tool_throttled(identity, tool_name)
            if throttled:
                await self._send_429(send, retry_after, tool_name)
                return

        await self._app(scope, receive, send)

    @staticmethod
    async def _send_429(send, retry_after: int, context: str) -> None:
        body = json.dumps({
            "error": f"Rate limit exceeded for '{context}'. Retry after {retry_after} seconds.",
            "retry_after_seconds": retry_after,
        }).encode()
        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"retry-after", str(retry_after).encode()),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body, "more_body": False})
