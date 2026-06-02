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

# Cap the number of tracked identities so a caller rotating tokens (or a flood of
# distinct source IPs) can't grow these dicts without bound. When exceeded, stale
# identities (no request within the window) are dropped.
_MAX_IDENTITIES = int(os.getenv("WAZUH_MCP_RATE_LIMIT_MAX_IDENTITIES", "10000"))


def _prune_if_needed() -> None:
    """Drop identities with no activity inside the window once a dict grows past
    the cap. Bounds memory against token-rotation / IP-spray keyspace blowup."""
    now = time.monotonic()
    cutoff = now - _WINDOW_SECONDS
    for d in (_windows, _write_windows, _admin_windows):
        if len(d) > _MAX_IDENTITIES:
            stale = [k for k, dq in d.items() if not dq or dq[-1] < cutoff]
            for k in stale:
                del d[k]


def _identity_from_scope(scope: dict) -> str:
    """Derive a stable, opaque identity for rate-limiting.

    Authenticated callers are bucketed by their Authorization header. Anonymous
    callers are bucketed by client IP so a single unauthenticated source cannot
    exhaust a shared 'anonymous' bucket and starve every other anonymous client.
    """
    headers = dict(scope.get("headers", []))
    auth = headers.get(b"authorization", b"").decode("utf-8", errors="replace").strip()
    if auth:
        return hashlib.sha256(auth.encode()).hexdigest()[:16]
    client = scope.get("client")
    ip = client[0] if client else "unknown"
    return "ip:" + hashlib.sha256(ip.encode()).hexdigest()[:16]


def _tool_name_from_scope(scope: dict) -> str | None:
    """Return the MCP tool name previously stashed on the scope by the middleware
    (set from the JSON-RPC body). Kept for downstream consumers/tests."""
    return scope.get("wazuh_mcp_tool_name")


def _tool_name_from_body(body_bytes: bytes) -> str | None:
    """Extract the MCP tool name from a JSON-RPC ``tools/call`` request body."""
    try:
        payload = json.loads(body_bytes) if body_bytes else {}
    except Exception:
        return None
    if isinstance(payload, dict) and payload.get("method") == "tools/call":
        params = payload.get("params") or {}
        name = params.get("name")
        return name if isinstance(name, str) else None
    return None


async def _buffer_body(receive):
    """Read the full request body once and return (body_bytes, replay_receive).

    Mirrors AuditMiddleware: the body stream can only be consumed once, so we
    buffer it and hand the downstream app a receive() that replays it. Without
    this the MCP SDK would see an empty body."""
    chunks: list[bytes] = []
    more = True
    while more:
        msg = await receive()
        chunks.append(msg.get("body", b""))
        more = msg.get("more_body", False)
    body = b"".join(chunks)

    replayed = False

    async def replay_receive():
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return body, replay_receive


def _is_throttled(identity: str) -> tuple[bool, int]:
    """
    Returns (throttled, retry_after_seconds).
    Advances the sliding window, evicts stale entries, then checks the limit.
    """
    _prune_if_needed()
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

        # Per-tool limits for write/admin tools. The tool name lives in the
        # JSON-RPC body, so buffer + replay it (POST only) and expose it on the
        # scope. Previously this read a scope key that nothing ever set, so the
        # stricter write/admin limits never fired. An already-set scope key (from
        # an upstream middleware) is honoured as-is.
        tool_name = scope.get("wazuh_mcp_tool_name")
        if tool_name is None and scope.get("method") == "POST":
            body_bytes, receive = await _buffer_body(receive)
            tool_name = _tool_name_from_body(body_bytes)
            if tool_name:
                scope["wazuh_mcp_tool_name"] = tool_name
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
