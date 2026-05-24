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


# Per-identity sliding window: deque of request timestamps (float, epoch seconds)
_windows: dict[str, Deque[float]] = collections.defaultdict(collections.deque)

_WINDOW_SECONDS = 60.0


def _identity_from_scope(scope: dict) -> str:
    """Derive a stable, opaque identity from the Authorization header in ASGI scope."""
    headers = dict(scope.get("headers", []))
    auth = headers.get(b"authorization", b"anonymous").decode("utf-8", errors="replace")
    return hashlib.sha256(auth.encode()).hexdigest()[:16]


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
        throttled, retry_after = _is_throttled(identity)
        if throttled:
            body = json.dumps({
                "error": f"Rate limit exceeded. Retry after {retry_after} seconds.",
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
            return

        await self._app(scope, receive, send)
