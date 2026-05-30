"""MaxBodySizeMiddleware — pure ASGI middleware that rejects oversized request bodies.

Reads Content-Length header and returns HTTP 413 Request Entity Too Large when
the declared or actual body exceeds the configured limit. Protects AuditMiddleware
(which buffers the full body in memory) from memory-exhaustion DoS attacks.

Configure with env var WAZUH_MCP_MAX_BODY_KB (default: 4096 KB / 4 MB).
"""
from __future__ import annotations

import os

_DEFAULT_MAX_KB = 4096  # 4 MB — allows bulk IOC lists and rule XML uploads


def _max_bytes() -> int:
    try:
        return int(os.getenv("WAZUH_MCP_MAX_BODY_KB", str(_DEFAULT_MAX_KB))) * 1024
    except (ValueError, TypeError):
        return _DEFAULT_MAX_KB * 1024


class MaxBodySizeMiddleware:
    """Pure ASGI middleware — safe with streaming MCP body reads."""

    def __init__(self, app) -> None:
        self._app = app
        self._max_bytes = _max_bytes()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        # Fast-path: check Content-Length header first (no body read needed)
        headers = dict(scope.get("headers", []))
        content_length_raw = headers.get(b"content-length", b"")
        if content_length_raw:
            try:
                content_length = int(content_length_raw)
                if content_length > self._max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                pass

        # Wrap receive to track actual bytes read and enforce limit mid-stream
        total_bytes: list[int] = [0]
        rejected: list[bool] = [False]

        async def limited_receive():
            if rejected[0]:
                # Already sent 413 — drain and discard remaining chunks
                return {"type": "http.request", "body": b"", "more_body": False}
            msg = await receive()
            chunk = msg.get("body", b"")
            total_bytes[0] += len(chunk)
            if total_bytes[0] > self._max_bytes:
                rejected[0] = True
                await self._reject(send)
                return {"type": "http.request", "body": b"", "more_body": False}
            return msg

        await self._app(scope, limited_receive, send)

    @staticmethod
    async def _reject(send) -> None:
        body = b'{"error": "Request body too large. Limit: WAZUH_MCP_MAX_BODY_KB."}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
