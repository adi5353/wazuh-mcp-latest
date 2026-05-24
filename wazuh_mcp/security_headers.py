"""Security headers ASGI middleware.

Injects standard HTTP security headers on every response from the MCP
HTTP transport. Protects against clickjacking, MIME sniffing, and enables
HSTS for TLS deployments.

Usage in server.py (outermost after MaxBodySizeMiddleware)::

    from .security_headers import SecurityHeadersMiddleware
    app = SecurityHeadersMiddleware(app, tls_enabled=tls_enabled())
"""
from __future__ import annotations

_BASE_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options",  b"nosniff"),
    (b"x-frame-options",         b"DENY"),
    (b"x-xss-protection",        b"1; mode=block"),
    (b"referrer-policy",         b"strict-origin-when-cross-origin"),
    (b"content-security-policy", b"default-src 'none'"),
    (b"cache-control",           b"no-store"),
    (b"permissions-policy",      b"geolocation=(), microphone=(), camera=()"),
]

_HSTS: tuple[bytes, bytes] = (
    b"strict-transport-security",
    b"max-age=31536000; includeSubDomains",
)


class SecurityHeadersMiddleware:
    """Pure ASGI middleware — appends security headers to every HTTP response."""

    def __init__(self, app, *, tls_enabled: bool = False) -> None:
        self._app = app
        self._headers = list(_BASE_HEADERS)
        if tls_enabled:
            self._headers.append(_HSTS)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def _send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(self._headers)
                message = {**message, "headers": headers}
            await send(message)

        await self._app(scope, receive, _send_with_headers)
