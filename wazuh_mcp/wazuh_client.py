"""Wazuh Manager REST API client. Handles JWT auth, token refresh, and retry backoff.

Retry policy (Gap 12):
  3 attempts — delays of ~1s, ~2s, ~4s (capped at 10s) + randomised ±1s jitter.
  Retries on: network errors (httpx.RequestError) and transient 5xx responses.
  Does NOT retry 4xx client errors (except 429 Too Many Requests).

Connection pooling:
  A single httpx.AsyncClient is shared across all requests (20 max connections,
  10 keepalive). Call aclose() / use as async context manager on server shutdown.
"""
from __future__ import annotations
import asyncio
import base64
import logging
import os
import random
import time
from typing import Any, Optional

import httpx

from .config import Config
from .circuit_breaker import wazuh_manager_breaker

log = logging.getLogger(__name__)

# Wazuh JWT tokens default to 900 seconds; refresh ~100s early for safety.
TOKEN_TTL_SECONDS = 800

# ── Retry configuration ────────────────────────────────────────────────────────
_MAX_RETRIES  = 3
_RETRY_BASE   = 1.0   # seconds — first delay before jitter
_RETRY_CAP    = 10.0  # seconds — maximum delay before jitter

# ── Connection pool limits (override via env vars) ────────────────────────────
# Defaults raised to 100/40 to prevent pool saturation under real SOC load
# (130+ concurrent tools + batch operations).  Tune down for low-resource deployments.
_POOL_MAX_CONNECTIONS: int = int(os.getenv("WAZUH_HTTP_POOL_SIZE",    "100"))
_POOL_MAX_KEEPALIVE:   int = int(os.getenv("WAZUH_HTTP_MAX_KEEPALIVE",  "40"))


# Allowed Manager file-API route prefixes for uploads. These are the only
# Manager endpoints this server writes files to (rules, decoders, and CDB lists).
# Anything else — or any path containing '..' — is rejected to prevent traversal
# and arbitrary-endpoint writes via a crafted path.
_ALLOWED_UPLOAD_PREFIXES = ("/rules/files/", "/decoders/files/", "/lists/files/")


def _validate_manager_file_path(path: str) -> None:
    """Reject any upload path outside the Manager rules/decoders file API.

    Guards against path traversal (``..``) and arbitrary-endpoint writes. The
    query string (``?overwrite=true``) is ignored for prefix matching.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("upload path must be a non-empty string")
    route = path.split("?", 1)[0]
    if ".." in route:
        raise ValueError(f"Refusing upload path containing '..': {path!r}")
    if not route.startswith(_ALLOWED_UPLOAD_PREFIXES):
        raise ValueError(
            f"Refusing upload to disallowed path {path!r}. "
            f"Allowed prefixes: {_ALLOWED_UPLOAD_PREFIXES}"
        )


def _is_retryable(exc: Exception) -> bool:
    """Return True if the exception warrants a retry."""
    if isinstance(exc, httpx.RequestError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status >= 500 or status == 429
    return False


async def _retry_sleep(attempt: int) -> None:
    """Exponential backoff with ±1s uniform jitter."""
    delay = min(_RETRY_BASE * (2 ** attempt), _RETRY_CAP) + random.uniform(0, 1)
    log.warning("Wazuh Manager: transient error on attempt %d/%d — retrying in %.1fs",
                attempt + 1, _MAX_RETRIES, delay)
    await asyncio.sleep(delay)


_TOKEN_PROACTIVE_REFRESH_WINDOW = 100  # seconds before expiry to trigger background refresh


class WazuhClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._token: Optional[str] = None
        self._token_expires: float = 0.0
        self._login_lock = asyncio.Lock()
        self._refresh_task: Optional[asyncio.Task] = None  # background proactive refresh
        # Use CA bundle when provided, otherwise fall back to verify_ssl flag.
        self._ssl: bool | str = cfg.ca_bundle if cfg.ca_bundle else cfg.verify_ssl
        # Persistent connection pool — reused across all requests.
        self._client = httpx.AsyncClient(
            verify=self._ssl,
            limits=httpx.Limits(
                max_connections=_POOL_MAX_CONNECTIONS,
                max_keepalive_connections=_POOL_MAX_KEEPALIVE,
            ),
            timeout=httpx.Timeout(cfg.request_timeout),
        )

    async def aclose(self) -> None:
        """Release the connection pool. Call on server shutdown."""
        await self._client.aclose()

    async def __aenter__(self) -> "WazuhClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def _login(self) -> None:
        auth = base64.b64encode(
            f"{self.cfg.manager_user}:{self.cfg.manager_pass}".encode()
        ).decode()
        r = await self._client.post(
            f"{self.cfg.manager_host}/security/user/authenticate",
            headers={"Authorization": f"Basic {auth}"},
            timeout=10,
        )
        r.raise_for_status()
        self._token = r.json()["data"]["token"]
        self._token_expires = time.time() + TOKEN_TTL_SECONDS
        log.info("Wazuh Manager: authenticated, token cached")

    async def _proactive_refresh(self) -> None:
        """Background token refresh — runs without blocking ongoing requests."""
        try:
            async with self._login_lock:
                # Another concurrent task may have already refreshed the token.
                if self._token and time.time() < self._token_expires:
                    return
                self._token = None
                await self._login()
        except Exception as exc:
            log.warning("Wazuh Manager: proactive token refresh failed: %s", exc)

    async def _ensure_token(self) -> None:
        """Ensure a valid token exists, preferring non-blocking proactive refresh."""
        now = time.time()
        if self._token and now < self._token_expires:
            # Token is valid; schedule a background refresh when nearing expiry.
            if now > self._token_expires - _TOKEN_PROACTIVE_REFRESH_WINDOW:
                if self._refresh_task is None or self._refresh_task.done():
                    self._refresh_task = asyncio.ensure_future(self._proactive_refresh())
            return
        # Token absent or already expired — must block until we have a fresh one.
        async with self._login_lock:
            if self._token and time.time() < self._token_expires:
                return  # another coroutine already refreshed it
            self._token = None
            await self._login()

    async def request(self, method: str, path: str, **kwargs: Any) -> dict:
        if not wazuh_manager_breaker.allow():
            s = wazuh_manager_breaker.status()
            raise RuntimeError(
                f"Wazuh Manager circuit breaker open — backend unavailable. "
                f"Retry in {s['circuit_resets_in_seconds']}s."
            )
        try:
            result = await self._request_impl(method, path, **kwargs)
            wazuh_manager_breaker.record_success()
            return result
        except Exception:
            wazuh_manager_breaker.record_failure()
            raise

    async def _request_impl(self, method: str, path: str, **kwargs: Any) -> dict:
        last_exc: BaseException = RuntimeError("unreachable")
        for attempt in range(_MAX_RETRIES + 1):
            try:
                return await self._request_once(method, path, **kwargs)
            except Exception as exc:
                if not _is_retryable(exc) or attempt == _MAX_RETRIES:
                    raise
                last_exc = exc
                await _retry_sleep(attempt)
        raise last_exc  # unreachable — loop always raises or returns first

    async def _request_once(self, method: str, path: str, **kwargs: Any) -> dict:
        await self._ensure_token()

        r = await self._client.request(
            method,
            f"{self.cfg.manager_host}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            **kwargs,
        )
        if r.status_code == 401:
            log.info("Wazuh Manager: token rejected, re-authenticating")
            async with self._login_lock:
                # Another concurrent request may have already refreshed the token.
                if self._token and time.time() <= self._token_expires:
                    pass
                else:
                    self._token = None
                    await self._login()
            r = await self._client.request(
                method,
                f"{self.cfg.manager_host}{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                **kwargs,
            )
        r.raise_for_status()
        return r.json()

    async def detect_api_version(self) -> dict:
        """Detect the Wazuh Manager API version at startup.

        Returns a dict with keys: major (int), minor (int), patch (int), full (str).
        Used to select correct API paths for v4 vs v5 compatibility shims.
        """
        try:
            data = await self.request("GET", "/")
            raw = (
                data.get("data", {}).get("api_version")
                or data.get("api_version")
                or ""
            )
            parts = str(raw).lstrip("v").split(".")
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            log.info("Wazuh Manager API version detected: %s", raw)
            return {"major": major, "minor": minor, "patch": patch, "full": raw}
        except Exception as exc:
            log.warning("Could not detect Wazuh API version: %s", exc)
            return {"major": 0, "minor": 0, "patch": 0, "full": "unknown"}

    async def upload_xml_file(self, path: str, xml_content: str, overwrite: bool = True) -> dict:  # noqa: E501
        """Upload a raw XML file to the Wazuh Manager (rules or decoders).

        Uses application/octet-stream as required by the Manager file upload API.
        Automatically appends ?overwrite=true so existing files are replaced.
        Retries on transient network/5xx errors (same policy as request()).

        ``path`` is restricted to the Manager rules/decoders file-API routes to
        prevent traversal or arbitrary-endpoint writes via a crafted path.
        """
        _validate_manager_file_path(path)
        if not wazuh_manager_breaker.allow():
            s = wazuh_manager_breaker.status()
            raise RuntimeError(
                f"Wazuh Manager circuit breaker open — backend unavailable. "
                f"Retry in {s['circuit_resets_in_seconds']}s."
            )
        try:
            result = await self._upload_xml_impl(path, xml_content, overwrite)
            wazuh_manager_breaker.record_success()
            return result
        except Exception:
            wazuh_manager_breaker.record_failure()
            raise

    async def _upload_xml_impl(self, path: str, xml_content: str, overwrite: bool) -> dict:
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                return await self._upload_xml_once(path, xml_content, overwrite)
            except Exception as exc:
                if not _is_retryable(exc) or attempt == _MAX_RETRIES:
                    raise
                last_exc = exc
                await _retry_sleep(attempt)
        raise last_exc  # type: ignore[misc]

    async def _upload_xml_once(self, path: str, xml_content: str, overwrite: bool) -> dict:
        if not self._token or time.time() > self._token_expires:
            async with self._login_lock:
                if not self._token or time.time() > self._token_expires:
                    await self._login()

        url = f"{self.cfg.manager_host}{path}"
        if overwrite and "overwrite" not in path:
            url += ("&" if "?" in path else "?") + "overwrite=true"

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/octet-stream",
        }

        r = await self._client.put(
            url,
            content=xml_content.encode("utf-8"),
            headers=headers,
        )
        if r.status_code == 401:
            log.info("Wazuh Manager: token rejected, re-authenticating")
            async with self._login_lock:
                if self._token and time.time() <= self._token_expires:
                    pass
                else:
                    self._token = None
                    await self._login()
            headers["Authorization"] = f"Bearer {self._token}"
            r = await self._client.put(
                url,
                content=xml_content.encode("utf-8"),
                headers=headers,
            )
        r.raise_for_status()
        return r.json()
