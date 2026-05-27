"""Wazuh Indexer (OpenSearch) client. Used for alerts and vulnerability state.

Retry policy (mirrors WazuhClient):
  3 attempts — delays of ~1s, ~2s, ~4s (capped at 10s) + randomised ±1s jitter.
  Retries on: network errors (httpx.RequestError) and transient 5xx / 429 responses.
  Does NOT retry 4xx client errors (except 429).

Connection pooling:
  A single httpx.AsyncClient is shared across all requests. Pool size is configurable
  via WAZUH_INDEXER_POOL_SIZE and WAZUH_INDEXER_MAX_KEEPALIVE env vars.
  Call aclose() / use as async context manager on server shutdown.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
from typing import Any, Optional

import httpx

from .config import Config
from .circuit_breaker import opensearch_breaker

log = logging.getLogger(__name__)

# ── Retry configuration (same policy as WazuhClient) ─────────────────────────
_MAX_RETRIES = 3
_RETRY_BASE  = 1.0   # seconds — first delay before jitter
_RETRY_CAP   = 10.0  # seconds — maximum delay before jitter

# ── Connection pool limits (override via env vars) ────────────────────────────
_POOL_MAX_CONNECTIONS: int = int(os.getenv("WAZUH_INDEXER_POOL_SIZE",    "20"))
_POOL_MAX_KEEPALIVE:   int = int(os.getenv("WAZUH_INDEXER_MAX_KEEPALIVE", "10"))


def _is_retryable(exc: Exception) -> bool:
    """Return True when the exception warrants a retry."""
    if isinstance(exc, httpx.RequestError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status >= 500 or status == 429
    return False


async def _retry_sleep(attempt: int) -> None:
    """Exponential backoff with ±1s uniform jitter."""
    delay = min(_RETRY_BASE * (2 ** attempt), _RETRY_CAP) + random.uniform(0, 1)
    log.warning(
        "Wazuh Indexer: transient error on attempt %d/%d — retrying in %.1fs",
        attempt + 1, _MAX_RETRIES, delay,
    )
    await asyncio.sleep(delay)


class WazuhIndexer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._ssl: bool | str = cfg.ca_bundle if cfg.ca_bundle else cfg.verify_ssl
        self._client = httpx.AsyncClient(
            verify=self._ssl,
            auth=(cfg.indexer_user, cfg.indexer_pass),
            headers={"Content-Type": "application/json"},
            limits=httpx.Limits(
                max_connections=_POOL_MAX_CONNECTIONS,
                max_keepalive_connections=_POOL_MAX_KEEPALIVE,
            ),
            timeout=httpx.Timeout(cfg.request_timeout),
        )

    async def aclose(self) -> None:
        """Release the connection pool. Call on server shutdown."""
        await self._client.aclose()

    async def __aenter__(self) -> "WazuhIndexer":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def search(self, body: dict, index: Optional[str] = None) -> dict:
        """Run an OpenSearch query with circuit breaker + automatic retry on transient failures."""
        if not opensearch_breaker.allow():
            s = opensearch_breaker.status()
            raise RuntimeError(
                f"OpenSearch circuit breaker open — backend unavailable. "
                f"Retry in {s['circuit_resets_in_seconds']}s."
            )
        try:
            result = await self._search_impl(body, index)
            opensearch_breaker.record_success()
            return result
        except Exception:
            opensearch_breaker.record_failure()
            raise

    async def _search_impl(self, body: dict, index: Optional[str] = None) -> dict:
        """Internal search with retry logic (no circuit breaker — called by search())."""
        idx = index or self.cfg.alerts_index
        url = f"{self.cfg.indexer_host}/{idx}/_search"
        last_exc: Exception = RuntimeError("No attempts made")
        for attempt in range(_MAX_RETRIES):
            try:
                r = await self._client.post(url, json=body)
                r.raise_for_status()
                return r.json()
            except Exception as exc:
                last_exc = exc
                if _is_retryable(exc) and attempt < _MAX_RETRIES - 1:
                    await _retry_sleep(attempt)
                    continue
                raise
        raise last_exc  # unreachable but satisfies type checker

    async def count(self, query: dict, index: Optional[str] = None) -> int:
        """Count matching documents with circuit breaker + automatic retry on transient failures."""
        if not opensearch_breaker.allow():
            s = opensearch_breaker.status()
            raise RuntimeError(
                f"OpenSearch circuit breaker open — backend unavailable. "
                f"Retry in {s['circuit_resets_in_seconds']}s."
            )
        try:
            result = await self._count_impl(query, index)
            opensearch_breaker.record_success()
            return result
        except Exception:
            opensearch_breaker.record_failure()
            raise

    async def _count_impl(self, query: dict, index: Optional[str] = None) -> int:
        """Internal count with retry logic (no circuit breaker — called by count())."""
        idx = index or self.cfg.alerts_index
        url = f"{self.cfg.indexer_host}/{idx}/_count"
        last_exc: Exception = RuntimeError("No attempts made")
        for attempt in range(_MAX_RETRIES):
            try:
                r = await self._client.post(url, json={"query": query})
                r.raise_for_status()
                return r.json()["count"]
            except Exception as exc:
                last_exc = exc
                if _is_retryable(exc) and attempt < _MAX_RETRIES - 1:
                    await _retry_sleep(attempt)
                    continue
                raise
        raise last_exc  # unreachable but satisfies type checker
