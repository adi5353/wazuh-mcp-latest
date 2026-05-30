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

# M4: field-name allow-list enforcement ─────────────────────────────────────
# When validate_fields=True is passed to search/count, leaf field names inside
# the Elasticsearch DSL are checked against the validators allow-list.
# Internal (server-constructed) queries should NOT set validate_fields=True.
# Only queries that contain user-supplied field names need this flag.

def _extract_leaf_fields(obj: Any, fields: set | None = None) -> set:
    """Recursively collect all string keys from term/terms/match/range clauses."""
    if fields is None:
        fields = set()
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in ("term", "terms", "match", "match_phrase", "range", "wildcard", "prefix"):
                if isinstance(val, dict):
                    fields.update(val.keys())
            else:
                _extract_leaf_fields(val, fields)
    elif isinstance(obj, list):
        for item in obj:
            _extract_leaf_fields(item, fields)
    return fields


def _validate_query_fields(body: dict) -> None:
    """Raise ValueError if any leaf field name is not in the allow-list."""
    from .validators import validate_es_field
    fields = _extract_leaf_fields(body)
    for field in fields:
        # Skip internal ES meta-fields
        if field.startswith("_"):
            continue
        try:
            validate_es_field(field)
        except ValueError as exc:
            raise ValueError(f"Query field validation failed: {exc}") from exc

log = logging.getLogger(__name__)

# ── Retry configuration (same policy as WazuhClient) ─────────────────────────
_MAX_RETRIES = 3
_RETRY_BASE  = 1.0   # seconds — first delay before jitter
_RETRY_CAP   = 10.0  # seconds — maximum delay before jitter

# ── Connection pool limits (override via env vars) ────────────────────────────
# Defaults raised to 100/40 to prevent pool saturation under real SOC load
# (130+ concurrent tools + batch operations).  Tune down for low-resource deployments.
_POOL_MAX_CONNECTIONS: int = int(os.getenv("WAZUH_INDEXER_POOL_SIZE",    "100"))
_POOL_MAX_KEEPALIVE:   int = int(os.getenv("WAZUH_INDEXER_MAX_KEEPALIVE",  "40"))


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
        # Fix 8: in-flight deduplication — concurrent identical queries share one response
        self._inflight: dict[str, asyncio.Future] = {}
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

    async def search(self, body: dict, index: Optional[str] = None,
                     validate_fields: bool = False) -> dict:
        """Run an OpenSearch query with circuit breaker + deduplication + retry.

        Args:
            body: Elasticsearch DSL query body.
            index: Index pattern to search. Defaults to cfg.alerts_index.
            validate_fields: When True, leaf field names in term/match/range
                clauses are checked against the allow-list in validators.py.
                Set this for queries that contain user-supplied field names.
        """
        # M4: reject user-controlled fields not in the allow-list
        if validate_fields:
            _validate_query_fields(body)
        if not opensearch_breaker.allow():
            s = opensearch_breaker.status()
            raise RuntimeError(
                f"OpenSearch circuit breaker open — backend unavailable. "
                f"Retry in {s['circuit_resets_in_seconds']}s."
            )
        # Fix 8: coalesce identical concurrent queries into one wire call
        import json as _json
        _idx = index or self.cfg.alerts_index
        _key = _idx + ":" + _json.dumps(body, sort_keys=True, separators=(",", ":"))
        if _key in self._inflight:
            return await asyncio.shield(self._inflight[_key])
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._inflight[_key] = fut
        try:
            result = await self._search_impl(body, index)
            opensearch_breaker.record_success()
            fut.set_result(result)
            return result
        except Exception as exc:
            opensearch_breaker.record_failure()
            fut.set_exception(exc)
            raise
        finally:
            self._inflight.pop(_key, None)
    async def _search_impl(self, body: dict, index: Optional[str] = None) -> dict:
        """Internal search with retry logic (no circuit breaker — called by search())."""
        # Enforce server-side pagination cap: never request more than 500 docs in one call.
        # Callers should use search_after / page_token for large result sets.
        _MAX_PAGE_SIZE = 500
        if "size" in body:
            assert body["size"] <= _MAX_PAGE_SIZE, (
                f"Indexer size={body['size']} exceeds hard cap of {_MAX_PAGE_SIZE}. "
                "Use pagination (search_after) for large result sets."
            )
            body = {**body, "size": min(body["size"], _MAX_PAGE_SIZE)}
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

    async def count(self, query: dict, index: Optional[str] = None,
                    validate_fields: bool = False) -> int:
        """Count matching documents with circuit breaker + automatic retry on transient failures.

        Args:
            query: Elasticsearch query clause (the inner query, not the full body).
            index: Index pattern. Defaults to cfg.alerts_index.
            validate_fields: When True, field names are validated against the allow-list.
        """
        # M4: reject user-controlled fields not in the allow-list
        if validate_fields:
            _validate_query_fields({"query": query})
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
