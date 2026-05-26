"""TTL + LRU in-process cache for read-only MCP tool results.

Avoids repeated identical API calls to Wazuh Manager / Indexer within
a configurable time window. Only use the `@cached` decorator on
idempotent, side-effect-free tools — never on write operations.

Configuration (env vars):
    WAZUH_MCP_CACHE_TTL_SECONDS   — TTL in seconds (default 60; 0 = disabled)
    WAZUH_MCP_CACHE_MAX_SIZE      — max entries before LRU eviction (default 1000)
    WAZUH_CACHE_BACKEND           — "memory" (default) or "redis"
    WAZUH_REDIS_URL               — Redis connection URL (default redis://localhost:6379/0)
    WAZUH_REDIS_KEY_PREFIX        — key namespace for Redis (default "wazuh_mcp:")
"""
from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from typing import Any, Callable

log = logging.getLogger("wazuh-mcp.cache")

_TTL: int = int(os.getenv("WAZUH_MCP_CACHE_TTL_SECONDS", "60"))
_MAX_SIZE: int = int(os.getenv("WAZUH_MCP_CACHE_MAX_SIZE", "1000"))
_BACKEND: str = os.getenv("WAZUH_CACHE_BACKEND", "memory").lower()
_REDIS_URL: str = os.getenv("WAZUH_REDIS_URL", "redis://localhost:6379/0")
_REDIS_PREFIX: str = os.getenv("WAZUH_REDIS_KEY_PREFIX", "wazuh_mcp:")

# ── Hit / miss counters ────────────────────────────────────────────────────────
_hits: int = 0
_misses: int = 0


# ── In-memory LRU store ────────────────────────────────────────────────────────
# OrderedDict: key → (expire_monotonic, value)
# Most-recently used moves to end; when full, pop from front (LRU).

class _LRUStore:
    def __init__(self, max_size: int) -> None:
        self._max_size = max_size
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()

    def get(self, key: str) -> tuple[bool, Any]:
        entry = self._data.get(key)
        if entry is None:
            return False, None
        expire_at, value = entry
        if time.monotonic() > expire_at:
            del self._data[key]
            return False, None
        # Move to end (most recently used)
        self._data.move_to_end(key)
        return True, value

    def put(self, key: str, value: Any, ttl: int) -> None:
        if ttl <= 0:
            return
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = (time.monotonic() + ttl, value)
        # Evict LRU entries if over max size
        while self._max_size > 0 and len(self._data) > self._max_size:
            evicted_key, _ = self._data.popitem(last=False)
            log.debug("cache LRU evict key=%s", evicted_key[:12])

    def invalidate_all(self) -> int:
        count = len(self._data)
        self._data.clear()
        return count

    def stats(self) -> dict:
        now = time.monotonic()
        valid = sum(1 for exp, _ in self._data.values() if exp > now)
        return {
            "total_entries": len(self._data),
            "valid_entries": valid,
            "expired_entries": len(self._data) - valid,
            "max_size": self._max_size,
        }


_lru_store = _LRUStore(_MAX_SIZE)


# ── Redis backend ──────────────────────────────────────────────────────────────

class _RedisStore:
    """Thin async Redis wrapper using aioredis / redis[asyncio]."""

    def __init__(self, url: str, prefix: str) -> None:
        self._url = url
        self._prefix = prefix
        self._client: Any = None

    async def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import redis.asyncio as aioredis  # redis>=4.2 ships asyncio support
            self._client = aioredis.from_url(self._url, decode_responses=False)
            log.info("Redis cache backend connected — %s", self._url)
        except ImportError:
            log.warning(
                "redis package not installed — falling back to in-memory cache. "
                "Install with: pip install redis"
            )
            self._client = None
        return self._client

    def _key(self, k: str) -> str:
        return f"{self._prefix}{k}"

    async def get(self, key: str) -> tuple[bool, Any]:
        client = await self._get_client()
        if client is None:
            return _lru_store.get(key)
        try:
            raw = await client.get(self._key(key))
            if raw is None:
                return False, None
            return True, json.loads(raw)
        except Exception as exc:
            log.warning("Redis GET failed, using memory fallback: %s", exc)
            return _lru_store.get(key)

    async def put(self, key: str, value: Any, ttl: int) -> None:
        if ttl <= 0:
            return
        client = await self._get_client()
        if client is None:
            _lru_store.put(key, value, ttl)
            return
        try:
            await client.setex(self._key(key), ttl, json.dumps(value, default=str))
        except Exception as exc:
            log.warning("Redis SET failed, using memory fallback: %s", exc)
            _lru_store.put(key, value, ttl)

    async def invalidate_all(self) -> int:
        client = await self._get_client()
        if client is None:
            return _lru_store.invalidate_all()
        try:
            pattern = f"{self._prefix}*"
            keys = await client.keys(pattern)
            if keys:
                await client.delete(*keys)
            return len(keys)
        except Exception as exc:
            log.warning("Redis FLUSH failed: %s", exc)
            return 0

    async def stats(self) -> dict:
        client = await self._get_client()
        if client is None:
            return {**_lru_store.stats(), "backend": "memory_fallback"}
        try:
            info = await client.info("memory")
            key_count_raw = await client.dbsize()
            return {
                "backend": "redis",
                "url": self._url,
                "prefix": self._prefix,
                "approx_keys_in_db": key_count_raw,
                "used_memory_human": info.get("used_memory_human", "?"),
            }
        except Exception as exc:
            return {"backend": "redis", "error": str(exc)}


_redis_store = _RedisStore(_REDIS_URL, _REDIS_PREFIX) if _BACKEND == "redis" else None


# ── Key generation ─────────────────────────────────────────────────────────────

def _make_key(fn_name: str, kwargs: dict) -> str:
    canonical = json.dumps(kwargs, sort_keys=True, default=str)
    return hashlib.sha256(f"{fn_name}:{canonical}".encode()).hexdigest()[:24]


# ── Public decorator ───────────────────────────────────────────────────────────

def cached(fn: Callable) -> Callable:
    """Decorator: cache async tool results for WAZUH_MCP_CACHE_TTL_SECONDS.

    Apply only to idempotent read tools. Cache is keyed on function name
    + all kwargs so different parameter combinations are cached separately.

    With WAZUH_CACHE_BACKEND=redis, results are stored in Redis and shared
    across multiple server instances. Falls back to in-memory LRU if the
    Redis connection fails.
    """
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        global _hits, _misses
        if _TTL <= 0:
            return await fn(*args, **kwargs)
        key = _make_key(fn.__name__, kwargs)

        if _redis_store is not None:
            hit, value = await _redis_store.get(key)
        else:
            hit, value = _lru_store.get(key)

        if hit:
            _hits += 1
            return value

        _misses += 1
        result = await fn(*args, **kwargs)

        if _redis_store is not None:
            await _redis_store.put(key, result, _TTL)
        else:
            _lru_store.put(key, result, _TTL)

        return result
    return wrapper


# ── Management helpers ─────────────────────────────────────────────────────────

async def invalidate_all_async() -> int:
    """Flush the entire cache (async — for Redis backend). Returns entries removed."""
    if _redis_store is not None:
        return await _redis_store.invalidate_all()
    return _lru_store.invalidate_all()


def invalidate_all() -> int:
    """Flush the in-memory cache synchronously. Use invalidate_all_async() for Redis."""
    return _lru_store.invalidate_all()


async def cache_stats_async() -> dict:
    """Return cache diagnostics including hit/miss ratio (async for Redis)."""
    total_requests = _hits + _misses
    hit_rate = round(_hits / total_requests * 100, 1) if total_requests else 0.0

    base = {
        "backend": _BACKEND,
        "ttl_seconds": _TTL,
        "enabled": _TTL > 0,
        "hits": _hits,
        "misses": _misses,
        "hit_rate_pct": hit_rate,
    }

    if _redis_store is not None:
        backend_stats = await _redis_store.stats()
    else:
        backend_stats = _lru_store.stats()

    return {**base, **backend_stats}


def cache_stats() -> dict:
    """Return cache diagnostics (sync — memory backend only)."""
    total_requests = _hits + _misses
    hit_rate = round(_hits / total_requests * 100, 1) if total_requests else 0.0
    return {
        "backend": _BACKEND,
        "ttl_seconds": _TTL,
        "enabled": _TTL > 0,
        "hits": _hits,
        "misses": _misses,
        "hit_rate_pct": hit_rate,
        **_lru_store.stats(),
    }
