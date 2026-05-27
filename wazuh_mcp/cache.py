"""TTL-based in-process cache for read-only MCP tool results.

Avoids repeated identical API calls to Wazuh Manager / Indexer within
a configurable time window. Only use the `@cached` decorator on
idempotent, side-effect-free tools — never on write operations.

Configuration:
    WAZUH_MCP_CACHE_TTL_SECONDS  — TTL in seconds (default 60; 0 = disabled)
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import time
from typing import Any, Callable

_TTL: int = int(os.getenv("WAZUH_MCP_CACHE_TTL_SECONDS", "60"))

# _store: cache_key → (expire_monotonic, result, fn_name)
_store: dict[str, tuple[float, Any, str]] = {}

# Hit/miss counters for observability
_hits:   int = 0
_misses: int = 0


def _make_key(fn_name: str, kwargs: dict) -> str:
    canonical = json.dumps(kwargs, sort_keys=True, default=str)
    return hashlib.sha256(f"{fn_name}:{canonical}".encode()).hexdigest()[:24]


def _get(key: str) -> tuple[bool, Any]:
    global _hits, _misses
    entry = _store.get(key)
    if entry is None:
        _misses += 1
        return False, None
    expire_at, value, _ = entry
    if time.monotonic() > expire_at:
        del _store[key]
        _misses += 1
        return False, None
    _hits += 1
    return True, value


def _put(key: str, fn_name: str, value: Any) -> None:
    if _TTL > 0:
        _store[key] = (time.monotonic() + _TTL, value, fn_name)


def cached(fn: Callable) -> Callable:
    """Decorator: cache async tool results for WAZUH_MCP_CACHE_TTL_SECONDS.

    Apply only to idempotent read tools. Cache is keyed on function name
    + all kwargs so different parameter combinations are cached separately.
    """
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        if _TTL <= 0:
            return await fn(*args, **kwargs)
        key = _make_key(fn.__name__, kwargs)
        hit, value = _get(key)
        if hit:
            return value
        result = await fn(*args, **kwargs)
        _put(key, fn.__name__, result)
        return result
    return wrapper


def invalidate_all() -> int:
    """Flush the entire cache. Returns the number of entries removed."""
    count = len(_store)
    _store.clear()
    return count


def invalidate_tool(tool_name: str) -> int:
    """Flush all cached entries for a specific tool. Returns entries removed."""
    keys_to_delete = [k for k, (_, _, fn) in _store.items() if fn == tool_name]
    for k in keys_to_delete:
        del _store[k]
    return len(keys_to_delete)


def cache_stats() -> dict:
    """Return cache diagnostics including hit/miss ratio."""
    now = time.monotonic()
    valid = sum(1 for exp, _, _fn in _store.values() if exp > now)
    total_requests = _hits + _misses
    return {
        "total_entries": len(_store),
        "valid_entries": valid,
        "expired_entries": len(_store) - valid,
        "ttl_seconds": _TTL,
        "enabled": _TTL > 0,
        "hits": _hits,
        "misses": _misses,
        "hit_ratio": round(_hits / total_requests, 3) if total_requests else 0.0,
    }
