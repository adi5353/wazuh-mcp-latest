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

# _store: cache_key → (expire_monotonic, result)
_store: dict[str, tuple[float, Any]] = {}


def _make_key(fn_name: str, kwargs: dict) -> str:
    canonical = json.dumps(kwargs, sort_keys=True, default=str)
    return hashlib.sha256(f"{fn_name}:{canonical}".encode()).hexdigest()[:24]


def _get(key: str) -> tuple[bool, Any]:
    entry = _store.get(key)
    if entry is None:
        return False, None
    expire_at, value = entry
    if time.monotonic() > expire_at:
        del _store[key]
        return False, None
    return True, value


def _put(key: str, value: Any) -> None:
    if _TTL > 0:
        _store[key] = (time.monotonic() + _TTL, value)


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
        _put(key, result)
        return result
    return wrapper


def invalidate_all() -> int:
    """Flush the entire cache. Returns the number of entries removed."""
    count = len(_store)
    _store.clear()
    return count


def cache_stats() -> dict:
    """Return cache diagnostics."""
    now = time.monotonic()
    valid = sum(1 for _, (exp, _) in _store.items() if exp > now)
    return {
        "total_entries": len(_store),
        "valid_entries": valid,
        "expired_entries": len(_store) - valid,
        "ttl_seconds": _TTL,
        "enabled": _TTL > 0,
    }
