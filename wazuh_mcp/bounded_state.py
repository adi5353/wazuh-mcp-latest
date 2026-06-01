"""Size- and TTL-bounded key store to prevent unbounded per-identity growth.

A long-lived multi-client HTTP server accumulates one entry per distinct caller
identity (active operational contexts, injection counters, …). Plain dicts never
shrink, so memory grows with the number of callers ever seen. This store evicts
by idle-TTL and caps total entries (LRU), keeping per-identity state bounded.

Thread-safe; suitable as the backing store for state mutated from concurrent
asyncio tasks (HTTP transport) and the playbook engine.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable, Generic, Optional, TypeVar

V = TypeVar("V")


class BoundedTTLStore(Generic[V]):
    def __init__(
        self,
        *,
        max_entries: int,
        ttl_seconds: float,
        default_factory: Optional[Callable[[], V]] = None,
    ) -> None:
        self._max = max(1, max_entries)
        self._ttl = ttl_seconds
        self._factory = default_factory
        self._data: "OrderedDict[str, V]" = OrderedDict()
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def _evict_locked(self) -> None:
        now = time.time()
        if self._ttl > 0:
            stale = [k for k, t in self._seen.items() if now - t > self._ttl]
            for k in stale:
                self._data.pop(k, None)
                self._seen.pop(k, None)
        # LRU = front of the OrderedDict.
        while len(self._data) > self._max:
            k, _ = self._data.popitem(last=False)
            self._seen.pop(k, None)

    def get(self, key: str, default: Optional[V] = None) -> Optional[V]:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self._seen[key] = time.time()
                return self._data[key]
            return default

    def get_or_create(self, key: str) -> V:
        if self._factory is None:  # pragma: no cover - misuse guard
            raise RuntimeError("get_or_create requires a default_factory")
        with self._lock:
            if key not in self._data:
                self._data[key] = self._factory()
            self._data.move_to_end(key)
            self._seen[key] = time.time()
            self._evict_locked()
            return self._data[key]

    def set(self, key: str, value: V) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            self._seen[key] = time.time()
            self._evict_locked()

    def pop(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)
            self._seen.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._seen.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
