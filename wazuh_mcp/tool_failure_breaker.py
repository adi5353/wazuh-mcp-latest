"""Per-(identity, tool, args) failure circuit breaker — stops LLM retry loops.

A non-deterministic agent that gets an error from a tool will often retry the
*exact same call* in a tight loop, hammering the Wazuh backend and burning the
operator's quota. This breaker tracks consecutive identical failures keyed on
``(identity, tool_name, args_fingerprint)``. After N failures in a row it opens
for a cooldown and returns a structured "stop retrying" payload instructing the
model to ask the human operator instead of looping.

This complements the existing breakers in ``circuit_breaker.py``:
  • ``circuit_breaker.breaker``  — third-party API quota/outage (per API)
  • ``BackendCircuitBreaker``     — backend outage (per backend)
  • this module                   — *caller-driven* bad-input retry storms (per call)

Configuration (env vars):
    WAZUH_MCP_TOOL_FAIL_THRESHOLD     — consecutive identical failures before the
                                        breaker opens (default 3)
    WAZUH_MCP_TOOL_FAIL_RESET_SECONDS — seconds the breaker stays open (default 60)

Usage (inside the tool middleware)::

    from .tool_failure_breaker import tool_failure_breaker as tfb

    err = tfb.check(identity, tool_name, args)
    if err is not None:
        return err                       # circuit open — do not run the tool
    try:
        result = await fn(...)
    except Exception:
        tfb.record_failure(identity, tool_name, args)
        raise
    if isinstance(result, dict) and "error" in result:
        tfb.record_failure(identity, tool_name, args)
    else:
        tfb.record_success(identity, tool_name, args)
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field


def _threshold() -> int:
    try:
        return max(1, int(os.getenv("WAZUH_MCP_TOOL_FAIL_THRESHOLD", "3")))
    except ValueError:
        return 3


def _reset_seconds() -> int:
    try:
        return max(1, int(os.getenv("WAZUH_MCP_TOOL_FAIL_RESET_SECONDS", "60")))
    except ValueError:
        return 60


def _args_fingerprint(args: dict | None) -> str:
    """Stable short hash of the call arguments, order-independent."""
    try:
        blob = json.dumps(args or {}, sort_keys=True, default=str)
    except Exception:
        blob = repr(args)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@dataclass
class _Entry:
    consecutive_failures: int = 0
    open_until: float = 0.0          # epoch; 0 = closed
    last_failure: float = field(default_factory=time.time)


class ToolFailureBreaker:
    """Tracks consecutive identical tool failures per caller and trips a breaker.

    Thread-safe: a process-wide lock guards the entry map so concurrent asyncio
    tasks (HTTP transport) and the playbook engine increment atomically.
    """

    def __init__(self) -> None:
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(identity: str, tool: str, args: dict | None) -> str:
        return f"{identity}:{tool}:{_args_fingerprint(args)}"

    def check(self, identity: str, tool: str, args: dict | None) -> dict | None:
        """Return a structured error dict if the breaker is open, else None.

        Does not mutate state — calling ``check`` while open does not extend the
        cooldown, so a looping agent cannot keep the circuit open forever.
        """
        key = self._key(identity, tool, args)
        now = time.time()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or now >= entry.open_until:
                return None
            resets_in = round(entry.open_until - now)
        return {
            "error": (
                f"Tool '{tool}' has failed {_threshold()} times in a row with "
                f"identical arguments. Automatic retries are paused for "
                f"{resets_in}s. Stop retrying — ask the human operator to verify "
                f"the parameters (e.g. index name, agent ID, query syntax) before "
                f"calling this tool again."
            ),
            "retry": False,
            "circuit_open": True,
            "tool": tool,
            "circuit_resets_in_seconds": resets_in,
        }

    def record_failure(self, identity: str, tool: str, args: dict | None) -> None:
        key = self._key(identity, tool, args)
        now = time.time()
        threshold = _threshold()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = _Entry()
                self._entries[key] = entry
            elif entry.open_until and now >= entry.open_until:
                # Cooldown elapsed since it last opened — start a fresh streak.
                entry.consecutive_failures = 0
                entry.open_until = 0.0
            entry.consecutive_failures += 1
            entry.last_failure = now
            if entry.consecutive_failures >= threshold:
                entry.open_until = now + _reset_seconds()

    def record_success(self, identity: str, tool: str, args: dict | None) -> None:
        key = self._key(identity, tool, args)
        with self._lock:
            self._entries.pop(key, None)

    def open_circuits(self) -> list[dict]:
        """Return the currently-open circuits — surfaced via server metrics."""
        now = time.time()
        with self._lock:
            return [
                {
                    "key": key,
                    "consecutive_failures": entry.consecutive_failures,
                    "circuit_resets_in_seconds": round(entry.open_until - now),
                }
                for key, entry in self._entries.items()
                if now < entry.open_until
            ]

    def reset(self) -> None:
        """Clear all tracked state (test/admin use)."""
        with self._lock:
            self._entries.clear()


# Module-level singleton — imported by the tool middleware.
tool_failure_breaker = ToolFailureBreaker()
