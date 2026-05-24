"""API circuit breaker + daily quota tracker for third-party threat intel APIs.

Protects VirusTotal (500 req/day free) and AbuseIPDB (1000 req/day free) from
quota exhaustion. Also implements a circuit breaker that pauses an API after
N consecutive failures, preventing cascading timeouts.

Configuration (env vars):
    VIRUSTOTAL_DAILY_LIMIT    — default 450  (leave buffer below 500)
    ABUSEIPDB_DAILY_LIMIT     — default 900  (leave buffer below 1000)
    TI_CIRCUIT_FAIL_THRESHOLD — consecutive failures before opening circuit (default 5)
    TI_CIRCUIT_RESET_SECONDS  — seconds to wait before retrying (default 300)

Usage::

    from .circuit_breaker import breaker

    async def _vt_get(path):
        if not breaker.allow("virustotal"):
            return None          # circuit open or quota exhausted
        try:
            result = await _do_vt_call(path)
            breaker.record_success("virustotal")
            return result
        except Exception as exc:
            breaker.record_failure("virustotal")
            raise
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field


# ── Per-API state ─────────────────────────────────────────────────────────────

@dataclass
class _APIState:
    name: str
    daily_limit: int

    # Daily quota tracking
    request_count: int = 0
    quota_reset_at: float = field(default_factory=time.time)

    # Circuit breaker
    consecutive_failures: int = 0
    circuit_open_until: float = 0.0   # epoch; 0 = circuit closed

    def _reset_quota_if_new_day(self) -> None:
        now = time.time()
        if now - self.quota_reset_at >= 86400:
            self.request_count = 0
            self.quota_reset_at = now

    @property
    def quota_exhausted(self) -> bool:
        self._reset_quota_if_new_day()
        return self.request_count >= self.daily_limit

    @property
    def circuit_open(self) -> bool:
        return time.time() < self.circuit_open_until

    @property
    def requests_remaining(self) -> int:
        self._reset_quota_if_new_day()
        return max(0, self.daily_limit - self.request_count)

    def allow(self) -> bool:
        if self.circuit_open:
            return False
        if self.quota_exhausted:
            return False
        self._reset_quota_if_new_day()
        self.request_count += 1
        return True

    def record_success(self) -> None:
        self.consecutive_failures = 0

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        threshold = int(os.getenv("TI_CIRCUIT_FAIL_THRESHOLD", "5"))
        if self.consecutive_failures >= threshold:
            reset_secs = int(os.getenv("TI_CIRCUIT_RESET_SECONDS", "300"))
            self.circuit_open_until = time.time() + reset_secs
            self.consecutive_failures = 0

    def status(self) -> dict:
        self._reset_quota_if_new_day()
        return {
            "api": self.name,
            "requests_today": self.request_count,
            "daily_limit": self.daily_limit,
            "requests_remaining": self.requests_remaining,
            "quota_exhausted": self.quota_exhausted,
            "circuit_open": self.circuit_open,
            "circuit_resets_in_seconds": (
                max(0, round(self.circuit_open_until - time.time()))
                if self.circuit_open else 0
            ),
        }


# ── Global registry ───────────────────────────────────────────────────────────

class CircuitBreakerRegistry:
    """Central registry for all third-party API states."""

    def __init__(self) -> None:
        self._apis: dict[str, _APIState] = {}

    def _get(self, name: str) -> _APIState:
        if name not in self._apis:
            limits = {
                "virustotal": int(os.getenv("VIRUSTOTAL_DAILY_LIMIT", "450")),
                "abuseipdb":  int(os.getenv("ABUSEIPDB_DAILY_LIMIT",  "900")),
            }
            self._apis[name] = _APIState(
                name=name,
                daily_limit=limits.get(name, 500),
            )
        return self._apis[name]

    def allow(self, api: str) -> bool:
        """Return True if the API is available and quota remains. Increments counter."""
        return self._get(api).allow()

    def record_success(self, api: str) -> None:
        self._get(api).record_success()

    def record_failure(self, api: str) -> None:
        self._get(api).record_failure()

    def status(self, api: str | None = None) -> dict:
        """Return status for one API or all registered APIs."""
        if api:
            return self._get(api).status()
        return {name: state.status() for name, state in self._apis.items()}

    def reset(self, api: str) -> None:
        """Force-reset an API's circuit and quota counter (admin use)."""
        if api in self._apis:
            s = self._apis[api]
            s.consecutive_failures = 0
            s.circuit_open_until = 0.0
            s.request_count = 0


# Module-level singleton
breaker = CircuitBreakerRegistry()
