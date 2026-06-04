"""Shared HTTP retry/backoff policy for the Wazuh Manager and Indexer clients.

Single source of truth so the two backend clients can't drift on retry behaviour.
Connection-pool sizes remain per-client (different env vars and workloads) and are
intentionally NOT centralized here.

Policy: 3 attempts — delays of ~1s, ~2s, ~4s (capped at 10s) + randomised ±1s jitter.
"""
from __future__ import annotations

import asyncio
import logging
import random

import httpx

log = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BASE = 1.0   # seconds — first delay before jitter
RETRY_CAP = 10.0   # seconds — maximum delay before jitter


def is_retryable(exc: Exception) -> bool:
    """True when an exception warrants a retry (transient network error, 5xx, 429)."""
    if isinstance(exc, httpx.RequestError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status >= 500 or status == 429
    return False


# Methods with no side effects — safe to retry on any transient error.
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Failures where the request provably never reached the server (the connection
# was never established), so even a non-idempotent write is safe to retry.
_CONNECTION_PHASE_ERRORS = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)


def is_retryable_for_method(exc: Exception, method: str) -> bool:
    """Retry decision that respects HTTP idempotency.

    Idempotent reads (GET/HEAD/OPTIONS) retry on any transient error. For
    non-idempotent writes (POST/PUT/DELETE/PATCH) we retry ONLY when the request
    is known to have never reached the server — a connection-establishment
    failure — and never on a read timeout or 5xx, where the Manager may already
    have applied the change. This prevents a timed-out active-response or agent
    restart from being silently re-sent and firing twice.
    """
    if method.upper() in _IDEMPOTENT_METHODS:
        return is_retryable(exc)
    return isinstance(exc, _CONNECTION_PHASE_ERRORS)


def backoff_delay(attempt: int) -> float:
    """Exponential backoff with ±1s uniform jitter."""
    return min(RETRY_BASE * (2 ** attempt), RETRY_CAP) + random.uniform(0, 1)


async def retry_sleep(attempt: int, *, label: str) -> None:
    """Log a transient-error warning and sleep for the backoff delay."""
    delay = backoff_delay(attempt)
    log.warning("%s: transient error on attempt %d/%d — retrying in %.1fs",
                label, attempt + 1, MAX_RETRIES, delay)
    await asyncio.sleep(delay)
