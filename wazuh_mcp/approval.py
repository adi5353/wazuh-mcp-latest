"""Human-in-the-loop approval store for active response proposals.

Stores pending active response tokens with TTL expiration.
Tokens are created by propose_active_response and consumed by
approve_response / deny_response in tools/active_response.py.

Backend selection:
  - If REDIS_URL is set: uses redis.asyncio with SETEX for TTL-based expiry.
    Key pattern: "wazuh-mcp:approval:{token}"
  - Otherwise: falls back to an in-memory dict and emits a startup WARNING.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time

log = logging.getLogger(__name__)

_REDIS_URL = os.getenv("REDIS_URL")
_KEY_PREFIX = "wazuh-mcp:approval:"

if not _REDIS_URL:
    _allow_writes = os.getenv("WAZUH_ALLOW_WRITES", "false").lower() == "true"
    if _allow_writes:
        log.warning(
            "ApprovalStore using in-memory backend — pending approvals lost on restart. "
            "Set REDIS_URL for persistence."
        )


class ApprovalStore:
    """Dual-backend approval store: Redis when REDIS_URL is set, else in-memory."""

    _DEFAULT_TTL = 300  # 5 minutes

    def __init__(self) -> None:
        self._pending: dict[str, dict] = {}
        self._redis = None
        if _REDIS_URL:
            try:
                import redis.asyncio as aioredis  # type: ignore[import-untyped]
                self._redis = aioredis.from_url(_REDIS_URL, decode_responses=True)
                log.info("ApprovalStore using Redis backend at %s", _REDIS_URL)
            except ImportError:
                log.warning(
                    "REDIS_URL is set but 'redis' package is not installed. "
                    "Falling back to in-memory ApprovalStore. "
                    "Install with: pip install redis[asyncio]"
                )

    def create(self, action: str, params: dict, ttl: int = _DEFAULT_TTL) -> str:
        """Create a pending approval and return the opaque token."""
        token = secrets.token_urlsafe(16)
        entry = {
            "action": action,
            "params": params,
            "status": "pending",
            "created_at": time.time(),
            "expire_at": time.time() + ttl,
        }
        if self._redis is not None:
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                self._redis.setex(_KEY_PREFIX + token, ttl, json.dumps(entry))
            )
        else:
            self._pending[token] = entry
        log.info("Approval token created action=%s token=%s ttl=%ds", action, token, ttl)
        return token

    async def acreate(self, action: str, params: dict, ttl: int = _DEFAULT_TTL) -> str:
        """Async version of create."""
        token = secrets.token_urlsafe(16)
        entry = {
            "action": action,
            "params": params,
            "status": "pending",
            "created_at": time.time(),
            "expire_at": time.time() + ttl,
        }
        if self._redis is not None:
            await self._redis.setex(_KEY_PREFIX + token, ttl, json.dumps(entry))
        else:
            self._pending[token] = entry
        log.info("Approval token created action=%s token=%s ttl=%ds", action, token, ttl)
        return token

    def approve(self, token: str) -> dict | None:
        """Pop and return the entry if the token is valid and not expired."""
        if self._redis is not None:
            import asyncio
            return asyncio.get_event_loop().run_until_complete(self.aapprove(token))
        entry = self._pending.pop(token, None)
        if entry is None:
            return None
        if time.time() > entry["expire_at"]:
            log.warning("Approval token %s expired before approval", token)
            return None
        log.info("Approval token approved token=%s", token)
        return entry

    async def aapprove(self, token: str) -> dict | None:
        """Async version of approve."""
        if self._redis is not None:
            key = _KEY_PREFIX + token
            raw = await self._redis.get(key)
            if raw is None:
                return None
            await self._redis.delete(key)
            entry = json.loads(raw)
            if time.time() > entry["expire_at"]:
                log.warning("Approval token %s expired before approval", token)
                return None
            log.info("Approval token approved token=%s", token)
            return entry
        entry = self._pending.pop(token, None)
        if entry is None:
            return None
        if time.time() > entry["expire_at"]:
            log.warning("Approval token %s expired before approval", token)
            return None
        log.info("Approval token approved token=%s", token)
        return entry

    def deny(self, token: str) -> bool:
        """Remove a pending entry and return True if it existed."""
        if self._redis is not None:
            import asyncio
            return asyncio.get_event_loop().run_until_complete(self.adeny(token))
        entry = self._pending.pop(token, None)
        if entry is not None:
            log.info("Approval token denied token=%s", token)
            return True
        return False

    async def adeny(self, token: str) -> bool:
        """Async version of deny."""
        if self._redis is not None:
            deleted = await self._redis.delete(_KEY_PREFIX + token)
            if deleted:
                log.info("Approval token denied token=%s", token)
                return True
            return False
        entry = self._pending.pop(token, None)
        if entry is not None:
            log.info("Approval token denied token=%s", token)
            return True
        return False

    def expire_stale(self) -> int:
        """Remove entries past their TTL. Returns count removed. (In-memory only; Redis uses SETEX TTL.)"""
        if self._redis is not None:
            return 0  # Redis handles expiry automatically via SETEX
        now = time.time()
        stale = [t for t, e in self._pending.items() if now > e["expire_at"]]
        for t in stale:
            del self._pending[t]
        return len(stale)

    def list_pending(self) -> list[dict]:
        """Return all pending (non-expired) approvals for admin inspection."""
        if self._redis is not None:
            import asyncio
            return asyncio.get_event_loop().run_until_complete(self.alist_pending())
        now = time.time()
        return [
            {
                "token": token,
                "action": e["action"],
                "params": e["params"],
                "expires_in_seconds": max(0, round(e["expire_at"] - now)),
            }
            for token, e in self._pending.items()
            if now <= e["expire_at"]
        ]

    async def alist_pending(self) -> list[dict]:
        """Async version of list_pending."""
        if self._redis is not None:
            keys = await self._redis.keys(_KEY_PREFIX + "*")
            result = []
            now = time.time()
            for key in keys:
                raw = await self._redis.get(key)
                if raw:
                    entry = json.loads(raw)
                    token = key[len(_KEY_PREFIX):]
                    result.append({
                        "token": token,
                        "action": entry["action"],
                        "params": entry["params"],
                        "expires_in_seconds": max(0, round(entry["expire_at"] - now)),
                    })
            return result
        return self.list_pending()


# Module-level singleton shared across all tool registrations
approval_store = ApprovalStore()
