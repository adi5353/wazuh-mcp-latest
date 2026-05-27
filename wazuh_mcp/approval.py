"""Human-in-the-loop approval store for active response proposals.

Stores pending active response tokens with TTL expiration.
Tokens are created by propose_active_response and consumed by
approve_response / deny_response in tools/active_response.py.
"""
from __future__ import annotations

import logging
import secrets
import time

log = logging.getLogger(__name__)


class ApprovalStore:
    """In-memory store for pending active response approvals."""

    _DEFAULT_TTL = 300  # 5 minutes

    def __init__(self) -> None:
        self._pending: dict[str, dict] = {}

    def create(self, action: str, params: dict, ttl: int = _DEFAULT_TTL) -> str:
        """Create a pending approval and return the opaque token."""
        token = secrets.token_urlsafe(16)
        self._pending[token] = {
            "action": action,
            "params": params,
            "status": "pending",
            "created_at": time.time(),
            "expire_at": time.time() + ttl,
        }
        log.info("Approval token created action=%s token=%s ttl=%ds", action, token, ttl)
        return token

    def approve(self, token: str) -> dict | None:
        """Pop and return the entry if the token is valid and not expired."""
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
        entry = self._pending.pop(token, None)
        if entry is not None:
            log.info("Approval token denied token=%s", token)
            return True
        return False

    def expire_stale(self) -> int:
        """Remove entries past their TTL. Returns count removed."""
        now = time.time()
        stale = [t for t, e in self._pending.items() if now > e["expire_at"]]
        for t in stale:
            del self._pending[t]
        return len(stale)

    def list_pending(self) -> list[dict]:
        """Return all pending (non-expired) approvals for admin inspection."""
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


# Module-level singleton shared across all tool registrations
approval_store = ApprovalStore()
