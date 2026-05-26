"""Wazuh Indexer (OpenSearch) client. Used for alerts and vulnerability state.

Connection pooling:
  A single httpx.AsyncClient is shared across all requests (20 max connections,
  10 keepalive). Call aclose() / use as async context manager on server shutdown.
"""
from __future__ import annotations
import logging
from typing import Any, Optional

import httpx

from .config import Config

log = logging.getLogger(__name__)

# ── Connection pool limits ─────────────────────────────────────────────────────
_POOL_MAX_CONNECTIONS   = 20
_POOL_MAX_KEEPALIVE     = 10


class WazuhIndexer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        # Use CA bundle when provided, otherwise fall back to verify_ssl flag.
        self._ssl: bool | str = cfg.ca_bundle if cfg.ca_bundle else cfg.verify_ssl
        # Persistent connection pool with Basic auth set at client level.
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

    async def search(self, body: dict, index: Optional[str] = None) -> dict:
        idx = index or self.cfg.alerts_index
        r = await self._client.post(
            f"{self.cfg.indexer_host}/{idx}/_search",
            json=body,
        )
        r.raise_for_status()
        return r.json()

    async def count(self, query: dict, index: Optional[str] = None) -> int:
        idx = index or self.cfg.alerts_index
        r = await self._client.post(
            f"{self.cfg.indexer_host}/{idx}/_count",
            json={"query": query},
        )
        r.raise_for_status()
        return r.json()["count"]
