"""Wazuh Indexer (OpenSearch) client. Used for alerts and vulnerability state."""
from __future__ import annotations
import logging
from typing import Optional

import httpx

from .config import Config

log = logging.getLogger(__name__)


class WazuhIndexer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        # Use CA bundle when provided, otherwise fall back to verify_ssl flag.
        self._ssl: bool | str = cfg.ca_bundle if cfg.ca_bundle else cfg.verify_ssl

    async def search(self, body: dict, index: Optional[str] = None) -> dict:
        idx = index or self.cfg.alerts_index
        async with httpx.AsyncClient(
            verify=self._ssl,
            auth=(self.cfg.indexer_user, self.cfg.indexer_pass),
            timeout=self.cfg.request_timeout,
        ) as c:
            r = await c.post(
                f"{self.cfg.indexer_host}/{idx}/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
            return r.json()

    async def count(self, query: dict, index: Optional[str] = None) -> int:
        idx = index or self.cfg.alerts_index
        async with httpx.AsyncClient(
            verify=self._ssl,
            auth=(self.cfg.indexer_user, self.cfg.indexer_pass),
            timeout=self.cfg.request_timeout,
        ) as c:
            r = await c.post(
                f"{self.cfg.indexer_host}/{idx}/_count",
                json={"query": query},
                headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
            return r.json()["count"]
