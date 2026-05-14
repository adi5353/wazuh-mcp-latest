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

    async def search(self, body: dict, index: Optional[str] = None) -> dict:
        idx = index or self.cfg.alerts_index
        async with httpx.AsyncClient(
            verify=self.cfg.verify_ssl,
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
            verify=self.cfg.verify_ssl,
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
