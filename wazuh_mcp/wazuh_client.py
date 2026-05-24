"""Wazuh Manager REST API client. Handles JWT auth and token refresh."""
from __future__ import annotations
import base64
import logging
import time
from typing import Any, Optional

import httpx

from .config import Config

log = logging.getLogger(__name__)

# Wazuh JWT tokens default to 900 seconds; refresh ~100s early for safety.
TOKEN_TTL_SECONDS = 800


class WazuhClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._token: Optional[str] = None
        self._token_expires: float = 0.0
        # Use CA bundle when provided, otherwise fall back to verify_ssl flag.
        self._ssl: bool | str = cfg.ca_bundle if cfg.ca_bundle else cfg.verify_ssl

    async def _login(self) -> None:
        auth = base64.b64encode(
            f"{self.cfg.manager_user}:{self.cfg.manager_pass}".encode()
        ).decode()
        async with httpx.AsyncClient(verify=self._ssl) as c:
            r = await c.post(
                f"{self.cfg.manager_host}/security/user/authenticate",
                headers={"Authorization": f"Basic {auth}"},
                timeout=10,
            )
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            self._token_expires = time.time() + TOKEN_TTL_SECONDS
            log.info("Wazuh Manager: authenticated, token cached")

    async def request(self, method: str, path: str, **kwargs: Any) -> dict:
        if not self._token or time.time() > self._token_expires:
            await self._login()

        async def do_call(client: httpx.AsyncClient) -> httpx.Response:
            return await client.request(
                method,
                f"{self.cfg.manager_host}{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self.cfg.request_timeout,
                **kwargs,
            )

        async with httpx.AsyncClient(verify=self._ssl) as c:
            r = await do_call(c)
            if r.status_code == 401:
                log.info("Wazuh Manager: token rejected, re-authenticating")
                await self._login()
                r = await do_call(c)
            r.raise_for_status()
            return r.json()
