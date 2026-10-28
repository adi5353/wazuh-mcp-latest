"""F4: SOAR / ServiceNow integrations must reuse a pooled httpx client.

Previously each call opened (and closed) a fresh AsyncClient, paying a TLS
handshake per request. These tests assert the client is a reused singleton and
that close_* tears it down.
"""
import os

import pytest
from unittest.mock import patch

import wazuh_mcp.tools.notifications as notif
import wazuh_mcp.tools.servicenow as snow


@pytest.mark.asyncio
async def test_soar_client_is_reused():
    await notif.close_soar_client()
    c1 = notif._get_soar_client()
    c2 = notif._get_soar_client()
    assert c1 is c2, "SOAR client should be a reused singleton, not per-call"
    assert not c1.is_closed
    await notif.close_soar_client()
    assert notif._SOAR_CLIENT is None
    # Recreated lazily after close.
    c3 = notif._get_soar_client()
    assert c3 is not c1
    await notif.close_soar_client()


@pytest.mark.asyncio
async def test_soar_nullcontext_does_not_close_shared_client():
    await notif.close_soar_client()
    async with notif._soar_client() as client:
        assert not client.is_closed
    # Exiting the `async with` must NOT close the shared pool.
    assert not client.is_closed
    await notif.close_soar_client()


@pytest.mark.asyncio
async def test_servicenow_client_is_reused_when_configured():
    await snow.close_snow_client()
    env = {
        "SERVICENOW_INSTANCE": "acme",
        "SERVICENOW_USER": "svc",
        "SERVICENOW_PASS": "pw",
    }
    with patch.dict(os.environ, env):
        c1, err1 = snow._client()
        c2, err2 = snow._client()
        assert err1 is None and err2 is None
        assert c1 is c2, "ServiceNow client should be a reused singleton"
    await snow.close_snow_client()
    assert snow._SNOW_CLIENT is None


def test_servicenow_unconfigured_returns_error():
    env = {k: "" for k in ("SERVICENOW_INSTANCE", "SERVICENOW_USER", "SERVICENOW_PASS")}
    with patch.dict(os.environ, env):
        client, err = snow._client()
        assert client is None
        assert "not configured" in err
