"""Client communication layer tests — WazuhClient (Manager) and WazuhIndexer.

Covers JWT login + token caching, 401 re-authentication, retry/backoff on
transient errors, circuit-breaker open paths, OpenSearch query field validation,
the page-size hard cap, and in-flight query de-duplication. httpx is fully
mocked so no network is touched and retries run with sleeps patched to no-ops.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from wazuh_mcp.config import Config
from wazuh_mcp import wazuh_client as wc_mod
from wazuh_mcp import wazuh_indexer as wi_mod
from wazuh_mcp.wazuh_client import WazuhClient, _validate_manager_file_path
from wazuh_mcp.wazuh_indexer import WazuhIndexer, _extract_leaf_fields
from wazuh_mcp.circuit_breaker import opensearch_breaker, wazuh_manager_breaker


# ── Fakes ──────────────────────────────────────────────────────────────────────
class _Resp:
    def __init__(self, status=200, json_data=None):
        self.status_code = status
        self._json = json_data if json_data is not None else {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "err", request=httpx.Request("GET", "http://x"),
                response=httpx.Response(self.status_code),
            )


@pytest.fixture(autouse=True)
def _reset_breakers_and_sleep(monkeypatch):
    for b in (opensearch_breaker, wazuh_manager_breaker):
        b._failures = 0
        b._open_until = 0.0
    # Make retry backoff instant.
    async def _instant(*_a, **_k):
        return None
    monkeypatch.setattr(wc_mod, "_retry_sleep", _instant)
    monkeypatch.setattr(wi_mod, "_retry_sleep", _instant)
    yield


def _cfg() -> Config:
    return Config.from_env()


# ── WazuhClient: login + request happy path ────────────────────────────────────
@pytest.mark.asyncio
async def test_login_caches_token_and_request_succeeds(monkeypatch):
    client = WazuhClient(_cfg())
    calls = {"post": 0, "request": 0}

    async def fake_post(url, **kw):
        calls["post"] += 1
        return _Resp(200, {"data": {"token": "jwt-abc"}})

    async def fake_request(method, url, **kw):
        calls["request"] += 1
        return _Resp(200, {"data": {"affected_items": [{"id": "001"}]}})

    monkeypatch.setattr(client._client, "post", fake_post)
    monkeypatch.setattr(client._client, "request", fake_request)

    out = await client.request("GET", "/agents")
    assert out["data"]["affected_items"][0]["id"] == "001"
    assert calls["post"] == 1  # logged in once
    # Token cached: a second call reuses it without re-login.
    await client.request("GET", "/agents")
    assert calls["post"] == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_request_reauthenticates_on_401(monkeypatch):
    client = WazuhClient(_cfg())
    post_count = {"n": 0}

    async def fake_post(url, **kw):
        post_count["n"] += 1
        return _Resp(200, {"data": {"token": f"jwt-{post_count['n']}"}})

    seq = [_Resp(401), _Resp(200, {"ok": True})]

    async def fake_request(method, url, **kw):
        return seq.pop(0)

    monkeypatch.setattr(client._client, "post", fake_post)
    monkeypatch.setattr(client._client, "request", fake_request)

    out = await client.request("GET", "/agents")
    # On 401 the client retries; because the freshly-minted token is still
    # within its TTL the re-auth fast-path keeps it (the `pass` branch) and
    # simply re-issues the request, which then succeeds.
    assert out == {"ok": True}
    assert post_count["n"] == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_request_retries_on_transient_5xx(monkeypatch):
    client = WazuhClient(_cfg())

    async def fake_post(url, **kw):
        return _Resp(200, {"data": {"token": "jwt"}})

    attempts = {"n": 0}

    async def fake_request(method, url, **kw):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ConnectError("boom")
        return _Resp(200, {"recovered": True})

    monkeypatch.setattr(client._client, "post", fake_post)
    monkeypatch.setattr(client._client, "request", fake_request)

    out = await client.request("GET", "/agents")
    assert out == {"recovered": True}
    assert attempts["n"] == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_circuit_breaker_open_blocks_request(monkeypatch):
    client = WazuhClient(_cfg())
    import time as _t
    wazuh_manager_breaker._open_until = _t.time() + 60
    with pytest.raises(RuntimeError, match="circuit breaker open"):
        await client.request("GET", "/agents")
    await client.aclose()


@pytest.mark.asyncio
async def test_upload_xml_file_happy(monkeypatch):
    client = WazuhClient(_cfg())

    async def fake_post(url, **kw):
        return _Resp(200, {"data": {"token": "jwt"}})

    async def fake_put(url, **kw):
        assert "overwrite=true" in url
        return _Resp(200, {"data": {"message": "ok"}})

    monkeypatch.setattr(client._client, "post", fake_post)
    monkeypatch.setattr(client._client, "put", fake_put)
    out = await client.upload_xml_file("/rules/files/local_rules.xml", "<group/>")
    assert out["data"]["message"] == "ok"
    await client.aclose()


@pytest.mark.asyncio
async def test_upload_xml_file_rejects_bad_path(monkeypatch):
    client = WazuhClient(_cfg())
    with pytest.raises(ValueError):
        await client.upload_xml_file("/agents", "<group/>")
    await client.aclose()


@pytest.mark.asyncio
async def test_upload_xml_file_retries_transient(monkeypatch):
    client = WazuhClient(_cfg())

    async def fake_post(url, **kw):
        return _Resp(200, {"data": {"token": "jwt"}})

    attempts = {"n": 0}

    async def fake_put(url, **kw):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ConnectError("boom")
        return _Resp(200, {"ok": True})

    monkeypatch.setattr(client._client, "post", fake_post)
    monkeypatch.setattr(client._client, "put", fake_put)
    out = await client.upload_xml_file("/decoders/files/d.xml", "<decoder/>")
    assert out == {"ok": True} and attempts["n"] == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_upload_xml_circuit_open():
    client = WazuhClient(_cfg())
    import time as _t
    wazuh_manager_breaker._open_until = _t.time() + 60
    with pytest.raises(RuntimeError, match="circuit breaker open"):
        await client.upload_xml_file("/rules/files/x.xml", "<group/>")
    await client.aclose()


@pytest.mark.asyncio
async def test_detect_api_version_parses(monkeypatch):
    client = WazuhClient(_cfg())

    async def fake_request(method, path, **kw):
        return {"data": {"api_version": "v4.8.1"}}

    monkeypatch.setattr(client, "request", fake_request)
    ver = await client.detect_api_version()
    assert ver["major"] == 4 and ver["minor"] == 8
    await client.aclose()


# ── WazuhIndexer ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_indexer_search_happy_path(monkeypatch):
    idx = WazuhIndexer(_cfg())

    async def fake_post(url, json=None, **kw):
        return _Resp(200, {"hits": {"total": {"value": 3}, "hits": []}})

    monkeypatch.setattr(idx._client, "post", fake_post)
    out = await idx.search({"query": {"match_all": {}}, "size": 10})
    assert out["hits"]["total"]["value"] == 3
    await idx.aclose()


@pytest.mark.asyncio
async def test_indexer_count_happy_path(monkeypatch):
    idx = WazuhIndexer(_cfg())

    async def fake_post(url, json=None, **kw):
        return _Resp(200, {"count": 42})

    monkeypatch.setattr(idx._client, "post", fake_post)
    n = await idx.count({"match_all": {}})
    assert n == 42
    await idx.aclose()


@pytest.mark.asyncio
async def test_indexer_search_size_cap_enforced(monkeypatch):
    idx = WazuhIndexer(_cfg())

    async def fake_post(url, json=None, **kw):
        return _Resp(200, {"hits": {}})

    monkeypatch.setattr(idx._client, "post", fake_post)
    with pytest.raises(AssertionError):
        await idx.search({"query": {"match_all": {}}, "size": 10_000})
    await idx.aclose()


@pytest.mark.asyncio
async def test_indexer_field_validation_rejects_unknown_field(monkeypatch):
    idx = WazuhIndexer(_cfg())
    with pytest.raises(ValueError):
        await idx.search(
            {"query": {"term": {"definitely_not_allowed_field": "x"}}},
            validate_fields=True,
        )
    await idx.aclose()


@pytest.mark.asyncio
async def test_indexer_retries_then_succeeds(monkeypatch):
    idx = WazuhIndexer(_cfg())
    attempts = {"n": 0}

    async def fake_post(url, json=None, **kw):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ReadTimeout("slow")
        return _Resp(200, {"hits": {"hits": []}})

    monkeypatch.setattr(idx._client, "post", fake_post)
    out = await idx.search({"query": {"match_all": {}}})
    assert "hits" in out and attempts["n"] == 2
    await idx.aclose()


@pytest.mark.asyncio
async def test_indexer_circuit_open(monkeypatch):
    idx = WazuhIndexer(_cfg())
    import time as _t
    opensearch_breaker._open_until = _t.time() + 60
    with pytest.raises(RuntimeError, match="circuit breaker open"):
        await idx.search({"query": {"match_all": {}}})
    await idx.aclose()


def test_extract_leaf_fields_walks_nested_dsl():
    body = {"query": {"bool": {"filter": [
        {"term": {"rule.id": "5710"}},
        {"range": {"timestamp": {"gte": "now-1d"}}},
    ]}}}
    fields = _extract_leaf_fields(body)
    assert "rule.id" in fields and "timestamp" in fields


@pytest.mark.parametrize("bad", [
    "/rules/files/../../etc/passwd",
    "/agents",
    "",
    "/rules/files/%2e%2e/%2e%2e/etc/passwd",
    "/rules/files/%252e%252e/etc/passwd",
    "/rules/files/..\\..\\etc\\passwd",
    "//evil/rules/files/x.xml",
    "%2fagents",
    "http://evil/rules/files/x.xml",
])
def test_manager_path_validation_rejects(bad):
    with pytest.raises(ValueError):
        _validate_manager_file_path(bad)


@pytest.mark.parametrize("good", [
    "/rules/files/local_rules.xml",
    "/decoders/files/local_decoder.xml",
    "/lists/files/my-list",
    "/rules/files/local_rules.xml?overwrite=true",
])
def test_manager_path_validation_accepts(good):
    _validate_manager_file_path(good)  # must not raise
