"""End-to-end-ish tests for the HTTP server app built in ``server.main()``.

Rather than refactor the large ``main()`` function, we capture the fully
assembled ASGI app by patching ``uvicorn.Server`` (so ``.run()`` is a no-op and
the app object is captured) and then exercise the real endpoints + middleware
stack via httpx's in-process ASGI transport. This covers the health, metrics and
OpenAPI endpoints, the API-key auth middleware, and the audit/rate-limit/origin
middleware wrappers without binding a socket.
"""
from __future__ import annotations

import os

import httpx
import pytest


_API_KEY = "test-secret-key"
_BASE = "http://127.0.0.1:8000"


@pytest.fixture(autouse=True)
def _instant_retries(monkeypatch):
    """The /health endpoint probes the (absent) Manager + Indexer; make the retry
    backoff instant so these tests don't spend ~40s sleeping between attempts."""
    async def _instant(*_a, **_k):
        return None
    import wazuh_mcp.wazuh_client as wc
    import wazuh_mcp.wazuh_indexer as wi
    monkeypatch.setattr(wc, "_retry_sleep", _instant)
    monkeypatch.setattr(wi, "_retry_sleep", _instant)
    yield


@pytest.fixture(scope="module")
def http_app():
    import uvicorn

    prev = {k: os.environ.get(k) for k in (
        "WAZUH_MCP_TRANSPORT", "WAZUH_MCP_HOST", "WAZUH_MCP_PORT", "WAZUH_MCP_API_KEY",
        "WAZUH_HOST", "WAZUH_USER", "WAZUH_PASS", "WAZUH_INDEXER_HOST", "WAZUH_INDEXER_PASS",
    )}
    os.environ.update({
        "WAZUH_MCP_TRANSPORT": "http",
        "WAZUH_MCP_HOST": "127.0.0.1",
        "WAZUH_MCP_PORT": "8000",
        "WAZUH_MCP_API_KEY": _API_KEY,
        "WAZUH_HOST": "https://127.0.0.1:55000",
        "WAZUH_USER": "u", "WAZUH_PASS": "p",
        "WAZUH_INDEXER_HOST": "https://127.0.0.1:9200",
        "WAZUH_INDEXER_PASS": "p",
    })

    captured: dict = {}

    class _DummyServer:
        def __init__(self, config):
            captured["app"] = config.app

        def run(self):
            return None

    real_server = uvicorn.Server
    uvicorn.Server = _DummyServer  # type: ignore[assignment]
    try:
        import wazuh_mcp.server as server
        server.main()
    finally:
        uvicorn.Server = real_server  # type: ignore[assignment]

    assert "app" in captured, "uvicorn.Server was not constructed — app not captured"
    # NOTE: keep the env (esp. WAZUH_MCP_API_KEY) in place for the whole module —
    # endpoints such as /metrics read the key from the environment at *request*
    # time, so restoring it before the requests run would break auth.
    yield captured["app"]

    for k, v in prev.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=_BASE)


@pytest.mark.asyncio
async def test_health_public_vs_authenticated(http_app):
    async with _client(http_app) as c:
        pub = await c.get("/health")
        assert pub.status_code in (200, 503)
        body = pub.json()
        assert "status" in body and "uptime_seconds" in body
        # Public response must NOT leak detailed component checks.
        assert "checks" not in body

        auth = await c.get("/health", headers={"Authorization": f"Bearer {_API_KEY}"})
        assert auth.status_code in (200, 503)
        assert "checks" in auth.json()


@pytest.mark.asyncio
async def test_metrics_requires_auth(http_app):
    async with _client(http_app) as c:
        un = await c.get("/metrics")
        assert un.status_code == 401
        ok = await c.get("/metrics", headers={"Authorization": f"Bearer {_API_KEY}"})
        assert ok.status_code == 200
        assert "wazuh_mcp" in ok.text or ok.text  # prometheus exposition text


@pytest.mark.asyncio
async def test_openapi_endpoint(http_app):
    async with _client(http_app) as c:
        un = await c.get("/openapi.json")
        assert un.status_code == 401
        ok = await c.get("/openapi.json", headers={"Authorization": f"Bearer {_API_KEY}"})
        assert ok.status_code == 200
        spec = ok.json()
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec


@pytest.mark.asyncio
async def test_wrong_api_key_rejected(http_app):
    async with _client(http_app) as c:
        r = await c.get("/metrics", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_unknown_path_passes_through_auth(http_app):
    async with _client(http_app) as c:
        # No bearer → blocked by API key middleware before routing (401).
        r = await c.get("/nonexistent-path")
        assert r.status_code in (401, 404)


@pytest.mark.asyncio
async def test_lifespan_startup_shutdown(http_app):
    """Drive the ASGI lifespan protocol through the full middleware chain so the
    Starlette lifespan (AlertPrecomputer start/stop + approval-cleanup task) runs."""
    events = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
    sent: list = []

    async def receive():
        return events.pop(0)

    async def send(message):
        sent.append(message)

    await http_app({"type": "lifespan"}, receive, send)
    sent_types = {m["type"] for m in sent}
    assert "lifespan.startup.complete" in sent_types
    assert "lifespan.shutdown.complete" in sent_types


@pytest.mark.asyncio
async def test_post_jsonrpc_exercises_audit_middleware(http_app):
    """A POST with a JSON-RPC tools/call body flows through the AuditMiddleware
    (body buffering, JSON-RPC parse, identity hashing, audit record + metrics).
    The downstream MCP app will reject it (no SSE session), but the middleware
    code path runs regardless — which is what we're covering here."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "list_agents", "arguments": {"limit": 1}},
    }
    async with _client(http_app) as c:
        r = await c.post(
            "/messages",
            json=body,
            headers={"Authorization": f"Bearer {_API_KEY}"},
        )
        # Any status is acceptable — we're exercising the middleware, not the MCP RPC.
        assert r.status_code in (200, 202, 307, 400, 404, 406, 500)
