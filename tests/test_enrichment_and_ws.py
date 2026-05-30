"""Tests for the alert enrichment pipeline and the WebSocket alert streamer."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from wazuh_mcp.enrichment import pipeline as P
from wazuh_mcp import ws_alerts


# ── Enrichment helpers ─────────────────────────────────────────────────────────
def test_src_ip_extraction_variants():
    assert P._src_ip({"data": {"srcip": "1.1.1.1"}}) == "1.1.1.1"
    assert P._src_ip({"data": {"src_ip": "2.2.2.2"}}) == "2.2.2.2"
    assert P._src_ip({"_source": {"data": {"srcip": "3.3.3.3"}}}) == "3.3.3.3"
    assert P._src_ip({"data": {}}) is None


def test_rule_id_and_technique_ids():
    assert P._rule_id({"rule": {"id": 5710}}) == "5710"
    assert P._rule_id({"rule": {}}) is None
    assert P._technique_ids({"rule": {"mitre": {"id": ["T1110"]}}}) == ["T1110"]
    assert P._technique_ids({"rule": {"mitre": {"id": "T1078"}}}) == ["T1078"]
    assert P._technique_ids({"rule": {}}) == []


@pytest.mark.asyncio
async def test_enrich_agent_context_populates_enrichment():
    wz = MagicMock()
    wz.request = AsyncMock(return_value={
        "data": {"affected_items": [{
            "name": "srv1", "os": {"name": "Ubuntu"}, "group": ["linux"],
            "lastKeepAlive": "2024-01-01", "status": "active",
        }]}
    })
    alert = {"agent": {"id": "001"}}
    await P._enrich_agent_context(alert, wz=wz)
    assert alert["enrichment"]["agent"]["name"] == "srv1"
    assert alert["enrichment"]["agent"]["os"] == "Ubuntu"


@pytest.mark.asyncio
async def test_enrich_agent_context_skips_manager_and_missing():
    wz = MagicMock()
    wz.request = AsyncMock(return_value={})
    alert = {"agent": {"id": "000"}}
    await P._enrich_agent_context(alert, wz=wz)
    assert "enrichment" not in alert
    # No wz at all → silent skip
    await P._enrich_agent_context({"agent": {"id": "001"}}, wz=None)


@pytest.mark.asyncio
async def test_enrich_mitre_adds_technique_data():
    alert = {"rule": {"mitre": {"id": ["T1110"]}}}
    await P._enrich_mitre(alert)
    assert "mitre" in alert["enrichment"]


@pytest.mark.asyncio
async def test_enrich_frequency_marks_noisy():
    idx = MagicMock()
    idx.count = AsyncMock(return_value=150)
    cfg = MagicMock()
    alert = {"rule": {"id": "5710"}}
    await P._enrich_frequency(alert, idx=idx, cfg=cfg)
    assert alert["enrichment"]["frequency"]["noisy"] is True
    assert alert["enrichment"]["frequency"]["count_7d"] == 150


@pytest.mark.asyncio
async def test_enrich_frequency_skips_without_idx():
    await P._enrich_frequency({"rule": {"id": "1"}}, idx=None, cfg=None)


@pytest.mark.asyncio
async def test_enrich_reputation_skips_private_ip():
    alert = {"data": {"srcip": "10.0.0.5"}}
    cfg = MagicMock()
    await P._enrich_reputation(alert, cfg=cfg)
    assert "enrichment" not in alert


@pytest.mark.asyncio
async def test_pipeline_run_and_batch():
    wz = MagicMock()
    wz.request = AsyncMock(return_value={"data": {"affected_items": [{"name": "a"}]}})
    idx = MagicMock()
    idx.count = AsyncMock(return_value=3)
    cfg = MagicMock()
    pipe = P.EnrichmentPipeline(wz=wz, idx=idx, cfg=cfg)
    alert = {"agent": {"id": "001"}, "rule": {"id": "5710", "mitre": {"id": ["T1110"]}},
             "data": {"srcip": "10.0.0.5"}}
    out = await pipe.run(dict(alert))
    assert "enrichment" in out

    batch = await pipe.run_batch([dict(alert), dict(alert)], max_concurrent=2)
    assert len(batch) == 2


@pytest.mark.asyncio
async def test_module_convenience_functions():
    idx = MagicMock()
    idx.count = AsyncMock(return_value=1)
    cfg = MagicMock()
    out = await P.enrich_alert({"rule": {"id": "1"}}, idx=idx, cfg=cfg)
    assert isinstance(out, dict)
    batch = await P.enrich_alerts_batch([{"rule": {"id": "1"}}], idx=idx, cfg=cfg)
    assert len(batch) == 1


# ── WebSocket alert streamer ────────────────────────────────────────────────────
class _FakeWS:
    """Minimal Starlette-WebSocket stand-in driving a few loop iterations."""

    def __init__(self, query=None, recv_frames=None, search_results=None):
        self.query_params = query or {}
        self._recv = list(recv_frames or [])
        self.sent: list = []
        self.accepted = False
        self.closed = False
        self._search_results = list(search_results or [])
        self._max_sends = 6

    async def accept(self):
        self.accepted = True

    async def receive_text(self):
        if self._recv:
            return self._recv.pop(0)
        raise asyncio.TimeoutError()

    async def send_json(self, obj):
        self.sent.append(obj)
        if len(self.sent) >= self._max_sends:
            raise RuntimeError("client disconnect")

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_ws_alerts_streams_then_disconnects(monkeypatch):
    # Avoid real sleeps inside the poll loop.
    async def _no_sleep(*_a, **_k):
        return None
    monkeypatch.setattr(ws_alerts.asyncio, "sleep", _no_sleep)

    idx = MagicMock()
    idx.search = AsyncMock(return_value={"hits": {"hits": [
        {"_source": {"timestamp": "2030-01-01T00:00:01.000Z", "rule": {"level": 9}}},
    ]}})
    cfg = MagicMock()

    ws = _FakeWS(query={"min_level": "7", "agent_id": "001", "interval": "2"})
    await ws_alerts.ws_alerts_handler(ws, idx=idx, cfg=cfg)

    assert ws.accepted and ws.closed
    assert any(m.get("type") == "alert" for m in ws.sent)


@pytest.mark.asyncio
async def test_ws_alerts_handles_search_error(monkeypatch):
    async def _no_sleep(*_a, **_k):
        return None
    monkeypatch.setattr(ws_alerts.asyncio, "sleep", _no_sleep)

    idx = MagicMock()
    idx.search = AsyncMock(side_effect=RuntimeError("opensearch down"))
    cfg = MagicMock()

    ws = _FakeWS(query={}, recv_frames=['{"min_level": 5}'])
    await ws_alerts.ws_alerts_handler(ws, idx=idx, cfg=cfg)
    assert any(m.get("type") == "error" for m in ws.sent)


def test_mount_ws_route_appends_route():
    routes: list = []
    ws_alerts.mount_ws_route(routes, idx=MagicMock(), cfg=MagicMock())
    assert len(routes) == 1
    assert routes[0].path == "/ws/alerts"
