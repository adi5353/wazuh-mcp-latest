"""Regression tests for domain normalization in threat_intel.enrich_domain.

Guards the bug where ``str.lstrip("https://")`` stripped a *character set*
rather than the prefix, mangling hostnames like "stackoverflow.com" into
"ackoverflow.com" before the VirusTotal lookup.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from wazuh_mcp import tool_context as _tc
from wazuh_mcp.tools import threat_intel


def _register_threat_intel():
    """Register threat_intel tools against a minimal mocked ToolContext."""
    reg: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: reg.setdefault(fn.__name__, fn) or fn)
    ctx = _tc.ToolContext(
        mcp=mcp, wz=MagicMock(), idx=MagicMock(), cfg=MagicMock(),
        cap=lambda n: n,
        require_writes=lambda: None,
        truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [],
        geoip_lookup=lambda ip: {},
        incident_recommendations=lambda a: [],
    )
    threat_intel.register(ctx)
    return reg


@pytest.mark.parametrize("given,expected", [
    ("https://stackoverflow.com", "stackoverflow.com"),
    ("http://shop.example.com/path?q=1", "shop.example.com"),
    ("HTTPS://Example.COM", "Example.COM"),
    ("example.com", "example.com"),
])
def test_enrich_domain_strips_scheme_without_mangling_host(monkeypatch, given, expected):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    captured: dict = {}

    async def _fake_vt_get(path: str):
        captured["path"] = path
        return None  # short-circuits to a deterministic dict that echoes `domain`

    monkeypatch.setattr(threat_intel, "_vt_get", _fake_vt_get)

    reg = _register_threat_intel()
    result = asyncio.run(reg["enrich_domain"](given))

    # The hostname handed to VirusTotal — and echoed back — must be intact.
    assert result["domain"] == expected
    assert captured["path"] == f"domains/{expected}"
