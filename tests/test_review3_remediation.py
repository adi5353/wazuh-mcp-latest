"""Regression tests for the third-review remediation.

  M1 — KEV/EPSS feed outages surface feed_status instead of looking "clean"
  M2 — aggregation truncation is flagged (results_truncated / controls_truncated)
  M3 — baseline day-counts use a single date_histogram (one search per series)
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wazuh_mcp.tool_context import ToolContext


def _run(coro):
    return asyncio.run(coro)


def _tools(module_name, idx=None, cfg=None):
    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    ctx = ToolContext(
        mcp=mcp, wz=AsyncMock(), idx=idx or AsyncMock(), cfg=cfg or MagicMock(),
        cap=lambda n: n, require_writes=lambda: None, truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda *a, **k: [], tool_registry={}, shared={},
    )
    __import__(module_name, fromlist=["register"]).register(ctx)
    return tools


# ── M1: feed outage ≠ "clean" ─────────────────────────────────────────────────

class TestFeedFailureSurfaced:
    def test_enrich_cve_epss_reports_outage(self):
        import wazuh_mcp.tools.vulnerabilities as v
        tools = _tools("wazuh_mcp.tools.vulnerabilities")
        with patch.object(v, "_fetch_epss", AsyncMock(return_value=None)):
            out = _run(tools["enrich_cve_epss"](["CVE-2021-44228"]))
        assert out.get("feed_status") == "unavailable"
        assert "error" in out  # fails loud, not an empty/low-risk result

    def test_enrich_cve_epss_ok_when_feed_up(self):
        import wazuh_mcp.tools.vulnerabilities as v
        tools = _tools("wazuh_mcp.tools.vulnerabilities")
        with patch.object(v, "_fetch_epss", AsyncMock(return_value={})):
            out = _run(tools["enrich_cve_epss"](["CVE-2021-44228"]))
        # Genuinely-empty EPSS (CVE absent) is NOT an outage.
        assert "error" not in out
        assert out["results"][0]["risk_label"] == "UNKNOWN"

    def test_prioritize_flags_partial_feeds(self):
        import wazuh_mcp.tools.vulnerabilities as v
        idx = AsyncMock()
        idx.search.return_value = {"aggregations": {"by_cve": {"buckets": [
            {"key": "CVE-2021-44228", "agents": {"value": 3}, "avg_cvss": {"value": 9.8},
             "sample": {"hits": {"hits": [{"_source": {
                 "vulnerability": {"severity": "Critical"}, "package": {"name": "log4j"}}}]}}},
        ]}}}
        cfg = MagicMock(); cfg.vuln_index = "wazuh-states-vulnerabilities-*"
        tools = _tools("wazuh_mcp.tools.vulnerabilities", idx=idx, cfg=cfg)
        with patch.object(v, "_fetch_epss", AsyncMock(return_value=None)), \
             patch.object(v, "_fetch_kev", AsyncMock(return_value=None)):
            out = _run(tools["prioritize_patches_with_epss"]())
        assert out["feed_status"] == {"epss": "unavailable", "kev": "unavailable"}
        assert "warning" in out


# ── M2: aggregation truncation flagged ────────────────────────────────────────

class TestAggregationTruncation:
    def test_kev_exposure_truncation_flag(self):
        import wazuh_mcp.tools.vulnerabilities as v
        idx = AsyncMock()
        idx.search.return_value = {"aggregations": {"by_cve": {
            "sum_other_doc_count": 42,  # more CVEs than the cap
            "buckets": [],
        }}}
        cfg = MagicMock(); cfg.vuln_index = "wazuh-states-vulnerabilities-*"
        tools = _tools("wazuh_mcp.tools.vulnerabilities", idx=idx, cfg=cfg)
        with patch.object(v, "_fetch_kev", AsyncMock(return_value={"CVE-X": {}})):
            out = _run(tools["check_kev_exposure"]())
        assert out["results_truncated"] is True
        assert "truncation_warning" in out

    def test_compliance_summary_truncation_flag(self):
        idx = AsyncMock()
        idx.search.return_value = {
            "hits": {"total": {"value": 100}},
            "aggregations": {"by_control": {
                "sum_other_doc_count": 7,
                "buckets": [{"key": "1.1", "doc_count": 5,
                             "top_rules": {"buckets": []}, "top_agents": {"buckets": []}}],
            }},
        }
        tools = _tools("wazuh_mcp.tools.compliance", idx=idx)
        out = _run(tools["compliance_summary"](framework="pci_dss"))
        assert out["controls_truncated"] is True
        assert "truncation_warning" in out


# ── M3: baseline uses one date_histogram per series ───────────────────────────

class TestBaselineHistogram:
    def test_single_search_per_series(self):
        import wazuh_mcp.tools.baseline as b
        idx = AsyncMock()
        idx.search.return_value = {"aggregations": {"per_day": {"buckets": [
            {"doc_count": 3}, {"doc_count": 5}, {"doc_count": 0},
        ]}}}
        wz = AsyncMock()
        wz.request.return_value = {"data": {"affected_items": [
            {"id": "001", "name": "web1", "ip": "10.0.0.1", "status": "active"}]}}
        mcp = MagicMock()
        tools: dict = {}
        mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
        cfg = MagicMock()
        ctx = ToolContext(
            mcp=mcp, wz=wz, idx=idx, cfg=cfg, cap=lambda n: n, require_writes=lambda: None,
            truncate=lambda s, n=300: s, enrich_mitre_ids=lambda ids: [],
            geoip_lookup=AsyncMock(return_value={}), incident_recommendations=lambda *a, **k: [],
            tool_registry={}, shared={},
        )
        b._BASELINES.clear()
        b.register(ctx)
        out = _run(tools["compute_agent_baseline"]("001", days=30))
        assert out.get("status") == "baseline_computed"
        # Two series (volume + critical) → exactly two searches, not 2*30.
        assert idx.search.await_count == 2
        # And the query is a date_histogram, not a per-day count loop.
        body = idx.search.await_args_list[0].args[0]
        assert "per_day" in body["aggs"] and "date_histogram" in body["aggs"]["per_day"]
        # newest-first order preserved (buckets reversed).
        assert out["alert_volume"]["daily_counts"] == [0.0, 5.0, 3.0]

    def test_daily_counts_empty_on_no_aggs(self):
        import wazuh_mcp.tools.baseline as b
        idx = AsyncMock()
        idx.search.return_value = {"hits": {"total": {"value": 0}}}  # no aggregations
        counts = _run(b._get_daily_alert_counts(idx, "001", days=7))
        assert counts == []
