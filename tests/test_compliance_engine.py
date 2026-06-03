"""Unit tests for the shared compliance scoring engine (M4 refactor).

The five framework summaries (iso27001 / nist_csf2 / soc2 / pci_dss / hipaa)
were collapsed onto shared helpers in compliance.py. These tests pin the
helper semantics and verify a realistic scoring path end-to-end so the
refactor stays behaviour-preserving.
"""
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wazuh_mcp.tools import compliance as c
from wazuh_mcp.tool_context import ToolContext


def _agg(buckets, name="by_group"):
    return {
        "hits": {"total": {"value": sum(b["doc_count"] for b in buckets)}, "hits": []},
        "aggregations": {name: {"buckets": buckets}},
    }


def _bucket(key, total, critical, agents):
    return {
        "key": key,
        "doc_count": total,
        "critical": {"doc_count": critical},
        "top_agents": {"buckets": [{"key": a} for a in agents]},
    }


class TestStatus:
    def test_failing_on_any_critical(self):
        assert c._status(0, 1) == "FAILING"

    def test_warning_when_noisy_no_critical(self):
        assert c._status(11, 0) == "WARNING"

    def test_ok_when_quiet(self):
        assert c._status(10, 0) == "OK"


class TestScoreGroups:
    def test_sums_matched_groups_only(self):
        gc = {
            "authentication_failed": {"total": 10, "critical": 2, "agents": ["h1"]},
            "brute_force": {"total": 5, "critical": 0, "agents": ["h2"]},
            "unrelated": {"total": 99, "critical": 9, "agents": ["h3"]},
        }
        total, critical, agents, matched = c._score_groups(
            ["authentication_failed", "brute_force", "absent"], gc
        )
        assert total == 15
        assert critical == 2
        assert agents == {"h1", "h2"}
        assert matched == ["authentication_failed", "brute_force"]

    def test_empty_when_no_match(self):
        total, critical, agents, matched = c._score_groups(["x"], {})
        assert (total, critical, agents, matched) == (0, 0, set(), [])


class TestScoreNative:
    def test_predicate_selects_matching_keys(self):
        nc = {
            "10.2.1": {"total": 3, "critical": 1, "agents": ["h1"]},
            "10.6.1": {"total": 2, "critical": 0, "agents": ["h2"]},
            "1.1.1": {"total": 7, "critical": 0, "agents": ["h3"]},
        }
        total, critical, agents, matched = c._score_native(
            nc, lambda k: k.startswith("10.")
        )
        assert total == 5
        assert critical == 1
        assert agents == {"h1", "h2"}
        assert set(matched) == {"10.2.1", "10.6.1"}


class TestRunGroupAggregation:
    def test_parses_group_and_native_counts(self):
        async def run():
            idx = MagicMock()
            res = _agg([_bucket("firewall", 4, 1, ["h1"])])
            res["aggregations"]["by_native"] = {
                "buckets": [_bucket("10.2.1", 3, 0, ["h2"])]
            }
            idx.search = AsyncMock(return_value=res)
            total, groups, native = await c._run_group_aggregation(
                idx, "30d", 5, native_field="rule.pci_dss"
            )
            assert total == 4
            assert groups["firewall"]["critical"] == 1
            assert native["10.2.1"]["total"] == 3
            # native aggregation was requested
            body = idx.search.await_args.args[0]
            assert "by_native" in body["aggs"]
            assert body["aggs"]["by_native"]["terms"]["field"] == "rule.pci_dss"
        asyncio.run(run())

    def test_no_native_field_skips_native_agg(self):
        async def run():
            idx = MagicMock()
            idx.search = AsyncMock(return_value=_agg([_bucket("ids", 2, 0, [])]))
            total, groups, native = await c._run_group_aggregation(idx, "30d", 5)
            assert native == {}
            body = idx.search.await_args.args[0]
            assert "by_native" not in body["aggs"]
        asyncio.run(run())


def _register_compliance(search_return):
    """Register the compliance module against a mock indexer; return {name: fn}."""
    captured = {}
    mcp = MagicMock()

    def tool_deco(*a, **k):
        def wrap(fn):
            captured[fn.__name__] = fn
            return fn
        return wrap

    mcp.tool = tool_deco
    idx = MagicMock()
    idx.search = AsyncMock(return_value=search_return)
    ctx = ToolContext(
        mcp=mcp, wz=None, idx=idx, cfg=None, cap=lambda x: x,
        require_writes=lambda: None, truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [], geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda a: [],
    )
    c.register(ctx)
    return captured


_LEGACY_TOOLS = [
    "iso27001_compliance_summary", "nist_csf2_compliance_summary",
    "soc2_compliance_summary", "pci_dss_compliance_summary",
    "hipaa_compliance_summary",
]


class TestLegacyAliasSuppression:
    def test_aliases_registered_by_default(self):
        tools = _register_compliance(_agg([]))
        for name in _LEGACY_TOOLS:
            assert name in tools, f"{name} should register by default"
        assert "compliance_framework_summary" in tools

    def test_aliases_suppressed_when_disabled(self):
        with patch.dict(os.environ, {"WAZUH_MCP_LEGACY_ALIASES": "false"}):
            tools = _register_compliance(_agg([
                _bucket("authentication_failed", 10, 2, ["h1"]),
            ]))
        # Legacy per-framework tools are no longer advertised...
        for name in _LEGACY_TOOLS:
            assert name not in tools, f"{name} should be suppressed"
        # ...but the unified tool is, and still produces a report.
        assert "compliance_framework_summary" in tools
        out = asyncio.run(tools["compliance_framework_summary"](framework="iso27001"))
        assert out["report_type"] == "iso27001_2022_annex_a"


class TestIso27001ScoringEndToEnd:
    def _tools(self, search_return):
        return _register_compliance(search_return)

    def test_unified_dispatch_matches_dedicated_tool(self):
        res = _agg([
            _bucket("authentication_failed", 10, 2, ["h1"]),
            _bucket("brute_force", 5, 0, ["h2"]),
        ])
        tools = self._tools(res)
        unified = asyncio.run(tools["compliance_framework_summary"](framework="iso27001"))
        dedicated = asyncio.run(tools["iso27001_compliance_summary"]())
        # Same report content (generated_at timestamp aside).
        assert unified["report_type"] == dedicated["report_type"] == "iso27001_2022_annex_a"
        assert unified["controls"] == dedicated["controls"]

    def test_unified_unknown_framework(self):
        tools = self._tools(_agg([]))
        out = asyncio.run(tools["compliance_framework_summary"](framework="bogus"))
        assert "error" in out and "supported" in out
        assert "iso27001" in out["supported"]

    def test_control_a85_aggregates_auth_groups(self):
        # A.8.5 "Secure authentication" maps to authentication_failed/brute_force/pam.
        res = _agg([
            _bucket("authentication_failed", 10, 2, ["h1"]),
            _bucket("brute_force", 5, 0, ["h2"]),
        ])
        tools = self._tools(res)
        out = asyncio.run(tools["iso27001_compliance_summary"]())
        a85 = next(c for c in out["controls"] if c["control_id"] == "A.8.5")
        assert a85["total_alerts"] == 15
        assert a85["critical_alerts"] == 2
        assert a85["status"] == "FAILING"
        assert set(a85["top_agents"]) <= {"h1", "h2"}
        assert out["summary"]["failing"] >= 1
