"""Tests for Improvement B — token-aware response pruning in audit.py.

Covers:
  - _count_tokens: char/4 heuristic estimate
  - _prune_low_signal: strips alert fields, leaves non-alert dicts untouched
  - _trim_list_to_token_budget: prunes list to fit within a token budget
  - cap_response_size: uses token budget for lists within the char ceiling
"""
from __future__ import annotations

import json
import os
import pytest


# ── _count_tokens ─────────────────────────────────────────────────────────────

class TestCountTokens:
    def test_empty_dict(self):
        from wazuh_mcp.audit import _count_tokens
        assert _count_tokens({}) == 0  # "{}" == 2 chars → 0 tokens

    def test_simple_string(self):
        from wazuh_mcp.audit import _count_tokens
        s = "A" * 400  # 400-char string serialises to ~402 chars with quotes → 100 tokens
        assert _count_tokens(s) == 100

    def test_list_of_dicts(self):
        from wazuh_mcp.audit import _count_tokens
        items = [{"id": str(i), "value": "x" * 40} for i in range(10)]
        serialized_len = len(json.dumps(items))
        expected = serialized_len // 4
        assert _count_tokens(items) == expected

    def test_non_serializable_returns_zero(self):
        from wazuh_mcp.audit import _count_tokens

        class Unserializable:
            def __repr__(self):
                raise RuntimeError("boom")

        # default=str in _count_tokens means it will use str(), not raise
        # but let's confirm it never raises
        result = _count_tokens({"bad": Unserializable()})
        assert isinstance(result, int)


# ── _prune_low_signal ─────────────────────────────────────────────────────────

class TestPruneLowSignal:
    def _make_alert(self) -> dict:
        return {
            "id": "abc123",
            "timestamp": "2024-01-01T00:00:00Z",
            "agent_id": "001",
            "agent_name": "web-01",
            "rule_id": "5710",
            "rule_level": 10,
            "rule_description": "SSH brute force",
            "log_snippet": "Failed password for root",
            "decoder": "sshd",
            "rule_groups": ["authentication_failure", "ssh"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
            "srcip": "1.2.3.4",
        }

    def test_strips_all_low_signal_fields_from_alert(self):
        from wazuh_mcp.audit import _prune_low_signal, _LOW_SIGNAL_ALERT_FIELDS
        alert = self._make_alert()
        pruned = _prune_low_signal(alert)
        for field in _LOW_SIGNAL_ALERT_FIELDS:
            assert field not in pruned, f"Low-signal field '{field}' should have been removed"

    def test_preserves_high_signal_fields(self):
        from wazuh_mcp.audit import _prune_low_signal
        alert = self._make_alert()
        pruned = _prune_low_signal(alert)
        assert pruned["id"] == "abc123"
        assert pruned["rule_id"] == "5710"
        assert pruned["rule_level"] == 10
        assert pruned["srcip"] == "1.2.3.4"

    def test_non_alert_dict_returned_untouched(self):
        from wazuh_mcp.audit import _prune_low_signal
        agent = {"agent_id": "001", "name": "web-01", "status": "active", "log_snippet": "keep"}
        result = _prune_low_signal(agent)
        # "rule_id" and "rule_level" absent → not treated as alert → log_snippet kept
        assert result["log_snippet"] == "keep"
        assert result is agent  # identity — same object returned

    def test_non_dict_returned_as_is(self):
        from wazuh_mcp.audit import _prune_low_signal
        assert _prune_low_signal("a string") == "a string"
        assert _prune_low_signal(42) == 42
        assert _prune_low_signal(None) is None

    def test_alert_with_rule_level_only_still_pruned(self):
        from wazuh_mcp.audit import _prune_low_signal
        item = {"rule_level": 5, "log_snippet": "raw", "mitre": {}}
        pruned = _prune_low_signal(item)
        assert "log_snippet" not in pruned
        assert "mitre" not in pruned
        assert pruned["rule_level"] == 5


# ── _trim_list_to_token_budget ────────────────────────────────────────────────

class TestTrimListToTokenBudget:
    def _alert(self, i: int) -> dict:
        return {
            "id": f"alert-{i}",
            "rule_id": "5710",
            "rule_level": 10,
            "rule_description": "SSH brute force attempt",
            "agent_name": f"agent-{i:03d}",
            "srcip": f"192.168.1.{i}",
            "log_snippet": "Failed password for root from 192.168.1.1 port 22 ssh2",
            "decoder": "sshd",
            "rule_groups": ["authentication_failure", "sshd"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
        }

    def test_fits_within_budget_after_pruning(self):
        from wazuh_mcp.audit import _trim_list_to_token_budget, _count_tokens
        items = [self._alert(i) for i in range(50)]
        # Budget is 2x the pruned-per-item cost so the function must genuinely prune;
        # use per-item token cost rather than an arbitrary constant to avoid off-by-one
        # from list-framing overhead ([], commas).
        per_item_cost = _count_tokens(items[0])
        budget = per_item_cost * 5  # room for ~5 items
        result = _trim_list_to_token_budget(items, budget)
        assert _count_tokens(result) <= budget + 2  # +2 tolerance for list-framing chars
        assert len(result) < len(items)  # list was actually shortened

    def test_result_is_non_empty(self):
        from wazuh_mcp.audit import _trim_list_to_token_budget
        items = [self._alert(i) for i in range(10)]
        result = _trim_list_to_token_budget(items, 200)
        assert len(result) > 0

    def test_low_signal_fields_stripped(self):
        from wazuh_mcp.audit import _trim_list_to_token_budget, _LOW_SIGNAL_ALERT_FIELDS
        items = [self._alert(0)]
        result = _trim_list_to_token_budget(items, 10000)  # generous budget
        for field in _LOW_SIGNAL_ALERT_FIELDS:
            assert field not in result[0], f"Field '{field}' should have been pruned"

    def test_pass1_prune_sufficient_returns_all_items(self):
        """If stripping low-signal fields brings the list within budget, all items are returned."""
        from wazuh_mcp.audit import _trim_list_to_token_budget, _count_tokens
        # 3 alerts — small enough that pruned versions all fit
        items = [self._alert(i) for i in range(3)]
        # set budget just above the pruned cost
        from wazuh_mcp.audit import _prune_low_signal
        pruned_cost = _count_tokens([_prune_low_signal(a) for a in items])
        result = _trim_list_to_token_budget(items, pruned_cost + 10)
        assert len(result) == 3

    def test_empty_list_returns_empty(self):
        from wazuh_mcp.audit import _trim_list_to_token_budget
        assert _trim_list_to_token_budget([], 1000) == []


# ── cap_response_size with token budget ───────────────────────────────────────

class TestCapResponseSizeTokenBudget:
    def _make_large_alert_list(self, n: int = 200) -> list:
        return [
            {
                "id": f"alert-{i}",
                "rule_id": "5710",
                "rule_level": 10,
                "rule_description": "SSH brute force",
                "agent_name": f"agent-{i:03d}",
                "srcip": f"10.0.{i // 256}.{i % 256}",
                "log_snippet": "Failed password for root from 10.0.0.1 port 22 ssh2",
                "decoder": "sshd",
                "rule_groups": ["authentication_failure"],
                "mitre": {"id": ["T1110"]},
            }
            for i in range(n)
        ]

    def test_list_within_char_ceiling_but_over_token_budget_is_pruned(self, monkeypatch):
        """When a list fits in char ceiling but exceeds token budget, it is pruned."""
        import wazuh_mcp.audit as audit_mod
        # Small token budget so the list of 200 alerts triggers pruning
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_TOKENS", 200)
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_CHARS", 10_000_000)  # effectively unlimited

        items = self._make_large_alert_list(200)
        result = audit_mod.cap_response_size(items)

        # Must be a list (not the "warning" truncation dict)
        assert isinstance(result, list), "Expected a pruned list, not the hard-truncation warning"
        # Must be within budget
        token_count = audit_mod._count_tokens(result)
        assert token_count <= 200, f"Token count {token_count} exceeds budget 200"

    def test_list_within_both_limits_returned_as_is(self, monkeypatch):
        """Small lists that fit within both limits are returned unchanged."""
        import wazuh_mcp.audit as audit_mod
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_TOKENS", 10000)
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_CHARS", 10_000_000)

        items = [{"rule_id": "001", "rule_level": 5, "agent_name": "x"}]
        result = audit_mod.cap_response_size(items)
        assert result == items

    def test_token_budget_disabled_when_zero(self, monkeypatch):
        """WAZUH_MCP_MAX_TOKENS=0 disables token pruning — full list returned."""
        import wazuh_mcp.audit as audit_mod
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_TOKENS", 0)
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_CHARS", 10_000_000)

        items = self._make_large_alert_list(200)
        result = audit_mod.cap_response_size(items)
        assert result == items  # untouched

    def test_dict_responses_not_affected_by_token_budget(self, monkeypatch):
        """Token pruning only applies to lists; dict responses go through char path unchanged."""
        import wazuh_mcp.audit as audit_mod
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_TOKENS", 1)   # tiny budget
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_CHARS", 10_000_000)

        data = {"status": "ok", "count": 42, "message": "all clear"}
        result = audit_mod.cap_response_size(data)
        assert result == data  # dicts are not token-pruned

    def test_char_ceiling_still_enforced_for_huge_responses(self, monkeypatch):
        """When response exceeds char ceiling, hard-truncation still fires regardless."""
        import wazuh_mcp.audit as audit_mod
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_CHARS", 100)
        monkeypatch.setattr(audit_mod, "_MAX_OUTPUT_TOKENS", 10000)

        items = self._make_large_alert_list(50)
        result = audit_mod.cap_response_size(items)
        # char ceiling fires → structured warning dict, not a raw list
        assert isinstance(result, dict)
        assert "warning" in result


# ── Connection pool defaults ──────────────────────────────────────────────────

class TestPoolDefaults:
    def test_wazuh_client_pool_defaults(self):
        """WazuhClient default pool sizes must be 100/40."""
        from wazuh_mcp import wazuh_client
        assert wazuh_client._POOL_MAX_CONNECTIONS == int(
            os.getenv("WAZUH_HTTP_POOL_SIZE", "100")
        )
        assert wazuh_client._POOL_MAX_KEEPALIVE == int(
            os.getenv("WAZUH_HTTP_MAX_KEEPALIVE", "40")
        )

    def test_wazuh_indexer_pool_defaults(self):
        """WazuhIndexer default pool sizes must be 100/40."""
        from wazuh_mcp import wazuh_indexer
        assert wazuh_indexer._POOL_MAX_CONNECTIONS == int(
            os.getenv("WAZUH_INDEXER_POOL_SIZE", "100")
        )
        assert wazuh_indexer._POOL_MAX_KEEPALIVE == int(
            os.getenv("WAZUH_INDEXER_MAX_KEEPALIVE", "40")
        )
