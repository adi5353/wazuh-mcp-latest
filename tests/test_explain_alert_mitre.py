"""Unit tests for explain_alert._pair_mitre.

Guards against the bug where a plain ``zip(ids, tactics)`` silently dropped
trailing MITRE technique IDs whenever Wazuh returned fewer tactics than IDs.
"""
from __future__ import annotations

from wazuh_mcp.tools.explain_alert import _pair_mitre


def test_equal_lengths_pair_one_to_one():
    assert _pair_mitre(["T1001", "T1002"], ["Exfil", "C2"]) == [
        ("T1001", "Exfil"),
        ("T1002", "C2"),
    ]


def test_fewer_tactics_keeps_every_id():
    # The original bug: the second ID was dropped entirely.
    assert _pair_mitre(["T1001", "T1002", "T1003"], ["Exfil"]) == [
        ("T1001", "Exfil"),
        ("T1002", ""),
        ("T1003", ""),
    ]


def test_empty_or_none_tactics():
    assert _pair_mitre(["T1001"], []) == [("T1001", "")]
    assert _pair_mitre(["T1001"], None) == [("T1001", "")]


def test_more_tactics_than_ids_does_not_invent_ids():
    # Extra tactics are ignored; we never emit an empty-ID entry.
    assert _pair_mitre(["T1001"], ["Exfil", "C2", "Recon"]) == [("T1001", "Exfil")]


def test_no_ids_yields_empty():
    assert _pair_mitre([], ["Exfil"]) == []
