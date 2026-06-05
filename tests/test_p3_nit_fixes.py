"""Regression tests for the P3 (nitpick) review fixes.

  * #10 — wazuh_client connection-pool docstring matches the real defaults
  * #11 — README tool/module counts match the generator (drift gate)
  * #12 — RBAC helpers renamed to accurate "_or_above" names; old "_only"
          aliases still work for backward compatibility
"""
from __future__ import annotations

import os

import pytest


# ── #10: pool docstring accuracy ────────────────────────────────────────────

def test_pool_docstring_matches_defaults():
    import wazuh_mcp.wazuh_client as wc
    doc = wc.__doc__ or ""
    # The stale "20 max connections, 10 keepalive" must be gone; real defaults
    # (and their env knobs) documented instead.
    assert "20 max connections" not in doc
    assert "100 max connections" in doc
    assert "40 keepalive" in doc
    assert wc._POOL_MAX_CONNECTIONS == 100
    assert wc._POOL_MAX_KEEPALIVE == 40


# ── #11: README count consistency ───────────────────────────────────────────

def test_readme_count_matches_inventory():
    """The README headline must match the generator's live count — guards the
    239-vs-242 drift that the old substring --check failed to catch."""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/generate_tool_table.py", "--check"],
        cwd=str(root), capture_output=True, text=True,
    )
    assert result.returncode == 0, f"tool-count check failed: {result.stderr or result.stdout}"


def test_readme_count_sites_all_agree():
    """--check must validate every count site, not just the headline. The badge
    and Tool Reference prose previously drifted to 240 while the headline read
    244 because only the headline was guarded."""
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "gen_tool_table", root / "scripts" / "generate_tool_table.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    data = mod.collect()
    readme = (root / "README.md").read_text(encoding="utf-8")
    for label, pattern, expected in mod._count_targets(data):
        found = pattern.search(readme)
        assert found is not None, f"README {label} count site missing"
        assert found.group(0) == expected, (
            f"README {label} is stale: {found.group(0)!r} != {expected!r}"
        )


# ── #12: RBAC helper naming ──────────────────────────────────────────────────

class TestRbacHelperNaming:
    def setup_method(self):
        os.environ["WAZUH_MCP_USER_ROLE"] = "analyst"

    def teardown_method(self):
        os.environ.pop("WAZUH_MCP_USER_ROLE", None)
        from wazuh_mcp import identity
        identity._ctx_role.set(None)

    def test_new_names_exist_and_enforce_minimum(self):
        from wazuh_mcp import rbac
        # analyst session: viewer/analyst pass, responder/admin blocked
        assert rbac.require_viewer_or_above() is None
        assert rbac.require_analyst_or_above() is None
        assert rbac.require_responder_or_above() is not None
        assert rbac.require_admin_or_above() is not None

    def test_deprecated_aliases_still_work(self):
        from wazuh_mcp import rbac
        # old names remain as aliases pointing at the new functions
        assert rbac.viewer_only is rbac.require_viewer_or_above
        assert rbac.analyst_only is rbac.require_analyst_or_above
        assert rbac.analyst_or_above is rbac.require_analyst_or_above
        assert rbac.responder_only is rbac.require_responder_or_above
        assert rbac.admin_only is rbac.require_admin_or_above

    def test_alias_behaviour_unchanged(self):
        from wazuh_mcp import rbac
        assert rbac.analyst_only() is None          # analyst >= analyst
        assert rbac.admin_only() is not None        # analyst < admin
