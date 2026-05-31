"""Fixtures for live integration tests against a real Wazuh Manager + Indexer.

These tests exercise the actual ``WazuhClient`` / ``WazuhIndexer`` against a
running Wazuh stack so they catch drift between this server's assumptions and
the *real* API response shapes — the class of bug that fully-mocked unit tests
cannot see.

They are marked ``integration`` and SKIP automatically when no live backend is
reachable, so they never produce a false green (passing without verifying
anything) or a false red (failing merely because no backend is present).

See ``tests/integration/README.md`` for how to stand up a backend.
"""
from __future__ import annotations

import os

import httpx
import pytest

from wazuh_mcp.config import Config

# Connection details the live backend needs. Without all of these we cannot even
# build a Config, so the whole module skips.
_REQUIRED_ENV = ("WAZUH_HOST", "WAZUH_USER", "WAZUH_PASS",
                 "WAZUH_INDEXER_HOST", "WAZUH_INDEXER_PASS")


@pytest.fixture(autouse=True)
def mock_env():
    """Neutralise the repo-wide autouse ``mock_env`` fixture.

    The top-level ``tests/conftest.py`` force-sets fake localhost credentials on
    every test. Integration tests must use the REAL environment instead, so we
    override that fixture here with a no-op for everything under this directory.
    """
    yield


@pytest.fixture(scope="session")
def live_config() -> Config:
    """Build a Config from the real environment, skipping if no backend is up.

    Skips (never fails) when the connection env vars are unset or the Manager is
    unreachable, so the suite is safe to run anywhere.
    """
    missing = [v for v in _REQUIRED_ENV if not os.getenv(v)]
    if missing:
        pytest.skip(
            "Live Wazuh env not set (missing: "
            + ", ".join(missing)
            + "). See tests/integration/README.md."
        )

    # Live stacks use self-signed certs by default; don't require operators to
    # opt out explicitly for the test run.
    os.environ.setdefault("WAZUH_VERIFY_SSL", "false")
    cfg = Config.from_env()

    # Reachability probe: any HTTP response (even 401) proves the Manager is up.
    # A connection error means there's nothing to test against — skip.
    try:
        httpx.get(f"{cfg.manager_host}/", verify=False, timeout=5.0)  # nosec B501
    except httpx.HTTPError as exc:
        pytest.skip(f"Wazuh Manager at {cfg.manager_host} unreachable: {exc}")

    return cfg
