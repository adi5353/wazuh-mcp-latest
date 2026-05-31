"""RBAC enforcement coverage — guards against a forgotten role check.

Every destructive tool (the write/admin sets used by the per-tool rate limiter in
``rate_limit.py``) must be unreachable by a VIEWER session. The codebase enforces
this two ways:

  1. **Registration-time gate** — the tool's module declares
     ``REQUIRED_ROLE >= RESPONDER`` so a VIEWER session never loads it
     (``server.py`` skips the module).
  2. **Call-time guard** — the tool calls ``require_role(...)`` /
     ``responder_only()`` and returns a role-error dict for low-tier callers
     (used when a write tool lives in an otherwise VIEWER-level module, e.g.
     ``restart_agent`` in ``agents.py``).

This test registers every tool module, locates each write/admin tool, and asserts
at least one mechanism protects it. A new destructive tool added without either
guard makes this test — and therefore CI — fail.
"""
import asyncio
import importlib
import inspect
import pkgutil

from unittest.mock import AsyncMock

import pytest

from wazuh_mcp import tools as tools_pkg
from wazuh_mcp import identity
from wazuh_mcp.config import Config
from wazuh_mcp.tool_context import ToolContext
from wazuh_mcp.rbac import ROLE
from wazuh_mcp.rate_limit import _WRITE_TOOLS, _ADMIN_TOOLS

DESTRUCTIVE_TOOLS = sorted(_WRITE_TOOLS | _ADMIN_TOOLS)


def _build_registry():
    """Register every tool module against a capturing context.

    Returns ``{tool_name: (module_name, fn, module_required_role)}``.
    """
    import os
    # The registry is built at collection time, before the autouse env fixture
    # runs, so seed the minimal env Config.from_env() requires.
    os.environ.setdefault("WAZUH_HOST", "https://127.0.0.1:55000")
    os.environ.setdefault("WAZUH_USER", "wazuh-mcp")
    os.environ.setdefault("WAZUH_PASS", "test-password-not-real")
    os.environ.setdefault("WAZUH_INDEXER_HOST", "https://127.0.0.1:9200")
    os.environ.setdefault("WAZUH_INDEXER_USER", "wazuh-mcp-readonly")
    os.environ.setdefault("WAZUH_INDEXER_PASS", "test-password-not-real")
    os.environ.setdefault("WAZUH_VERIFY_SSL", "false")

    registry: dict[str, tuple[str, object, ROLE]] = {}
    cfg = Config.from_env()

    for mod_info in pkgutil.iter_modules(tools_pkg.__path__):
        name = mod_info.name
        if name == "__init__":
            continue
        mod = importlib.import_module(f"wazuh_mcp.tools.{name}")
        if not hasattr(mod, "register"):
            continue
        required = getattr(mod, "REQUIRED_ROLE", ROLE.VIEWER)

        local: dict[str, object] = {}

        class _CapturingMcp:
            def tool(self, *a, **k):
                def deco(fn):
                    local[getattr(fn, "__name__", "?")] = fn
                    return fn
                return deco

            def prompt(self, *a, **k):
                return lambda fn: fn

            def resource(self, *a, **k):
                return lambda fn: fn

        ctx = ToolContext(
            mcp=_CapturingMcp(),
            wz=AsyncMock(),
            idx=AsyncMock(),
            cfg=cfg,
            cap=lambda x: x,
            require_writes=lambda: None,
            truncate=lambda s, n=300: s,
            enrich_mitre_ids=lambda ids: [],
            geoip_lookup=AsyncMock(return_value={}),
            incident_recommendations=lambda a: [],
        )
        try:
            mod.register(ctx)
        except Exception:  # pragma: no cover - module needs richer cfg; skip
            continue
        for tname, fn in local.items():
            registry.setdefault(tname, (name, fn, required))
    return registry


_REGISTRY = _build_registry()


def _dummy_args(fn) -> dict:
    """Build placeholder kwargs for every required parameter of *fn*."""
    kwargs: dict = {}
    for pname, p in inspect.signature(fn).parameters.items():
        if p.default is not inspect.Parameter.empty:
            continue
        if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        ann = p.annotation
        if ann is int:
            kwargs[pname] = 1
        elif ann is bool:
            kwargs[pname] = False
        elif ann is list:
            kwargs[pname] = []
        elif ann is dict:
            kwargs[pname] = {}
        else:
            kwargs[pname] = "test"
    return kwargs


@pytest.mark.parametrize("tool_name", DESTRUCTIVE_TOOLS)
def test_destructive_tool_is_guarded(tool_name):
    assert tool_name in _REGISTRY, (
        f"Destructive tool '{tool_name}' was not registered by any tool module — "
        f"it may have been renamed/moved. Update _WRITE_TOOLS/_ADMIN_TOOLS in "
        f"rate_limit.py or this test."
    )
    module_name, fn, module_required = _REGISTRY[tool_name]

    # Mechanism 1: module-level registration gate (VIEWER never loads the module).
    if module_required >= ROLE.RESPONDER:
        return

    # Mechanism 2: call-time role guard must reject a VIEWER.
    identity.set_session_role(ROLE.VIEWER)
    try:
        result = asyncio.run(fn(**_dummy_args(fn)))
    except Exception as exc:  # pragma: no cover - diagnostic path
        pytest.fail(
            f"'{tool_name}' (module '{module_name}', REQUIRED_ROLE={module_required!r}) "
            f"ran past any role guard and raised {exc!r}. A destructive tool in a "
            f"VIEWER-level module must call require_role()/responder_only() first."
        )

    assert isinstance(result, dict) and result.get("required_role"), (
        f"'{tool_name}' (module '{module_name}') is destructive but neither its "
        f"module REQUIRED_ROLE nor a call-time guard rejects a VIEWER. "
        f"Got: {result!r}"
    )
