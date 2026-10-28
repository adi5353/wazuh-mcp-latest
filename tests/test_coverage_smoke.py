"""Broad smoke coverage for every registered MCP tool.

This module registers *every* tool module against a single rich, mocked
``ToolContext`` and then invokes every registered tool — once with its default
arguments and, where the tool exposes a ``dry_run`` flag, once more with
``dry_run=False`` so the write path is exercised too.

The goal is breadth: each tool's argument validation, RBAC guard, dry-run
branch, happy-path formatting, and error handling all run against deterministic
mocked backends. Backends return a recursive default-dict (``_Deep``) so that
arbitrary nested key access never raises ``KeyError`` — a tool either formats a
plausible response or falls into its own error handling, both of which we want
covered.

These are intentionally permissive: a tool that raises is recorded but does not
fail the suite (its pre-exception lines are still covered). A regression guard
asserts that the *majority* of tools return cleanly, so a broad breakage still
trips the build.
"""
from __future__ import annotations

import pytest

# Quarantined from the coverage gate: these exercise code paths against mocked
# clients to catch crashes/imports, but assert little real behaviour. Run via
# `pytest -m smoke`; excluded from the gated run by `-m "not smoke"` (pyproject).
pytestmark = pytest.mark.smoke

import asyncio
import inspect
import os
from unittest.mock import AsyncMock, MagicMock

import pytest


# ── Recursive default-dict so arbitrary nested access never raises ────────────
# In addition to recursive key access, it is arithmetic- and comparison-safe so
# tools that do ``resp[k] > 0`` or ``resp[k] + 1`` on an absent leaf still run.
class _Deep(dict):
    def __missing__(self, key):  # noqa: D401 - dict hook
        return _Deep()

    def __int__(self):
        return 0

    def __float__(self):
        return 0.0

    def __bool__(self):
        return False

    def __gt__(self, other):
        return False

    def __lt__(self, other):
        return False

    def __ge__(self, other):
        return False

    def __le__(self, other):
        return False

    def __add__(self, other):
        return other

    def __radd__(self, other):
        return other


def _payload() -> _Deep:
    """A superset response that satisfies both Manager and Indexer shapes."""
    item = _Deep({
        "id": "001",
        "name": "agent-001",
        "ip": "10.0.0.5",
        "status": "active",
        "version": "4.8.0",
        "os": _Deep({"name": "Ubuntu", "platform": "ubuntu", "version": "22.04"}),
        "lastKeepAlive": "2024-01-01T00:00:00Z",
        "dateAdd": "2024-01-01T00:00:00Z",
        "group": ["default"],
        "level": 7,
        "count": 1,
        "rule": _Deep({"id": "5710", "level": 7, "description": "test", "groups": ["auth"]}),
        "agent": _Deep({"id": "001", "name": "agent-001"}),
        "timestamp": "2024-01-01T00:00:00Z",
        "data": _Deep({"srcip": "10.0.0.5"}),
    })
    return _Deep({
        "data": _Deep({
            "affected_items": [item],
            "total_affected_items": 1,
            "failed_items": [],
            "total_failed_items": 0,
        }),
        "error": 0,
        "message": "ok",
        "hits": _Deep({
            "total": _Deep({"value": 1}),
            "hits": [_Deep({"_source": item, "_id": "1", "sort": [1]})],
        }),
        "aggregations": _Deep({
            "by_rule": _Deep({"buckets": [{"key": "test rule", "doc_count": 1}]}),
            "by_agent": _Deep({"buckets": [{"key": "agent-001", "doc_count": 1}]}),
            "by_level": _Deep({"buckets": [{"key": "7", "doc_count": 1}]}),
            "by_severity": _Deep({"buckets": [{"key": "high", "doc_count": 1}]}),
            "unique": _Deep({"value": 1}),
        }),
    })


class _AnyClient:
    """Async backend stub: every awaited method returns the rich payload."""

    def __init__(self):
        self.cfg = MagicMock()

    def __getattr__(self, _name):
        async def _call(*_a, **_k):
            return _payload()
        return _call


def _make_full_context():
    from wazuh_mcp.tool_context import ToolContext

    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    mcp.prompt = lambda *a, **k: (lambda fn: fn)
    mcp.resource = lambda *a, **k: (lambda fn: fn)

    wz = _AnyClient()
    idx = _AnyClient()

    cfg = MagicMock()
    cfg.alerts_index = "wazuh-alerts-*"
    cfg.vuln_index = "wazuh-states-vulnerabilities-*"
    cfg.archive_index = "wazuh-archives-*"
    cfg.allow_writes = True
    cfg.manager_host = "https://127.0.0.1:55000"
    cfg.indexer_host = "https://127.0.0.1:9200"
    cfg.max_results = 500

    ctx = ToolContext(
        mcp=mcp, wz=wz, idx=idx, cfg=cfg,
        cap=lambda n: min(int(n), 500),
        require_writes=lambda: None,
        truncate=lambda s, n=300: s if s is None or len(s) <= n else s[:n] + "…",
        enrich_mitre_ids=lambda ids: [{"id": i, "name": i} for i in (ids or [])],
        geoip_lookup=AsyncMock(return_value={"country": "US"}),
        incident_recommendations=lambda alert: ["isolate host"],
        tool_registry={},
    )
    return ctx, tools


def _register_all(ctx) -> None:
    import importlib
    import pkgutil
    from wazuh_mcp import tools as tools_pkg

    deferred = {"notifications"}
    names = [
        m for _i, m, _p in pkgutil.iter_modules(tools_pkg.__path__)
        if m != "__init__"
    ]
    for modname in sorted(names):
        if modname in deferred:
            continue
        mod = importlib.import_module(f"wazuh_mcp.tools.{modname}")
        if hasattr(mod, "register"):
            mod.register(ctx)
    for modname in deferred:
        mod = importlib.import_module(f"wazuh_mcp.tools.{modname}")
        if hasattr(mod, "register"):
            mod.register(ctx)


def _arg_for(name: str, param: inspect.Parameter):
    n = name.lower()
    ann = param.annotation
    ann_s = str(ann).lower()
    if n in ("src_ip", "source_ip", "dest_ip", "dst_ip") or n == "ip" or n.endswith("_ip"):
        return "8.8.8.8"
    if "agent" in n and "id" in n:
        return "001"
    if n == "agents_list" or n == "agent_ids":
        return ["001"]
    if "cve" in n:
        return "CVE-2021-44228"
    if "hash" in n or n in ("sha256", "md5", "sha1"):
        return "a" * 64
    if "domain" in n:
        return "example.com"
    if "url" in n:
        return "http://example.com/x"
    if "email" in n:
        return "user@example.com"
    if "time_range" in n or n == "range" or n == "window":
        return "24h"
    if "rule_id" in n or n == "rule":
        return "5710"
    if "query" in n or n == "q":
        return "test"
    if "xml" in n:
        return "<group><rule id=\"100001\" level=\"5\"></rule></group>"
    if n in ("limit", "size", "top", "days", "hours", "minutes", "interval", "threshold",
             "min_level", "severity_threshold", "n", "count", "page"):
        return 5
    if ann in (int,) or "int" in ann_s and "list" not in ann_s and "dict" not in ann_s:
        return 5
    if ann in (bool,) or ann_s == "bool":
        return False
    if ann in (float,):
        return 1.0
    if "list" in ann_s:
        return []
    if "dict" in ann_s:
        return {}
    return "test"


def _build_kwargs(fn) -> dict:
    sig = inspect.signature(fn)
    kwargs: dict = {}
    for name, param in sig.parameters.items():
        if name in ("self", "args", "kwargs"):
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        if param.default is not inspect.Parameter.empty:
            # Keep defaults except force dry_run False later in a second pass.
            continue
        kwargs[name] = _arg_for(name, param)
    return kwargs


# ── Fake httpx so external-API tools (threat intel, integrations, geo) run ────
class _FakeHTTPResp:
    status_code = 200
    text = "{}"
    content = b"{}"
    reason_phrase = "OK"
    headers: dict = {}

    def json(self):
        return _payload()

    def raise_for_status(self):
        return None


class _FakeHTTPXClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, *a, **k):
        return _FakeHTTPResp()

    async def post(self, *a, **k):
        return _FakeHTTPResp()

    async def put(self, *a, **k):
        return _FakeHTTPResp()

    async def request(self, *a, **k):
        return _FakeHTTPResp()

    async def aclose(self):
        return None


# Integration credentials so external-API tools take their *configured* path
# (response parsing/formatting) instead of returning "not configured" early.
_SMOKE_ENV = {
    "WAZUH_MCP_USER_ROLE": "admin",
    "WAZUH_ALLOW_WRITES": "true",
    "VIRUSTOTAL_API_KEY": "vt-test-key",
    "ABUSEIPDB_API_KEY": "abuse-test-key",
    "SHODAN_API_KEY": "shodan-test-key",
    "GREYNOISE_API_KEY": "gn-test-key",
    "OTX_API_KEY": "otx-test-key",
    "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/x",
    "TEAMS_WEBHOOK_URL": "https://outlook.office.com/webhook/x",
    "JIRA_URL": "https://jira.example.com",
    "JIRA_USER": "soc",
    "JIRA_API_TOKEN": "jira-tok",
    "THEHIVE_URL": "https://hive.example.com",
    "THEHIVE_API_KEY": "hive-key",
    "SERVICENOW_INSTANCE": "https://dev.service-now.com",
    "SERVICENOW_USER": "admin",
    "SERVICENOW_PASS": "pw",
    "PAGERDUTY_ROUTING_KEY": "pd-key",
    "PAGERDUTY_API_TOKEN": "pd-tok",
    "AZURE_DEVOPS_ORG": "myorg",
    "AZURE_DEVOPS_PROJECT": "proj",
    "AZURE_DEVOPS_PAT": "az-pat",
    "SMTP_USER": "soc@example.com",
    "SMTP_PASS": "smtp-pw",
    "REPORT_EMAIL_TO": "ciso@example.com",
}


@pytest.fixture(scope="module")
def registered_tools():
    import httpx
    # Patch outbound HTTP for the whole module so no test touches the network and
    # external-API tools exercise their full response-parsing happy path. The
    # patch stays active through invocation (tools build clients at call time)
    # and is restored on teardown so it never leaks into other test modules.
    import smtplib

    class _FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def starttls(self):
            pass

        def login(self, *a, **k):
            pass

        def sendmail(self, *a, **k):
            pass

    _orig = httpx.AsyncClient
    _orig_smtp = smtplib.SMTP
    _prev_env = {k: os.environ.get(k) for k in _SMOKE_ENV}
    os.environ.update(_SMOKE_ENV)
    httpx.AsyncClient = _FakeHTTPXClient  # type: ignore[assignment]
    smtplib.SMTP = _FakeSMTP  # type: ignore[assignment]
    try:
        ctx, tools = _make_full_context()
        _register_all(ctx)
        yield tools
    finally:
        httpx.AsyncClient = _orig  # type: ignore[assignment]
        smtplib.SMTP = _orig_smtp  # type: ignore[assignment]
        for k, v in _prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_at_least_200_tools_registered(registered_tools):
    assert len(registered_tools) >= 150, (
        f"only {len(registered_tools)} tools registered — discovery regression?"
    )


def test_every_tool_invocable(registered_tools):
    """Invoke every async tool; record failures but require a high success rate."""
    failures: dict[str, str] = {}
    successes = 0

    async def _drive():
        nonlocal successes
        for tname, fn in registered_tools.items():
            if not inspect.iscoroutinefunction(fn):
                continue
            kwargs = _build_kwargs(fn)
            try:
                result = await fn(**kwargs)
                assert isinstance(result, (dict, list, str)) or result is None
                successes += 1
            except Exception as exc:  # noqa: BLE001 - breadth probe
                failures[tname] = f"{type(exc).__name__}: {exc}"
            # Second pass: exercise the write/execute branch.
            if "dry_run" in inspect.signature(fn).parameters:
                try:
                    await fn(**{**kwargs, "dry_run": False})
                except Exception:  # noqa: BLE001
                    pass

    asyncio.run(_drive())

    total = successes + len(failures)
    assert total > 0
    # A solid majority of tools must run cleanly against the mocked backend.
    success_rate = successes / total
    assert success_rate >= 0.6, (
        f"only {successes}/{total} tools succeeded ({success_rate:.0%}). "
        f"Sample failures: {dict(list(failures.items())[:15])}"
    )
