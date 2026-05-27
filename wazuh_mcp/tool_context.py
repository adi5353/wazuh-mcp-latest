"""Typed interface contract for all MCP tool module registration.

Every tool module exposes a single ``register(ctx: ToolContext)`` entry point.
The server constructs one ``ToolContext`` at startup and passes it to every
module — no more per-module positional argument lists.

Migration guide
---------------
Old pattern (still works, deprecated)::

    def register(mcp, wz, idx, cfg, _cap, _require_writes):
        ...

New pattern::

    from ..tool_context import ToolContext

    def register(ctx: ToolContext) -> None:
        mcp = ctx.mcp
        wz  = ctx.wz
        idx = ctx.idx
        cfg = ctx.cfg
        _cap           = ctx.cap
        _require_writes = ctx.require_writes
        ...

Cross-module dependencies (e.g. ``notifications`` needing callables from
``compliance`` and ``reporting``) are stored in ``ctx.shared`` — a plain dict
that modules can write to and read from during registration.  Modules that
produce shared callables should write into ``ctx.shared`` before ``register``
returns; consumers should read from it after all producers have run.

Example — producer (compliance.py)::

    def register(ctx: ToolContext) -> None:
        ...
        async def generate_compliance_report(...):
            ...
        ctx.shared["generate_compliance_report"] = generate_compliance_report

Example — consumer (notifications.py)::

    def register(ctx: ToolContext) -> None:
        gen_report = ctx.shared.get("generate_compliance_report")
        ...
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolContext:
    """All shared objects a tool module needs during ``register()``.

    Fields
    ------
    mcp
        The ``FastMCP`` server instance — tool modules call ``@ctx.mcp.tool()``
        to register their handlers.
    wz
        ``_ClientProxy`` wrapping ``WazuhClient``.  Swapped atomically on
        ``switch_tenant()``; all tool closures see the new backend immediately.
    idx
        ``_ClientProxy`` wrapping ``WazuhIndexer``.  Same swap semantics as wz.
    cfg
        Frozen ``Config`` dataclass — single source of truth for all settings.
    cap
        ``_cap(n: int) -> int`` — clamp a requested limit to
        ``MAX_RESULTS_GLOBAL``.
    require_writes
        ``_require_writes() -> dict | None`` — returns an error dict when
        ``WAZUH_ALLOW_WRITES=false``, else None.
    truncate
        ``_truncate(s: str | None, n: int) -> str | None`` — cap long strings
        so process command lines don't blow up payloads.
    enrich_mitre_ids
        ``enrich_mitre_ids(ids: list[str]) -> list[dict]`` — look up MITRE
        technique names and tactic labels by ID.
    geoip_lookup
        ``geoip_lookup(ip: str) -> dict`` — MaxMind GeoIP2 country/city/ISP
        enrichment.
    incident_recommendations
        ``incident_recommendations(alert: dict) -> list[str]`` — heuristic
        triage recommendations from the built-in triage engine.
    tool_registry
        ``dict[str, Callable]`` — maps tool name → async callable so the
        playbook engine and autonomous SOC can invoke tools by name without
        going through the MCP transport layer.
    shared
        Free-form dict for cross-module callables that are produced during
        registration and consumed by later modules (e.g. ``notifications``
        needs ``generate_compliance_report`` from ``compliance``).
    """

    mcp:   Any
    wz:    Any
    idx:   Any
    cfg:   Any
    cap:              Callable[[int], int]
    require_writes:   Callable[[], "dict | None"]
    truncate:         Callable[..., "str | None"]
    enrich_mitre_ids: Callable[..., Any]
    geoip_lookup:     Callable[..., Any]
    incident_recommendations: Callable[..., Any]
    tool_registry:    dict[str, Any] = field(default_factory=dict)
    shared:           dict[str, Any] = field(default_factory=dict)
