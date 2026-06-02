"""ToolMiddleware — single decorator that composes sanitization + registry capture.

Previously server.py monkey-patched mcp.tool twice in sequence, which was
order-dependent and brittle. This class wraps both concerns in one place.

Usage in server.py::

    from .middleware import ToolMiddleware
    _TOOL_REGISTRY: dict[str, Any] = {}
    mcp.tool = ToolMiddleware(mcp, _TOOL_REGISTRY).tool

RBAC enforcement
----------------
Every tool registered through this middleware has its required role enforced
before the tool body runs.  The effective role is resolved in priority order:

  1. ``role=`` kwarg passed directly to ``@mcp.tool(role=ROLE.ADMIN)``
  2. Module-level ``REQUIRED_ROLE`` on the module that defines the tool
  3. Fallback: ``ROLE.VIEWER`` (fail-closed — least privilege)

A WARNING is emitted on server startup for any tool whose module lacks a
``REQUIRED_ROLE`` declaration, so missing annotations surface immediately.
"""
from __future__ import annotations

import functools
import logging
import sys
import time
from typing import Any

log = logging.getLogger("wazuh-mcp")


def _resolve_tool_role(fn: Any, explicit_role: Any) -> Any:
    """Return the RBAC role that must be enforced for *fn*.

    Resolution order:
    1. *explicit_role* — passed as ``role=`` kwarg to ``@mcp.tool()``
    2. ``REQUIRED_ROLE`` declared on the tool's own module
    3. ``ROLE.VIEWER`` fallback with a startup WARNING so the gap is visible.
    """
    if explicit_role is not None:
        return explicit_role

    module = sys.modules.get(fn.__module__)
    if module is not None:
        required = getattr(module, "REQUIRED_ROLE", None)
        if required is not None:
            return required

    # No role declared — emit a loud warning so it surfaces in logs.
    log.warning(
        "Tool '%s' (module '%s') has no REQUIRED_ROLE declaration and no "
        "explicit role= kwarg. Defaulting to VIEWER (least privilege). "
        "Add REQUIRED_ROLE to the module to silence this warning.",
        fn.__name__,
        fn.__module__,
    )
    from ..rbac import ROLE
    return ROLE.VIEWER


class ToolMiddleware:
    """Wraps FastMCP.tool() to compose input sanitization, output sanitization,
    ROI/metrics timing, tool registry capture, and RBAC enforcement in a single
    decorator pass."""

    def __init__(self, mcp: Any, registry: dict[str, Any]) -> None:
        self._mcp = mcp
        self._registry = registry
        self._original_tool = mcp.tool

    def tool(self, *args: Any, **kwargs: Any) -> Any:
        """Drop-in replacement for mcp.tool().

        Accepts an optional ``role=`` kwarg (not forwarded to FastMCP) that
        sets the minimum RBAC role required to call this tool.  When omitted,
        the module-level ``REQUIRED_ROLE`` is used as the fallback.

        Wraps each registered function to:
        1. Enforce the minimum RBAC role (structural — cannot be bypassed)
        2. Sanitize input kwargs (injection, length, dangerous chars)
        3. Enforce operational-context gating + the failure circuit breaker
        4. Run the tool and record timing for ROI + Prometheus metrics
        5. Sanitize output (strip injection tokens, PII, secrets, cap size)
        6. Register the function by name in the tool registry
        """
        # Pop our custom kwarg before forwarding to FastMCP — it doesn't know
        # about role= and would raise on an unexpected keyword argument.
        explicit_role = kwargs.pop("role", None)
        decorator = self._original_tool(*args, **kwargs)
        registry = self._registry

        def capturing_decorator(fn: Any) -> Any:
            # Resolve the role once at registration time (not per call) so there
            # is zero per-call overhead and the decision is visible in logs during
            # server startup.
            _required_role = _resolve_tool_role(fn, explicit_role)

            @functools.wraps(fn)
            async def wrapped(*fn_args: Any, **fn_kwargs: Any) -> Any:
                from ..input_sanitizer import sanitize_input_value
                from ..identity import record_injection_attempt, _ctx_identity_key, get_identity_key
                from ..audit import sanitize_response, cap_response_size, sanitize_string
                from ..logging_config import bind_request_context, clear_request_context
                from ..tool_failure_breaker import tool_failure_breaker as _tfb, is_failure_result
                from ..tool_contexts import is_tool_allowed, gate_message

                # ── Structured-logging context (Improvement 3) ───────────
                # Bind a per-call trace_id + tool + identity so EVERY log line
                # emitted during this single tool execution can be correlated.
                bind_request_context(fn.__name__, _ctx_identity_key.get(None) or "local")
                try:
                    # ── RBAC enforcement (structural — runs before everything) ──
                    # Enforced here in the middleware so it is impossible to bypass
                    # by forgetting an inline require_role() call in the tool body.
                    from ..rbac import require_role as _require_role
                    _rbac_err = _require_role(_required_role)
                    if _rbac_err:
                        return _rbac_err

                    # ── INPUT sanitization ────────────────────────────────
                    clean_kwargs: dict = {}
                    for field, value in fn_kwargs.items():
                        try:
                            clean_kwargs[field] = sanitize_input_value(value, field)
                        except ValueError as exc:
                            locked_out = record_injection_attempt()
                            msg = f"Input rejected: {exc}"
                            if locked_out:
                                msg += " [session locked to VIEWER after repeated violations]"
                            return {"error": msg}

                    _tool_name = fn.__name__
                    _identity = get_identity_key()

                    # ── Operational-context gating ────────────────────────
                    # No-op unless WAZUH_MCP_CONTEXT_GATING is enabled. Keeps
                    # inert any tool whose context the caller has not entered.
                    if not is_tool_allowed(_tool_name, _identity):
                        return gate_message(_tool_name)

                    # ── Failure circuit breaker (stop LLM retry loops) ─────
                    # Keyed per (caller, tool, args): if this exact call has
                    # failed repeatedly, short-circuit before touching the
                    # backend.
                    _open = _tfb.check(_identity, _tool_name, clean_kwargs)
                    if _open is not None:
                        return _open

                    # ── Tool execution (with timing) ──────────────────────
                    t0 = time.monotonic()
                    try:
                        result = await fn(*fn_args, **clean_kwargs)
                    except Exception:
                        _tfb.record_failure(_identity, _tool_name, clean_kwargs)
                        raise
                    duration = time.monotonic() - t0

                    # Single failure contract (see tool_failure_breaker): any
                    # standardized failure shape ({"error"} or {"execute_error"})
                    # trips the breaker and counts as an error in metrics; any
                    # other shape resets the streak. Keeps detection reliable
                    # across tools that use different keys.
                    _failed = is_failure_result(result)
                    if _failed:
                        _tfb.record_failure(_identity, _tool_name, clean_kwargs)
                    else:
                        _tfb.record_success(_identity, _tool_name, clean_kwargs)

                    try:
                        from ..core.roi_tracker import record_call
                        record_call(fn.__name__, duration)
                    except Exception:
                        pass
                    try:
                        from ..tools.metrics import record_tool_call
                        record_tool_call(fn.__name__, duration, had_error=_failed)
                    except Exception:
                        pass

                    # ── OUTPUT sanitization ───────────────────────────────
                    # Pass the tool name so secret-redaction can be skipped for
                    # tools that intentionally return a credential (M5 allowlist).
                    if isinstance(result, dict):
                        result = sanitize_response(result, tool_name=_tool_name)
                    elif isinstance(result, str):
                        result = sanitize_string(result)
                    elif isinstance(result, list):
                        result = [
                            sanitize_response(item, tool_name=_tool_name) if isinstance(item, dict)
                            else (sanitize_string(item) if isinstance(item, str) else item)
                            for item in result
                        ]

                    return cap_response_size(result)
                finally:
                    clear_request_context()

            # Tag the tool with its operational context (based on the module
            # currently registering) so call-time gating can be enforced.
            try:
                from ..tool_contexts import tag_tool
                tag_tool(fn.__name__)
            except Exception:
                pass

            # Register the middleware-wrapped function so playbook / autonomous
            # SOC calls pass through input sanitization and output capping too.
            registry[fn.__name__] = wrapped
            return decorator(wrapped)

        return capturing_decorator

    def install(self) -> None:
        """Replace mcp.tool with this middleware's tool method."""
        self._mcp.tool = self.tool  # type: ignore[method-assign]
