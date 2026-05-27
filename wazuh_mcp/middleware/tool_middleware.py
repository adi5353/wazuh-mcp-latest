"""ToolMiddleware — single decorator that composes sanitization + registry capture.

Previously server.py monkey-patched mcp.tool twice in sequence, which was
order-dependent and brittle. This class wraps both concerns in one place.

Usage in server.py::

    from .middleware import ToolMiddleware
    _TOOL_REGISTRY: dict[str, Any] = {}
    mcp.tool = ToolMiddleware(mcp, _TOOL_REGISTRY).tool
"""
from __future__ import annotations

import functools
import time
from typing import Any


class ToolMiddleware:
    """Wraps FastMCP.tool() to compose input sanitization, output sanitization,
    ROI/metrics timing, and tool registry capture in a single decorator pass."""

    def __init__(self, mcp: Any, registry: dict[str, Any]) -> None:
        self._mcp = mcp
        self._registry = registry
        self._original_tool = mcp.tool

    def tool(self, *args: Any, **kwargs: Any) -> Any:
        """Drop-in replacement for mcp.tool().

        Wraps each registered function to:
        1. Sanitize input kwargs (injection, length, dangerous chars)
        2. Run the tool and record timing for ROI + Prometheus metrics
        3. Sanitize output (strip injection tokens, PII, secrets, cap size)
        4. Register the function by name in the tool registry
        """
        decorator = self._original_tool(*args, **kwargs)
        registry = self._registry

        def capturing_decorator(fn: Any) -> Any:
            @functools.wraps(fn)
            async def wrapped(*fn_args: Any, **fn_kwargs: Any) -> Any:
                from ..input_sanitizer import sanitize_input_value
                from ..identity import record_injection_attempt
                from ..audit import sanitize_response, cap_response_size, sanitize_string

                # ── INPUT sanitization ────────────────────────────────────
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

                # ── Tool execution (with timing) ──────────────────────────
                t0 = time.monotonic()
                result = await fn(*fn_args, **clean_kwargs)
                duration = time.monotonic() - t0

                try:
                    from ..core.roi_tracker import record_call
                    record_call(fn.__name__, duration)
                except Exception:
                    pass
                try:
                    from ..tools.metrics import record_tool_call
                    record_tool_call(fn.__name__, duration)
                except Exception:
                    pass

                # ── OUTPUT sanitization ───────────────────────────────────
                if isinstance(result, dict):
                    result = sanitize_response(result)
                elif isinstance(result, str):
                    result = sanitize_string(result)
                elif isinstance(result, list):
                    result = [
                        sanitize_response(item) if isinstance(item, dict)
                        else (sanitize_string(item) if isinstance(item, str) else item)
                        for item in result
                    ]

                return cap_response_size(result)

            # Register the middleware-wrapped function so playbook / autonomous
            # SOC calls pass through input sanitization and output capping too.
            registry[fn.__name__] = wrapped
            return decorator(wrapped)

        return capturing_decorator

    def install(self) -> None:
        """Replace mcp.tool with this middleware's tool method."""
        self._mcp.tool = self.tool  # type: ignore[method-assign]
