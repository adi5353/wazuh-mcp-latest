"""Decoder Wizard — deterministic generation of official Wazuh decoder XML.

The LLM supplies the regex and the ordered field names it derived from a sample
log; this tool assembles correctly-escaped, official-format decoder XML and
self-validates it (schema + order/capture parity + regex-vs-sample simulation).
Non-mutating — nothing is written to the Manager.

Exposes ``register_generate(ctx)`` for the ``decoder_wizard`` aggregator.
"""
from __future__ import annotations

from ..rbac import require_analyst_or_above, ROLE
from ..tool_context import ToolContext
from .rule_wizard_generate import _xml_text, _xml_attr
from .decoder_wizard_validate import (
    _validate_decoder_xml_impl,
    _count_capture_groups,
    _REGEX_TYPES,
    _REGEX_OFFSETS,
)

REQUIRED_ROLE = ROLE.ANALYST


def _simulate_match(regex: str, sample: str) -> dict:
    """Best-effort simulation of a decoder regex against a sample log line.

    Uses Python's ``re`` — faithful for ``type="pcre2"`` patterns, approximate
    for OS_Regex (some Wazuh classes like ``\\p`` won't compile). Returns
    ``{matched, captures, fidelity, note}``.
    """
    import re as _re
    try:
        compiled = _re.compile(regex)
    except _re.error as exc:
        return {"matched": None, "captures": [], "fidelity": "unavailable",
                "note": f"Pattern not analysable with Python re: {exc}"}
    m = compiled.search(sample)
    return {
        "matched": bool(m),
        "captures": list(m.groups()) if m else [],
        "fidelity": "exact",  # caller downgrades to 'approximate' for osregex
        "note": "",
    }


def register_generate(ctx: ToolContext) -> None:
    mcp = ctx.mcp

    @mcp.tool()
    async def generate_decoder_xml(
        decoder_name: str,
        fields: list,
        regex: str,
        sample_log: str = "",
        parent: str = "",
        regex_type: str = "pcre2",
        regex_offset: str = "",
        prematch: str = "",
        program_name: str = "",
    ) -> dict:
        """Assemble official Wazuh DECODER XML from an LLM-authored regex + fields.

        You (the LLM) read the raw log, design the capture regex and the ordered
        list of field names; this tool emits correctly-escaped, official-format
        XML, then validates schema + <order>/capture parity and (if sample_log is
        given) simulates the regex against the sample. Non-mutating, role: analyst.

        decoder_name: Unique decoder name (root) or the child decoder's name.
        fields:       Ordered field names; becomes <order> (count must equal the
                      number of regex capture groups).
        regex:        Capture regex. Each '(...)' group maps to one order field.
        sample_log:   Optional raw log line — used to simulate the match.
        parent:       If set, emit a CHILD decoder (<parent>) of this decoder.
        regex_type:   osregex | osmatch | sregex | pcre2 (default pcre2).
        regex_offset: '' | after_parent | after_prematch.
        prematch:     Optional <prematch> pattern.
        program_name: Optional <program_name> pattern (root decoders).

        Returns {xml, decoder_name, capture_groups, order_count, validation,
        simulation, blockers, warnings, tip}.
        """
        err = require_analyst_or_above()
        if err:
            return err

        if not decoder_name or not decoder_name.strip():
            return {"error": "decoder_name must not be empty."}
        if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
            return {"error": "fields must be a list of strings (the <order> names)."}
        if regex_type not in _REGEX_TYPES:
            return {"error": f"regex_type must be one of: {', '.join(sorted(_REGEX_TYPES))}."}
        if regex_offset and regex_offset not in _REGEX_OFFSETS:
            return {"error": f"regex_offset must be one of: {', '.join(sorted(_REGEX_OFFSETS))}."}

        type_attr   = f' type="{_xml_attr(regex_type)}"' if regex else ""
        offset_attr = f' offset="{_xml_attr(regex_offset)}"' if regex_offset else ""

        lines = [f'<decoder name="{_xml_attr(decoder_name)}">']
        if parent:
            lines.append(f"  <parent>{_xml_text(parent)}</parent>")
        if program_name:
            lines.append(f"  <program_name>{_xml_text(program_name)}</program_name>")
        if prematch:
            lines.append(f"  <prematch>{_xml_text(prematch)}</prematch>")
        if regex:
            lines.append(f"  <regex{offset_attr}{type_attr}>{_xml_text(regex)}</regex>")
        if fields:
            lines.append(f"  <order>{_xml_text(', '.join(fields))}</order>")
        lines.append("</decoder>")
        xml_out = "\n".join(lines)

        validation = _validate_decoder_xml_impl(xml_out)
        groups = _count_capture_groups(regex)

        simulation = None
        if sample_log and regex:
            simulation = _simulate_match(regex, sample_log)
            if regex_type != "pcre2" and simulation.get("fidelity") == "exact":
                simulation["fidelity"] = "approximate"
                simulation["note"] = (
                    "OS_Regex simulated with Python re — approximate. Declare "
                    "type=\"pcre2\" for a faithful match."
                )

        return {
            "xml": xml_out,
            "decoder_name": decoder_name,
            "capture_groups": groups,
            "order_count": len(fields),
            "validation": validation,
            "simulation": simulation,
            "blockers": validation.get("blockers", []),
            "warnings": validation.get("warnings", []),
            "tip": (
                "Review the XML, then call test_detection_candidate(decoder_xml, "
                "rule_xml, sample_logs) to run the full non-mutating test pipeline."
            ),
        }
