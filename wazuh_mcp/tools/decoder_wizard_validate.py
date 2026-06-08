"""Decoder Wizard — official-format validation for Wazuh decoder XML.

Enforces the official Wazuh decoder schema (allow-listed elements/attributes,
regex type/offset, plugin_decoder names, no "grandchild" decoders, and
``<order>``/capture-group parity). Pure, non-mutating logic — no I/O.

Format authority: https://documentation.wazuh.com/current/user-manual/ruleset/
ruleset-xml-syntax/decoders.html and the wazuh/wazuh-ruleset repository.

Exposes ``register_validate(ctx)`` for the ``decoder_wizard`` aggregator.
"""
from __future__ import annotations

import re as _re

import defusedxml.ElementTree as ET

from ..rbac import require_analyst_or_above, ROLE
from ..tool_context import ToolContext

REQUIRED_ROLE = ROLE.ANALYST

# ── Official decoder schema (do NOT extend with invented elements) ────────────
_DECODER_CHILD_TAGS = {
    "parent", "prematch", "regex", "order", "program_name",
    "plugin_decoder", "use_own_name", "type", "json_null_field",
}
_PLUGIN_DECODERS = {
    "PF_Decoder", "SymantecWS_Decoder", "SonicWall_Decoder",
    "OSSECAlert_Decoder", "JSON_Decoder",
}
_REGEX_TYPES   = {"osregex", "osmatch", "sregex", "pcre2"}
_REGEX_OFFSETS = {"after_parent", "after_prematch"}
_JSON_NULL_FIELD = {"string", "discard"}


def _parse_fragment(xml: str) -> "tuple[list, str | None]":
    """Parse a decoder fragment tolerant of multiple top-level ``<decoder>``.

    A Wazuh decoder file is not necessarily a single-rooted XML document — it
    commonly contains several sibling ``<decoder>`` elements. Wrap in a synthetic
    root so ``defusedxml`` accepts it, then return the contained ``<decoder>``
    elements. Returns ``(decoders, error)``; ``error`` is set on parse failure.
    """
    if not xml or not xml.strip():
        return [], "XML content is empty."
    body = xml.strip()
    # Drop an optional XML declaration so wrapping stays well-formed.
    body = _re.sub(r"^<\?xml[^>]*\?>", "", body).strip()
    try:
        root = ET.fromstring(f"<_wztest>{body}</_wztest>")
    except ET.ParseError as exc:
        return [], f"XML parse error: {exc}"
    return list(root.iter("decoder")), None


def _count_capture_groups(regex: str) -> int:
    """Return the number of capturing groups, or -1 if the pattern can't be
    analysed with Python's ``re`` (e.g. Wazuh-specific classes like ``\\p``).

    Used both for ``<order>`` parity and as a signal that osregex-specific
    syntax can't be faithfully simulated.
    """
    if not regex:
        return 0
    try:
        return _re.compile(regex).groups
    except _re.error:
        return -1


def _osregex_pitfalls(regex: str) -> list[str]:
    """Best-effort detection of OS_Regex constructs that silently fail unless the
    regex is declared ``type="pcre2"``: bare quantifiers and alternation."""
    warnings: list[str] = []
    # Alternation inside a group, e.g. (foo|bar) — unsupported by osregex.
    if _re.search(r"\([^)]*\|[^)]*\)", regex):
        warnings.append(
            "Regex uses alternation '(a|b)', which OS_Regex (osregex) does not "
            "support. Declare type=\"pcre2\" for this pattern."
        )
    # Bare quantifier on a literal/class, e.g. '0+' or 'abc*' (osregex allows
    # quantifiers only on backslash classes like \\d+). Heuristic, not exhaustive.
    if _re.search(r"(?<!\\)[A-Za-z0-9\]]\s*[+*]", regex):
        warnings.append(
            "Regex appears to apply '+'/'*' to a literal/class. OS_Regex only "
            "allows quantifiers on backslash classes (e.g. \\d+). Use type=\"pcre2\"."
        )
    return warnings


def _validate_decoder_xml_impl(xml_content: str) -> dict:
    """Pure validator for Wazuh decoder XML. Callable from other modules.

    Returns::

        {
          "valid": bool,            # False if there are blockers or a parse error
          "decoders_found": int,
          "fields": [str, ...],     # union of <order> field names declared
          "order_parity": [{decoder, capture_groups, order_count, ok}],
          "blockers": [str, ...],   # MUST be empty before deploy
          "warnings": [str, ...],
          "error": str | None,
        }
    """
    decoders, err = _parse_fragment(xml_content)
    if err:
        return {"valid": False, "error": err, "blockers": [err],
                "warnings": [], "decoders_found": 0, "fields": [], "order_parity": []}
    if not decoders:
        msg = "No <decoder> elements found. A decoder file needs at least one <decoder name=\"...\">."
        return {"valid": False, "error": msg, "blockers": [msg],
                "warnings": [], "decoders_found": 0, "fields": [], "order_parity": []}

    blockers: list[str] = []
    warnings: list[str] = []
    fields: list[str] = []
    order_parity: list[dict] = []

    # Names that are children (declare a <parent>) — used for grandchild detection.
    child_names = {
        (d.get("name") or "").strip()
        for d in decoders if d.find("parent") is not None and d.get("name")
    }

    for d in decoders:
        name = (d.get("name") or "").strip()
        label = name or "?"
        if not name:
            blockers.append("A <decoder> element is missing the required 'name' attribute.")

        # Element allow-list — reject anything not in the official schema.
        for child in list(d):
            tag = child.tag
            if tag not in _DECODER_CHILD_TAGS:
                blockers.append(
                    f"Decoder '{label}' contains invented element <{tag}>. "
                    f"Allowed: {', '.join(sorted(_DECODER_CHILD_TAGS))}."
                )

        # regex / prematch type + offset attributes.
        regex_el = d.find("regex")
        for el_name in ("regex", "prematch"):
            el = d.find(el_name)
            if el is None:
                continue
            rtype = (el.get("type") or "").strip()
            if rtype and rtype not in _REGEX_TYPES:
                blockers.append(
                    f"Decoder '{label}' <{el_name} type=\"{rtype}\"> is invalid. "
                    f"Allowed types: {', '.join(sorted(_REGEX_TYPES))}."
                )
            offset = (el.get("offset") or "").strip()
            if offset and offset not in _REGEX_OFFSETS:
                blockers.append(
                    f"Decoder '{label}' <{el_name} offset=\"{offset}\"> is invalid. "
                    f"Allowed offsets: {', '.join(sorted(_REGEX_OFFSETS))}."
                )

        # plugin_decoder allow-list.
        plugin_el = d.find("plugin_decoder")
        if plugin_el is not None:
            val = (plugin_el.text or "").strip()
            if val and val not in _PLUGIN_DECODERS:
                blockers.append(
                    f"Decoder '{label}' uses unknown plugin_decoder '{val}'. "
                    f"Allowed: {', '.join(sorted(_PLUGIN_DECODERS))}."
                )

        # json_null_field allow-list.
        jnf = d.find("json_null_field")
        if jnf is not None:
            val = (jnf.text or "").strip()
            if val and val not in _JSON_NULL_FIELD:
                warnings.append(
                    f"Decoder '{label}' json_null_field '{val}' is non-standard "
                    f"(expected one of: {', '.join(sorted(_JSON_NULL_FIELD))})."
                )

        # No grandchildren: a decoder that is itself a child may not be a parent.
        parent_el = d.find("parent")
        if parent_el is not None:
            parent_name = (parent_el.text or "").strip()
            if parent_name in child_names:
                blockers.append(
                    f"Decoder '{label}' lists parent '{parent_name}', but that "
                    "decoder is itself a child. Wazuh does not allow grandchild "
                    "decoders."
                )

        # <order>/capture-group parity.
        order_el = d.find("order")
        if order_el is not None and (order_el.text or "").strip():
            order_fields = [f.strip() for f in order_el.text.split(",") if f.strip()]
            fields.extend(order_fields)
            regex_text = (regex_el.text or "") if regex_el is not None else ""
            groups = _count_capture_groups(regex_text)
            ok = True
            if regex_el is None:
                blockers.append(
                    f"Decoder '{label}' has <order> but no <regex> — order fields "
                    "are filled from regex capture groups."
                )
                ok = False
            elif groups == -1:
                warnings.append(
                    f"Decoder '{label}' regex could not be analysed for capture "
                    "groups (Wazuh-specific syntax). Verify order/regex parity manually."
                )
                ok = None  # unknown
            elif groups != len(order_fields):
                blockers.append(
                    f"Decoder '{label}' <order> lists {len(order_fields)} field(s) "
                    f"but <regex> has {groups} capture group(s) — they must match."
                )
                ok = False
            order_parity.append({
                "decoder": label,
                "capture_groups": groups,
                "order_count": len(order_fields),
                "ok": ok,
            })

        # osregex pitfalls (regex without an explicit pcre2 type).
        if regex_el is not None and (regex_el.get("type") or "osregex") != "pcre2":
            warnings.extend(_osregex_pitfalls(regex_el.text or ""))

    return {
        "valid": not blockers,
        "decoders_found": len(decoders),
        "fields": sorted(set(fields)),
        "order_parity": order_parity,
        "blockers": blockers,
        "warnings": warnings,
        "error": None,
    }


def register_validate(ctx: ToolContext) -> None:
    mcp = ctx.mcp

    @mcp.tool()
    async def validate_decoder_xml(xml_content: str) -> dict:
        """Validate Wazuh DECODER XML against the official format before deployment.

        Checks (non-mutating, nothing is written to the Manager):
          - Well-formed XML; at least one <decoder> with a required name attribute
          - Only official child elements (parent, prematch, regex, order,
            program_name, plugin_decoder, use_own_name, type, json_null_field) —
            invented elements are reported as blockers
          - regex/prematch type ∈ {osregex, osmatch, sregex, pcre2} and
            offset ∈ {after_parent, after_prematch}
          - plugin_decoder ∈ the official set; no grandchild decoders
          - <order> field count equals the <regex> capture-group count
          - OS_Regex pitfalls (alternation, bare quantifiers) → use type="pcre2"

        Returns valid/blockers/warnings plus the extracted field names.
        Requires role: analyst.
        """
        err = require_analyst_or_above()
        if err:
            return err
        return _validate_decoder_xml_impl(xml_content)
