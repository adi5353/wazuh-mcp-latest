"""Detection Drafter — non-mutating "logs → decoder + rule → test" orchestrator.

Given raw log samples and an LLM-authored candidate decoder + rule, this module
runs every test that does NOT require deploying or restarting the Manager:

  A. Static schema validation (official Wazuh decoder + rule format).
  B. <order>/capture parity + Python regex simulation against the samples.
  C. Live logtest (PUT /logtest — non-mutating) for CONTEXT ONLY: baseline gap
     detection and verification that referenced parents (if_sid / decoded_as /
     parent decoder) actually exist and fire on the samples.
  D. Duplicate rule-id check against the live ruleset (GET /rules).
  E. Decoder-before-rule dependency direction check.
  F. An honesty note (the candidate is NOT loaded, so firing is simulated, not
     proven) plus the exact manual recipe to deploy + verify on STAGING using the
     existing admin tools.

NOTHING here writes to or restarts the Manager. Deployment stays manual via
push_custom_decoder / push_custom_rule / rollback_custom_rule.
"""
from __future__ import annotations

import re as _re

import defusedxml.ElementTree as ET

from ..rbac import require_analyst_or_above, ROLE
from ..tool_context import ToolContext
from .rule_wizard_validate import _validate_rule_xml_impl
from .rule_wizard_generate import WAZUH_STATIC_FIELDS
from .decoder_wizard_validate import _validate_decoder_xml_impl, _parse_fragment
from .decoder_wizard_generate import _simulate_match

REQUIRED_ROLE = ROLE.ANALYST

# ── Official rule schema — every valid <rule> child element (do NOT extend with
# invented elements). Source: official Wazuh rules XML syntax. ────────────────
_RULE_CHILD_TAGS = {
    # matching
    "match", "regex", "decoded_as", "category", "field",
    # dedicated static-field match elements
    "srcip", "dstip", "srcport", "dstport", "data", "extra_data", "user",
    "srcuser", "dstuser", "system_name", "program_name", "protocol",
    "hostname", "id", "url", "location", "action", "status",
    "srcgeoip", "dstgeoip",
    # time windows
    "time", "weekday",
    # composition / hierarchy
    "if_sid", "if_group", "if_level", "if_matched_sid", "if_matched_group",
    # correlation (same_*/different_*)
    "same_id", "different_id", "same_srcip", "different_srcip",
    "same_dstip", "different_dstip", "same_srcport", "different_srcport",
    "same_dstport", "different_dstport", "same_location", "different_location",
    "same_srcuser", "different_srcuser", "same_user", "different_user",
    "same_field", "different_field", "same_protocol", "different_protocol",
    "same_action", "different_action", "same_data", "different_data",
    "same_extra_data", "different_extra_data", "same_status", "different_status",
    "same_system_name", "different_system_name", "same_url", "different_url",
    "same_srcgeoip", "different_srcgeoip", "same_dstgeoip", "different_dstgeoip",
    "same_source_ip",  # deprecated alias of same_srcip
    # frequency / metadata / control
    "frequency", "timeframe", "options", "description", "list", "info",
    "check_diff", "group", "mitre", "var",
}
_RULE_OPTIONS = {"no_full_log", "no_alert", "no_counter", "alert_by_email"}
_MITRE_ID = _re.compile(r"^T\d{4}(\.\d{3})?$")

# Official custom rule id range (documentation.wazuh.com). The repo's lenient
# validator allows up to 199999 (system space); we WARN between the official
# ceiling and that, and only BLOCK outside the system space.
_OFFICIAL_MIN, _OFFICIAL_MAX = 100000, 120000
_SYSTEM_MIN, _SYSTEM_MAX = 100000, 199999


def _parse_rules(xml: str) -> "tuple[list, str | None]":
    """Parse a rule fragment tolerant of multiple top-level elements."""
    if not xml or not xml.strip():
        return [], "XML content is empty."
    body = _re.sub(r"^<\?xml[^>]*\?>", "", xml.strip()).strip()
    try:
        root = ET.fromstring(f"<_wztest>{body}</_wztest>")
    except ET.ParseError as exc:
        return [], f"XML parse error: {exc}"
    return list(root.iter("rule")), None


def _validate_rule_official_impl(xml_content: str) -> dict:
    """Strict official-format rule validation (extends _validate_rule_xml_impl).

    Returns valid/blockers/warnings plus dependency metadata the pipeline needs:
    rule_ids, field_names, decoded_as[], if_sid[], if_group[], uses_fields.
    """
    base = _validate_rule_xml_impl(xml_content)
    if not base.get("valid"):
        return {**base, "blockers": [base.get("error", "Invalid rule XML.")],
                "warnings": base.get("warnings", []), "rule_ids": [],
                "field_names": [], "decoded_as": [], "if_sid": [],
                "if_group": [], "uses_fields": False}

    rules, err = _parse_rules(xml_content)
    if err:
        return {"valid": False, "blockers": [err], "warnings": [], "rule_ids": [],
                "field_names": [], "decoded_as": [], "if_sid": [], "if_group": [],
                "uses_fields": False}

    blockers: list[str] = []
    warnings: list[str] = list(base.get("warnings", []))
    rule_ids: list[int] = []
    field_names: list[str] = []
    decoded_as: list[str] = []
    if_sid: list[str] = []
    if_group: list[str] = []

    for r in rules:
        rid_str = (r.get("id") or "").strip()
        label = rid_str or "?"
        if rid_str.isdigit():
            rid = int(rid_str)
            rule_ids.append(rid)
            if rid < _SYSTEM_MIN or rid > _SYSTEM_MAX:
                blockers.append(
                    f"Rule id {rid} is outside the custom space {_SYSTEM_MIN}-"
                    f"{_SYSTEM_MAX}; it would collide with built-in Wazuh rules."
                )
            elif rid > _OFFICIAL_MAX:
                warnings.append(
                    f"Rule id {rid} is outside the officially documented custom "
                    f"range {_OFFICIAL_MIN}-{_OFFICIAL_MAX} (still in user space)."
                )

        lvl_str = (r.get("level") or "").strip()
        if lvl_str.lstrip("-").isdigit():
            lvl = int(lvl_str)
            if lvl < 0 or lvl > 16:
                blockers.append(f"Rule {label} level {lvl} is invalid (must be 0-16).")

        has_freq = has_tf = False
        for child in list(r):
            tag = child.tag
            if tag not in _RULE_CHILD_TAGS:
                blockers.append(
                    f"Rule {label} contains invented element <{tag}>. Allowed: "
                    f"{', '.join(sorted(_RULE_CHILD_TAGS))}."
                )
                continue
            if tag == "field":
                fname = (child.get("name") or "").strip()
                if fname in WAZUH_STATIC_FIELDS:
                    blockers.append(
                        f"Rule {label} uses <field name=\"{fname}\"> but '{fname}' "
                        f"is a Wazuh static field — match it with the dedicated "
                        f"<{fname}> element instead. Using <field> here fails "
                        f"ruleset load with \"Field '{fname}' is static\"."
                    )
                elif fname:
                    field_names.append(fname)
            elif tag == "decoded_as":
                decoded_as.append((child.text or "").strip())
            elif tag == "if_sid":
                if_sid.extend(p.strip() for p in (child.text or "").split(",") if p.strip())
            elif tag == "if_group":
                if_group.append((child.text or "").strip())
            elif tag in ("srcip", "dstip"):
                field_names.append(tag)
            elif tag == "options":
                opt = (child.text or "").strip()
                if opt and opt not in _RULE_OPTIONS:
                    warnings.append(f"Rule {label} <options>{opt}</options> is non-standard.")
            elif tag == "mitre":
                for mid in child.findall("id"):
                    val = (mid.text or "").strip()
                    if val and not _MITRE_ID.match(val):
                        warnings.append(
                            f"Rule {label} MITRE id '{val}' is not a valid technique "
                            "id (expected like T1110 or T1543.003)."
                        )
            elif tag == "frequency":
                has_freq = True
            elif tag == "timeframe":
                has_tf = True
        if has_freq != has_tf:
            warnings.append(
                f"Rule {label} uses <frequency> and <timeframe> together — one is "
                "missing; correlation rules need both."
            )

    return {
        "valid": not blockers,
        "rules_found": base.get("rules_found", len(rules)),
        "blockers": blockers,
        "warnings": warnings,
        "rule_ids": rule_ids,
        "field_names": sorted(set(field_names)),
        "decoded_as": [d for d in decoded_as if d],
        "if_sid": if_sid,
        "if_group": [g for g in if_group if g],
        "uses_fields": bool(field_names) or bool(decoded_as),
    }


def _decoder_regexes(decoder_xml: str) -> list[dict]:
    """Extract (name, regex, type, order_fields) per decoder for simulation."""
    decoders, err = _parse_fragment(decoder_xml)
    if err:
        return []
    out: list[dict] = []
    for d in decoders:
        rex = d.find("regex")
        order = d.find("order")
        out.append({
            "name": (d.get("name") or "").strip(),
            "regex": (rex.text or "") if rex is not None else "",
            "type": (rex.get("type") or "osregex") if rex is not None else "",
            "order": [f.strip() for f in (order.text or "").split(",") if f.strip()]
                     if order is not None and order.text else [],
        })
    return out


_MANUAL_RECIPE = [
    "On the STAGING manager only (never prod):",
    "1. push_custom_decoder(decoder_xml, filename='0900-candidate_decoders.xml', dry_run=False)  # admin",
    "2. push_custom_rule(rule_xml, filename='candidate_rules.xml', dry_run=False)  # admin",
    "3. Restart/reload the staging manager so analysisd loads the files (manual — this tool never restarts).",
    "4. test_log_against_rules(log_samples=[...]) to confirm the candidate decoder fires and fields decode.",
    "5. If anything regresses, rollback_custom_rule(filename='candidate_rules.xml') to restore the prior version.",
]


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz

    async def _logtest(event: str, log_format: str) -> dict:
        """Non-mutating PUT /logtest against the configured (point at staging) Manager."""
        return await wz.request("PUT", "/logtest", json={
            "event": str(event), "log_format": log_format, "location": "test",
        })

    @mcp.tool()
    async def test_detection_candidate(
        decoder_xml: str,
        rule_xml: str,
        sample_logs: list,
        log_format: str = "syslog",
    ) -> dict:
        """Run the full NON-MUTATING test pipeline on a candidate decoder + rule.

        Never writes to or restarts the Manager. Combines static official-format
        validation, <order>/capture parity, Python regex simulation against the
        samples, and live logtest (PUT /logtest) used ONLY for context: baseline
        gap detection, parent if_sid/decoded_as existence, and duplicate-id check.

        Because the candidate is not loaded into analysisd, this CANNOT prove the
        candidate fires — it returns an honesty_note and the exact manual recipe
        to deploy + verify on a STAGING manager via the existing admin tools.

        decoder_xml: Candidate decoder XML (may be empty if only adding a rule).
        rule_xml:    Candidate rule XML (wrapped in <group>).
        sample_logs: Up to 20 raw log lines the detection should match.
        log_format:  syslog | json | audit | eventchannel | apache | nginx
        Requires role: analyst.
        """
        err = require_analyst_or_above()
        if err:
            return err
        if not isinstance(sample_logs, list) or not sample_logs:
            return {"error": "sample_logs must be a non-empty list of raw log lines."}
        samples = [str(s) for s in sample_logs[:20]]

        blockers: list[str] = []
        warnings: list[str] = []

        # ── A. Static schema validation ──────────────────────────────────────
        decoder_validation: dict = (
            _validate_decoder_xml_impl(decoder_xml) if decoder_xml.strip()
            else {"valid": True, "blockers": [], "warnings": [], "fields": [],
                  "decoders_found": 0, "order_parity": []}
        )
        rule_validation = _validate_rule_official_impl(rule_xml)
        blockers += decoder_validation.get("blockers", [])
        blockers += rule_validation.get("blockers", [])
        warnings += decoder_validation.get("warnings", [])
        warnings += rule_validation.get("warnings", [])

        # ── B. Regex simulation against the samples ──────────────────────────
        decoders = _decoder_regexes(decoder_xml) if decoder_xml.strip() else []
        sim_results = []
        fidelity = "exact"
        matched_count = 0
        for sample in samples:
            per: dict = {"sample": sample[:120], "decoder_matches": []}
            sample_matched = False
            for d in decoders:
                if not d["regex"]:
                    continue
                sim = _simulate_match(d["regex"], sample)
                if d["type"] and d["type"] != "pcre2" and sim.get("fidelity") == "exact":
                    sim["fidelity"] = "approximate"
                    fidelity = "approximate"
                if sim.get("fidelity") in ("approximate", "unavailable"):
                    fidelity = "approximate"
                captures = sim.get("captures") or []
                per["decoder_matches"].append({
                    "decoder": d["name"],
                    "matched": sim.get("matched"),
                    "captured": captures,
                    "order_parity_ok": (len(captures) == len(d["order"])) if sim.get("matched") else None,
                    "fidelity": sim.get("fidelity"),
                })
                sample_matched = sample_matched or bool(sim.get("matched"))
            if sample_matched:
                matched_count += 1
            sim_results.append(per)

        if decoders and matched_count == 0:
            blockers.append(
                "The candidate decoder regex matched none of the sample logs — it "
                "would not extract any fields. Revise the regex."
            )

        # ── C. Live logtest: baseline + parent existence (context only) ──────
        baseline = []
        baseline_fired_ids: set[str] = set()
        for sample in samples:
            try:
                r = await _logtest(sample, log_format)
                out = (r.get("data") or {}).get("output", {}) if isinstance(r, dict) else {}
                rule = out.get("rule", {}) or {}
                rid = str(rule.get("id")) if rule.get("id") else None
                if rid:
                    baseline_fired_ids.add(rid)
                baseline.append({
                    "sample": sample[:120],
                    "decoder": (out.get("decoder") or {}).get("name"),
                    "rule_id": rid,
                    "level": rule.get("level"),
                    "already_detected": bool(rid),
                })
            except Exception as exc:  # logtest is best-effort context
                baseline.append({"sample": sample[:120], "error": str(exc)})
                warnings.append(f"logtest unavailable for a sample: {exc}")

        if baseline and all(b.get("already_detected") for b in baseline if "error" not in b):
            warnings.append(
                "Every sample is already detected by the current ruleset — confirm "
                "this is a real gap before adding a duplicate rule."
            )

        # ── C/D. Parent existence + duplicate-id (GET /rules) ────────────────
        parent_check: dict = {"if_sid": rule_validation.get("if_sid", []),
                              "decoded_as": rule_validation.get("decoded_as", []),
                              "checks": []}
        for pid in rule_validation.get("if_sid", []):
            exists: "bool | None" = False
            try:
                resp = await wz.request("GET", f"/rules?rule_ids={pid}")
                exists = bool((resp.get("data") or {}).get("affected_items"))
            except Exception:
                exists = None
            if exists is False:
                blockers.append(
                    f"Rule references <if_sid>{pid}</if_sid> but no such rule exists — "
                    "the child would silently never fire."
                )
            parent_check["checks"].append({
                "if_sid": pid, "exists": exists,
                "fires_on_samples": pid in baseline_fired_ids,
            })

        # decoded_as parent decoder must be present (candidate or live baseline).
        candidate_decoder_names = {d["name"] for d in decoders if d["name"]}
        baseline_decoders = {b.get("decoder") for b in baseline if b.get("decoder")}
        for dname in rule_validation.get("decoded_as", []):
            present = dname in candidate_decoder_names or dname in baseline_decoders
            if not present:
                blockers.append(
                    f"Rule uses <decoded_as>{dname}</decoded_as> but no such decoder "
                    "is in the candidate or fired on the samples — field matches will fail."
                )

        duplicate_id = []
        for rid in rule_validation.get("rule_ids", []):
            conflict: "bool | None"
            try:
                resp = await wz.request("GET", f"/rules?rule_ids={rid}")
                conflict = bool((resp.get("data") or {}).get("affected_items"))
            except Exception:
                conflict = None
            if conflict:
                blockers.append(
                    f"Rule id {rid} already exists in the live ruleset — duplicate "
                    "ids break analysisd. Choose an unused id."
                )
            duplicate_id.append({"rule_id": rid, "conflict": conflict})

        # ── E. Decoder-before-rule dependency direction ──────────────────────
        dependency: dict = {"rule_needs_decoder": rule_validation.get("uses_fields", False),
                            "satisfied": True, "missing_fields": []}
        if rule_validation.get("uses_fields"):
            produced = set(decoder_validation.get("fields", []))
            # Fields decoders implicitly produce (extracted by live decoders).
            for fname in rule_validation.get("field_names", []):
                base_field = fname.split(".")[-1]
                if (fname not in produced and base_field not in produced
                        and not decoder_validation.get("fields") and not decoders):
                    dependency["missing_fields"].append(fname)
            if dependency["missing_fields"]:
                dependency["satisfied"] = False
                warnings.append(
                    "Rule matches fields "
                    f"{dependency['missing_fields']} but the candidate decoder does "
                    "not declare them in <order>. Confirm a decoder (candidate or "
                    "existing) extracts these fields, or the rule will never fire."
                )

        # ── F. Verdict + honesty + manual recipe ─────────────────────────────
        verdict = "HAS_BLOCKERS" if blockers else "READY_FOR_MANUAL_STAGING_TEST"
        return {
            "verdict": verdict,
            "blockers": blockers,
            "warnings": warnings,
            "decoder_validation": decoder_validation,
            "rule_validation": {k: rule_validation[k] for k in
                                ("valid", "rules_found", "rule_ids", "field_names",
                                 "decoded_as", "if_sid", "uses_fields")},
            "regex_simulation": {
                "fidelity": fidelity,
                "matched_samples": matched_count,
                "total_samples": len(samples),
                "results": sim_results,
            },
            "baseline_logtest": baseline,
            "parent_check": parent_check,
            "duplicate_id": duplicate_id,
            "dependency_check": dependency,
            "honesty_note": (
                "The candidate decoder/rule is NOT loaded into the Manager. The "
                "logtest results above only validate context (baseline + parent "
                "existence). This pipeline CANNOT prove the candidate fires — "
                "regex matching is simulated in Python. For faithful end-to-end "
                "proof, deploy to a STAGING manager via the manual recipe and run "
                "test_log_against_rules there."
            ),
            "manual_recipe": _MANUAL_RECIPE,
        }

    @mcp.tool()
    async def draft_detection_from_logs(
        sample_logs: list,
        decoder_xml: str = "",
        rule_xml: str = "",
        log_format: str = "syslog",
    ) -> dict:
        """Entry point for 'paste logs → build a Wazuh decoder + rule'.

        Call 1 (no XML yet): pass only sample_logs. Returns a baseline (are these
        logs ALREADY decoded/alerting?) plus authoring hints — the existing
        decoder/fields/parent rule ids logtest reports — so you (the LLM) can
        author an official-format decoder + rule that fills the gap.

        Call 2: pass the decoder_xml + rule_xml you authored (e.g. via
        generate_decoder_xml + generate_rule_xml) to run the full non-mutating
        test pipeline (delegates to test_detection_candidate).

        This tool never authors XML and never deploys. Requires role: analyst.
        """
        err = require_analyst_or_above()
        if err:
            return err
        if not isinstance(sample_logs, list) or not sample_logs:
            return {"error": "sample_logs must be a non-empty list of raw log lines."}

        if decoder_xml.strip() or rule_xml.strip():
            return await test_detection_candidate(
                decoder_xml=decoder_xml, rule_xml=rule_xml,
                sample_logs=sample_logs, log_format=log_format,
            )

        # Baseline + hints stage.
        hints = []
        for sample in [str(s) for s in sample_logs[:20]]:
            try:
                r = await _logtest(sample, log_format)
                out = (r.get("data") or {}).get("output", {}) if isinstance(r, dict) else {}
                decoder = out.get("decoder", {}) or {}
                rule = out.get("rule", {}) or {}
                decoded_fields = {
                    k: v for k, v in out.items()
                    if k not in ("decoder", "rule", "agent", "manager", "id",
                                 "cluster", "@timestamp", "location", "timestamp",
                                 "hostname", "program_name", "decoders")
                }
                hints.append({
                    "sample": sample[:160],
                    "current_decoder": decoder.get("name"),
                    "current_parent_decoder": decoder.get("parent"),
                    "decoded_fields": decoded_fields,
                    "current_rule_id": rule.get("id"),
                    "already_detected": bool(rule.get("id")),
                })
            except Exception as exc:
                hints.append({"sample": sample[:160], "error": str(exc)})

        return {
            "stage": "baseline_and_hints",
            "samples": hints,
            "next_steps": [
                "Decide whether a NEW decoder is needed (only if current_decoder is "
                "missing or doesn't extract the fields you want).",
                "Author a decoder with generate_decoder_xml(...) if needed, choosing a "
                "<parent> or <program_name> and a capture regex (prefer type='pcre2').",
                "Author a rule with generate_rule_xml(...) in the 100000-120000 id range; "
                "use <if_sid> to chain from current_rule_id when present.",
                "Call draft_detection_from_logs again (or test_detection_candidate) with "
                "the decoder_xml + rule_xml to run the full non-mutating test pipeline.",
            ],
            "guidance": (
                "Official format only — see https://documentation.wazuh.com/current/"
                "user-manual/ruleset/. Rules using <field>/<decoded_as> require a "
                "decoder to extract those fields first."
            ),
        }
