"""explain_alert — natural-language narrative for a single alert or recent alert set.

Translates raw Wazuh alert JSON into a plain-English summary that any analyst
(Tier 1, CISO, or compliance officer) can act on immediately.
"""
from __future__ import annotations

import datetime


def register(mcp, wz, idx, cfg, _cap, _geoip_lookup=None):

    @mcp.tool()
    async def explain_alert(alert_id: str, audience: str = "analyst") -> dict:
        """Return a plain-English narrative explanation of a single alert.

        Fetches the alert by ID, enriches it with rule context and (where possible)
        IP reputation, then produces a human-readable narrative tailored to the
        requested audience.

        Args:
            alert_id: Wazuh alert document ID (from get_alert_by_id or search_alerts).
            audience:  One of 'analyst' (default), 'tier1', 'ciso', or 'compliance'.
                       Controls the depth and framing of the explanation.
        """
        valid_audiences = {"analyst", "tier1", "ciso", "compliance"}
        if audience not in valid_audiences:
            return {"error": f"audience must be one of: {', '.join(sorted(valid_audiences))}"}

        # Fetch the alert document
        try:
            res = await idx.search({
                "size": 1,
                "query": {"ids": {"values": [alert_id]}},
            })
            hits = res.get("hits", {}).get("hits", [])
            if not hits:
                return {"error": f"Alert '{alert_id}' not found. Verify the ID with search_alerts."}
            doc = hits[0].get("_source", {})
        except Exception as e:
            return {"error": f"Failed to fetch alert: {e}"}

        # Extract key fields
        rule = doc.get("rule", {})
        agent = doc.get("agent", {})
        src_ip = (doc.get("data", {}).get("srcip") or
                  doc.get("data", {}).get("src_ip") or
                  doc.get("network", {}).get("destination", {}).get("ip", ""))
        dst_ip = (doc.get("data", {}).get("dstip") or
                  doc.get("data", {}).get("dst_ip") or "")
        user = (doc.get("data", {}).get("srcuser") or
                doc.get("data", {}).get("dstuser") or
                doc.get("data", {}).get("user") or "")
        timestamp_raw = doc.get("@timestamp", "")
        rule_desc = rule.get("description", "Unknown rule")
        rule_level = int(rule.get("level", 0))
        rule_id = rule.get("id", "?")
        mitre_ids = rule.get("mitre", {}).get("id", [])
        mitre_tactics = rule.get("mitre", {}).get("tactic", [])
        groups = rule.get("groups", [])
        agent_name = agent.get("name", "unknown")
        agent_ip = agent.get("ip", "")
        full_log = doc.get("full_log", "")

        # Human-readable timestamp
        try:
            ts = datetime.datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
            ts_human = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            ts_human = timestamp_raw or "unknown time"

        # Severity label
        if rule_level >= 15:
            severity = "CRITICAL"
        elif rule_level >= 12:
            severity = "HIGH"
        elif rule_level >= 7:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # IP geo enrichment (best-effort)
        geo_context = ""
        if src_ip and _geoip_lookup:
            try:
                geo = await _geoip_lookup(src_ip)
                if "country" in geo:
                    geo_context = f" (from {geo.get('city', '')}, {geo['country']}, {geo.get('isp', '')})"
            except Exception:
                pass

        # MITRE context
        mitre_context = ""
        if mitre_ids:
            pairs = list(zip(mitre_ids, mitre_tactics or [""] * len(mitre_ids)))
            mitre_context = "; ".join(
                f"{mid} ({tac})" if tac else mid for mid, tac in pairs
            )

        # Build narrative per audience
        if audience == "tier1":
            narrative = _tier1_narrative(
                ts_human, rule_desc, rule_level, severity, agent_name, agent_ip,
                src_ip, geo_context, user, groups, full_log,
            )
        elif audience == "ciso":
            narrative = _ciso_narrative(
                ts_human, rule_desc, severity, agent_name, src_ip, geo_context,
                mitre_context, mitre_tactics,
            )
        elif audience == "compliance":
            narrative = _compliance_narrative(
                ts_human, rule_desc, severity, agent_name, rule_id, groups,
                mitre_context,
            )
        else:  # analyst (default)
            narrative = _analyst_narrative(
                ts_human, rule_desc, rule_level, severity, rule_id, agent_name,
                agent_ip, src_ip, dst_ip, geo_context, user, mitre_context,
                groups, full_log,
            )

        return {
            "alert_id": alert_id,
            "audience": audience,
            "severity": severity,
            "rule_level": rule_level,
            "timestamp": ts_human,
            "agent": agent_name,
            "narrative": narrative,
            "quick_actions": _quick_actions(severity, src_ip, groups, mitre_tactics),
        }

    @mcp.tool()
    async def explain_recent_alerts(
        time_range: str = "1h",
        min_level: int = 10,
        limit: int = 5,
        audience: str = "analyst",
    ) -> dict:
        """Fetch the top recent alerts and return plain-English explanations for each.

        Useful for shift start briefings or rapid triage. Returns individual
        narratives for the top `limit` alerts by severity in the given window.

        Args:
            time_range: Time window to search (e.g. '1h', '24h', '7d').
            min_level:  Minimum Wazuh rule level to include (default 10).
            limit:      Maximum number of alerts to explain (default 5, max 10).
            audience:   Narrative style — 'analyst', 'tier1', 'ciso', or 'compliance'.
        """
        limit = min(limit, 10)
        valid_audiences = {"analyst", "tier1", "ciso", "compliance"}
        if audience not in valid_audiences:
            return {"error": f"audience must be one of: {', '.join(sorted(valid_audiences))}"}

        try:
            res = await idx.search({
                "size": limit,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                            {"range": {"rule.level": {"gte": min_level}}},
                        ]
                    }
                },
                "sort": [{"rule.level": {"order": "desc"}}, {"@timestamp": {"order": "desc"}}],
            })
        except Exception as e:
            return {"error": f"Search failed: {e}"}

        hits = res.get("hits", {}).get("hits", [])
        total = res.get("hits", {}).get("total", {}).get("value", 0)

        if not hits:
            return {
                "total_matching": total,
                "alerts_explained": 0,
                "message": f"No alerts at level ≥{min_level} in the last {time_range}.",
            }

        explanations = []
        for hit in hits:
            doc = hit.get("_source", {})
            alert_id = hit.get("_id", "?")
            rule = doc.get("rule", {})
            agent = doc.get("agent", {})
            rule_level = int(rule.get("level", 0))

            if rule_level >= 15:
                severity = "CRITICAL"
            elif rule_level >= 12:
                severity = "HIGH"
            elif rule_level >= 7:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            ts_raw = doc.get("@timestamp", "")
            try:
                ts = datetime.datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                ts_human = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                ts_human = ts_raw

            src_ip = (doc.get("data", {}).get("srcip") or
                      doc.get("data", {}).get("src_ip") or "")
            geo_context = ""
            if src_ip and _geoip_lookup:
                try:
                    geo = await _geoip_lookup(src_ip)
                    if "country" in geo:
                        geo_context = f" ({geo.get('city', '')}, {geo['country']})"
                except Exception:
                    pass

            mitre_ids = rule.get("mitre", {}).get("id", [])
            mitre_tactics = rule.get("mitre", {}).get("tactic", [])
            mitre_context = ""
            if mitre_ids:
                pairs = list(zip(mitre_ids, mitre_tactics or [""] * len(mitre_ids)))
                mitre_context = "; ".join(
                    f"{m} ({t})" if t else m for m, t in pairs
                )

            one_line = (
                f"[{severity}] {ts_human} — {rule.get('description', '?')} "
                f"on {agent.get('name', '?')}"
                f"{geo_context}"
                f"{' | MITRE: ' + mitre_context if mitre_context else ''}"
            )
            explanations.append({
                "alert_id": alert_id,
                "severity": severity,
                "rule_level": rule_level,
                "timestamp": ts_human,
                "agent": agent.get("name", "?"),
                "src_ip": src_ip or None,
                "summary": one_line,
                "quick_actions": _quick_actions(severity, src_ip, rule.get("groups", []), mitre_tactics),
            })

        return {
            "total_matching": total,
            "alerts_explained": len(explanations),
            "time_range": time_range,
            "min_level": min_level,
            "audience": audience,
            "alerts": explanations,
            "next_step": (
                "Call explain_alert(alert_id, audience=...) on any of the above "
                "IDs for a full narrative."
            ),
        }


# ── Narrative builders ─────────────────────────────────────────────────────────

def _tier1_narrative(ts, rule_desc, rule_level, severity, agent_name, agent_ip,
                     src_ip, geo_context, user, groups, full_log) -> str:
    lines = [
        f"WHAT HAPPENED: At {ts}, a {severity} alert fired on agent '{agent_name}'"
        f" ({agent_ip}).",
        f"",
        f"RULE: {rule_desc} (level {rule_level}/15).",
    ]
    if src_ip:
        lines.append(f"SOURCE IP: {src_ip}{geo_context}.")
    if user:
        lines.append(f"USER INVOLVED: {user}.")
    if full_log:
        lines.append(f"")
        lines.append(f"RAW LOG SNIPPET: {full_log[:300]}")
    lines += [
        f"",
        f"WHAT TO DO NEXT:",
        f"  1. Check if {src_ip or agent_name} appears in other recent alerts.",
        f"  2. If src IP is external and unknown — run enrich_ip('{src_ip or '?'}').",
        f"  3. Escalate to Tier 2 if you see repeated hits or CRITICAL severity.",
        f"  4. Tag this alert with tag_alert() once reviewed.",
    ]
    return "\n".join(lines)


def _analyst_narrative(ts, rule_desc, rule_level, severity, rule_id, agent_name,
                       agent_ip, src_ip, dst_ip, geo_context, user, mitre_context,
                       groups, full_log) -> str:
    lines = [
        f"At {ts}, Wazuh fired rule {rule_id} ({severity}, level {rule_level}/15):",
        f"  \"{rule_desc}\"",
        f"",
        f"Affected agent: {agent_name} ({agent_ip})",
    ]
    if src_ip:
        lines.append(f"Source IP: {src_ip}{geo_context}")
    if dst_ip:
        lines.append(f"Destination IP: {dst_ip}")
    if user:
        lines.append(f"User: {user}")
    if mitre_context:
        lines.append(f"MITRE ATT&CK: {mitre_context}")
    if groups:
        lines.append(f"Rule groups: {', '.join(groups)}")
    if full_log:
        lines += ["", f"Log evidence: {full_log[:400]}"]
    lines += [
        "",
        "Investigation path:",
        f"  → search_by_source_ip('{src_ip}', time_range='24h') — full attack context" if src_ip else
        f"  → search_alerts(agent_name='{agent_name}', time_range='24h') — agent activity",
        f"  → enrich_ip('{src_ip}') — VirusTotal + AbuseIPDB verdict" if src_ip else "",
        f"  → blast_radius_analysis — how far has this spread?",
        f"  → correlate_alert_with_response — did Wazuh auto-block?",
    ]
    return "\n".join(l for l in lines if l is not None)


def _ciso_narrative(ts, rule_desc, severity, agent_name, src_ip, geo_context,
                    mitre_context, mitre_tactics) -> str:
    tactic_str = ", ".join(set(mitre_tactics)) if mitre_tactics else "unknown"
    lines = [
        f"EXECUTIVE SUMMARY",
        f"",
        f"Severity:  {severity}",
        f"Time:      {ts}",
        f"System:    {agent_name}",
        f"Event:     {rule_desc}",
    ]
    if src_ip:
        lines.append(f"Source:    {src_ip}{geo_context}")
    if mitre_context:
        lines += [
            f"",
            f"THREAT CLASSIFICATION",
            f"ATT&CK Tactics: {tactic_str}",
            f"Techniques: {mitre_context}",
        ]
    lines += [
        f"",
        f"BUSINESS RISK",
        f"{'Immediate containment required. Potential data breach or system compromise.' if severity in ('CRITICAL','HIGH') else 'Monitor closely. No immediate business impact identified.'}",
        f"",
        f"RECOMMENDED ACTION",
        f"{'Engage incident response team. Isolate affected system pending investigation.' if severity == 'CRITICAL' else 'Security team investigating. Update within 4 hours.' if severity == 'HIGH' else 'Analyst review underway. No escalation required at this time.'}",
    ]
    return "\n".join(lines)


def _compliance_narrative(ts, rule_desc, severity, agent_name, rule_id, groups,
                          mitre_context) -> str:
    # Map common rule groups to compliance frameworks
    framework_hints: list[str] = []
    g = [x.lower() for x in groups]
    if any(k in x for x in g for k in ("authentication", "login", "pam", "ssh")):
        framework_hints += ["PCI-DSS 8.x (Authentication Controls)", "HIPAA 164.312(d)"]
    if any(k in x for x in g for k in ("fim", "syscheck", "integrity")):
        framework_hints += ["PCI-DSS 11.5 (File Integrity Monitoring)", "NIST SI-7"]
    if any(k in x for x in g for k in ("web", "attack", "exploit")):
        framework_hints += ["PCI-DSS 6.x (Web Application Security)", "NIST SI-3"]
    if not framework_hints:
        framework_hints = ["Review against applicable framework controls manually."]

    lines = [
        f"COMPLIANCE EVENT RECORD",
        f"",
        f"Timestamp:    {ts}",
        f"System:       {agent_name}",
        f"Event:        {rule_desc}",
        f"Rule ID:      {rule_id}",
        f"Severity:     {severity}",
        f"Rule Groups:  {', '.join(groups) if groups else 'none'}",
    ]
    if mitre_context:
        lines.append(f"MITRE:        {mitre_context}")
    lines += [
        f"",
        f"APPLICABLE CONTROLS",
    ] + [f"  • {f}" for f in framework_hints] + [
        f"",
        f"DOCUMENTATION",
        f"  Generate a full compliance report with: generate_compliance_report()",
        f"  Export for audit trail with: export_compliance_csv()",
    ]
    return "\n".join(lines)


def _quick_actions(severity: str, src_ip: str, groups: list, mitre_tactics: list) -> list[str]:
    actions: list[str] = []
    if severity in ("CRITICAL", "HIGH"):
        actions.append("blast_radius_analysis() — assess spread immediately")
    if src_ip:
        actions.append(f"enrich_ip('{src_ip}') — check reputation")
        if severity in ("CRITICAL", "HIGH"):
            actions.append(f"add_to_cdb_list('blacklist-ip', '{src_ip}') — block if malicious")
    g = [x.lower() for x in groups]
    if any(k in x for x in g for k in ("authentication", "brute", "login")):
        actions.append("search_authentication_failures(time_range='1h') — full brute-force picture")
    if any(k in x for x in g for k in ("fim", "syscheck")):
        actions.append("search_fim_alerts(time_range='1h') — related file changes")
    t = [x.lower() for x in mitre_tactics]
    if any(k in x for x in t for k in ("lateral", "movement")):
        actions.append("hunt_lateral_movement(time_range='24h') — check spread")
    if not actions:
        actions.append("search_alerts(time_range='1h') — broader context")
    return actions
