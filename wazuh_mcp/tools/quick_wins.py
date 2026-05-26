"""Quick-win tools: ABAC status, natural-language → OpenSearch DSL, auto-triage."""
from __future__ import annotations

import re
import datetime


# ── Natural-language patterns → OpenSearch DSL fragments ──────────────────────

_TIME_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b(last\s+)?(\d+)\s+minute', re.I), lambda m: f"{m.group(2)}m"),
    (re.compile(r'\b(last\s+)?(\d+)\s+hour',   re.I), lambda m: f"{m.group(2)}h"),
    (re.compile(r'\b(last\s+)?(\d+)\s+day',    re.I), lambda m: f"{m.group(2)}d"),
    (re.compile(r'\byesterday\b',               re.I), lambda _: "24h"),
    (re.compile(r'\btoday\b',                   re.I), lambda _: "24h"),
    (re.compile(r'\bthis\s+week\b',             re.I), lambda _: "7d"),
    (re.compile(r'\bthis\s+month\b',            re.I), lambda _: "30d"),
    (re.compile(r'\blast\s+week\b',             re.I), lambda _: "7d"),
]

_SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "critical": ["critical", "severity 15", "level 15", "level 14", "level 13"],
    "high":     ["high", "major", "severity high", "level 12", "level 11", "level 10"],
    "medium":   ["medium", "moderate", "level 7", "level 8", "level 9"],
    "low":      ["low", "minor", "informational"],
}

_GROUP_KEYWORDS: dict[str, list[str]] = {
    "authentication_failed": ["failed login", "failed auth", "authentication failure", "auth fail",
                               "login fail", "bad password", "wrong password"],
    "brute_force":           ["brute force", "brute-force", "dictionary attack", "password spray"],
    "web_attack":            ["web attack", "sqli", "sql injection", "xss", "cross site",
                               "web exploit", "rfi", "lfi", "path traversal"],
    "exploit":               ["exploit", "exploitation", "cve", "vulnerability exploit"],
    "rootkit":               ["rootkit", "kernel module", "hide process"],
    "malware":               ["malware", "ransomware", "trojan", "virus", "worm"],
    "syscheck":              ["file change", "file modified", "fim", "integrity", "file integrity"],
    "privilege_escalation":  ["privilege escalation", "priv esc", "sudo", "su root", "setuid"],
    "network_scan":          ["port scan", "network scan", "nmap", "scanning"],
    "firewall":              ["firewall", "iptables", "blocked", "dropped"],
    "pam":                   ["pam", "ssh", "sshd", "login"],
}

_GEO_COUNTRY_PATTERN = re.compile(
    r'\bfrom\s+([A-Z][a-zA-Z\s]{2,30})\b', re.I
)
_IP_PATTERN = re.compile(
    r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
)
_AGENT_PATTERN = re.compile(
    r'\bon\s+(?:agent\s+)?["\']?([a-zA-Z0-9_\-\.]+)["\']?\b', re.I
)
_RULE_LEVEL_PATTERN = re.compile(
    r'\b(?:level|severity)\s*[>>=]?\s*(\d{1,2})\b', re.I
)
_RULE_ID_PATTERN = re.compile(r'\brule\s+(?:id\s+)?(\d{3,6})\b', re.I)


def _extract_time_range(text: str) -> str:
    for pat, fn in _TIME_PATTERNS:
        m = pat.search(text)
        if m:
            return fn(m) if callable(fn) else fn
    return "24h"


def _extract_groups(text: str) -> list[str]:
    tl = text.lower()
    groups = []
    for grp, keywords in _GROUP_KEYWORDS.items():
        if any(kw in tl for kw in keywords):
            groups.append(grp)
    return groups


def _extract_min_level(text: str) -> int:
    tl = text.lower()
    for sev, keywords in _SEVERITY_KEYWORDS.items():
        if any(kw in tl for kw in keywords):
            return {"critical": 13, "high": 10, "medium": 7, "low": 1}[sev]
    m = _RULE_LEVEL_PATTERN.search(text)
    if m:
        return max(1, min(15, int(m.group(1))))
    return 7


def register(mcp, wz, idx, cfg, _cap):

    @mcp.tool()
    async def get_abac_status() -> dict:
        """Show the current Attribute-Based Access Control (ABAC) configuration.

        Reports which agent groups, agent IDs, and denied groups are in effect
        for this session. Useful for debugging permission issues.

        Configure via env vars:
          WAZUH_MCP_ALLOWED_GROUPS  — comma-separated allowed group names
          WAZUH_MCP_DENIED_GROUPS   — comma-separated denied group names
          WAZUH_MCP_ALLOWED_AGENTS  — comma-separated allowed agent IDs
        """
        from ..abac import abac_status
        return abac_status()

    @mcp.tool()
    async def nl_to_opensearch_query(
        query: str,
        execute: bool = False,
        limit: int = 50,
    ) -> dict:
        """Translate a natural-language security query into an OpenSearch DSL query.

        Extracts time ranges, severity levels, rule groups, IPs, agent names,
        countries, and rule IDs from plain English and builds the corresponding
        OpenSearch bool query.

        query:   e.g. "failed SSH logins from China in the last 7 days"
                      "critical alerts on agent web-server-01 today"
                      "brute force attacks against 10.0.0.5 this week level 10+"
        execute: If True, run the generated query and return results too.
        limit:   Max results if execute=True (default 50).

        Returns the DSL JSON so you can review, copy, or pass to idx.search().
        """
        if not query or not query.strip():
            return {"error": "query must not be empty."}
        if len(query) > 500:
            return {"error": "query too long (max 500 chars)."}

        time_range = _extract_time_range(query)
        min_level  = _extract_min_level(query)
        groups     = _extract_groups(query)
        src_ips    = _IP_PATTERN.findall(query)
        agents     = _AGENT_PATTERN.findall(query)
        rule_ids   = _RULE_ID_PATTERN.findall(query)

        # Country → geo filter: Wazuh stores country in GeoLocation fields
        country_match = _GEO_COUNTRY_PATTERN.search(query)
        country = country_match.group(1).strip().title() if country_match else None

        filters: list[dict] = [
            {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]
        explanation: list[str] = [
            f"time_range: last {time_range}",
            f"min_level: {min_level}",
        ]

        if groups:
            filters.append({"terms": {"rule.groups": groups}})
            explanation.append(f"rule_groups: {groups}")

        if src_ips:
            filters.append({"terms": {"data.srcip": src_ips}})
            explanation.append(f"src_ips: {src_ips}")

        if agents:
            filters.append({"terms": {"agent.name": agents}})
            explanation.append(f"agents: {agents}")

        if rule_ids:
            filters.append({"terms": {"rule.id": rule_ids}})
            explanation.append(f"rule_ids: {rule_ids}")

        if country:
            filters.append({"term": {"GeoLocation.country_name": country}})
            explanation.append(f"country: {country}")

        dsl = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": filters}},
        }

        result: dict = {
            "natural_language_query": query,
            "extracted_parameters": explanation,
            "opensearch_dsl": dsl,
            "tip": (
                "Pass opensearch_dsl to idx.search() or set execute=True to run immediately."
            ),
        }

        if execute:
            try:
                from ..helpers import trim_alert
                res = await idx.search(dsl)
                result["total"] = res["hits"]["total"]["value"]
                result["alerts"] = [trim_alert(h) for h in res["hits"]["hits"]]
                result["executed"] = True
            except Exception as exc:
                result["execute_error"] = str(exc)

        return result

    @mcp.tool()
    async def auto_triage_alert(alert_id: str) -> dict:
        """Automatically classify an alert as True Positive, False Positive, or Needs Review.

        Uses heuristic rules across rule level, known FP patterns, MITRE mapping,
        IP context, FIM path, and historical recurrence to produce a confident
        disposition with supporting evidence and recommended next action.

        alert_id: Wazuh alert document ID (from search_alerts or get_recent_alerts_24h).
        """
        # Fetch alert
        try:
            res = await idx.search({
                "size": 1,
                "query": {"ids": {"values": [alert_id]}},
            })
            hits = res.get("hits", {}).get("hits", [])
            if not hits:
                return {"error": f"Alert '{alert_id}' not found."}
            doc = hits[0]["_source"]
        except Exception as exc:
            return {"error": f"Failed to fetch alert: {exc}"}

        rule     = doc.get("rule", {})
        agent    = doc.get("agent", {})
        data     = doc.get("data", {})
        level    = int(rule.get("level", 0))
        groups   = [g.lower() for g in rule.get("groups", [])]
        mitre    = rule.get("mitre", {})
        src_ip   = data.get("srcip") or data.get("src_ip", "")
        filepath = (doc.get("syscheck") or {}).get("path", "")
        rule_id  = rule.get("id", "")

        score = 0          # positive = TP confidence, negative = FP confidence
        evidence: list[str] = []
        fp_signals: list[str] = []
        tp_signals: list[str] = []

        # ── Level scoring ────────────────────────────────────────────────────
        if level >= 13:
            score += 30
            tp_signals.append(f"Very high rule level ({level}/15) — rarely a false positive")
        elif level >= 10:
            score += 15
            tp_signals.append(f"High rule level ({level}/15)")
        elif level <= 3:
            score -= 20
            fp_signals.append(f"Low rule level ({level}/15) — commonly informational")

        # ── MITRE mapping ────────────────────────────────────────────────────
        if mitre.get("id"):
            score += 10
            tp_signals.append(f"Mapped to MITRE ATT&CK: {mitre.get('id')}")

        # ── Group-based heuristics ────────────────────────────────────────────
        STRONG_TP_GROUPS = {
            "rootkit", "exploit", "malware", "ransomware",
            "privilege_escalation", "web_attack", "injection",
        }
        LIKELY_FP_GROUPS = {
            "ossec", "ossec_hids", "service_control",
            "system_call_ratelimit", "audit_command",
        }
        HIGH_NOISE_GROUPS = {
            "authentication_failed", "pam", "sshd",
        }

        matched_tp  = set(groups) & STRONG_TP_GROUPS
        matched_fp  = set(groups) & LIKELY_FP_GROUPS
        matched_noise = set(groups) & HIGH_NOISE_GROUPS

        if matched_tp:
            score += 25
            tp_signals.append(f"Rule group(s) strongly indicate real threat: {sorted(matched_tp)}")
        if matched_fp:
            score -= 15
            fp_signals.append(f"Rule group(s) associated with noisy/FP rules: {sorted(matched_fp)}")
        if matched_noise:
            score -= 5
            fp_signals.append(f"High-noise group(s) — check for recurrence: {sorted(matched_noise)}")

        # ── FIM path heuristics ───────────────────────────────────────────────
        SENSITIVE_PATHS = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/bin/", "/sbin/",
                           "C:\\Windows\\System32", "C:\\Windows\\SysWOW64"]
        BENIGN_PATHS    = ["/tmp/", "/var/log/", "/var/run/", "/proc/", ".log", ".tmp", ".pid"]

        if filepath:
            if any(p in filepath for p in SENSITIVE_PATHS):
                score += 20
                tp_signals.append(f"FIM change on sensitive path: {filepath}")
            elif any(p in filepath for p in BENIGN_PATHS):
                score -= 10
                fp_signals.append(f"FIM change on commonly benign path: {filepath}")

        # ── Recurrence check (same rule, same agent, last hour) ───────────────
        recurrence_count = 0
        try:
            rec_res = await idx.search({
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": "now-1h"}}},
                            {"term": {"rule.id": rule_id}},
                            {"term": {"agent.id": agent.get("id", "")}},
                        ]
                    }
                },
            })
            recurrence_count = rec_res["hits"]["total"]["value"]
        except Exception:
            pass

        if recurrence_count > 50:
            score -= 10
            fp_signals.append(f"Rule fired {recurrence_count} times in last hour on this agent — may be noisy")
        elif recurrence_count > 5:
            score += 5
            tp_signals.append(f"Rule fired {recurrence_count} times in last hour — sustained activity")

        # ── Source IP check ──────────────────────────────────────────────────
        if src_ip:
            import ipaddress as _ip
            try:
                parsed = _ip.ip_address(src_ip)
                if parsed.is_private:
                    fp_signals.append(f"Source IP {src_ip} is private — likely internal activity")
                    score -= 5
                elif parsed.is_loopback:
                    fp_signals.append(f"Source IP {src_ip} is loopback — very likely benign")
                    score -= 15
                else:
                    tp_signals.append(f"External source IP {src_ip} — warrants investigation")
                    score += 5
            except ValueError:
                pass

        # ── Disposition ───────────────────────────────────────────────────────
        if score >= 30:
            disposition = "TRUE_POSITIVE"
            confidence  = min(95, 50 + score)
            next_action = "Escalate for investigation. Run blast_radius_analysis() to assess scope."
            urgency     = "HIGH" if level >= 12 else "MEDIUM"
        elif score <= -10:
            disposition = "FALSE_POSITIVE"
            confidence  = min(95, 50 + abs(score))
            next_action = (
                "Tag with tag_alert(alert_id, tag='false_positive'). "
                "Consider bulk_suppress_rule() if this fires repeatedly."
            )
            urgency = "LOW"
        else:
            disposition = "NEEDS_REVIEW"
            confidence  = 50
            next_action = (
                "Insufficient signal for automatic classification. "
                "Run explain_alert(alert_id) for full context, then enrich_ip() if src_ip present."
            )
            urgency = "MEDIUM"

        return {
            "alert_id":    alert_id,
            "disposition": disposition,
            "confidence":  f"{confidence}%",
            "urgency":     urgency,
            "rule_id":     rule_id,
            "rule_level":  level,
            "agent":       agent.get("name", "unknown"),
            "src_ip":      src_ip or None,
            "filepath":    filepath or None,
            "recurrence_last_1h": recurrence_count,
            "tp_signals":  tp_signals,
            "fp_signals":  fp_signals,
            "triage_score": score,
            "recommended_action": next_action,
            "next_tools": (
                ["blast_radius_analysis()", f"enrich_ip('{src_ip}')"] if disposition == "TRUE_POSITIVE" and src_ip
                else ["blast_radius_analysis()"] if disposition == "TRUE_POSITIVE"
                else ["bulk_suppress_rule()", f"noise_score_rule('{rule_id}')"] if disposition == "FALSE_POSITIVE"
                else ["explain_alert(alert_id, audience='analyst')", "enrich_ip(src_ip)"]
            ),
        }

    @mcp.tool()
    async def batch_auto_triage(
        time_range: str = "1h",
        min_level: int = 7,
        limit: int = 20,
    ) -> dict:
        """Auto-triage the top recent alerts and return a disposition for each.

        Useful for morning triage workflows — get a classified list of alerts
        with True Positive / False Positive / Needs Review labels in one call.

        time_range: how far back to look (default: 1h)
        min_level:  minimum rule level (default: 7)
        limit:      max alerts to triage (default 20, max 50)
        """
        from ..helpers import trim_alert

        limit = min(limit, 50)
        try:
            res = await idx.search({
                "size": limit,
                "sort": [{"rule.level": "desc"}, {"@timestamp": "desc"}],
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                            {"range": {"rule.level": {"gte": min_level}}},
                        ]
                    }
                },
            })
        except Exception as exc:
            return {"error": str(exc)}

        hits = res.get("hits", {}).get("hits", [])
        total = res.get("hits", {}).get("total", {}).get("value", 0)

        if not hits:
            return {
                "total_matching": total,
                "message": f"No alerts at level ≥{min_level} in the last {time_range}.",
            }

        results = []
        for hit in hits:
            try:
                triage = await auto_triage_alert(hit["_id"])
                results.append(triage)
            except Exception as exc:
                results.append({"alert_id": hit["_id"], "error": str(exc)})

        tp    = [r for r in results if r.get("disposition") == "TRUE_POSITIVE"]
        fp    = [r for r in results if r.get("disposition") == "FALSE_POSITIVE"]
        needs = [r for r in results if r.get("disposition") == "NEEDS_REVIEW"]

        return {
            "time_range": time_range,
            "min_level":  min_level,
            "total_matching": total,
            "triaged": len(results),
            "summary": {
                "true_positive":  len(tp),
                "false_positive": len(fp),
                "needs_review":   len(needs),
            },
            "true_positives":  tp,
            "needs_review":    needs,
            "false_positives": fp,
        }
