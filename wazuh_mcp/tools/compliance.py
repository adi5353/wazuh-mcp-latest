"""Compliance tools — framework summaries, control drill-down, and report generation."""
from __future__ import annotations

import datetime

from ..helpers import trim_alert, time_window

COMPLIANCE_FIELDS = {
    "pci_dss": "rule.pci_dss",
    "hipaa": "rule.hipaa",
    "gdpr": "rule.gdpr",
    "nist_800_53": "rule.nist_800_53",
    "tsc": "rule.tsc",
}

# ISO 27001:2022 control mapping derived from Wazuh rule groups + native compliance fields.
# Each entry: control_id → {title, rule_groups, nist_equivalent, description}
_ISO27001_CONTROLS: list[dict] = [
    {"id": "A.5.7",  "title": "Threat intelligence",
     "rule_groups": ["attack", "web_attack", "intrusion_detection"],
     "nist": "SI-5", "description": "Collect and analyse threat intelligence."},
    {"id": "A.6.8",  "title": "Information security event reporting",
     "rule_groups": ["syslog", "ossec", "ids"], "nist": "IR-6",
     "description": "Report information security events through appropriate channels."},
    {"id": "A.8.2",  "title": "Privileged access rights",
     "rule_groups": ["authentication_success", "su", "sudo", "privilege_escalation"],
     "nist": "AC-6", "description": "Restrict and manage privileged access rights."},
    {"id": "A.8.3",  "title": "Information access restriction",
     "rule_groups": ["authentication_failed", "access_control"],
     "nist": "AC-3", "description": "Restrict access to information per the access control policy."},
    {"id": "A.8.5",  "title": "Secure authentication",
     "rule_groups": ["authentication_failed", "brute_force", "pam"],
     "nist": "IA-5", "description": "Secure authentication technologies and procedures."},
    {"id": "A.8.6",  "title": "Capacity management",
     "rule_groups": ["resource_exhaustion", "high_memory", "disk_full"],
     "nist": "CP-2", "description": "Monitor, adjust, and project future capacity requirements."},
    {"id": "A.8.8",  "title": "Management of technical vulnerabilities",
     "rule_groups": ["vulnerability", "exploit", "cve"],
     "nist": "SI-2", "description": "Obtain timely information about technical vulnerabilities and remediate."},
    {"id": "A.8.15", "title": "Logging",
     "rule_groups": ["ossec", "audit", "auditd"],
     "nist": "AU-2", "description": "Produce, store, protect and analyse logs."},
    {"id": "A.8.16", "title": "Monitoring activities",
     "rule_groups": ["ids", "attack", "web_attack", "intrusion_detection"],
     "nist": "SI-4", "description": "Monitor networks and systems for anomalous behaviour."},
    {"id": "A.8.19", "title": "Installation of software on operational systems",
     "rule_groups": ["ossec", "syscheck", "package_installed"],
     "nist": "CM-7", "description": "Secure procedures for software installation."},
    {"id": "A.8.20", "title": "Networks security",
     "rule_groups": ["firewall", "network", "iptables"],
     "nist": "SC-7", "description": "Secure, manage and control networks."},
    {"id": "A.8.22", "title": "Segregation of networks",
     "rule_groups": ["firewall", "network_scan", "port_scan"],
     "nist": "SC-7", "description": "Segregate groups of information services in the network."},
    {"id": "A.8.23", "title": "Web filtering",
     "rule_groups": ["web", "web_attack", "sqli", "xss"],
     "nist": "SI-3", "description": "Manage access to external websites."},
    {"id": "A.8.25", "title": "Secure development life cycle",
     "rule_groups": ["exploit", "web_attack", "injection"],
     "nist": "SA-15", "description": "Rules for secure development of software."},
    {"id": "A.8.32", "title": "Change management",
     "rule_groups": ["syscheck", "fim", "configuration_changed"],
     "nist": "CM-3", "description": "Manage changes to information processing facilities."},
    {"id": "A.5.24", "title": "Information security incident management",
     "rule_groups": ["ids", "attack", "intrusion_detection"],
     "nist": "IR-4", "description": "Plan and prepare for managing security incidents."},
    {"id": "A.5.26", "title": "Response to information security incidents",
     "rule_groups": ["active_response", "block", "firewall"],
     "nist": "IR-5", "description": "Respond to information security incidents in accordance with procedures."},
    {"id": "A.5.28", "title": "Collection of evidence",
     "rule_groups": ["ossec", "audit", "fim", "syscheck"],
     "nist": "AU-9", "description": "Establish and apply procedures for evidence identification."},
    {"id": "A.8.34", "title": "Protection of information systems during audit testing",
     "rule_groups": ["scan", "nmap", "vulnerability_scanner"],
     "nist": "CA-7", "description": "Protect operational systems during audit and test activities."},
]

# Build a flat lookup: rule_group → list of ISO controls
_GROUP_TO_ISO: dict[str, list[str]] = {}
for _ctrl in _ISO27001_CONTROLS:
    for _grp in _ctrl["rule_groups"]:
        _GROUP_TO_ISO.setdefault(_grp, []).append(_ctrl["id"])


def register(mcp, wz, idx, cfg, _cap):

    @mcp.tool()
    async def compliance_summary(
        framework: str = "pci_dss", time_range: str = "30d", min_level: int = 5
    ) -> dict:
        """Aggregate alerts by compliance control for a given framework.

        framework: pci_dss | hipaa | gdpr | nist_800_53 | tsc
        Returns counts per control, plus top rules and top agents driving each.
        """
        field = COMPLIANCE_FIELDS.get(framework)
        if not field:
            return {
                "error": f"Unknown framework '{framework}'",
                "supported": list(COMPLIANCE_FIELDS),
            }
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                        {"exists": {"field": field}},
                    ]
                }
            },
            "aggs": {
                "by_control": {
                    "terms": {"field": field, "size": 30},
                    "aggs": {
                        "top_rules": {"terms": {"field": "rule.id", "size": 3}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                }
            },
        }
        res = await idx.search(body)
        return {
            "framework": framework,
            "time_range": time_range,
            "total_alerts_with_control_mapping": res["hits"]["total"]["value"],
            "by_control": [
                {
                    "control": b["key"],
                    "count": b["doc_count"],
                    "top_rules": [r["key"] for r in b["top_rules"]["buckets"]],
                    "top_agents": [a["key"] for a in b["top_agents"]["buckets"]],
                }
                for b in res["aggregations"]["by_control"]["buckets"]
            ],
        }

    @mcp.tool()
    async def compliance_control_details(
        framework: str, control_id: str, time_range: str = "30d", limit: int = 50
    ) -> dict:
        """Drill into alerts mapped to one specific compliance control."""
        field = COMPLIANCE_FIELDS.get(framework)
        if not field:
            return {
                "error": f"Unknown framework '{framework}'",
                "supported": list(COMPLIANCE_FIELDS),
            }
        body = {
            "size": _cap(limit),
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"term": {field: control_id}},
                    ]
                }
            },
        }
        res = await idx.search(body)
        return {
            "framework": framework,
            "control": control_id,
            "total": res["hits"]["total"]["value"],
            "alerts": [trim_alert(h) for h in res["hits"]["hits"]],
        }

    @mcp.tool()
    async def generate_compliance_report(
        framework: str = "pci_dss",
        time_range: str = "168h",
    ) -> dict:
        """Generate a compliance posture report for a given framework.

        Supported: pci_dss, hipaa, gdpr, nist_800_53, tsc.
        Returns control coverage, failing controls, and alert counts per control.
        """
        field = COMPLIANCE_FIELDS.get(framework)
        if not field:
            return {
                "error": f"Unknown framework '{framework}'",
                "supported": list(COMPLIANCE_FIELDS),
            }
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                        {"exists": {"field": field}},
                    ]
                }
            },
            "aggs": {
                "by_control": {
                    "terms": {"field": field, "size": 50},
                    "aggs": {
                        "by_level": {"terms": {"field": "rule.level", "size": 5}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                }
            },
            "size": 0,
        }
        res = await idx.search(body)
        buckets = res.get("aggregations", {}).get("by_control", {}).get("buckets", [])
        total = res["hits"]["total"]["value"]

        controls = []
        for b in buckets:
            levels = {str(lv["key"]): lv["doc_count"] for lv in b.get("by_level", {}).get("buckets", [])}
            critical_count = sum(v for k, v in levels.items() if int(k) >= 10)
            controls.append({
                "control": b["key"],
                "total_alerts": b["doc_count"],
                "critical_alerts": critical_count,
                "top_agents": [a["key"] for a in b.get("top_agents", {}).get("buckets", [])],
                "by_level": levels,
                "status": "FAILING" if critical_count > 0 else "WARNING" if b["doc_count"] > 10 else "OK",
            })

        controls.sort(key=lambda x: x["critical_alerts"], reverse=True)
        failing = [c for c in controls if c["status"] == "FAILING"]

        return {
            "report_type": "compliance_report",
            "framework": framework,
            "time_window": time_range,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "total_alerts": total,
            "controls_with_alerts": len(controls),
            "failing_controls_count": len(failing),
            "controls": controls,
        }

    @mcp.tool()
    async def iso27001_compliance_summary(time_range: str = "30d", min_level: int = 5) -> dict:
        """Generate an ISO 27001:2022 Annex A compliance posture report.

        Since Wazuh doesn't ship native ISO 27001 field mappings, this tool
        derives control coverage by mapping Wazuh rule groups to ISO 27001
        Annex A controls and querying alert counts per group.

        Returns: per-control status (OK / WARNING / FAILING), alert counts,
        top agents, and NIST 800-53 equivalents for cross-framework context.
        """
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "aggs": {
                "by_group": {
                    "terms": {"field": "rule.groups", "size": 200},
                    "aggs": {
                        "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                }
            },
        }
        res = await idx.search(body)
        group_counts: dict[str, dict] = {}
        for b in res["aggregations"]["by_group"]["buckets"]:
            group_counts[b["key"]] = {
                "total": b["doc_count"],
                "critical": b["critical"]["doc_count"],
                "top_agents": [a["key"] for a in b["top_agents"]["buckets"]],
            }

        control_results = []
        for ctrl in _ISO27001_CONTROLS:
            total = 0
            critical = 0
            agents: set = set()
            matched_groups: list = []
            for grp in ctrl["rule_groups"]:
                if grp in group_counts:
                    total   += group_counts[grp]["total"]
                    critical += group_counts[grp]["critical"]
                    agents.update(group_counts[grp]["top_agents"])
                    matched_groups.append(grp)
            status = (
                "FAILING" if critical > 0
                else "WARNING" if total > 10
                else "OK"
            )
            control_results.append({
                "control_id": ctrl["id"],
                "title": ctrl["title"],
                "description": ctrl["description"],
                "nist_800_53_equivalent": ctrl["nist"],
                "total_alerts": total,
                "critical_alerts": critical,
                "top_agents": list(agents)[:3],
                "matched_rule_groups": matched_groups,
                "status": status,
            })

        control_results.sort(key=lambda x: x["critical_alerts"], reverse=True)
        failing  = [c for c in control_results if c["status"] == "FAILING"]
        warning  = [c for c in control_results if c["status"] == "WARNING"]

        return {
            "report_type": "iso27001_2022_annex_a",
            "time_range": time_range,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_controls_assessed": len(control_results),
                "failing": len(failing),
                "warning": len(warning),
                "ok": len(control_results) - len(failing) - len(warning),
                "posture": (
                    "CRITICAL" if len(failing) > 5
                    else "HIGH"   if len(failing) > 2
                    else "MEDIUM" if len(warning) > 3
                    else "LOW"
                ),
            },
            "failing_controls": failing,
            "controls": control_results,
            "note": (
                "Mapping is derived from Wazuh rule groups. "
                "For a full ISO 27001 audit, pair this with generate_compliance_report() "
                "for PCI-DSS/NIST and export_compliance_csv() for evidence packages."
            ),
        }

    @mcp.tool()
    async def nist_csf2_compliance_summary(
        time_range: str = "30d",
        min_level: int = 5,
    ) -> dict:
        """Generate a NIST Cybersecurity Framework 2.0 compliance posture report.

        Maps Wazuh rule groups and NIST 800-53 fields to the six CSF 2.0 Functions:
        GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER.

        Returns per-function status, alert counts, and control-level breakdown.
        Pairs well with iso27001_compliance_summary() for multi-framework views.
        """
        # CSF 2.0 function → {categories, rule_groups, nist_800_53_controls}
        CSF2_FUNCTIONS: list[dict] = [
            {
                "id": "GV", "name": "GOVERN",
                "description": "Organizational context, risk management strategy, supply chain risk.",
                "rule_groups": ["audit", "ossec", "policy_violation"],
                "nist_controls": ["PM-1", "PM-9", "RA-1"],
                "categories": ["GV.OC", "GV.RM", "GV.RR", "GV.PO", "GV.OV", "GV.SC"],
            },
            {
                "id": "ID", "name": "IDENTIFY",
                "description": "Asset management, risk assessment, improvement activities.",
                "rule_groups": ["vulnerability", "cve", "syscheck", "ossec"],
                "nist_controls": ["CA-2", "RA-3", "RA-5"],
                "categories": ["ID.AM", "ID.RA", "ID.IM"],
            },
            {
                "id": "PR", "name": "PROTECT",
                "description": "Identity management, access control, awareness, data security.",
                "rule_groups": [
                    "authentication_failed", "authentication_success",
                    "privilege_escalation", "pam", "sudo", "firewall",
                    "access_control", "fim", "syscheck",
                ],
                "nist_controls": ["AC-2", "AC-3", "AC-6", "IA-5", "SC-28"],
                "categories": ["PR.AA", "PR.AT", "PR.DS", "PR.IR", "PR.PS"],
            },
            {
                "id": "DE", "name": "DETECT",
                "description": "Continuous monitoring, adverse event analysis.",
                "rule_groups": [
                    "ids", "attack", "web_attack", "intrusion_detection",
                    "network_scan", "brute_force", "malware", "rootkit",
                ],
                "nist_controls": ["AU-6", "CA-7", "SI-4"],
                "categories": ["DE.CM", "DE.AE"],
            },
            {
                "id": "RS", "name": "RESPOND",
                "description": "Incident management, analysis, mitigation, reporting.",
                "rule_groups": [
                    "active_response", "block", "ids",
                    "intrusion_detection", "incident_handling",
                ],
                "nist_controls": ["IR-4", "IR-5", "IR-6", "IR-8"],
                "categories": ["RS.MA", "RS.AN", "RS.CO", "RS.MI", "RS.RP"],
            },
            {
                "id": "RC", "name": "RECOVER",
                "description": "Incident recovery, restoration, and communication.",
                "rule_groups": ["backup", "restore", "recovery", "service_restart"],
                "nist_controls": ["CP-2", "CP-10", "IR-4"],
                "categories": ["RC.RP", "RC.CO"],
            },
        ]

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "aggs": {
                "by_group": {
                    "terms": {"field": "rule.groups", "size": 300},
                    "aggs": {
                        "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                }
            },
        }
        res = await idx.search(body)
        group_counts: dict[str, dict] = {
            b["key"]: {
                "total":    b["doc_count"],
                "critical": b["critical"]["doc_count"],
                "agents":   [a["key"] for a in b["top_agents"]["buckets"]],
            }
            for b in res["aggregations"]["by_group"]["buckets"]
        }

        function_results = []
        for fn in CSF2_FUNCTIONS:
            total = critical = 0
            agents: set = set()
            matched: list = []
            for grp in fn["rule_groups"]:
                if grp in group_counts:
                    total    += group_counts[grp]["total"]
                    critical += group_counts[grp]["critical"]
                    agents.update(group_counts[grp]["agents"])
                    matched.append(grp)
            status = "FAILING" if critical > 0 else "WARNING" if total > 10 else "OK"
            function_results.append({
                "function_id":   fn["id"],
                "function_name": fn["name"],
                "description":   fn["description"],
                "categories":    fn["categories"],
                "nist_controls": fn["nist_controls"],
                "total_alerts":  total,
                "critical_alerts": critical,
                "top_agents":    list(agents)[:3],
                "matched_groups": matched,
                "status":        status,
            })

        function_results.sort(key=lambda x: x["critical_alerts"], reverse=True)
        failing = [f for f in function_results if f["status"] == "FAILING"]
        warning = [f for f in function_results if f["status"] == "WARNING"]

        return {
            "report_type": "nist_csf_2.0",
            "time_range":  time_range,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_functions":    len(function_results),
                "failing":  len(failing),
                "warning":  len(warning),
                "ok":       len(function_results) - len(failing) - len(warning),
                "posture": (
                    "CRITICAL" if len(failing) >= 3
                    else "HIGH"   if len(failing) >= 1
                    else "MEDIUM" if len(warning) >= 2
                    else "LOW"
                ),
            },
            "failing_functions": failing,
            "functions":         function_results,
            "note": (
                "NIST CSF 2.0 mapping is derived from Wazuh rule groups and NIST 800-53 fields. "
                "For full NIST 800-53 detail use compliance_summary(framework='nist_800_53'). "
                "Pair with iso27001_compliance_summary() for ISO 27001 cross-reference."
            ),
        }

    @mcp.tool()
    async def soc2_compliance_summary(
        time_range: str = "30d",
        min_level: int = 5,
    ) -> dict:
        """Generate a SOC 2 Type II compliance posture report.

        Maps Wazuh rule groups to the five SOC 2 Trust Services Criteria (TSC):
        Security (CC), Availability (A), Processing Integrity (PI),
        Confidentiality (C), and Privacy (P).

        Returns per-criterion status (OK / WARNING / FAILING), alert counts,
        top agents, and a recommended remediation priority.
        """
        # SOC 2 TSC → Wazuh rule group mapping
        SOC2_CRITERIA: list[dict] = [
            {
                "id": "CC", "name": "Common Criteria (Security)",
                "description": "Logical and physical access controls, risk assessment, monitoring.",
                "rule_groups": [
                    "authentication_failed", "authentication_success",
                    "brute_force", "privilege_escalation", "pam", "sudo",
                    "access_control", "firewall", "ids", "attack",
                ],
                "key_controls": ["CC6.1 Logical access", "CC6.2 Authentication", "CC7.2 Security events"],
            },
            {
                "id": "A", "name": "Availability",
                "description": "System availability commitments and performance.",
                "rule_groups": [
                    "resource_exhaustion", "high_memory", "disk_full",
                    "service_down", "service_restart", "system_error",
                ],
                "key_controls": ["A1.1 Capacity management", "A1.2 Environmental threats"],
            },
            {
                "id": "PI", "name": "Processing Integrity",
                "description": "Complete and accurate processing commitments.",
                "rule_groups": [
                    "syscheck", "fim", "configuration_changed",
                    "file_modified", "integrity_checksum_changed",
                ],
                "key_controls": ["PI1.1 Processing accuracy", "PI1.2 Processing completeness"],
            },
            {
                "id": "C", "name": "Confidentiality",
                "description": "Confidential information protection and disposal.",
                "rule_groups": [
                    "data_exfiltration", "web_attack", "sqli", "injection",
                    "sensitive_data", "encryption", "fim",
                ],
                "key_controls": ["C1.1 Confidential information identification", "C1.2 Disposal"],
            },
            {
                "id": "P", "name": "Privacy",
                "description": "Personal information collection, use, retention, and disposal.",
                "rule_groups": [
                    "gdpr", "pii", "data_exfiltration", "authentication_failed",
                ],
                "key_controls": ["P1.1 Privacy notice", "P4.1 Data access", "P8.1 Data quality"],
            },
        ]

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "aggs": {
                "by_group": {
                    "terms": {"field": "rule.groups", "size": 300},
                    "aggs": {
                        "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                }
            },
        }
        res = await idx.search(body)
        group_counts: dict[str, dict] = {
            b["key"]: {
                "total":    b["doc_count"],
                "critical": b["critical"]["doc_count"],
                "agents":   [a["key"] for a in b["top_agents"]["buckets"]],
            }
            for b in res["aggregations"]["by_group"]["buckets"]
        }

        criterion_results = []
        for crit in SOC2_CRITERIA:
            total = critical = 0
            agents: set = set()
            matched: list = []
            for grp in crit["rule_groups"]:
                if grp in group_counts:
                    total    += group_counts[grp]["total"]
                    critical += group_counts[grp]["critical"]
                    agents.update(group_counts[grp]["agents"])
                    matched.append(grp)
            status = "FAILING" if critical > 0 else "WARNING" if total > 10 else "OK"
            criterion_results.append({
                "criterion_id":   crit["id"],
                "criterion_name": crit["name"],
                "description":    crit["description"],
                "key_controls":   crit["key_controls"],
                "total_alerts":   total,
                "critical_alerts": critical,
                "top_agents":     list(agents)[:3],
                "matched_groups": matched,
                "status":         status,
                "remediation_priority": "P1-URGENT" if critical > 0 else "P2-HIGH" if total > 20 else "P3-MEDIUM" if total > 5 else "P4-LOW",
            })

        criterion_results.sort(key=lambda x: x["critical_alerts"], reverse=True)
        failing = [c for c in criterion_results if c["status"] == "FAILING"]
        warning = [c for c in criterion_results if c["status"] == "WARNING"]

        return {
            "report_type":  "soc2_type_ii",
            "time_range":   time_range,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_criteria": len(criterion_results),
                "failing": len(failing),
                "warning": len(warning),
                "ok":      len(criterion_results) - len(failing) - len(warning),
                "audit_readiness": (
                    "NOT AUDIT READY"     if len(failing) > 1
                    else "CONDITIONAL"    if len(failing) == 1 or len(warning) > 2
                    else "AUDIT READY"
                ),
            },
            "failing_criteria":  failing,
            "criteria":          criterion_results,
            "note": (
                "SOC 2 mapping derived from Wazuh rule groups. "
                "P1-URGENT criteria require remediation before audit. "
                "Pair with generate_compliance_report(framework='tsc') for native TSC field data."
            ),
        }

    # ── PCI-DSS dedicated summary ─────────────────────────────────────────────

    @mcp.tool()
    async def pci_dss_compliance_summary(
        time_range: str = "30d",
        min_level: int = 5,
    ) -> dict:
        """Generate a PCI-DSS v4.0 compliance posture report.

        Maps Wazuh's native rule.pci_dss field to the 12 PCI-DSS requirements,
        then adds rule-group heuristics for requirements not directly tagged.

        Returns per-requirement status (OK / WARNING / FAILING), alert counts,
        top violating agents, and a prioritised remediation list.
        """
        PCI_REQUIREMENTS: list[dict] = [
            {"id": "1",  "title": "Network Security Controls",
             "rule_groups": ["firewall", "iptables", "network", "port_scan"]},
            {"id": "2",  "title": "Secure Configurations",
             "rule_groups": ["syscheck", "configuration_changed", "fim"]},
            {"id": "3",  "title": "Account Data Protection",
             "rule_groups": ["sensitive_data", "data_exfiltration", "fim"]},
            {"id": "4",  "title": "Encryption in Transit",
             "rule_groups": ["ssl", "tls", "encryption"]},
            {"id": "5",  "title": "Malware Protection",
             "rule_groups": ["malware", "ransomware", "rootkit", "virus"]},
            {"id": "6",  "title": "Secure System & Software Development",
             "rule_groups": ["web_attack", "exploit", "injection", "sqli", "xss"]},
            {"id": "7",  "title": "Restrict Access by Business Need",
             "rule_groups": ["access_control", "privilege_escalation", "sudo", "su"]},
            {"id": "8",  "title": "Identify Users & Authenticate Access",
             "rule_groups": ["authentication_failed", "brute_force", "pam", "sshd"]},
            {"id": "9",  "title": "Restrict Physical Access",
             "rule_groups": ["physical_access", "removable_media", "usb"]},
            {"id": "10", "title": "Log All Access to System Components",
             "rule_groups": ["audit", "auditd", "ossec", "syslog"]},
            {"id": "11", "title": "Test Security of Systems & Networks",
             "rule_groups": ["vulnerability", "cve", "network_scan", "ids"]},
            {"id": "12", "title": "Support Information Security with Policies",
             "rule_groups": ["policy_violation", "ossec", "audit"]},
        ]

        # Query native pci_dss field + rule groups simultaneously
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "aggs": {
                "by_pci_control": {
                    "terms": {"field": "rule.pci_dss", "size": 100},
                    "aggs": {
                        "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                },
                "by_group": {
                    "terms": {"field": "rule.groups", "size": 300},
                    "aggs": {
                        "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                },
            },
        }
        res = await idx.search(body)

        pci_control_counts: dict[str, dict] = {
            b["key"]: {
                "total": b["doc_count"],
                "critical": b["critical"]["doc_count"],
                "agents": [a["key"] for a in b["top_agents"]["buckets"]],
            }
            for b in res["aggregations"]["by_pci_control"]["buckets"]
        }
        group_counts: dict[str, dict] = {
            b["key"]: {
                "total": b["doc_count"],
                "critical": b["critical"]["doc_count"],
                "agents": [a["key"] for a in b["top_agents"]["buckets"]],
            }
            for b in res["aggregations"]["by_group"]["buckets"]
        }

        req_results = []
        for req in PCI_REQUIREMENTS:
            req_id = req["id"]
            # Merge native PCI field hits (controls starting with req_id.)
            total = critical = 0
            agents: set = set()
            native_controls = [
                k for k in pci_control_counts if k.startswith(f"{req_id}.")
            ]
            for ctrl in native_controls:
                total    += pci_control_counts[ctrl]["total"]
                critical += pci_control_counts[ctrl]["critical"]
                agents.update(pci_control_counts[ctrl]["agents"])
            # Add rule-group heuristic counts
            for grp in req["rule_groups"]:
                if grp in group_counts:
                    total    += group_counts[grp]["total"]
                    critical += group_counts[grp]["critical"]
                    agents.update(group_counts[grp]["agents"])

            status = "FAILING" if critical > 0 else "WARNING" if total > 10 else "OK"
            req_results.append({
                "requirement": req_id,
                "title": req["title"],
                "total_alerts": total,
                "critical_alerts": critical,
                "top_agents": list(agents)[:5],
                "native_controls_hit": native_controls[:10],
                "status": status,
                "remediation_priority": (
                    "P0-CRITICAL" if critical > 20
                    else "P1-URGENT" if critical > 0
                    else "P2-HIGH" if total > 50
                    else "P3-MEDIUM" if total > 10
                    else "P4-LOW"
                ),
            })

        req_results.sort(key=lambda x: (x["critical_alerts"], x["total_alerts"]), reverse=True)
        failing = [r for r in req_results if r["status"] == "FAILING"]
        warning = [r for r in req_results if r["status"] == "WARNING"]

        return {
            "report_type":  "pci_dss_v4.0",
            "time_range":   time_range,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_requirements": len(req_results),
                "failing": len(failing),
                "warning": len(warning),
                "ok":      len(req_results) - len(failing) - len(warning),
                "audit_readiness": (
                    "NOT AUDIT READY" if len(failing) > 2
                    else "CONDITIONAL" if len(failing) > 0
                    else "AUDIT READY"
                ),
            },
            "failing_requirements": failing,
            "requirements":         req_results,
            "note": (
                "PCI-DSS mapping combines native rule.pci_dss field data with "
                "rule-group heuristics. For control-level drill-down use "
                "compliance_control_details(framework='pci_dss', control_id='10.2.1')."
            ),
        }

    # ── HIPAA dedicated summary ───────────────────────────────────────────────

    @mcp.tool()
    async def hipaa_compliance_summary(
        time_range: str = "30d",
        min_level: int = 5,
    ) -> dict:
        """Generate a HIPAA Security Rule compliance posture report.

        Maps Wazuh's native rule.hipaa field to HIPAA Security Rule safeguard
        categories (Administrative, Physical, Technical), with rule-group heuristics.

        Returns per-safeguard status, alert counts, and remediation priorities.
        """
        HIPAA_SAFEGUARDS: list[dict] = [
            {
                "id": "164.308", "category": "Administrative Safeguards",
                "rule_groups": ["audit", "policy_violation", "ossec", "auditd"],
                "controls": ["164.308(a)(1)", "164.308(a)(3)", "164.308(a)(4)",
                             "164.308(a)(5)", "164.308(a)(6)", "164.308(a)(8)"],
            },
            {
                "id": "164.310", "category": "Physical Safeguards",
                "rule_groups": ["physical_access", "removable_media", "usb"],
                "controls": ["164.310(a)(1)", "164.310(b)", "164.310(c)", "164.310(d)(1)"],
            },
            {
                "id": "164.312", "category": "Technical Safeguards",
                "rule_groups": [
                    "authentication_failed", "brute_force", "pam",
                    "access_control", "encryption", "ssl", "tls",
                    "audit", "auditd", "syscheck", "fim",
                ],
                "controls": ["164.312(a)(1)", "164.312(a)(2)", "164.312(b)",
                             "164.312(c)(1)", "164.312(d)", "164.312(e)(1)"],
            },
            {
                "id": "164.314", "category": "Organizational Requirements",
                "rule_groups": ["policy_violation", "ossec"],
                "controls": ["164.314(a)(1)", "164.314(b)(1)"],
            },
            {
                "id": "164.316", "category": "Policies and Procedures",
                "rule_groups": ["policy_violation", "configuration_changed", "audit"],
                "controls": ["164.316(a)", "164.316(b)(1)"],
            },
        ]

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "aggs": {
                "by_hipaa_control": {
                    "terms": {"field": "rule.hipaa", "size": 100},
                    "aggs": {
                        "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                },
                "by_group": {
                    "terms": {"field": "rule.groups", "size": 300},
                    "aggs": {
                        "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                        "top_agents": {"terms": {"field": "agent.name", "size": 3}},
                    },
                },
            },
        }
        res = await idx.search(body)

        hipaa_control_counts: dict[str, dict] = {
            b["key"]: {
                "total": b["doc_count"],
                "critical": b["critical"]["doc_count"],
                "agents": [a["key"] for a in b["top_agents"]["buckets"]],
            }
            for b in res["aggregations"]["by_hipaa_control"]["buckets"]
        }
        group_counts: dict[str, dict] = {
            b["key"]: {
                "total": b["doc_count"],
                "critical": b["critical"]["doc_count"],
                "agents": [a["key"] for a in b["top_agents"]["buckets"]],
            }
            for b in res["aggregations"]["by_group"]["buckets"]
        }

        safeguard_results = []
        for sg in HIPAA_SAFEGUARDS:
            total = critical = 0
            agents: set = set()
            native_hits = [
                ctrl for ctrl in sg["controls"] if ctrl in hipaa_control_counts
            ]
            for ctrl in native_hits:
                total    += hipaa_control_counts[ctrl]["total"]
                critical += hipaa_control_counts[ctrl]["critical"]
                agents.update(hipaa_control_counts[ctrl]["agents"])
            for grp in sg["rule_groups"]:
                if grp in group_counts:
                    total    += group_counts[grp]["total"]
                    critical += group_counts[grp]["critical"]
                    agents.update(group_counts[grp]["agents"])

            status = "FAILING" if critical > 0 else "WARNING" if total > 10 else "OK"
            safeguard_results.append({
                "safeguard_id":   sg["id"],
                "category":       sg["category"],
                "total_alerts":   total,
                "critical_alerts": critical,
                "top_agents":     list(agents)[:5],
                "native_controls_hit": native_hits,
                "status": status,
                "remediation_priority": (
                    "P0-CRITICAL" if critical > 20
                    else "P1-URGENT" if critical > 0
                    else "P2-HIGH"   if total > 50
                    else "P3-MEDIUM" if total > 10
                    else "P4-LOW"
                ),
            })

        safeguard_results.sort(key=lambda x: (x["critical_alerts"], x["total_alerts"]), reverse=True)
        failing = [s for s in safeguard_results if s["status"] == "FAILING"]
        warning = [s for s in safeguard_results if s["status"] == "WARNING"]

        return {
            "report_type":  "hipaa_security_rule",
            "time_range":   time_range,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_safeguards": len(safeguard_results),
                "failing": len(failing),
                "warning": len(warning),
                "ok":      len(safeguard_results) - len(failing) - len(warning),
                "audit_readiness": (
                    "NOT AUDIT READY" if len(failing) > 1
                    else "CONDITIONAL" if len(failing) > 0
                    else "AUDIT READY"
                ),
            },
            "failing_safeguards": failing,
            "safeguards":         safeguard_results,
            "note": (
                "HIPAA mapping combines native rule.hipaa field data with rule-group heuristics. "
                "For control-level drill-down use compliance_control_details(framework='hipaa', control_id='164.312(b)'). "
                "HIPAA Breach Notification Rule events require manual review."
            ),
        }

    # ── Compliance drift detection ────────────────────────────────────────────

    # In-memory baseline store: (framework, time_range) → baseline snapshot
    _compliance_baselines: dict[str, dict] = {}

    @mcp.tool()
    async def compliance_drift(
        framework: str = "pci_dss",
        time_range: str = "30d",
        min_level: int = 5,
        save_baseline: bool = False,
    ) -> dict:
        """Detect compliance posture drift by comparing current state to a saved baseline.

        On first call (or with save_baseline=True), saves the current compliance
        summary as the baseline.  On subsequent calls, diffs current vs baseline
        and returns controls that have worsened, improved, or are newly failing.

        framework:     pci_dss | hipaa | gdpr | nist_800_53 | tsc
        time_range:    lookback window for the current snapshot (default 30d)
        save_baseline: If True, overwrite the stored baseline with current state.
        """
        field = COMPLIANCE_FIELDS.get(framework)
        if not field:
            return {"error": f"Unknown framework '{framework}'", "supported": list(COMPLIANCE_FIELDS)}

        # Get current snapshot
        current_body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        time_window(f"now-{time_range}"),
                        {"range": {"rule.level": {"gte": min_level}}},
                        {"exists": {"field": field}},
                    ]
                }
            },
            "aggs": {
                "by_control": {
                    "terms": {"field": field, "size": 50},
                    "aggs": {
                        "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                    },
                }
            },
        }
        res = await idx.search(current_body)
        current_snapshot: dict[str, dict] = {
            b["key"]: {
                "total":    b["doc_count"],
                "critical": b["critical"]["doc_count"],
            }
            for b in res["aggregations"]["by_control"]["buckets"]
        }

        baseline_key = f"{framework}::{time_range}"

        if save_baseline or baseline_key not in _compliance_baselines:
            _compliance_baselines[baseline_key] = {
                "snapshot": current_snapshot,
                "saved_at": datetime.datetime.utcnow().isoformat() + "Z",
            }
            return {
                "status": "baseline_saved",
                "framework": framework,
                "saved_at": _compliance_baselines[baseline_key]["saved_at"],
                "controls_tracked": len(current_snapshot),
                "message": (
                    "Baseline saved. Call compliance_drift() again (without save_baseline=True) "
                    "to detect drift against this baseline."
                ),
            }

        baseline_data = _compliance_baselines[baseline_key]
        baseline_snapshot: dict[str, dict] = baseline_data["snapshot"]

        # Diff current vs baseline
        worsened: list[dict] = []
        improved: list[dict] = []
        new_failing: list[dict] = []
        all_controls = set(current_snapshot) | set(baseline_snapshot)

        for ctrl in sorted(all_controls):
            cur  = current_snapshot.get(ctrl,  {"total": 0, "critical": 0})
            base = baseline_snapshot.get(ctrl, {"total": 0, "critical": 0})

            delta_total    = cur["total"]    - base["total"]
            delta_critical = cur["critical"] - base["critical"]

            if ctrl not in baseline_snapshot and cur["critical"] > 0:
                new_failing.append({
                    "control": ctrl,
                    "current_total": cur["total"],
                    "current_critical": cur["critical"],
                    "note": "New control — not in baseline",
                })
            elif delta_critical > 0 or (delta_total > 0 and cur["critical"] > 0):
                worsened.append({
                    "control": ctrl,
                    "baseline_total": base["total"],
                    "current_total":  cur["total"],
                    "delta_total":    delta_total,
                    "baseline_critical": base["critical"],
                    "current_critical":  cur["critical"],
                    "delta_critical":    delta_critical,
                })
            elif delta_critical < 0 or delta_total < -5:
                improved.append({
                    "control": ctrl,
                    "baseline_total": base["total"],
                    "current_total":  cur["total"],
                    "delta_total":    delta_total,
                    "baseline_critical": base["critical"],
                    "current_critical":  cur["critical"],
                    "delta_critical":    delta_critical,
                })

        worsened.sort(key=lambda x: x["delta_critical"], reverse=True)

        overall_drift = (
            "DEGRADED"   if len(worsened) > 3 or len(new_failing) > 0
            else "SLIGHT_DEGRADATION" if len(worsened) > 0
            else "IMPROVED"  if len(improved) > 0
            else "STABLE"
        )

        return {
            "framework": framework,
            "drift_status": overall_drift,
            "baseline_saved_at": baseline_data["saved_at"],
            "compared_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {
                "worsened_controls":  len(worsened),
                "improved_controls":  len(improved),
                "new_failing":        len(new_failing),
            },
            "worsened_controls":  worsened[:20],
            "improved_controls":  improved[:10],
            "new_failing_controls": new_failing,
            "tip": (
                "Call compliance_drift(save_baseline=True) after a remediation sprint "
                "to reset the baseline. Use compliance_control_details() to drill into worsened controls."
            ),
        }
