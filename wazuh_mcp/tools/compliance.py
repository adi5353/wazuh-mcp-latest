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

    return {"generate_compliance_report": generate_compliance_report}
