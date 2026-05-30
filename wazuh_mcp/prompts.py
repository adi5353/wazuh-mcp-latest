"""MCP prompt definitions — one-click investigation and reporting workflows.

Extracted from ``server.py`` to keep the server module focused on lifecycle and
transport concerns. Each function is a pure, self-contained builder that returns
the prompt text for a given workflow; they hold no module-level state.

Registration with the MCP instance happens via :func:`register_prompts`, which
``server.py`` calls once at import time. The functions are also re-exported from
``server`` for backwards compatibility with callers/tests that reference them as
``server.<prompt_name>``.
"""
from __future__ import annotations


# ============================================================================
# MCP Prompts — one-click investigation workflows
# ============================================================================

def investigate_brute_force(time_range: str = "1h") -> str:
    """One-click brute force investigation."""
    return f"""Perform a complete brute force investigation for the last {time_range}:

1. search_authentication_failures(time_range="{time_range}", threshold=5) — find candidate IPs
2. For the top 3 IPs: search_by_source_ip to get full alert context
3. enrich_ip for each top IP — VirusTotal + AbuseIPDB reputation
4. enrich_ip_geo for each top IP — geolocation context
5. correlate_alert_with_response for the highest-volume IP — did Wazuh block it?
6. If NOT blocked: blast_radius_analysis to assess lateral spread

Conclude with:
- What happened and which accounts/services were targeted
- Whether the attack is ongoing or was blocked
- Recommended action (add_to_cdb_list if ALLOW_WRITES=true, or escalate)"""


def weekly_soc_briefing() -> str:
    """Generate a complete weekly SOC executive briefing."""
    return """Generate the weekly SOC executive briefing by calling these tools in order:

1. compare_alert_volume(current_range="7d", baseline_offset="7d") — volume trend
2. detect_rule_anomalies(current_range="7d") — new/spiking/silent rules
3. generate_weekly_summary() — aggregated top rules, agents, MITRE
4. vulnerability_summary(min_severity="Critical") — fleet CVE posture
5. prioritize_patches(top_n=5) — top patches by exposure × CVSS
6. active_response_effectiveness(time_range="7d") — block effectiveness rate
7. fleet_sca_weakest_agents(limit=5) — most misconfigured agents
8. mitre_coverage_analysis() — ATT&CK technique coverage stats

Format as an executive briefing with:
- Executive Summary (3 sentences)
- Key Metrics table
- Top 3 Risks this week
- Recommended Actions (owner + priority)"""


def triage_alert(alert_id: str) -> str:
    """Full structured triage for a single alert document ID."""
    return f"""Perform full triage on alert ID: {alert_id}

1. get_alert_by_id("{alert_id}") — full alert detail
2. get_rule_details(rule_id from alert) — what does this rule detect?
3. If alert has src_ip: search_by_source_ip(src_ip, time_range="24h")
4. enrich_ip(src_ip) — VirusTotal + AbuseIPDB verdict
5. enrich_ip_geo([src_ip]) — geolocation
6. correlate_alert_with_response(src_ip=src_ip) — automated response triggered?
7. blast_radius_analysis(src_ip=src_ip, time_range="2h") — scope of compromise
8. If alert involves file change: enrich_file_hash(sha256 from alert)

Produce a triage report:
- Classification: True Positive / False Positive / Needs Investigation
- Severity: Critical / High / Medium / Low
- Evidence summary (3 bullets)
- Recommended response
- Escalate: Yes/No — and to whom"""


def cve_emergency_response(cve_id: str) -> str:
    """Immediate CVE emergency response workflow."""
    return f"""Emergency response for {cve_id}:

1. search_cve("{cve_id}") — find every affected agent immediately
2. For top 5 affected agents: get_agent_vulnerabilities_detailed
3. prioritize_patches() — where does {cve_id} rank overall?
4. search_alerts(time_range="7d", rule_groups=["exploit","web_attack"]) — exploitation attempts?
5. fleet_find_package(package_name) — confirm package spread across fleet

Emergency response brief:
- Impact: agent count, environments affected
- Exploitation evidence: confirmed / suspected / not observed
- Immediate mitigations available
- Patch priority: P0 (now) / P1 (this week) / P2 (next cycle)
- Monitoring to add until patched"""


def morning_briefing() -> str:
    """Morning SOC shift briefing — run at the start of each shift."""
    return """Run a morning SOC briefing. Please:
1. alert_summary(time_range="24h") — overnight alert overview with trend
2. compare_alert_volume(current_range="24h", baseline_offset="24h") — vs yesterday
3. search_authentication_failures(time_range="24h", threshold=5) — overnight brute force
4. active_response_effectiveness(time_range="24h") — did overnight blocks work?
5. check_event_queue_health() — confirm the pipeline is healthy

Summarize findings as a shift handover with:
- Risk rating: LOW / MEDIUM / HIGH / CRITICAL
- 3 recommended actions for this shift
- Anything that needs immediate attention"""


def incident_triage_full(agent_name: str = "", src_ip: str = "") -> str:
    """Full incident triage for a specific agent or source IP."""
    target = f"agent '{agent_name}'" if agent_name else f"source IP '{src_ip}'"
    return f"""Run a full incident triage for {target}:
1. search_alerts(time_range="48h") filtered to the target
2. search_fim_alerts(time_range="48h") for the agent if known
3. get_agent_login_history(agent_name="{agent_name}") if agent known
4. correlate_alert_with_response(src_ip="{src_ip}") if IP known
5. enrich_ip_geo(["{src_ip}"]) if IP known — geolocation
6. blast_radius_analysis — assess lateral spread
7. create_incident_report from the top alert IDs found

End with:
- Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
- Recommended containment steps
- Whether to tag alerts as investigated or escalate"""


def threat_hunt_session() -> str:
    """Structured threat hunt across lateral movement, persistence, and exfiltration."""
    return """Run a full threat hunt session across the last 48 hours:
1. hunt_lateral_movement(time_range="48h") — auth patterns + multi-agent spread
2. hunt_persistence_mechanisms(time_range="48h") — startup/registry/cron changes
3. hunt_data_exfiltration(time_range="48h") — unusual outbound event volumes
4. For any agent flagged in 2+ hunts: get_agent_login_history and search_fim_alerts
5. Correlate findings — identify composite-risk agents (appear in multiple hunts)

Rate each finding LOW/MEDIUM/HIGH/CRITICAL.
Finish with a prioritised list of agents to investigate further."""


def end_of_shift_handover() -> str:
    """End-of-shift handover report."""
    return """Generate an end-of-shift handover report for the last 12 hours:
1. generate_shift_handover(shift_duration="12h")
2. generate_weekly_summary() for broader context
3. prioritize_patches(top_n=3) — top CVEs to patch
4. fleet_sca_weakest_agents(limit=5) — config posture
5. hunt_lateral_movement(time_range="12h") — any active threats?

Format as a handover document:
SUMMARY | OPEN INCIDENTS | PATCH QUEUE | CONFIG ISSUES | WATCH LIST"""


# ── Role-optimized prompts ────────────────────────────────────────────────────

def tier1_analyst_guide(alert_id: str = "") -> str:
    """Step-by-step alert walkthrough for Tier 1 SOC analysts.

    Designed for analysts who are new to Wazuh or to a particular alert type.
    Explains every step before executing it so the analyst builds understanding.
    """
    target = f'alert ID {alert_id}' if alert_id else 'the most recent high-severity alert'
    return f"""You are helping a Tier 1 SOC analyst investigate {target}.
Explain WHAT each tool does and WHY before calling it. Use simple language — assume the analyst
is learning on the job and may not know Wazuh terminology.

Step 1 — Get the alert details:
  Call: {'get_alert_by_id("' + alert_id + '")' if alert_id else 'explain_recent_alerts(time_range="1h", min_level=10, audience="tier1")'}
  Explain what each field means (rule.level, rule.description, agent.name, data.srcip).

Step 2 — Get a plain-English explanation:
  Call: explain_alert("{alert_id or '<id from step 1>'}", audience="tier1")
  Read the narrative aloud and confirm you understand the WHAT HAPPENED section.

Step 3 — Is the source IP suspicious?
  If there is a src_ip, call: enrich_ip("<src_ip>")
  Explain: VirusTotal score >5 = likely malicious. AbuseIPDB confidence >50 = block it.

Step 4 — Did Wazuh already respond?
  Call: correlate_alert_with_response(src_ip="<src_ip>")
  If active response fired = the IP was blocked. If not = we may need to act.

Step 5 — Decide and document:
  - False positive? → tag_alert(alert_id, tag="false_positive", note="your reason")
  - True positive, handled? → tag_alert(alert_id, tag="investigated")
  - Not sure? → Escalate to Tier 2 and describe what you found in Steps 1-4.

Remember: it is always OK to escalate. Document your findings before doing so."""


def tier2_analyst_deep_dive(agent_name: str = "", src_ip: str = "", time_range: str = "24h") -> str:
    """Deep-dive investigation workflow for experienced Tier 2 / IR analysts.

    Assumes familiarity with Wazuh, MITRE ATT&CK, and incident response procedures.
    Focuses on breadth-first evidence gathering followed by hypothesis testing.
    """
    target = f"agent '{agent_name}'" if agent_name else f"source IP '{src_ip}'" if src_ip else "the active incident"
    return f"""Tier 2 deep-dive investigation for {target} over the last {time_range}.

Phase 1 — Evidence collection (run in parallel where possible):
  search_alerts(time_range="{time_range}") filtered to target
  search_fim_alerts(time_range="{time_range}") — file integrity events
  {'get_agent_login_history(agent_name="' + agent_name + '")' if agent_name else 'search_authentication_failures(time_range="' + time_range + '", threshold=3)'}
  {'enrich_ip("' + src_ip + '")' if src_ip else 'get_agent_processes(agent_name="' + agent_name + '")'}
  {'enrich_ip_extended("' + src_ip + '")' if src_ip else ''}

Phase 2 — Lateral movement check:
  hunt_lateral_movement(time_range="{time_range}")
  get_agent_neighbors({'agent_name="' + agent_name + '"' if agent_name else ''})
  blast_radius_analysis({'src_ip="' + src_ip + '"' if src_ip else 'agent_name="' + agent_name + '"'}, time_range="{time_range}")

Phase 3 — Persistence check:
  hunt_persistence_mechanisms(time_range="{time_range}")
  critical_file_changes({'agent_name="' + agent_name + '"' if agent_name else ''}, time_range="{time_range}")

Phase 4 — MITRE mapping:
  search_by_mitre() on all technique IDs found in alerts above
  mitre_coverage_analysis() — confirm detection coverage for observed techniques

Phase 5 — Containment decision:
  Score findings: CONFIRMED / SUSPECTED / BENIGN
  If CONFIRMED HIGH/CRITICAL:
    run_active_response(agent_id, command="firewall-drop", src_ip="{src_ip or '?'}")  [requires ALLOW_WRITES]
    create_incident_report(alert_ids=[...], title="...", severity="HIGH")
    create_jira_ticket(summary="...", description="...", priority="High")
  Document all findings in create_workspace() for handover."""


def ciso_security_briefing(period: str = "7d") -> str:
    """Executive security briefing formatted for CISO / leadership consumption.

    No technical jargon. Business risk framing. Action items with owners.
    """
    return f"""Generate an executive security briefing for the last {period}.

Data collection (run these first):
  alert_summary(time_range="{period}", min_level=7)
  vulnerability_summary(min_severity="High")
  prioritize_patches(top_n=5)
  compliance_summary(framework="PCI-DSS")
  fleet_sca_weakest_agents(limit=3)
  active_response_effectiveness(time_range="{period}")

Format the output as:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY BRIEFING — {period.upper()} SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OVERALL RISK POSTURE:  [GREEN / YELLOW / RED]

KEY METRICS
  Total alerts:         [n]   vs prior period [n] ([+/-x%])
  Critical/High:        [n]   requiring immediate attention
  Systems monitored:    [n]   agents
  Unpatched CVEs (High+): [n]

TOP 3 RISKS THIS PERIOD
  1. [Risk name] — [1-sentence business impact] — Owner: [team]
  2. [Risk name] — [1-sentence business impact] — Owner: [team]
  3. [Risk name] — [1-sentence business impact] — Owner: [team]

COMPLIANCE STATUS
  [Framework]: [PASS/PARTIAL/FAIL] — [key finding]

ACTIONS REQUIRED
  • [Action] — Priority: [P0/P1/P2] — Due: [timeframe] — Owner: [team]

No further escalation required at this time. / Recommend emergency review."""


def compliance_officer_review(framework: str = "PCI-DSS", period: str = "30d") -> str:
    """Compliance review workflow for compliance officers and auditors.

    Maps security events to specific control requirements and produces
    audit-ready evidence summaries.
    """
    return f"""Run a {framework} compliance review for the last {period}.

Step 1 — Framework compliance status:
  compliance_summary(framework="{framework}", time_range="{period}")
  compliance_control_details(framework="{framework}")

Step 2 — Evidence collection:
  export_compliance_csv(framework="{framework}", time_range="{period}")
  generate_compliance_report(framework="{framework}")

Step 3 — Security controls verification:
  fleet_sca_weakest_agents(limit=10) — configuration compliance posture
  get_agent_sca_policies(agent_id=<worst agent>) — specific policy failures
  critical_file_changes(time_range="{period}") — file integrity evidence

Step 4 — Access control review:
  search_authentication_failures(time_range="{period}") — failed access attempts
  list_privileged_escalations(time_range="{period}") — privilege escalation events
  get_credential_age() — credential rotation compliance

Step 5 — Audit trail verification:
  verify_audit_log_integrity() — confirm logs are tamper-evident
  get_audit_log_stats() — coverage and completeness

Format output as audit-ready evidence with:
  Control ID | Requirement | Status | Evidence | Risk | Remediation

Flag any control failures with FAIL status and link to specific alert IDs as evidence.
Export final report with: email_compliance_report(framework="{framework}", recipient="compliance@yourorg.com")"""


# ============================================================================
# P3 Prompts — executive summary, audit prep, post-incident review, onboarding
# ============================================================================

def executive_summary(period: str = "7d") -> str:
    """C-suite security posture summary — no jargon, business-risk framing."""
    return f"""Generate a concise executive summary of the security posture for the last {period}.

Gather this data first (run in parallel):
  alert_summary(time_range="{period}", min_level=9)
  vulnerability_summary(min_severity="Critical")
  compliance_summary(framework="PCI-DSS")
  active_response_effectiveness(time_range="{period}")
  get_mitre_gaps()

Then write a 1-page brief in plain English:

HEADLINE:  One sentence — is the environment under active threat right now?

KEY NUMBERS (table):
  Critical alerts this {period}:   [n]
  High-severity CVEs unpatched:    [n]
  Agents monitored:                [n]
  Automated blocks executed:       [n]

TOP RISKS  (max 3, each in one sentence explaining business impact):
  1. [Risk] — [what could go wrong for the business]
  2. [Risk] — [what could go wrong for the business]
  3. [Risk] — [what could go wrong for the business]

REQUIRED ACTIONS  (owner + deadline):
  • [Action] — Owner: [team] — Due: [timeframe]

STATUS:  GREEN / YELLOW / RED — one sentence justification."""


def compliance_audit_prep(framework: str = "PCI-DSS", audit_date: str = "") -> str:
    """Pre-audit checklist and gap analysis for compliance officers."""
    deadline = f" (audit date: {audit_date})" if audit_date else ""
    return f"""Prepare for a {framework} audit{deadline}.

Step 1 — Current posture:
  compliance_summary(framework="{framework}")
  compliance_control_details(framework="{framework}")

Step 2 — Evidence collection:
  generate_compliance_report(framework="{framework}")
  export_compliance_csv(framework="{framework}", time_range="30d")
  verify_audit_log_integrity()
  get_audit_log_stats()

Step 3 — Access control evidence:
  search_authentication_failures(time_range="30d")
  list_privileged_escalations(time_range="30d")
  get_credential_age()

Step 4 — Configuration evidence:
  fleet_sca_weakest_agents(limit=10)
  critical_file_changes(time_range="30d")

Step 5 — Gap analysis:
  For each FAILED control from Step 1:
    - List the specific requirement
    - Describe the gap in one sentence
    - Recommend remediation with priority (P0/P1/P2) and owner

Output format:
  READY FOR AUDIT:  YES / NO (with conditions)
  CONTROLS PASSING: [n] / [total]
  GAPS TO CLOSE BEFORE AUDIT: [prioritised list]
  EVIDENCE PACKAGE: [list of exported files / report IDs]"""


def post_incident_review(incident_id: str = "", time_range: str = "48h") -> str:
    """Structured post-mortem template for completed security incidents."""
    target = f"incident {incident_id}" if incident_id else f"the most recent high-severity incident in the last {time_range}"
    return f"""Conduct a post-incident review for {target}.

1. TIMELINE RECONSTRUCTION
   incident_timeline({'incident_id="' + incident_id + '"' if incident_id else f'time_range="{time_range}"'})
   alert_timeline(time_range="{time_range}")

2. SCOPE & IMPACT
   blast_radius_analysis(time_range="{time_range}")
   search_fim_alerts(time_range="{time_range}") — file changes during incident
   get_agent_login_history — accounts accessed during incident window

3. DETECTION ANALYSIS
   get_mitre_gaps() — which tactics were NOT detected?
   correlate_alerts(time_range="{time_range}") — were alerts correlated?
   check_sla_breaches() — was response within SLA?

4. RESPONSE EFFECTIVENESS
   active_response_effectiveness(time_range="{time_range}")
   get_playbook_status() — which playbooks ran?

5. ROOT CAUSE
   hunt_persistence_mechanisms(time_range="{time_range}") — initial foothold?
   search_authentication_failures(time_range="{time_range}") — access vector?

Format the output as:

INCIDENT SUMMARY (2 sentences)
TIMELINE (chronological bullet list)
ROOT CAUSE (1 sentence)
WHAT WENT WELL
WHAT NEEDS IMPROVEMENT
ACTION ITEMS (owner + deadline per item)
DETECTION GAPS TO CLOSE"""


def new_analyst_onboarding() -> str:
    """Guided environment tour for analysts joining a new Wazuh deployment."""
    return """Welcome to the SOC. This prompt runs a guided tour of the Wazuh environment.
Work through each step in order — each one builds understanding for the next.

STEP 1 — Know your fleet:
  list_agents() — how many agents? what OS mix?
  list_groups() — what groups exist?
  get_cluster_health() — is the cluster healthy?
  Explain what you found in plain English.

STEP 2 — Understand the alert landscape:
  alert_summary(time_range="7d") — what are the top rules firing?
  search_by_mitre() — which MITRE tactics are most active?
  compare_alert_volume(current_range="7d", baseline_offset="7d") — is volume normal?

STEP 3 — Know the vulnerabilities:
  vulnerability_summary(min_severity="Critical") — what CVEs need attention?
  prioritize_patches(top_n=5) — which systems to patch first?

STEP 4 — Understand compliance posture:
  compliance_summary(framework="PCI-DSS")
  fleet_sca_weakest_agents(limit=5) — most misconfigured agents

STEP 5 — Run your first threat hunt:
  hunt_lateral_movement(time_range="24h")
  hunt_persistence_mechanisms(time_range="24h")
  Summarise any findings and rate them LOW / MEDIUM / HIGH.

STEP 6 — Know your tools:
  List the 5 MCP tools you'll use most often, with one sentence on when to use each.
  Describe how to create an incident report and assign it in Jira.

End with: "I am ready to take my first shift." and list 3 things you would watch for today."""


# All prompt builders, in registration order. ``server.py`` registers each of
# these with the MCP instance via :func:`register_prompts`.
ALL_PROMPTS = (
    investigate_brute_force,
    weekly_soc_briefing,
    triage_alert,
    cve_emergency_response,
    morning_briefing,
    incident_triage_full,
    threat_hunt_session,
    end_of_shift_handover,
    tier1_analyst_guide,
    tier2_analyst_deep_dive,
    ciso_security_briefing,
    compliance_officer_review,
    executive_summary,
    compliance_audit_prep,
    post_incident_review,
    new_analyst_onboarding,
)


def register_prompts(mcp) -> None:
    """Register every prompt builder in :data:`ALL_PROMPTS` with *mcp*.

    Mirrors the previous ``@mcp.prompt()`` decorations exactly — registration
    order and function identity are preserved.
    """
    for fn in ALL_PROMPTS:
        mcp.prompt()(fn)
