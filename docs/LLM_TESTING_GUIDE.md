# Testing Everything from Your LLM Interface

This guide shows how to exercise **every capability and integration** of the
Wazuh MCP server by *talking to it* from your LLM client (Claude Desktop,
Open WebUI + Ollama, or any MCP client). For each area you get:

- the **env vars** that must be set for the integration to be live,
- the exact **natural-language prompt** to type,
- the **tool(s)** the model should call, and
- **what a good result looks like** (how to verify).

> For container/curl/pytest-level verification (auth, 413, RBAC internals,
> schema parsing, container hardening), see the companion
> [testing-guide.md](./testing-guide.md). This doc is the *conversational* test
> plan. Architecture context: [TOOL_FLOW.md](./TOOL_FLOW.md).

---

## 0. Before you start

### 0.1 Connect your LLM client
- **Claude Desktop (remote/Docker):** add the `mcp-remote` server pointing at
  `http://YOUR_SERVER_IP:8000/sse` (see README → *Connect Claude Desktop*).
- **Claude Desktop (local stdio):** point at `python -m wazuh_mcp`.
- **Open WebUI:** Settings → Tools → Add Tool Server → `http://wazuh-mcp:8000/sse`
  + your `WAZUH_MCP_API_KEY` (see [open-webui-integration.md](./open-webui-integration.md)).

Confirm the tools icon appears and the model can list tools.

### 0.2 Sanity checks (ask the model)
```
"List the Wazuh MCP tools you have available."
"What is the Wazuh API health right now?"        → get_wazuh_api_health
"Give me the server metrics."                     → get_mcp_server_metrics
```
If those work, your transport, auth, and Wazuh connectivity are good.

### 0.3 Role matters
Your session role (`WAZUH_MCP_USER_ROLE`, default `analyst`, or via
`set_session_role_tool`) controls which tools run. Write/admin tests below note
the required tier. If a tool returns *"Insufficient role… required_role: X"*,
that's expected — raise the role and retry.

### 0.4 If context-gating is on
If `WAZUH_MCP_CONTEXT_GATING=true`, a gated tool returns *"…belongs to the 'X'
operational context…"*. First say:
```
"Enter the threat_hunting operational context."   → enter_operational_context
```
(Default is OFF — skip this unless you enabled gating.)

---

## 1. Alerts & investigation (CORE, analyst)

| Prompt | Tool | Verify |
|---|---|---|
| "Summarize the last 24 hours of alerts." | `alert_summary` | Counts by rule/agent/MITRE + trend vs prior period |
| "Search alerts above level 10 in the last 7 days." | `search_alerts` | Trimmed alert list, `next_page_token` if many |
| "Show alerts mapped to MITRE T1110 this week." | `search_by_mitre` | Alerts tagged with the technique |
| "Which IPs caused the most auth failures today?" | `search_authentication_failures` / `search_by_source_ip` | Top source IPs |
| "Build a timeline for alert `<id>`." | `alert_timeline` | Ordered events |
| "Explain alert `<id>` for my CISO." | `explain_alert` | Plain-language narrative + MITRE |
| "Convert 'failed root logins from outside the office' to an OpenSearch query and run it." | `nl_to_opensearch_query` | Validated DSL + results |

---

## 2. Threat intelligence (analyst; context `threat_hunting` if gating on)

**Env:** `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `IPINFO_TOKEN` (geo/ASN),
`HIBP`/`Hunter` keys for email. Without keys, tools return a clear
"not configured" / status message — check with `get_threat_intel_status`.

```
"What threat-intel providers are configured?"          → get_threat_intel_status
"Is IP 45.33.32.156 malicious?"                         → enrich_ip   (VT + AbuseIPDB)
"Check this file hash <sha256>."                        → enrich_file_hash
"Reputation of domain evil-c2.example?"                 → enrich_domain
"Is this URL dangerous: http://bad.example/x?"          → enrich_url
"Has admin@acme.com been in any breaches?"              → enrich_email   (HIBP/Hunter)
"Enrich these IOCs: 1.2.3.4, evil.com, <hash>, http://x.io" → bulk_enrich_iocs (auto-detects type)
"Do any of these IOCs appear in my live alerts?"        → ioc_to_alert_match
"Give me full geo + ASN + infra type for 8.8.8.8."      → enrich_ip_extended / classify_ip_infrastructure
```
**Verify:** malicious counts, country/ASN, and (for `ioc_to_alert_match`) an
`ACTIVE_THREATS_DETECTED` verdict when an IOC matches recent alerts.

---

## 3. Threat hunting & correlation (analyst; context `threat_hunting`)

```
"Hunt for lateral movement in the last 48 hours."       → hunt_lateral_movement
"Hunt for persistence mechanisms this week."            → hunt_persistence_mechanisms
"Look for data exfiltration patterns."                  → hunt_data_exfiltration
"Correlate alerts around agent 001 into attack chains." → correlate_alerts / get_attack_chains
"Build a cross-agent incident from alert <id>."         → correlate_multi_agent_incident
```
**Verify:** grouped findings, pivot IPs/usernames, MITRE kill-chain, confidence
score 0–99 with tier.

---

## 4. UEBA & behavioral baselining (analyst; context `threat_hunting`/`system_health`)

```
"Show the activity profile for user 'root' over 24h."   → get_user_activity_profile
"Detect users logging into more than 3 agents."         → detect_user_anomalies
"List privilege-escalation events in the last 48h."      → list_privileged_escalations
"Compute a 7-day behavioral baseline for agent 001."     → compute_agent_baseline
"What's agent 001's deviation score right now?"          → score_agent_deviation
"List anomalous agents above deviation 40."              → list_anomalous_agents
```
**Verify:** risk level/flags for users; mean/std baseline; deviation 0–100 with
label (NORMAL→CRITICAL).

---

## 5. Vulnerabilities & CVE (analyst)

```
"Summarize vulnerabilities across the fleet."           → vulnerability_summary
"Show detailed vulns for agent 001."                     → get_agent_vulnerabilities_detailed
"Search for CVE-2021-44228."                             → search_cve
"Prioritize patches using EPSS and KEV."                 → prioritize_patches_with_epss / check_kev_exposure
"Add CVE-2024-3094 to the watchlist."                    → add_cve_to_watchlist  (persists to CDB)
"Which watchlisted CVEs are breaching SLA?"              → check_sla_breaches
```
**Verify:** CVSS/EPSS scores, KEV flags, watchlist persists across restarts.

---

## 6. Active response & blocklisting (responder; context `active_response`)

> All writes default to **dry-run** and require **responder**.

```
"Propose an active response to block IP 1.2.3.4."        → propose_active_response
"Preview adding 1.2.3.4 to the malware-ips CDB list."    → preview_cdb_list_impact (dry-run)
"Approve response <id>."                                 → approve_response  (then run_active_response)
"Add 1.2.3.4 to the malware-ips blocklist."              → add_to_cdb_list
"List CDB lists / show contents of malware-ips."         → list_cdb_lists / get_cdb_list_contents
"Back up the malware-ips CDB list."                      → export_cdb_backup
```
**Verify:** dry-run returns a preview (no change); approval gate enforced;
`analyst` role is blocked with a role error.

---

## 7. Alert suppression / noise (responder; context `active_response`)

```
"Which rules are noisiest? Give me a noise score for rule 5710." → noise_score_rule
"Suppress rule 5710 for 24 hours."                       → bulk_suppress_rule
"List active suppressions."                              → list_suppressed_rules
"Expire the suppression on rule 5710."                   → expire_suppression
```

---

## 8. Incidents & SOAR ticketing (analyst→responder)

### 8.1 Build the incident
```
"Create an incident report from alert <id>."             → create_incident_report
"What's the blast radius of agent 001's compromise?"     → blast_radius_analysis
"Tag alert <id> as 'confirmed-phishing'."                → tag_alert
```

### 8.2 Jira  — **env:** `JIRA_URL`, `JIRA_USER`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`
```
"Open a Jira ticket for this incident, severity High."   → create_jira_ticket
"Mark Jira SOC-123 as In Progress."                      → update_ticket_status
```
**Verify:** returns the created issue key/URL; ticket appears in your Jira
project with `wazuh-mcp` + `severity-*` labels. If unset, you'll get
*"Jira not configured. Add JIRA_URL, JIRA_USER, JIRA_API_TOKEN to .env."*

### 8.3 TheHive — **env:** `THEHIVE_URL`, `THEHIVE_API_KEY`
```
"Create a TheHive case for this incident."               → create_thehive_case
```

### 8.4 ServiceNow — **env:** ServiceNow instance creds
```
"Open a ServiceNow incident for agent 001's malware alert." → create_servicenow_incident
"Get ServiceNow incident INC0010023."                    → get_servicenow_incident
"Update that ServiceNow incident to resolved."           → update_servicenow_incident
```

### 8.5 PagerDuty — **env:** PagerDuty routing/integration key
```
"Page on-call: critical ransomware on agent 001."        → trigger_pagerduty_alert
"Acknowledge / resolve that PagerDuty alert."            → acknowledge_pagerduty_alert / resolve_pagerduty_alert
```

### 8.6 Azure DevOps — **env:** Azure DevOps org/PAT
```
"Create an Azure DevOps work item for this incident."    → create_azure_devops_work_item
"Get / update Azure DevOps work item 4567."              → get_azure_devops_work_item / update_azure_devops_work_item
```
**Verify (all SOAR):** each returns the created record ID/URL; unconfigured
integrations return an explicit "not configured" error rather than failing.

---

## 9. Notifications (analyst→responder)

### 9.1 Slack — **env:** `SLACK_WEBHOOK_URL` (or `SLACK_BOT_TOKEN` + `SLACK_DEFAULT_CHANNEL`)
```
"Send alert <id> to Slack."                              → send_alert_to_slack
"Post the shift handover to Slack."                      → send_shift_handover_to_slack
"Send this week's summary to Slack."                     → send_weekly_summary_to_slack
```
### 9.2 Microsoft Teams — **env:** `TEAMS_WEBHOOK_URL`
```
"Send a critical-alert card to Teams for alert <id>."    → send_critical_alert_to_teams
"Post the weekly summary to Teams."                      → send_weekly_summary_to_teams
```
### 9.3 Email — **env:** `SMTP_HOST/PORT/USER/PASS`, `REPORT_EMAIL_FROM/TO`
```
"Email the PCI-DSS compliance report to the team."       → email_compliance_report
```
**Verify:** message appears in the Slack channel / Teams channel / inbox.
Test the wiring first with a benign summary before real alerts.

---

## 10. Compliance & reporting (analyst; context `compliance`)

```
"Give me a PCI-DSS v4.0 readiness report."               → pci_dss_compliance_summary
"HIPAA Security Rule posture?"                            → hipaa_compliance_summary
"NIST CSF 2.0 summary across all 6 functions."           → nist_csf2_compliance_summary
"ISO 27001 / SOC 2 Type II summary."                      → iso27001_compliance_summary / soc2_compliance_summary
"Detail control 10.2 and its evidence."                   → compliance_control_details
"Save a compliance baseline now."                         → compliance_drift (save_baseline=true)
"How has compliance drifted since the baseline?"          → compliance_drift
"Generate the full compliance report and export to HTML." → generate_compliance_report → export_report_html
```
**Verify:** per-control status, audit-readiness verdict, drift deltas
(worsened/improved/new-failing). Drift baselines persist across restarts.

### Reporting & exports
```
"Generate this week's SOC summary."                      → generate_weekly_summary
"Generate a shift handover."                             → generate_shift_handover
"Compare alert volume vs last week."                     → compare_alert_volume
"Export the last 24h of alerts to CSV (streaming)."       → export_alerts_csv (stream=true)
"Export alerts as NDJSON / JSON."                        → export_alerts_ndjson / export_alerts_json
"Generate the ROI report for this month."                → generate_roi_report
```

---

## 11. Fleet & system health (analyst→admin; context `system_health`)

```
"Score the health of agent 001."                         → get_agent_health_score
"List unhealthy agents."                                 → list_unhealthy_agents
"What packages/processes/ports are on agent 001?"        → get_agent_packages / _processes / _open_ports
"Which agents have package openssl < X?"                 → fleet_find_package
"Show FIM changes / critical file changes recently."     → get_recent_fim_changes / critical_file_changes
"SCA failed checks for agent 001 / weakest agents."      → get_sca_failed_checks / fleet_sca_weakest_agents
"Rootcheck results / last scan for agent 001."           → get_agent_rootcheck_results / get_rootcheck_last_scan
"Cluster + event queue health."                          → get_cluster_health / check_event_queue_health
"List/trigger agent upgrades (admin)."                   → list_agent_upgrades / trigger_agent_upgrade
```

---

## 12. Network topology (analyst)

```
"Map the network topology by /24 subnet."                → get_network_topology
"What's exposed in 192.168.1.0/24?"                       → map_subnet_exposure
"Find network neighbors of agent 001 in 24h."             → get_agent_neighbors
```

---

## 13. Rules & detection engineering (analyst→admin; context `active_response` for deploy)

```
"Show details for rule 5710 / search rules for 'sshd'."  → get_rule_details / search_rules
"Test this log line against the rules: <log>."            → test_log_against_rules
"Which decoder fires for this log line: <log>?"           → test_decoder
"Convert this Sigma rule to a Wazuh rule."                → convert_sigma_rule → generate_rule_xml
"Validate this rule XML."                                 → validate_rule_xml
"Backtest the rule against archive logs."                 → test_sigma_rule_against_archive
"Where are my MITRE coverage gaps?"                       → sigma_coverage_gap / get_mitre_gaps
"Push this custom rule (admin)."                          → push_custom_rule
"Roll back custom rule local_rules.xml."                  → rollback_custom_rule
```
**Verify:** validation catches malformed XML; push requires admin; rollback
restores the prior on-disk version.

---

## 14. Automated playbooks (responder→admin; dry-run first)

```
"List available playbooks."                              → list_playbooks
"Run 'isolate-compromised-host' for agent 001, dry run." → run_playbook (dry_run=true)
"Run 'brute-force-response' for IP 1.2.3.4, dry run."     → run_playbook
"Status of playbook run <id> / resume it."                → get_playbook_status / resume_playbook
```
**Verify:** dry-run shows resolved steps with approval gates marked; nothing
executes until you confirm.

---

## 15. Autonomous SOC monitor (admin)

```
"Status of the autonomous SOC monitor?"                  → get_autonomous_status
"Start the autonomous monitor, 60s interval, threshold 10." → start_autonomous_monitor
"Configure auto-ticketing to Jira for true positives."   → configure_auto_ticketing
"List pending auto-suppressions / approve <id>."          → list_pending_suppressions / approve_suppression
"Configure weekly scheduled reports."                     → configure_scheduled_reports
"Stop the autonomous monitor."                            → stop_autonomous_monitor
```
**Verify:** start/stop require admin (`analyst` is blocked); status reflects
running state.

---

## 16. Onboarding, scheduling, workspaces

```
"Generate an enrollment command for a new Ubuntu agent." → generate_enrollment_command
"List agents that never connected."                      → list_never_connected_agents
"Create a daily SOC-summary report schedule."            → create_report_schedule
"List / delete report schedules."                        → list_report_schedules / delete_report_schedule
"Create an investigation workspace 'phish-2024'."        → create_workspace
"Add alert <id> to that workspace and export it."        → add_to_workspace / export_workspace
```

---

## 17. Operations & security self-tests (admin)

```
"Show MCP server metrics and slow queries."              → get_mcp_server_metrics / get_slow_queries
"Per-tool usage stats (p50/p95/p99)?"                    → get_tool_usage_stats
"How old are the Wazuh API credentials?"                 → get_credential_age
"Verify the audit-log integrity."                        → verify_audit_log_integrity
"Search the audit log for run_active_response calls."    → search_audit_log
"List manager API users / login history."                → list_manager_api_users / get_manager_login_history
```
**Verify:** audit integrity returns `OK` (or lists tampered lines);
metrics show real latency percentiles.

---

## 18. MSSP multi-tenant (admin)

```
"List the tenants you can manage."                       → list_tenants
"Switch to tenant 'acme-corp'."                          → switch_tenant
"Now summarize acme-corp's alerts for the last 24h."     → alert_summary (scoped)
"Search alerts only for the linux-servers group."         → search_alerts (group_filter)
```
**Verify:** results are scoped to the active tenant/group; switching changes the
data set.

---

## 19. MCP prompts (guided multi-tool workflows)

In Claude Desktop use the **prompt picker** (or just ask by name); each expands
into several tool calls:

| Prompt | What it runs |
|---|---|
| `morning_briefing` | alert summary + unhealthy agents + vuln + drift |
| `incident_triage_full` | source-IP search + blast radius + enrichment + incident report |
| `threat_hunt_session` | lateral movement / persistence / exfil hunts |
| `end_of_shift_handover` | shift summary for the next analyst |
| `ciso_security_briefing` | exec-level risk narrative for a period |
| `compliance_officer_review` | framework posture + drift + evidence |
| `compliance_audit_prep` | audit-readiness checklist for a framework |
| `post_incident_review` | timeline + root cause + lessons |
| `new_analyst_onboarding` | orientation walkthrough |

**Verify:** the model chains the expected tools and produces the composite report.

---

## 20. End-to-end scripted conversation (copy/paste)

Run this top-to-bottom to touch alerting → enrichment → correlation → ticket →
notify → report in one session:

```
1.  "Summarize the last 24 hours of alerts."
2.  "What are the top 3 source IPs in those alerts?"
3.  "Enrich the #1 IP with VirusTotal and AbuseIPDB."
4.  "Do any of those IPs appear in my live alerts? (ioc_to_alert_match)"
5.  "Build a cross-agent incident from the worst alert."
6.  "Analyze its blast radius."
7.  "Create an incident report, then open a Jira ticket (severity High)."
8.  "Send a critical-alert card to Teams for it."
9.  "Generate this week's SOC summary and export it to HTML."
10. "Give me the ROI report for the time we just saved."
```

If every step returns structured data (and configured integrations create real
tickets/messages), the full stack — Wazuh connectivity, RBAC, enrichment,
correlation, SOAR, notifications, reporting — is working end to end.

---

## 21. Troubleshooting quick reference

| Symptom in chat | Likely cause | Fix |
|---|---|---|
| "Insufficient role… required_role: X" | Session role too low | Raise `WAZUH_MCP_USER_ROLE` or `set_session_role_tool` |
| "…belongs to the 'X' operational context…" | Context gating on | `enter_operational_context("X")` first |
| "<Integration> not configured" | Missing env vars | Set the integration's env vars, restart |
| Empty/zero results | No matching data / wrong time range | Widen `time_range`, check Wazuh has data |
| Tool not offered by the model | Not in `tools/list` / role-filtered | Check role; re-list tools; verify client connected |
| 401 / can't connect | API key / transport | Verify `WAZUH_MCP_API_KEY` and SSE URL |
| Slow or timing out | Upstream slow / breaker open | `get_slow_queries`, check Wazuh health |
