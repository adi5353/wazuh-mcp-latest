# Tool Flow — Wazuh MCP Server

How a request travels from the analyst's sentence to a Wazuh/3rd-party API and
back, how tools are grouped, and the end-to-end flows for the common SOC
workflows.

> Related: [PRD](./PRD.md) · [TRD](./TRD.md) · [LLM Testing Guide](./LLM_TESTING_GUIDE.md) · [Tool Table](./TOOL_TABLE.md)

---

## 1. Request lifecycle (one tool call)

```mermaid
sequenceDiagram
    participant A as Analyst
    participant L as LLM client (Claude / Open WebUI)
    participant H as HTTP middleware
    participant T as Tool middleware
    participant W as Tool handler
    participant U as Upstream (Wazuh / 3rd-party)

    A->>L: "Summarize the last 24h of alerts"
    L->>L: pick tool from tools/list (docstrings)
    L->>H: tools/call alert_summary{time_range:"24h"}
    Note over H: MaxBodySize→SecurityHeaders→[IPFilter]→[APIKey 401]<br/>→OriginValidation→RateLimit 429→Audit
    H->>T: authenticated request
    Note over T: identity/role → context-gate → sanitize+validate<br/>→ RBAC/ABAC → rate/quota → breaker → cache
    T->>W: invoke handler
    W->>U: OpenSearch _search (aggregations)
    U-->>W: raw results
    W->>W: parse (schemas) + enrich (MITRE/geo) + trim
    W-->>T: dict result
    Note over T: sanitize_response (strip secrets/injection)<br/>→ size cap → token-budget trim → audit (HMAC)
    T-->>H: clean result
    H-->>L: JSON-RPC response
    L-->>A: natural-language summary
```

**Fast-fail points:** `413` oversized body · `401` bad/missing API key · `429`
rate limit · RBAC error (`required_role`) · context-gate error
(`required_context`) · validation error · circuit/failure-breaker open.

---

## 2. Tool registration flow (startup)

```mermaid
flowchart TD
    M["server.py: mcp = FastMCP('wazuh')"] --> C["build ToolContext<br/>(WazuhClient, WazuhIndexer, Config, helpers)"]
    C --> R{"for each module in wazuh_mcp/tools/*"}
    R --> S["set_registering_module(name)"]
    S --> Reg["module.register(ctx)<br/>@mcp.tool() closures capture wz/idx/cfg"]
    Reg --> Tag["tag_tool() → map tool → operational context"]
    Tag --> R
    R --> P["register_prompts(mcp)"]
    P --> Res["resources.register(mcp, wz, idx, cfg)"]
    Res --> X{"WAZUH_MCP_TRANSPORT"}
    X -->|stdio| Std["FastMCP stdio (JSON-RPC on stdout)"]
    X -->|http| Http["Starlette+Uvicorn, wrap middleware,<br/>expose /sse /messages /health /metrics"]
```

---

## 3. Tool groups → operational contexts

Modules are CORE (always available) unless gated into a context. With
`WAZUH_MCP_CONTEXT_GATING=true`, gated tools are inert until the caller runs
`enter_operational_context(<ctx>)` — keeping the model focused and reducing
mis-selection.

```mermaid
flowchart LR
    subgraph CORE["CORE — always on"]
        c1[alerts] --- c2[agents]
        c3[vulnerabilities] --- c4[incidents]
        c5[integrations] --- c6[notifications]
        c7[explain_alert] --- c8[reporting/export]
        c9[metrics/health] --- c10[routing]
    end
    subgraph TH["context: threat_hunting"]
        t1[threat_hunting] --- t2[threat_intel]
        t3[threat_feeds] --- t4[correlation]
        t5[ueba]
    end
    subgraph AR["context: active_response"]
        a1[active_response] --- a2[cdb]
        a3[suppression] --- a4[rule_wizard_deploy]
    end
    subgraph CO["context: compliance"]
        o1[compliance] --- o2[reporting]
        o3[scheduler]
    end
    subgraph SH["context: system_health"]
        h1[agent_upgrades] --- h2[fim]
        h3[rootcheck] --- h4[sca]
        h5[fleet]
    end
```

| Context | Enter with | Representative tools |
|---|---|---|
| **threat_hunting** | `enter_operational_context("threat_hunting")` | `hunt_lateral_movement`, `enrich_ip`, `bulk_enrich_iocs`, `correlate_alerts`, `detect_user_anomalies` |
| **active_response** | `enter_operational_context("active_response")` | `propose_active_response`, `add_to_cdb_list`, `bulk_suppress_rule`, `push_custom_rule` |
| **compliance** | `enter_operational_context("compliance")` | `pci_dss_compliance_summary`, `compliance_drift`, `generate_compliance_report`, `create_report_schedule` |
| **system_health** | `enter_operational_context("system_health")` | `get_agent_health_score`, `fim_summary`, `get_sca_failed_checks`, `trigger_agent_upgrade` |

`list_operational_contexts` / `exit_operational_context` manage the session set.
(Gating is **off** by default — all tools are available without entering a context.)

---

## 4. RBAC gating by tool class

```mermaid
flowchart TD
    Call[tool call] --> Role{role >= required?}
    Role -->|no| Err["error: requires 'responder' or above<br/>(required_role, current_role)"]
    Role -->|yes| Run[execute]

    subgraph Tiers
      V["viewer (10): read summaries/searches"]
      An["analyst (20): + enrich, hunt, compliance, incidents, rules"]
      Re["responder (30): + active response, CDB writes, suppression, feed sync"]
      Ad["admin (40): + cluster, agent restart, rule push, autonomous monitor"]
    end
```

---

## 5. Common workflow flows

### 5.1 Alert triage & investigation
```mermaid
flowchart LR
    A[alert_summary 24h] --> B[search_alerts / search_by_source_ip]
    B --> C[get_alert_by_id]
    C --> D[explain_alert]
    D --> E[auto_triage_alert<br/>+ KEV boost]
    E --> F{verdict}
    F -->|true positive| G[create_incident_report]
    F -->|noise| H[noise_score_rule → bulk_suppress_rule]
```

### 5.2 Threat-intel enrichment (the "is this IP/hash/domain malicious?" flow)
```mermaid
flowchart LR
    I[IOC from alert] --> T{type}
    T -->|ip| P1[enrich_ip<br/>VirusTotal+AbuseIPDB]
    T -->|hash| P2[enrich_file_hash]
    T -->|domain| P3[enrich_domain]
    T -->|url| P4[enrich_url]
    T -->|email| P5[enrich_email HIBP/Hunter]
    T -->|mixed list| P6[bulk_enrich_iocs auto-detect]
    P1 & P2 & P3 & P4 & P6 --> M[ioc_to_alert_match<br/>scan live alerts]
    M --> V{ACTIVE_THREATS_DETECTED?}
    V -->|yes| R[propose_active_response / add_to_cdb_list]
```

### 5.3 Incident → ticket (Jira / SOAR) flow
```mermaid
flowchart LR
    A[correlate_multi_agent_incident] --> B[blast_radius_analysis]
    B --> C[create_incident_report]
    C --> D{ticketing target}
    D -->|Jira| J[create_jira_ticket]
    D -->|TheHive| H[create_thehive_case]
    D -->|ServiceNow| S[create_servicenow_incident]
    D -->|PagerDuty| P[trigger_pagerduty_alert]
    D -->|Azure DevOps| Z[create_azure_devops_work_item]
    J & H & S --> U[update_ticket_status]
    C --> N[send_critical_alert_notify Slack/Teams]
```

### 5.4 Active response with safety gates
```mermaid
flowchart LR
    A[propose_active_response] --> B[preview_cdb_list_impact / dry_run=true]
    B --> C{responder approves?}
    C -->|approve_response| D[run_active_response / add_to_cdb_list]
    C -->|deny_response| E[no-op + audit]
    D --> F[correlate_alert_with_response]
    F --> G[active_response_effectiveness]
```

### 5.5 Compliance reporting & drift
```mermaid
flowchart LR
    A[pci_dss / hipaa / nist_csf2 / soc2 / iso27001 summary] --> B[compliance_control_details]
    B --> C[generate_compliance_report]
    C --> D[export_compliance_csv / export_report_html]
    A --> E[compliance_drift vs baseline]
    C --> F[create_report_schedule + email_compliance_report]
```

### 5.6 Detection engineering (Sigma → deployed rule)
```mermaid
flowchart LR
    A[convert_sigma_rule] --> B[generate_rule_xml]
    B --> C[validate_rule_xml]
    C --> D[test_log_against_rules / test_sigma_rule_against_archive]
    D --> E[suggest_rule_tuning]
    E --> F[push_custom_rule admin]
    F --> G{regression?}
    G -->|yes| H[rollback_custom_rule]
    A2[sigma_coverage_gap] --> A
```

### 5.7 Autonomous SOC loop
```mermaid
flowchart LR
    A[start_autonomous_monitor admin] --> B[poll alerts at interval]
    B --> C[auto_triage_alert]
    C --> D{configure_auto_ticketing}
    D -->|true positive| E[create_jira_ticket]
    C --> F[propose suppression]
    F --> G[list_pending_suppressions → approve/reject]
    B --> H[configure_scheduled_reports → weekly summary]
    A --> S[get_autonomous_status] --> Z[stop_autonomous_monitor]
```

---

## 6. Prompts & resources flow

- **Prompts** (guided workflows) are invoked by the LLM client's prompt picker and
  expand into a multi-tool plan, e.g. `morning_briefing` → `alert_summary` +
  `list_unhealthy_agents` + `vulnerability_summary` + `compliance_drift`.
- **Resources** are pulled as read-only context (no side effects):
  `agents`, `mitre techniques`, `rules summary`, `health`.

```mermaid
flowchart LR
    P[prompt: incident_triage_full] --> S1[search_by_source_ip]
    P --> S2[blast_radius_analysis]
    P --> S3[enrich_ip]
    P --> S4[create_incident_report]
    R[(resources: agents / mitre / health)] -.context.-> P
```

---

## 7. Where to look in code

| Concern | File |
|---|---|
| Server bootstrap, transport, middleware wiring | `wazuh_mcp/server.py` |
| Per-call pipeline | `wazuh_mcp/middleware/tool_middleware.py` |
| Operational-context grouping & gating | `wazuh_mcp/tool_contexts.py` |
| RBAC tiers / decorator | `wazuh_mcp/rbac.py` |
| Tool implementations | `wazuh_mcp/tools/<domain>.py` |
| Prompts / resources | `wazuh_mcp/prompts.py` / `wazuh_mcp/resources.py` |
| Upstream clients | `wazuh_mcp/wazuh_client.py` / `wazuh_mcp/wazuh_indexer.py` |
| Full tool inventory | `docs/TOOL_TABLE.md` (generate with `scripts/generate_tool_table.py`) |
