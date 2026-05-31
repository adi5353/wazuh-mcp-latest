# Product Requirements Document (PRD) — Wazuh MCP Server

| | |
|---|---|
| **Product** | Wazuh MCP — AI-Powered Security Operations |
| **Document type** | Product Requirements Document |
| **Status** | Living document |
| **Owner** | Platform / SOC engineering |
| **Related docs** | [TRD](./TRD.md) · [Tool Flow](./TOOL_FLOW.md) · [LLM Testing Guide](./LLM_TESTING_GUIDE.md) · [Tool Table](./TOOL_TABLE.md) |

---

## 1. Overview

Wazuh MCP is a **Model Context Protocol (MCP) server** that exposes the
capabilities of a Wazuh SIEM/XDR deployment (Manager API + Indexer/OpenSearch)
as natural-language **tools, prompts, and resources** consumable by any
MCP-compatible LLM client — Claude Desktop, Open WebUI + Ollama, and others.

It lets a security analyst *talk* to their SIEM: "summarize the last 24 hours of
alerts", "hunt for lateral movement", "open a Jira ticket for this incident",
"is this IP malicious?" — and the LLM orchestrates the right Wazuh and
third-party API calls behind the scenes.

The product ships **~239 tools across ~54 domain modules**, plus MCP prompts
(guided workflows) and MCP resources (live read-only context), wrapped in a
production-grade security, RBAC, audit, and observability envelope.

## 2. Problem statement

Wazuh is powerful but operationally heavy:

- Analysts must know OpenSearch DSL, the Wazuh REST API surface, and rule/decoder
  internals to get answers quickly.
- Triage, enrichment, correlation, and ticketing live in **separate tools**
  (SIEM, threat-intel portals, SOAR, chat) forcing constant context switching.
- Junior analysts ramp slowly; senior analysts spend time on repetitive lookups.
- Reporting (compliance, exec summaries, shift handovers) is manual and
  inconsistent.

LLMs can bridge this gap — but only if they are given **safe, structured,
auditable access** to the SIEM and surrounding tooling. That access layer is
this product.

## 3. Goals and non-goals

### Goals
- **G1 — Natural-language SecOps.** Let analysts run investigations, hunts,
  triage, and reporting through conversation instead of dashboards/queries.
- **G2 — Single pane via the LLM.** Unify Wazuh data with threat intel (VirusTotal,
  AbuseIPDB, etc.) and SOAR/ticketing (Jira, TheHive, ServiceNow, PagerDuty,
  Azure DevOps) so the LLM is the single orchestration point.
- **G3 — Safe by default.** Read-only by default; destructive actions require an
  elevated role, dry-run previews, and/or explicit approval.
- **G4 — Auditable & observable.** Every tool call is authenticated, rate-limited,
  audited (tamper-evident), and measured (Prometheus metrics).
- **G5 — Deployable anywhere.** Docker, systemd, and fully air-gapped
  (Ollama + Open WebUI) deployments; Wazuh Cloud and on-prem; single-tenant and
  MSSP multi-tenant.
- **G6 — Force-multiply analysts.** Autonomous monitoring, playbooks, baselining,
  and UEBA reduce manual toil and surface what matters.

### Non-goals
- **NG1** — Not a replacement for the Wazuh dashboard or detection engine; it
  *orchestrates* Wazuh, it does not re-implement it.
- **NG2** — Not a hosted LLM. The customer brings their own MCP client/model
  (Claude, Ollama, etc.).
- **NG3** — Not a data lake. It queries Wazuh's indexer live; it does not store a
  parallel copy of alert data (only small state: schedules, baselines, workspaces).
- **NG4** — Not an offensive-security tool.

## 4. Target users & personas

| Persona | Role tier | Primary jobs-to-be-done |
|---|---|---|
| **SOC Analyst (Tier 1/2)** | `analyst` | Triage alerts, enrich IOCs, hunt, open tickets, daily summaries |
| **Incident Responder (Tier 3)** | `responder` | Active response, blocklist IPs, suppress noisy rules, run playbooks |
| **SOC Manager / Lead** | `analyst`/`admin` | Shift handovers, weekly briefings, fleet health, ROI reporting |
| **CISO / Executive** | `viewer`/`analyst` | Exec summaries, compliance posture, risk narrative |
| **Compliance Officer** | `analyst` | PCI-DSS, HIPAA, NIST CSF, ISO 27001, SOC 2 reports & drift |
| **SOC Engineer / Admin** | `admin` | Rule/decoder authoring, agent fleet ops, autonomous monitor, server ops |
| **MSSP Operator** | `admin` | Multi-tenant switching, per-client scoping |

## 5. User stories (representative)

- *As an analyst*, I ask "what happened in the last 24h?" and get an aggregated
  summary with trends and MITRE mapping, without writing a query.
- *As an analyst*, I paste a suspicious IP/hash/domain/URL/email and get a
  reputation verdict enriched from VirusTotal/AbuseIPDB and correlated against my
  live alerts.
- *As a responder*, I say "block this C2 IP" and the server previews the CDB-list
  change (dry-run) before I approve the write.
- *As a responder*, I run an "isolate compromised host" playbook with a dry-run
  preview and approval gate before any destructive step executes.
- *As a manager*, I generate a shift handover or weekly summary and push it to
  Slack/Teams in one sentence.
- *As a compliance officer*, I produce a PCI-DSS v4.0 readiness report and a drift
  comparison against last month's baseline.
- *As an admin*, I author a detection rule from a Sigma rule, validate it against
  archive logs, and push it — with rollback available.
- *As an MSSP operator*, I switch tenant context and run the same workflows scoped
  to one client.

## 6. Functional requirements (capability areas)

The product groups its ~239 tools into capability domains. Each is a functional
requirement set; full per-tool detail is in [TOOL_TABLE.md](./TOOL_TABLE.md).

| # | Capability domain | What it does |
|---|---|---|
| FR-1 | **Alerts & investigation** | Summaries, search (DSL/NL), timelines, by-MITRE/IP/auth-failure, explain-alert |
| FR-2 | **Vulnerabilities & CVE** | Vuln summaries, CVE search, EPSS/KEV prioritization, CVE watchlist + SLA |
| FR-3 | **Threat intelligence** | IP/hash/domain/URL/email enrichment, bulk IOC, IOC↔alert matching, geo/ASN |
| FR-4 | **Threat hunting & correlation** | Lateral movement, persistence, exfiltration hunts; attack-chain correlation |
| FR-5 | **UEBA & baselining** | User activity profiles, anomaly/peer-group detection, agent behavioral baselines |
| FR-6 | **Active response** | Propose/approve/deny responses, run AR, CDB blocklists (dry-run), suppression |
| FR-7 | **Compliance & reporting** | PCI-DSS, HIPAA, NIST CSF 2.0, ISO 27001, SOC 2, drift; weekly/exec/handover reports; CSV/JSON/NDJSON/HTML export |
| FR-8 | **Fleet & system health** | Agent health scoring, syscollector inventory, FIM, SCA, rootcheck, upgrades, cluster health |
| FR-9 | **Rules & decoders** | Search/inspect, test logs, decoder testing, rule/decoder push + rollback, Sigma pipeline |
| FR-10 | **Incidents & SOAR** | Incident reports, blast radius, multi-agent correlation; Jira, TheHive, ServiceNow, PagerDuty, Azure DevOps tickets |
| FR-11 | **Notifications** | Slack & Microsoft Teams alerts/summaries/handovers; email reports |
| FR-12 | **Autonomous SOC** | Background monitor, auto-ticketing, scheduled reports, auto-suppression with approval |
| FR-13 | **Network topology** | Subnet mapping, neighbor discovery, exposure mapping |
| FR-14 | **Onboarding & ops** | Enrollment commands, never-connected agents, server metrics, credential rotation, audit-log integrity |
| FR-15 | **Workspaces & playbooks** | Investigation workspaces, automated playbooks (dry-run + approval), CVE watchlist |
| FR-16 | **MSSP multi-tenant** | List/switch tenants; per-tenant scoping of all of the above |
| FR-17 | **Guided prompts** | MCP prompts: morning briefing, incident triage, shift handover, CISO briefing, compliance review, onboarding, etc. |
| FR-18 | **MCP resources** | Live read-only context: agents, MITRE techniques, rules summary, health |

## 7. Non-functional requirements

| # | Requirement | Target |
|---|---|---|
| NFR-1 **Security** | Auth, RBAC, input sanitization, response redaction, prompt-injection defense | API-key bearer auth on non-loopback; 4-tier RBAC; secrets never logged |
| NFR-2 **Safety** | Destructive ops gated | `dry_run` default on writes; approval workflow; role gating |
| NFR-3 **Auditability** | Tamper-evident audit log | HMAC-SHA256 signed `audit.jsonl`, rotation, integrity verify tool |
| NFR-4 **Observability** | Metrics & health | `/health` (no info leak) + `/metrics` (Prometheus); per-tool latency p50/p95/p99 |
| NFR-5 **Reliability** | Resilient upstream calls | Connection pooling, retries w/ exponential backoff, circuit breakers, per-tool failure breaker |
| NFR-6 **Performance** | Bounded payloads | Global max-results cap, response size cap, token-budget trimming, cursor pagination |
| NFR-7 **Portability** | Multiple deployments | Docker, systemd, air-gapped Ollama; Wazuh Cloud + on-prem |
| NFR-8 **Quality** | Tested | ~248 automated tests, CI (ruff, mypy, bandit, pip-audit) across Py 3.10–3.12, 70% coverage gate |
| NFR-9 **Privacy/Tenancy** | Isolation | MSSP per-tenant routing; group-scoped queries |
| NFR-10 **Hardening** | Container | Non-root user, read-only FS, dropped capabilities, no-new-privileges |

## 8. Deployment & integration surface

- **MCP transports:** `stdio` (local Claude Desktop) and `http`/SSE (Docker/remote).
- **LLM clients:** Claude Desktop (via `mcp-remote` or stdio), Open WebUI (v0.6.31+), any MCP client.
- **Wazuh:** On-prem Manager API + Indexer, or Wazuh Cloud.
- **Optional third-party integrations** (enabled via env vars):
  threat intel (VirusTotal, AbuseIPDB, ipinfo, HIBP/Hunter), SOAR/ticketing
  (Jira, TheHive, ServiceNow, PagerDuty, Azure DevOps), chat (Slack, Teams),
  email (SMTP), secrets (Vault).

## 9. Success metrics

- **Adoption:** # active analyst sessions/week; # tools invoked/session.
- **Efficiency:** Mean time-to-triage and time-to-enrich reduction; ROI report
  (the built-in `generate_roi_report` quantifies analyst-time saved).
- **Coverage:** MITRE technique coverage %; compliance readiness scores trending up.
- **Safety:** Zero unauthenticated tool calls in audit log; 100% of writes pass
  through dry-run/approval/role gates.
- **Reliability:** p95 tool latency within budget; error rate < target; clean
  graceful shutdowns.

## 10. Release phases (delivered)

The product evolved through documented phases (see [CHANGELOG.md](../CHANGELOG.md)
and README "What's New"): foundation hardening (CI, pooling, audit rotation) →
correlation/Sigma/IOC enrichment → quick-wins depth & persistence → compliance
breadth (PCI v4, HIPAA, NIST CSF 2.0, SOC 2, drift) → autonomous SOC, UEBA,
baselining, MSSP multi-tenant. A
[production-readiness checklist](./production-readiness.md) defines "done".

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| LLM triggers a destructive action | Role gating + `dry_run` default + approval workflow |
| Prompt injection via alert/log content | Response sanitization strips injection tokens; secrets redaction |
| Credential/secret leakage | Secrets backend, log redaction, `/health` info-leak prevention |
| Upstream Wazuh/API outage | Retries, circuit breakers, failure breaker, graceful errors |
| Large responses exhaust LLM context | Token-budget trimming, global caps, cursor pagination |
| Multi-tenant data bleed | Per-identity tenant routing + group-scoped queries |
