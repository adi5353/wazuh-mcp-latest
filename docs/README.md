# Wazuh MCP — Documentation Index

Product, technical, and testing documentation for the Wazuh MCP server.

## Core documents

| Doc | What it covers |
|---|---|
| [PRD.md](./PRD.md) | **Product Requirements** — vision, personas, user stories, functional & non-functional requirements, success metrics, risks |
| [TRD.md](./TRD.md) | **Technical Requirements** — architecture, components, middleware/RBAC, data flows, deployment topologies, interfaces, quality gates |
| [TOOL_FLOW.md](./TOOL_FLOW.md) | **Tool flow** — request lifecycle, registration, tool groups/contexts, RBAC gating, and end-to-end flow diagrams for each SOC workflow |
| [LLM_TESTING_GUIDE.md](./LLM_TESTING_GUIDE.md) | **How to test everything from your LLM interface** — natural-language prompts per capability/integration (Jira, threat intel, SOAR, compliance, …) with what to expect |

## Reference & operations

| Doc | What it covers |
|---|---|
| [TOOL_TABLE.md](./TOOL_TABLE.md) | Generated inventory of all tools (run `scripts/generate_tool_table.py` to refresh) |
| [testing-guide.md](./testing-guide.md) | Container/curl/pytest-level verification (auth, 413, RBAC internals, schema parsing, container hardening) |
| [open-webui-integration.md](./open-webui-integration.md) | Connecting Open WebUI (+ Ollama, air-gapped) |
| [production-readiness.md](./production-readiness.md) | The definition of "done" / production checklist |

## Suggested reading order

1. **PRD** — what the product is and why.
2. **TRD** — how it's built.
3. **TOOL_FLOW** — how a request actually moves through it.
4. **LLM_TESTING_GUIDE** — drive it from your chat client and verify each piece.
