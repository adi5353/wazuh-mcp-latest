# Open WebUI Integration — F12-doc

Connect Open WebUI v0.6.31+ to Wazuh MCP Server for a browser-based SOC
dashboard without requiring Claude Desktop.

---

## Prerequisites

- Open WebUI ≥ 0.6.31
- Wazuh MCP Server running (this project)
- API key configured (`WAZUH_MCP_API_KEY` env var)

---

## Quick Setup

### 1. Native MCP Connection (Open WebUI 0.6.31+)

Open WebUI natively supports MCP tool servers via SSE. No plugin required.

1. Open **Settings → Tools → Add Tool Server**
2. Fill in:
   - **URL:** `http://localhost:8000/sse`
   - **API Key:** your `WAZUH_MCP_API_KEY` value
   - **Name:** `Wazuh SOC`
3. Click **Connect** — all 100+ Wazuh tools appear automatically

### 2. Docker Compose (Air-Gapped with Ollama)

Use the bundled compose file for a fully local deployment:

```bash
docker compose -f docker-compose.ollama.yaml up -d
docker exec ollama ollama pull llama3.1:8b
open http://localhost:3000
```

Open WebUI will be pre-configured to:
- Use Ollama (llama3.1:8b) as the LLM
- Connect to wazuh-mcp as the MCP tool server

---

## Tool Response Formats for Rich UI

Wazuh MCP tools return structured dicts that Open WebUI renders inline.
To get richer visualizations, ask Claude/Ollama to format output as:

### Network Topology (Mermaid)

Ask: *"Show the network topology as a Mermaid diagram"*

The LLM will convert `get_network_topology` output to:

```
graph TD
    subgraph 192.168.1.0/24
        A[web1\n192.168.1.10] -->|:443| B[web2\n192.168.1.11]
    end
    subgraph 10.0.1.0/24
        C[db1\n10.0.1.5]
    end
    A --> C
```

Open WebUI renders Mermaid diagrams natively.

### Alert Timeline (Plotly-style prompt hint)

Ask: *"Plot alert volume over the last 24 hours as a time series"*

Tools: `compare_alert_volume` → LLM generates Plotly JSON or markdown table.

### SCA Compliance Heatmap

Ask: *"Show SCA compliance as a heatmap across agents"*

Tools: `fleet_sca_weakest_agents` → LLM generates ASCII heatmap or markdown table.

---

## Recommended System Prompt for SOC Use

Add this to Open WebUI's **System Prompt** field:

```
You are a SOC analyst assistant with access to Wazuh SIEM tools.
When presenting security data:
- Use Mermaid diagrams for network topology and attack paths
- Use markdown tables for agent lists and alert summaries
- Highlight CRITICAL findings with ⚠️ and HIGH with 🔶
- Always include remediation steps with each finding
- For CVEs, include CVSS score and affected agent count
- Limit alert lists to the 10 most severe unless asked for more
```

---

## Performance Tips for Small Models (llama3.2:3b)

When using compact local models, all tool descriptions are automatically
trimmed to ≤ 100 words by the server. Additional tips:

- Ask one question at a time (small context window)
- Use specific agent IDs rather than "all agents"
- Prefer aggregation tools (`alert_summary`) over raw search (`search_alerts`)
- Time ranges: use `24h` not `today` (models parse ISO better)

---

## API Reference

The MCP server also exposes an OpenAI-compatible endpoint:

```
POST http://localhost:8000/openai/v1/chat/completions
Authorization: Bearer YOUR_API_KEY
```

This allows any OpenAI-compatible client (LiteLLM, Open WebUI, etc.) to
route through wazuh-mcp and have tools automatically injected.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| "Connection refused" | Check `WAZUH_MCP_API_KEY` matches in both server and Open WebUI |
| Tools not appearing | Verify SSE endpoint: `curl -H "X-API-Key: KEY" http://localhost:8000/sse` |
| Slow responses | Switch from `llama3.1:8b` to `llama3.2:3b` for faster inference |
| Tool call errors | Check `docker logs wazuh-mcp` for RBAC or validation errors |
