# Read-Only Mode

Wazuh MCP ships with a **server-wide read-only mode that is on by default**
(`WAZUH_MCP_READ_ONLY=true`). In this mode the server can search, summarise and
report on your Wazuh deployment, but it cannot change anything — on Wazuh or in any
third-party system.

## Why

Per-tool write checks (`WAZUH_ALLOW_WRITES`, role checks) depend on every tool
remembering to call them. Read-only mode adds an enforcement point that does not rely
on individual tools, so a new or mis-written tool cannot modify state.

## How it works

| Layer | What it does | Where |
|---|---|---|
| 1. Transport guard | `httpx` request hooks on the Manager and Indexer clients reject every request that is not a known read, before it leaves the process. | `wazuh_mcp/read_only.py`, `wazuh_client.py`, `wazuh_indexer.py` |
| 2. Tool hiding | Tools that write to Wazuh, to local state, or to external services (Slack, Teams, email, Jira, TheHive, PagerDuty, ServiceNow, Azure DevOps) are **not registered**. | `read_only.WRITE_TOOLS`, `middleware/tool_middleware.py` |
| 3. Write gate | `_require_writes()` always refuses. | `server.py` |

### Requests allowed

| Target | Allowed |
|---|---|
| Manager API | `GET`/`HEAD`/`OPTIONS`; JWT login (`POST /security/user/authenticate`); `PUT /logtest` and `DELETE /logtest/sessions/{id}` (dry-run rule testing) |
| Manager API — blocked reads | `GET /agents/{id}/key` (returns the agent enrolment key) |
| Indexer | `GET`/`HEAD`/`OPTIONS`; `POST` to `_search`, `_count`, `_msearch`, `_mget`, `_validate/query` |
| Everything else | Rejected with `ReadOnlyViolation` |

## Recommended deployment

Defence in depth — do not rely on the MCP server alone:

1. **Wazuh API user** with the built-in `readonly` role (not `wazuh`/`wazuh-wui`).
   `logtest` needs an additional policy if you want rule-testing tools.
2. **Indexer user** mapped to a role with `cluster_composite_ops_ro` and `read` on
   `wazuh-alerts-*`, `wazuh-archives-*`, `wazuh-states-*`, `wazuh-monitoring-*`,
   `wazuh-statistics-*` only.
3. `WAZUH_MCP_READ_ONLY=true`, `WAZUH_ALLOW_WRITES=false`, `WAZUH_MCP_USER_ROLE=viewer`.
4. Keep the HTTP transport bound to loopback, or set `WAZUH_MCP_API_KEY` and TLS.
5. Restrict network access to the Manager (55000) and Indexer (9200) to the host
   running the MCP server.

Example indexer role (OpenSearch Security API):

```json
PUT _plugins/_security/api/roles/mcp_readonly
{
  "cluster_permissions": ["cluster_composite_ops_ro"],
  "index_permissions": [{
    "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*", "wazuh-states-*",
                       "wazuh-monitoring-*", "wazuh-statistics-*"],
    "allowed_actions": ["read", "indices:admin/validate/query*",
                        "indices:admin/mappings/get", "indices:monitor/*"]
  }]
}
```

## Hidden tools

See `WRITE_TOOLS` in [`wazuh_mcp/read_only.py`](../wazuh_mcp/read_only.py) for the
authoritative list (agent restart/upgrade, active response, CDB writes, rule/decoder
push, alert tagging, suppression, notifications, ticketing, autonomous monitor,
playbook execution, schedules, workspaces, API password rotation).

## Leaving read-only mode

Set `WAZUH_MCP_READ_ONLY=false`. Behaviour then reverts to the previous model
(`WAZUH_ALLOW_WRITES`, RBAC role, per-tool dry-run/approval). Review the hidden-tool
list and your Wazuh RBAC before doing so.

## Testing

```bash
pytest tests/test_read_only.py
```

The suite checks allowed/blocked method–path pairs (including encoded traversal),
that uploads are refused, that the client hook fires before any network I/O, and
that no tool in `WRITE_TOOLS` is registered.
