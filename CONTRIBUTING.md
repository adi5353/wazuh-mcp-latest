# Contributing to Wazuh MCP

Thank you for helping improve this project. This guide covers everything you need to add a new tool, fix a bug, or improve existing functionality.

---

## Quick start

```bash
git clone https://github.com/adi5353/wazuh-mcp-latest.git
cd wazuh-mcp-latest
pip install -e ".[dev]"
pre-commit install       # installs ruff, bandit, detect-secrets hooks
cp env.example .env      # fill in your Wazuh credentials
```

Run the test suite:
```bash
make test
```

---

## Adding a new tool

### 1. Choose the right module

Tools live in `wazuh_mcp/tools/`. Pick the module that matches the domain:

| Module | Domain |
|---|---|
| `alerts.py` | Alert search and triage |
| `agents.py` | Agent management |
| `vulnerabilities.py` | CVE / patch management |
| `compliance.py` | PCI-DSS, NIST, SOC 2 |
| `threat_hunting.py` | Hunt workflows |
| `incidents.py` | Incident creation and tagging |
| `integrations.py` | Jira, Slack, TheHive, etc. |

If your tool doesn't fit an existing module, create `wazuh_mcp/tools/<domain>.py` and register it in `server.py`.

### 2. Write the tool function

```python
# wazuh_mcp/tools/alerts.py

def register(mcp, wz, idx, cfg, _cap, _enrich_mitre_ids):

    @mcp.tool()
    async def my_new_tool(param: str, limit: int = 10) -> dict:
        """One-line description shown to the LLM.

        Longer explanation of what this tool does and when to use it.

        Args:
            param:  Description of param.
            limit:  Maximum results to return (default 10, max 500).
        """
        from ..rbac import require_role, ROLE
        err = require_role(ROLE.ANALYST)   # set the minimum required role
        if err:
            return err

        # ... implementation
        return {"results": [...]}
```

### 3. RBAC annotation

Every tool **must** call `require_role()` as its first line:

| Minimum role | Use for |
|---|---|
| `ROLE.VIEWER` | Read-only summaries and listings |
| `ROLE.ANALYST` | Enrichment, hunt, compliance, rule management |
| `ROLE.RESPONDER` | Active response, CDB writes, alert suppression |
| `ROLE.ADMIN` | Cluster management, agent restart, rule push |

### 4. Register in `server.py`

If you created a new module:
```python
# server.py — add the import
from .tools import my_domain as _my_domain_module

# ... then register it
_my_domain_module.register(mcp, wz, idx, cfg, _cap)
```

### 5. Write tests

Create or extend a test file in `tests/`. Name it after the feature area:

```python
# tests/test_my_domain.py

import pytest
from unittest.mock import AsyncMock, MagicMock

class TestMyNewTool:
    def _register(self):
        from wazuh_mcp.tools import my_domain
        mcp = MagicMock()
        reg = {}
        mcp.tool = lambda **kw: (lambda fn: reg.setdefault(fn.__name__, fn) or fn)
        wz = AsyncMock(); idx = AsyncMock(); cfg = MagicMock()
        my_domain.register(mcp, wz, idx, cfg, lambda n: min(n, 500))
        return reg

    @pytest.mark.asyncio
    async def test_my_new_tool_returns_results(self):
        reg = self._register()
        reg["wz"].request = AsyncMock(return_value={"data": {"items": []}})
        result = await reg["my_new_tool"](param="test")
        assert "results" in result
```

---

## Running checks locally

```bash
make lint        # ruff + mypy
make test        # pytest with coverage
make test-cov    # pytest + open HTML coverage report
make security    # bandit + pip-audit
make docker      # build + start with docker compose
```

---

## Pull request checklist

- [ ] Tool has a `require_role()` guard
- [ ] Tool has a docstring (one-line summary + Args section)
- [ ] Test added or extended — `make test` passes
- [ ] Tests assert real behaviour (outputs/side-effects), **not** just `isinstance(x, dict)`. Breadth-only checks against mocks belong under the `smoke` marker and must not count toward coverage.
- [ ] `make lint` passes without new errors
- [ ] `make security` passes (no new bandit findings above medium)
- [ ] Entry added to `CHANGELOG.md` under `[Unreleased]`

For anything headed toward release, work against the
[Production Readiness checklist](docs/production-readiness.md) — the project's
definition of "done". Do not lower a quality gate to make CI pass; gates ratchet up.

---

## Commit message format

```
<type>(<scope>): <short description>

<body — optional, explains WHY not WHAT>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `perf`

Examples:
```
feat(alerts): add alert_timeline tool for chronological event view
fix(geo): switch GeoIP fallback to HTTPS endpoint
refactor(server): extract MITRE map to mitre_data.py
```

---

## Project structure

```
wazuh_mcp/
├── server.py          # bootstrap: FastMCP init, middleware, module registration
├── config.py          # Config dataclass loaded from env
├── wazuh_client.py    # Wazuh Manager REST client (JWT, retry, connection pool)
├── wazuh_indexer.py   # OpenSearch / Wazuh Indexer client
├── mitre_data.py      # MITRE ATT&CK technique map + enrichment helpers
├── geo.py             # GeoIP lookup (ipinfo.io + ip-api.com fallback)
├── triage.py          # Incident recommendation engine
├── middleware/        # ToolMiddleware (sanitization + registry)
├── rbac.py            # Role tiers and require_role() guard
├── identity.py        # Per-session role binding via contextvars
├── audit.py           # Audit trail (rotating JSONL, HMAC signing)
├── tools/             # 40+ domain-specific tool modules
└── core/              # ROI tracker, state store
```
