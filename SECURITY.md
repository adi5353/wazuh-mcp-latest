# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x (latest) | Yes — receives security patches |
| < 1.0 | No |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

**Email:** adi.sharma5353@gmail.com

Include in your report:
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept if possible)
- Affected component (tool name, module, endpoint)
- Suggested remediation if you have one

**Response SLA:**
- Acknowledgement within 48 hours
- Assessment and severity rating within 7 days
- Fix or mitigation plan within 30 days for critical/high findings

## Security Model

### Authentication
- API-key bearer token via `WAZUH_MCP_API_KEY` (HTTP transport)
- Per-session RBAC via `WAZUH_MCP_KEY_MAP` (multi-user deployments)

### Authorization
Four-tier RBAC: `viewer` < `analyst` < `responder` < `admin`. Every tool declares its minimum required role and rejects calls from lower-tier sessions.

### Input validation
All tool inputs are sanitized for prompt injection patterns, length limits, and dangerous characters before execution. After 3 injection attempts a session is downgraded to `viewer`.

### Output sanitization
All tool outputs are scanned for prompt injection tokens, plaintext secrets, PII (emails, SSNs, credit card numbers), and executable code patterns before being returned to the LLM client.

### Audit trail
Every tool invocation is written to `logs/audit.jsonl` (rotating, configurable via `WAZUH_AUDIT_MAX_BYTES`). Optional HMAC-SHA256 signing via `WAZUH_AUDIT_LOG_SIGNING_KEY` for tamper detection.

### Network security
- TLS support via `WAZUH_MCP_TLS_CERT` / `WAZUH_MCP_TLS_KEY` (mTLS supported)
- IP allowlist/blocklist via `WAZUH_MCP_ALLOWED_IPS` / `WAZUH_MCP_BLOCKED_IPS`
- Origin validation (CSRF) via `WAZUH_MCP_ALLOWED_ORIGINS`
- Rate limiting: 60 RPM per identity (configurable via `WAZUH_MCP_RATE_LIMIT_RPM`)
- Security headers: `Content-Security-Policy`, `X-Frame-Options`, `HSTS`, `Referrer-Policy`

### Secret management
Passwords and tokens are never logged. `Config.redacted()` produces a safe representation for audit output. JWT tokens are cleared from memory on expiry. Pluggable secrets backend supports HashiCorp Vault and AWS Secrets Manager via `WAZUH_SECRET_BACKEND`.

## Dependency Security

Dependencies are scanned on every CI run:
- `pip-audit` for known CVEs
- `bandit` for SAST findings
- `detect-secrets` pre-commit hook for accidental secret commits
- `semgrep` with OWASP Top 10 rules
