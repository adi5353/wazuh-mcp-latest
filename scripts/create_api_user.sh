#!/usr/bin/env bash
# H12: Create a least-privilege Wazuh API user for the MCP server.
#
# This script creates a dedicated Wazuh Manager API user with the minimum
# permissions required for wazuh-mcp to operate. It uses the Wazuh Manager
# REST API directly.
#
# Usage:
#   export WAZUH_HOST=https://your-wazuh-manager:55000
#   export WAZUH_ADMIN_USER=wazuh           # existing admin credentials
#   export WAZUH_ADMIN_PASS=wazuh
#   export MCP_USER=wazuh-mcp              # new user to create
#   export MCP_PASS=ChangeMe!2025          # password for new user
#   bash scripts/create_api_user.sh
#
# After running:
#   - Set WAZUH_USER=wazuh-mcp and WAZUH_PASS=<chosen password> in .env
#   - Set WAZUH_CRED_CREATED_AT=<current unix timestamp> in .env
#   - Only add WAZUH_ALLOW_WRITES=true if active-response tools are needed

set -euo pipefail

WAZUH_HOST="${WAZUH_HOST:-https://localhost:55000}"
WAZUH_ADMIN_USER="${WAZUH_ADMIN_USER:-wazuh}"
WAZUH_ADMIN_PASS="${WAZUH_ADMIN_PASS:-wazuh}"
MCP_USER="${MCP_USER:-wazuh-mcp}"
MCP_PASS="${MCP_PASS:-ChangeMe\!2025}"

CURL="curl -sk"  # -k allows self-signed certs; remove for production with valid certs

echo "==> Authenticating as ${WAZUH_ADMIN_USER} ..."
TOKEN=$(${CURL} -u "${WAZUH_ADMIN_USER}:${WAZUH_ADMIN_PASS}" \
    -X GET "${WAZUH_HOST}/security/user/authenticate?raw=true")

if [[ -z "${TOKEN}" || "${TOKEN}" == *"error"* ]]; then
    echo "ERROR: Failed to authenticate. Check WAZUH_HOST, WAZUH_ADMIN_USER, WAZUH_ADMIN_PASS."
    exit 1
fi
echo "    Token obtained."

AUTH="-H 'Authorization: Bearer ${TOKEN}'"

# ── 1. Create the MCP user ──────────────────────────────────────────────────
echo "==> Creating user '${MCP_USER}' ..."
CREATE_RESP=$(${CURL} -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -X POST "${WAZUH_HOST}/security/users" \
    -d "{\"username\": \"${MCP_USER}\", \"password\": \"${MCP_PASS}\"}")

echo "    Response: ${CREATE_RESP}"
USER_ID=$(echo "${CREATE_RESP}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('data', {}).get('affected_items', [])
if items: print(items[0]['id'])
" 2>/dev/null || true)

if [[ -z "${USER_ID}" ]]; then
    echo "WARN: Could not parse user ID — user may already exist. Searching..."
    SEARCH_RESP=$(${CURL} -H "Authorization: Bearer ${TOKEN}" \
        -X GET "${WAZUH_HOST}/security/users?pretty=true")
    USER_ID=$(echo "${SEARCH_RESP}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for u in d.get('data', {}).get('affected_items', []):
    if u.get('username') == '${MCP_USER}':
        print(u['id'])
        break
" 2>/dev/null || true)
fi

if [[ -z "${USER_ID}" ]]; then
    echo "ERROR: Could not determine user ID for '${MCP_USER}'. Aborting."
    exit 1
fi
echo "    User ID: ${USER_ID}"

# ── 2. Find or create a least-privilege role ────────────────────────────────
echo "==> Creating 'wazuh-mcp-readonly' role ..."

# Policy: broad read access over agents, rules, SCA, syscollector, syscheck,
#         vulnerability, security, cluster — all with read method.
POLICY_RESP=$(${CURL} -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -X POST "${WAZUH_HOST}/security/policies" \
    -d '{
  "name": "wazuh-mcp-read-policy",
  "policy": {
    "actions": [
      "agent:read", "group:read", "rule:read", "decoder:read",
      "sca:read", "syscheck:read", "syscollector:read",
      "vulnerability:read", "security:read", "cluster:read",
      "ciscat:read", "mitre:read", "lists:read", "event:read",
      "logtest:run"
    ],
    "resources": ["*:*:*"],
    "effect": "allow"
  }
}')
echo "    Policy response: ${POLICY_RESP}"
POLICY_ID=$(echo "${POLICY_RESP}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('data', {}).get('affected_items', [])
if items: print(items[0]['id'])
" 2>/dev/null || true)

if [[ -z "${POLICY_ID}" ]]; then
    echo "WARN: Policy may already exist — fetching existing ID ..."
    POLICY_ID=$(${CURL} -H "Authorization: Bearer ${TOKEN}" \
        -X GET "${WAZUH_HOST}/security/policies" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for p in d.get('data', {}).get('affected_items', []):
    if p.get('name') == 'wazuh-mcp-read-policy':
        print(p['id'])
        break
" 2>/dev/null || true)
fi

echo "    Policy ID: ${POLICY_ID}"

ROLE_RESP=$(${CURL} -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -X POST "${WAZUH_HOST}/security/roles" \
    -d '{"name": "wazuh-mcp-role"}')
echo "    Role response: ${ROLE_RESP}"
ROLE_ID=$(echo "${ROLE_RESP}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('data', {}).get('affected_items', [])
if items: print(items[0]['id'])
" 2>/dev/null || true)

if [[ -z "${ROLE_ID}" ]]; then
    echo "WARN: Role may already exist — fetching existing ID ..."
    ROLE_ID=$(${CURL} -H "Authorization: Bearer ${TOKEN}" \
        -X GET "${WAZUH_HOST}/security/roles" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for r in d.get('data', {}).get('affected_items', []):
    if r.get('name') == 'wazuh-mcp-role':
        print(r['id'])
        break
" 2>/dev/null || true)
fi

echo "    Role ID: ${ROLE_ID}"

# ── 3. Attach policy to role ────────────────────────────────────────────────
echo "==> Attaching policy ${POLICY_ID} to role ${ROLE_ID} ..."
${CURL} -H "Authorization: Bearer ${TOKEN}" \
    -X POST "${WAZUH_HOST}/security/roles/${ROLE_ID}/policies?policy_ids=${POLICY_ID}" \
    -o /dev/null
echo "    Done."

# ── 4. Optionally add write policy (only if WAZUH_ALLOW_WRITES=true) ────────
if [[ "${WAZUH_ALLOW_WRITES:-false}" == "true" ]]; then
    echo "==> WAZUH_ALLOW_WRITES=true — adding write/active-response policy ..."
    WRITE_POLICY_RESP=$(${CURL} -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -X POST "${WAZUH_HOST}/security/policies" \
        -d '{
      "name": "wazuh-mcp-write-policy",
      "policy": {
        "actions": [
          "active-response:command",
          "agent:modify_group", "group:modify_assignments",
          "lists:write", "security:edit_run_as"
        ],
        "resources": ["*:*:*"],
        "effect": "allow"
      }
    }')
    WRITE_POLICY_ID=$(echo "${WRITE_POLICY_RESP}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('data', {}).get('affected_items', [])
if items: print(items[0]['id'])
" 2>/dev/null || true)
    if [[ -n "${WRITE_POLICY_ID}" ]]; then
        ${CURL} -H "Authorization: Bearer ${TOKEN}" \
            -X POST "${WAZUH_HOST}/security/roles/${ROLE_ID}/policies?policy_ids=${WRITE_POLICY_ID}" \
            -o /dev/null
        echo "    Write policy ${WRITE_POLICY_ID} attached."
    fi
fi

# ── 5. Assign role to user ──────────────────────────────────────────────────
echo "==> Assigning role ${ROLE_ID} to user ${USER_ID} ..."
${CURL} -H "Authorization: Bearer ${TOKEN}" \
    -X POST "${WAZUH_HOST}/security/users/${USER_ID}/roles?role_ids=${ROLE_ID}" \
    -o /dev/null
echo "    Done."

# ── 6. Print .env snippet ───────────────────────────────────────────────────
TS=$(python3 -c "import time; print(int(time.time()))")
echo ""
echo "========================================================"
echo "SUCCESS! Add these lines to your .env file:"
echo "========================================================"
echo "WAZUH_USER=${MCP_USER}"
echo "WAZUH_PASS=${MCP_PASS}"
echo "WAZUH_CRED_CREATED_AT=${TS}"
echo "========================================================"
echo ""
echo "To check credential age later, call: get_credential_age"
echo "To rotate the password later, call:  rotate_wazuh_api_password"
