#!/bin/bash
# Wazuh Agent entrypoint — enroll and start the agent.
#
# Environment variables (set in docker-compose.yml):
#   WAZUH_MANAGER      — hostname/IP of the Wazuh manager (required)
#   WAZUH_AGENT_NAME   — friendly name shown in the Wazuh dashboard
#   WAZUH_AGENT_GROUP  — agent group (optional, default: default)

set -e

MANAGER="${WAZUH_MANAGER:-wazuh-manager}"
AGENT_NAME="${WAZUH_AGENT_NAME:-demo-agent}"
AGENT_GROUP="${WAZUH_AGENT_GROUP:-default}"
ENROLL_PORT="${WAZUH_ENROLL_PORT:-1515}"

echo "[entrypoint] Waiting for manager ${MANAGER}:${ENROLL_PORT} to accept enrollments…"
for i in $(seq 1 60); do
    if timeout 3 bash -c "echo > /dev/tcp/${MANAGER}/${ENROLL_PORT}" 2>/dev/null; then
        echo "[entrypoint] Manager is reachable."
        break
    fi
    echo "[entrypoint] Attempt ${i}/60 — not ready yet, retrying in 5s…"
    sleep 5
done

# Write ossec.conf pointing at the manager
cat > /var/ossec/etc/ossec.conf <<EOF
<ossec_config>
  <client>
    <server>
      <address>${MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
EOF

echo "[entrypoint] Enrolling agent '${AGENT_NAME}' (group: ${AGENT_GROUP}) with manager ${MANAGER}…"
/var/ossec/bin/agent-auth \
    -m "${MANAGER}" \
    -p "${ENROLL_PORT}" \
    -A "${AGENT_NAME}" \
    -G "${AGENT_GROUP}" \
    2>&1 || true   # non-fatal if already enrolled

echo "[entrypoint] Starting Wazuh agent…"
exec /var/ossec/bin/wazuh-agentd -f
