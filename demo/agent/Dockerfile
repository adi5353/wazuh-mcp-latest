FROM ubuntu:22.04

ARG WAZUH_VERSION=4.14.5

# Prevent interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg2 \
        ca-certificates \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Add Wazuh GPG key and repository
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list

# Install Wazuh agent (WAZUH_MANAGER placeholder; real value set at runtime)
RUN apt-get update && \
    WAZUH_MANAGER=localhost apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
