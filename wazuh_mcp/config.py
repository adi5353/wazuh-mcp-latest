"""Centralized configuration loaded from environment variables.

Credentials are resolved via the pluggable secrets backend (H4).
Set WAZUH_SECRET_BACKEND=vault or =aws to fetch from Vault/AWS Secrets Manager.
Falls back to environment variables when no backend is configured.
"""
from __future__ import annotations
import os
from dataclasses import dataclass
from .secrets_backend import get_secret


@dataclass(frozen=True)
class Config:
    # Wazuh Manager API
    manager_host: str
    manager_user: str
    manager_pass: str

    # Wazuh Indexer (OpenSearch)
    indexer_host: str
    indexer_user: str
    indexer_pass: str
    alerts_index: str
    vuln_index: str
    inventory_packages_index: str
    inventory_processes_index: str
    inventory_ports_index: str

    # Operational
    verify_ssl: bool
    ca_bundle: str | None       # path to custom CA cert bundle (PEM)
    allow_writes: bool
    request_timeout: int

    @classmethod
    def from_env(cls) -> "Config":
        def required(name: str) -> str:
            # get_secret() checks backend (Vault/AWS) first, then falls back to env
            v = get_secret(name)
            if not v:
                raise RuntimeError(f"Missing required env var: {name}")
            return v

        return cls(
            manager_host=required("WAZUH_HOST"),
            manager_user=required("WAZUH_USER"),
            manager_pass=required("WAZUH_PASS"),
            indexer_host=required("WAZUH_INDEXER_HOST"),
            indexer_user=get_secret("WAZUH_INDEXER_USER", default="wazuh-readonly"),
            indexer_pass=required("WAZUH_INDEXER_PASS"),
            alerts_index=os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*"),
            vuln_index=os.getenv("WAZUH_VULN_INDEX", "wazuh-states-vulnerabilities-*"),
            inventory_packages_index=os.getenv(
                "WAZUH_INV_PACKAGES_INDEX", "wazuh-states-inventory-packages-*"
            ),
            inventory_processes_index=os.getenv(
                "WAZUH_INV_PROCESSES_INDEX", "wazuh-states-inventory-processes-*"
            ),
            inventory_ports_index=os.getenv(
                "WAZUH_INV_PORTS_INDEX", "wazuh-states-inventory-ports-*"
            ),
            verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "true").lower() == "true",
            ca_bundle=os.getenv("WAZUH_CA_BUNDLE") or None,
            allow_writes=os.getenv("WAZUH_ALLOW_WRITES", "false").lower() == "true",
            request_timeout=int(os.getenv("WAZUH_REQUEST_TIMEOUT", "30")),
        )
