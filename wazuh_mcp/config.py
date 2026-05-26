"""Centralized configuration loaded from environment variables.

Credentials are resolved via the pluggable secrets backend (H4).
Set WAZUH_SECRET_BACKEND=vault or =aws to fetch from Vault/AWS Secrets Manager.
Falls back to environment variables when no backend is configured.

Wazuh Cloud: set WAZUH_CLOUD=true and only WAZUH_CLOUD_API_KEY + WAZUH_CLOUD_URL.

MSSP multi-instance: set WAZUH_INSTANCES as a JSON array:
    WAZUH_INSTANCES='[{"name":"client-a","host":"https://wazuh-a:55000","user":"u","pass":"p","indexer_host":"https://idx-a:9200","indexer_pass":"p"},...]'
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, field
from .secrets_backend import get_secret


@dataclass(frozen=True)
class TenantConfig:
    """Configuration for a single Wazuh instance (used in MSSP mode)."""
    name: str
    manager_host: str
    manager_user: str
    manager_pass: str
    indexer_host: str
    indexer_user: str
    indexer_pass: str


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

    # Wazuh Cloud mode
    cloud_mode: bool

    # MSSP multi-tenant instances (empty list = single-instance mode)
    tenants: tuple = field(default_factory=tuple)

    def redacted(self) -> dict:
        """Return a safe dict representation for logging — secrets replaced with [REDACTED].

        Use this instead of str(cfg) or vars(cfg) anywhere the output might be
        written to logs, error messages, or the audit trail.
        """
        return {
            "manager_host": self.manager_host,
            "manager_user": self.manager_user,
            "manager_pass": "[REDACTED]",
            "indexer_host": self.indexer_host,
            "indexer_user": self.indexer_user,
            "indexer_pass": "[REDACTED]",
            "alerts_index": self.alerts_index,
            "verify_ssl": self.verify_ssl,
            "allow_writes": self.allow_writes,
            "request_timeout": self.request_timeout,
            "cloud_mode": self.cloud_mode,
            "tenant_count": len(self.tenants),
        }

    @classmethod
    def from_env(cls) -> "Config":
        def required(name: str) -> str:
            # get_secret() checks backend (Vault/AWS) first, then falls back to env
            v = get_secret(name)
            if not v:
                raise RuntimeError(f"Missing required env var: {name}")
            return v

        cloud_mode = os.getenv("WAZUH_CLOUD", "false").lower() == "true"

        if cloud_mode:
            # Wazuh Cloud uses a single API URL + API key mapped to user:pass
            cloud_url = required("WAZUH_CLOUD_URL")
            cloud_key = required("WAZUH_CLOUD_API_KEY")
            # Cloud indexer is co-located — derive from cloud URL hostname
            cloud_indexer = os.getenv(
                "WAZUH_CLOUD_INDEXER_URL",
                cloud_url.replace(":55000", ":9200"),
            )
            manager_host = cloud_url
            manager_user = "wazuh-wui"
            manager_pass = cloud_key
            indexer_host = cloud_indexer
            indexer_user = os.getenv("WAZUH_CLOUD_INDEXER_USER", "admin")
            indexer_pass = get_secret("WAZUH_CLOUD_INDEXER_PASS") or cloud_key
        else:
            manager_host = required("WAZUH_HOST")
            manager_user = required("WAZUH_USER")
            manager_pass = required("WAZUH_PASS")
            indexer_host = required("WAZUH_INDEXER_HOST")
            indexer_user = get_secret("WAZUH_INDEXER_USER", default="wazuh-readonly")
            indexer_pass = required("WAZUH_INDEXER_PASS")

        # MSSP multi-instance parsing
        tenants: tuple = ()
        raw_instances = os.getenv("WAZUH_INSTANCES", "")
        if raw_instances:
            try:
                parsed = json.loads(raw_instances)
                tenants = tuple(
                    TenantConfig(
                        name=inst["name"],
                        manager_host=inst["host"],
                        manager_user=inst.get("user", manager_user),
                        manager_pass=inst.get("pass", manager_pass),
                        indexer_host=inst.get("indexer_host", indexer_host),
                        indexer_user=inst.get("indexer_user", indexer_user),
                        indexer_pass=inst.get("indexer_pass", indexer_pass),
                    )
                    for inst in parsed
                )
            except (json.JSONDecodeError, KeyError) as e:
                raise RuntimeError(f"Invalid WAZUH_INSTANCES JSON: {e}") from e

        return cls(
            manager_host=manager_host,
            manager_user=manager_user,
            manager_pass=manager_pass,
            indexer_host=indexer_host,
            indexer_user=indexer_user,
            indexer_pass=indexer_pass,
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
            cloud_mode=cloud_mode,
            tenants=tenants,
        )
