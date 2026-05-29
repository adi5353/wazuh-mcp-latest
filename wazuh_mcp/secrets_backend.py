"""H4: Pluggable secrets backend for wazuh-mcp.

Supports three modes selected by WAZUH_SECRET_BACKEND env var:
  - "" / unset  → plain environment variables (default, no extra deps)
  - "vault"     → HashiCorp Vault KV v2  (requires: pip install hvac)
  - "aws"       → AWS Secrets Manager    (requires: pip install boto3)

All backends fall back to environment variables on error so the server
continues to work even if the secret store is temporarily unavailable.

Usage in config.py::

    from .secrets_backend import get_secret

    manager_pass: str = field(
        default_factory=lambda: get_secret("WAZUH_PASS", default="wazuh")
    )

Environment variables for Vault:
    VAULT_ADDR          — e.g. https://vault.internal:8200
    VAULT_TOKEN         — root or AppRole token
    VAULT_SECRET_PATH   — KV v2 path, e.g. "secret/wazuh-mcp"
    VAULT_MOUNT_POINT   — KV mount point (default "secret")

Environment variables for AWS Secrets Manager:
    AWS_SECRET_NAME     — secret name or ARN, e.g. "wazuh-mcp/secrets"
    AWS_REGION          — AWS region, e.g. "us-east-1"
    (credentials via standard AWS env or IAM role)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

log = logging.getLogger("wazuh-mcp")

# ── Backend cache: loaded once at import time (or per reload in tests) ────────

_backend: str = (os.getenv("WAZUH_SECRET_BACKEND") or "").strip().lower()
_cache: dict[str, str] = {}
_loaded: bool = False


def _load_vault() -> dict[str, str]:
    """Fetch all key-value pairs from Vault KV v2."""
    try:
        import hvac  # type: ignore
    except ImportError:
        log.error("secrets_backend: 'vault' selected but hvac is not installed. "
                  "Run: pip install hvac")
        return {}
    try:
        addr = os.environ["VAULT_ADDR"]
        token = os.environ["VAULT_TOKEN"]
        path = os.environ.get("VAULT_SECRET_PATH", "secret/wazuh-mcp")
        mount = os.environ.get("VAULT_MOUNT_POINT", "secret")
        client = hvac.Client(url=addr, token=token)
        resp = client.secrets.kv.v2.read_secret_version(
            path=path.lstrip(f"{mount}/"),
            mount_point=mount,
        )
        data: dict = resp["data"]["data"]
        log.info("secrets_backend: loaded %d secrets from Vault path '%s'", len(data), path)
        return {str(k): str(v) for k, v in data.items()}
    except Exception as exc:
        log.warning("secrets_backend: Vault load failed (%s) — falling back to env vars", exc)
        return {}


def _load_aws() -> dict[str, str]:
    """Fetch all key-value pairs from AWS Secrets Manager (JSON SecretString)."""
    try:
        import boto3  # type: ignore
    except ImportError:
        log.error("secrets_backend: 'aws' selected but boto3 is not installed. "
                  "Run: pip install boto3")
        return {}
    try:
        secret_name = os.environ["AWS_SECRET_NAME"]
        region = os.environ.get("AWS_REGION", "us-east-1")
        client = boto3.client("secretsmanager", region_name=region)
        resp = client.get_secret_value(SecretId=secret_name)
        data: dict = json.loads(resp["SecretString"])
        # Log only the count and secret name — never the secret values themselves.
        secret_count = len(data)
        log.info("secrets_backend: loaded %d secrets from AWS ('%s')", secret_count, secret_name)
        return {str(k): str(v) for k, v in data.items()}
    except Exception as exc:
        log.warning("secrets_backend: AWS Secrets Manager load failed (%s) — falling back to env vars", exc)
        return {}


def _ensure_loaded() -> None:
    global _backend, _cache, _loaded
    # Re-read backend setting to support test reloads via importlib.reload()
    current_backend = (os.getenv("WAZUH_SECRET_BACKEND") or "").strip().lower()
    if _loaded and current_backend == _backend:
        return
    # Backend changed (or first load) — reset
    _backend = current_backend
    _cache = {}
    _loaded = False
    if _backend == "vault":
        _cache = _load_vault()
    elif _backend == "aws":
        _cache = _load_aws()
    elif _backend:
        log.warning("secrets_backend: unknown backend '%s' — falling back to env vars", _backend)
    _loaded = True


def get_secret(key: str, default: Any = None) -> Any:
    """Return the secret value for *key*.

    Lookup order:
      1. Secret store cache (Vault / AWS), if a backend is configured
      2. Environment variable
      3. *default*
    """
    _ensure_loaded()
    if _cache and key in _cache:
        return _cache[key]
    return os.getenv(key, default)


# Force load at import so startup errors surface early (non-fatal)
try:
    _ensure_loaded()
except Exception as exc:  # pragma: no cover
    log.warning("secrets_backend: startup load failed: %s", exc)
