"""H5: TLS / mTLS configuration helpers for the MCP server's Uvicorn instance.

Set environment variables to enable TLS:

    WAZUH_MCP_TLS_CERT   — path to PEM server certificate
    WAZUH_MCP_TLS_KEY    — path to PEM private key
    WAZUH_MCP_CLIENT_CA  — (optional) path to CA bundle for mutual TLS

When WAZUH_MCP_TLS_CERT and WAZUH_MCP_TLS_KEY are set, the server starts
with HTTPS. When WAZUH_MCP_CLIENT_CA is also set, clients must present a
certificate signed by that CA (mTLS).

Self-signed cert quick-start (development):
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \\
        -days 365 -nodes -subj '/CN=localhost'
    export WAZUH_MCP_TLS_CERT=/path/to/server.crt
    export WAZUH_MCP_TLS_KEY=/path/to/server.key

In compose.yaml, mount the certificate files as volumes:
    volumes:
      - ./certs/server.crt:/certs/server.crt:ro
      - ./certs/server.key:/certs/server.key:ro
    environment:
      WAZUH_MCP_TLS_CERT: /certs/server.crt
      WAZUH_MCP_TLS_KEY:  /certs/server.key
"""
from __future__ import annotations

import os
from pathlib import Path


def build_uvicorn_tls_kwargs() -> dict:
    """Return Uvicorn SSL keyword arguments based on environment variables.

    Returns an empty dict when TLS is not configured, so the caller can do::

        uvicorn.run(app, **build_uvicorn_tls_kwargs())

    Raises:
        ValueError       — if only one of cert/key is provided
        FileNotFoundError — if a configured file path does not exist
    """
    cert_path = os.getenv("WAZUH_MCP_TLS_CERT", "").strip()
    key_path  = os.getenv("WAZUH_MCP_TLS_KEY",  "").strip()
    ca_path   = os.getenv("WAZUH_MCP_CLIENT_CA", "").strip()

    # Neither configured → plain HTTP
    if not cert_path and not key_path:
        return {}

    # Both must be provided together
    if cert_path and not key_path:
        raise ValueError(
            "WAZUH_MCP_TLS_CERT is set but WAZUH_MCP_TLS_KEY is missing. "
            "Both must be provided to enable TLS."
        )
    if key_path and not cert_path:
        raise ValueError(
            "WAZUH_MCP_TLS_KEY is set but WAZUH_MCP_TLS_CERT is missing. "
            "Both must be provided to enable TLS."
        )

    # Validate files exist
    _check_file(cert_path, "WAZUH_MCP_TLS_CERT")
    _check_file(key_path,  "WAZUH_MCP_TLS_KEY")

    kwargs: dict = {
        "ssl_certfile": cert_path,
        "ssl_keyfile":  key_path,
    }

    if ca_path:
        _check_file(ca_path, "WAZUH_MCP_CLIENT_CA")
        kwargs["ssl_ca_certs"] = ca_path
        # ssl_cert_reqs="CERT_REQUIRED" is handled by Uvicorn automatically
        # when ssl_ca_certs is set.

    return kwargs


def _check_file(path: str, env_var: str) -> None:
    if not Path(path).exists():
        raise FileNotFoundError(
            f"{env_var}={path!r} — file not found. "
            "Ensure the certificate file exists and is readable by the container user."
        )


def tls_enabled() -> bool:
    """Return True if TLS is configured."""
    return bool(os.getenv("WAZUH_MCP_TLS_CERT", "").strip())
