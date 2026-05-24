"""Tool-level tests — verify dry_run safety and validator integration."""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_search_mock(total: int = 42, hits: list | None = None, aggs: dict | None = None):
    return AsyncMock(return_value={
        "hits": {"total": {"value": total}, "hits": hits or []},
        "aggregations": aggs or {
            "by_rule":  {"buckets": [{"key": "SSH brute force", "doc_count": total}]},
            "by_agent": {"buckets": [{"key": "Server1", "doc_count": total}]},
        },
    })


# ── Validator tests ───────────────────────────────────────────────────────────

def test_validate_time_range_valid():
    from wazuh_mcp.validators import validate_time_range
    assert validate_time_range("24h") == "24h"
    assert validate_time_range("7d") == "7d"
    assert validate_time_range("30m") == "30m"


def test_validate_time_range_invalid():
    from wazuh_mcp.validators import validate_time_range
    with pytest.raises(ValueError):
        validate_time_range("bad_range")
    with pytest.raises(ValueError):
        validate_time_range("1x")


def test_validate_ip_address_valid():
    from wazuh_mcp.validators import validate_ip_address
    assert validate_ip_address("1.2.3.4") == "1.2.3.4"
    assert validate_ip_address("::1") == "::1"


def test_validate_ip_address_invalid():
    from wazuh_mcp.validators import validate_ip_address
    with pytest.raises(ValueError):
        validate_ip_address("999.999.999.999")
    with pytest.raises(ValueError):
        validate_ip_address("not-an-ip")


def test_validate_cve_id_valid():
    from wazuh_mcp.validators import validate_cve_id
    assert validate_cve_id("CVE-2021-44228") == "CVE-2021-44228"
    assert validate_cve_id("cve-2024-3094") == "CVE-2024-3094"  # normalised to upper


def test_validate_cve_id_invalid():
    from wazuh_mcp.validators import validate_cve_id
    with pytest.raises(ValueError):
        validate_cve_id("not-a-cve")
    with pytest.raises(ValueError):
        validate_cve_id("CVE-2021")  # too short


def test_validate_agent_id_blocks_path_traversal():
    from wazuh_mcp.validators import validate_agent_id
    with pytest.raises(ValueError):
        validate_agent_id("../../etc/passwd")


def test_validate_min_level_bounds():
    from wazuh_mcp.validators import validate_min_level
    assert validate_min_level(1) == 1
    assert validate_min_level(15) == 15
    with pytest.raises(ValueError):
        validate_min_level(0)
    with pytest.raises(ValueError):
        validate_min_level(16)


def test_safe_validate_returns_error_dict():
    from wazuh_mcp.validators import safe_validate, validate_time_range
    value, err = safe_validate(validate_time_range, "bad!")
    assert value is None
    assert "error" in err


def test_validate_free_text_strips_dangerous_chars():
    from wazuh_mcp.validators import validate_free_text
    result = validate_free_text("hello; rm -rf /")
    assert ";" not in result
    assert "|" not in result


# ── Audit logger tests ────────────────────────────────────────────────────────

def test_audit_record_writes_file(tmp_path, monkeypatch):
    import wazuh_mcp.audit as audit_mod
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit_mod, "_AUDIT_LOG_PATH", audit_path)

    with audit_mod.audit_logger.record("test_tool", {"param": "value"}, identity="tester") as ctx:
        ctx.set_result_code("200")

    lines = audit_path.read_text().strip().splitlines()
    assert len(lines) == 1
    import json
    record = json.loads(lines[0])
    assert record["tool"] == "test_tool"
    assert record["result_code"] == "200"
    assert record["identity"] == "tester"
    assert "params_fp" in record


def test_audit_redacts_sensitive_params(tmp_path, monkeypatch):
    import wazuh_mcp.audit as audit_mod
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit_mod, "_AUDIT_LOG_PATH", audit_path)

    with audit_mod.audit_logger.record(
        "some_tool", {"password": "s3cr3t", "user": "admin"}, identity="tester"
    ):
        pass

    import json
    record = json.loads(audit_path.read_text().strip())
    assert record["params_scrubbed"]["password"] == "[REDACTED]"
    assert record["params_scrubbed"]["user"] == "admin"


# ── Log redaction tests ───────────────────────────────────────────────────────

def test_redact_sensitive_processor():
    from wazuh_mcp.logging_config import _redact_sensitive
    event = {
        "event": "login",
        "password": "mysecret",
        "api_key": "abc123",
        "user": "alice",
        "Authorization": "Bearer eyJhbGc...",
    }
    result = _redact_sensitive(None, "info", event)
    assert result["password"] == "[REDACTED]"
    assert result["api_key"] == "[REDACTED]"
    assert result["Authorization"] == "[REDACTED]"
    assert result["user"] == "alice"


def test_redact_bearer_in_string():
    from wazuh_mcp.logging_config import _redact_sensitive
    event = {"event": "request", "msg": "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload"}
    result = _redact_sensitive(None, "info", event)
    assert "eyJhbGc" not in result["msg"]
    assert "[REDACTED]" in result["msg"]
