"""Tests for H7: API circuit breaker and daily quota tracker."""
import os
import time
import pytest
from unittest.mock import patch


def fresh_breaker():
    """Return a brand-new registry with clean state for isolation."""
    from wazuh_mcp.circuit_breaker import CircuitBreakerRegistry
    return CircuitBreakerRegistry()


class TestDailyQuota:
    def test_allow_within_limit(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"VIRUSTOTAL_DAILY_LIMIT": "5"}):
            for _ in range(5):
                assert b.allow("virustotal") is True

    def test_block_after_limit_reached(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"VIRUSTOTAL_DAILY_LIMIT": "3"}):
            b.allow("virustotal")
            b.allow("virustotal")
            b.allow("virustotal")
            assert b.allow("virustotal") is False

    def test_requests_remaining_decrements(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"VIRUSTOTAL_DAILY_LIMIT": "10"}):
            b.allow("virustotal")
            b.allow("virustotal")
            assert b.status("virustotal")["requests_remaining"] == 8

    def test_quota_exhausted_flag(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"ABUSEIPDB_DAILY_LIMIT": "2"}):
            b.allow("abuseipdb")
            b.allow("abuseipdb")
            st = b.status("abuseipdb")
            assert st["quota_exhausted"] is True

    def test_quota_resets_after_24h(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"VIRUSTOTAL_DAILY_LIMIT": "1"}):
            b.allow("virustotal")                     # exhaust
            assert b.allow("virustotal") is False     # blocked

            # Simulate 24+ hours passing by rewinding quota_reset_at
            b._get("virustotal").quota_reset_at -= 86401
            assert b.allow("virustotal") is True      # allowed again

    def test_different_apis_independent(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {"VIRUSTOTAL_DAILY_LIMIT": "1", "ABUSEIPDB_DAILY_LIMIT": "10"}):
            b.allow("virustotal")
            assert b.allow("virustotal") is False     # vt exhausted
            assert b.allow("abuseipdb")  is True      # abuseipdb fine


class TestCircuitBreaker:
    def test_circuit_opens_after_threshold_failures(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {
            "TI_CIRCUIT_FAIL_THRESHOLD": "3",
            "TI_CIRCUIT_RESET_SECONDS": "60",
            "VIRUSTOTAL_DAILY_LIMIT": "1000",
        }):
            b.record_failure("virustotal")
            b.record_failure("virustotal")
            assert b.allow("virustotal") is True   # still closed
            b.record_failure("virustotal")         # threshold hit
            assert b.allow("virustotal") is False  # circuit open

    def test_circuit_closes_after_reset_period(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {
            "TI_CIRCUIT_FAIL_THRESHOLD": "1",
            "TI_CIRCUIT_RESET_SECONDS": "1",
            "VIRUSTOTAL_DAILY_LIMIT": "1000",
        }):
            b.record_failure("virustotal")
            assert b.allow("virustotal") is False  # open
            # Simulate reset period elapsed
            b._get("virustotal").circuit_open_until = time.time() - 1
            assert b.allow("virustotal") is True   # closed again

    def test_success_resets_failure_count(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {
            "TI_CIRCUIT_FAIL_THRESHOLD": "3",
            "VIRUSTOTAL_DAILY_LIMIT": "1000",
        }):
            b.record_failure("virustotal")
            b.record_failure("virustotal")
            b.record_success("virustotal")         # reset counter
            b.record_failure("virustotal")
            b.record_failure("virustotal")
            assert b.allow("virustotal") is True   # only 2 failures since reset

    def test_circuit_status_shows_open(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {
            "TI_CIRCUIT_FAIL_THRESHOLD": "1",
            "TI_CIRCUIT_RESET_SECONDS": "300",
            "VIRUSTOTAL_DAILY_LIMIT": "1000",
        }):
            b.record_failure("virustotal")
            st = b.status("virustotal")
            assert st["circuit_open"] is True
            assert st["circuit_resets_in_seconds"] > 0

    def test_admin_reset_clears_circuit(self):
        b = fresh_breaker()
        with patch.dict(os.environ, {
            "TI_CIRCUIT_FAIL_THRESHOLD": "1",
            "VIRUSTOTAL_DAILY_LIMIT": "1000",
        }):
            b.record_failure("virustotal")
            assert b.allow("virustotal") is False
            b.reset("virustotal")
            assert b.allow("virustotal") is True

    def test_status_all_apis(self):
        b = fresh_breaker()
        b.allow("virustotal")
        b.allow("abuseipdb")
        st = b.status()
        assert "virustotal" in st
        assert "abuseipdb" in st

    def test_module_imports_cleanly(self):
        from wazuh_mcp.circuit_breaker import breaker, CircuitBreakerRegistry
        assert breaker is not None
        assert isinstance(breaker, CircuitBreakerRegistry)
