"""Threat intelligence enrichment — IP reputation, file hash lookup, and geo lookup."""
from __future__ import annotations

import asyncio
import logging
import os

import httpx

from ..circuit_breaker import breaker

log = logging.getLogger("wazuh-mcp")


async def _vt_get(path: str) -> dict | None:
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return None
    if not breaker.allow("virustotal"):
        st = breaker.status("virustotal")
        reason = "circuit open" if st["circuit_open"] else "daily quota exhausted"
        log.warning("VirusTotal skipped — %s (%s/%s used today)",
                    reason, st["requests_today"], st["daily_limit"])
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": vt_key},
            )
            if r.status_code == 200:
                breaker.record_success("virustotal")
                return r.json()
            breaker.record_failure("virustotal")
            return None
    except Exception as e:
        log.warning("VirusTotal error: %s", e)
        breaker.record_failure("virustotal")
        return None


async def _abuse_get(ip: str) -> dict | None:
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if not abuse_key:
        return None
    if not breaker.allow("abuseipdb"):
        st = breaker.status("abuseipdb")
        reason = "circuit open" if st["circuit_open"] else "daily quota exhausted"
        log.warning("AbuseIPDB skipped — %s (%s/%s used today)",
                    reason, st["requests_today"], st["daily_limit"])
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": abuse_key, "Accept": "application/json"},
            )
            if r.status_code == 200:
                breaker.record_success("abuseipdb")
                return r.json().get("data")
            breaker.record_failure("abuseipdb")
            return None
    except Exception as e:
        log.warning("AbuseIPDB error: %s", e)
        breaker.record_failure("abuseipdb")
        return None


def register(mcp, wz, idx, cfg, _geoip_lookup):
    from ..validators import safe_validate, validate_ip_address, validate_ip_list

    @mcp.tool()
    async def enrich_ip(ip: str) -> dict:
        """Enrich a source IP with VirusTotal + AbuseIPDB reputation data.

        Returns malicious vote counts, abuse confidence, ASN, country, and a
        combined KNOWN MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN verdict.
        Requires VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY in .env.
        """
        _, err = safe_validate(validate_ip_address, ip)
        if err:
            return err
        vt_data, abuse_data = await asyncio.gather(
            _vt_get(f"ip_addresses/{ip}"),
            _abuse_get(ip),
            return_exceptions=False,
        )

        result: dict = {"ip": ip}

        if vt_data:
            attrs = vt_data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result["virustotal"] = {
                "malicious_votes": stats.get("malicious", 0),
                "suspicious_votes": stats.get("suspicious", 0),
                "harmless_votes": stats.get("harmless", 0),
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "reputation": attrs.get("reputation"),
            }
        else:
            result["virustotal"] = {"status": "unavailable — set VIRUSTOTAL_API_KEY"}

        if abuse_data:
            result["abuseipdb"] = {
                "abuse_confidence_score": abuse_data.get("abuseConfidenceScore"),
                "total_reports": abuse_data.get("totalReports"),
                "country_code": abuse_data.get("countryCode"),
                "isp": abuse_data.get("isp"),
                "domain": abuse_data.get("domain"),
                "is_tor": abuse_data.get("isTor"),
                "last_reported_at": abuse_data.get("lastReportedAt"),
            }
        else:
            result["abuseipdb"] = {"status": "unavailable — set ABUSEIPDB_API_KEY"}

        vt_mal = (result.get("virustotal") or {}).get("malicious_votes") or 0
        abuse_score = (result.get("abuseipdb") or {}).get("abuse_confidence_score") or 0
        result["verdict"] = (
            "KNOWN MALICIOUS" if vt_mal > 5 or abuse_score > 50
            else "SUSPICIOUS" if vt_mal > 0 or abuse_score > 10
            else "CLEAN" if (vt_data or abuse_data)
            else "UNKNOWN — configure TI API keys"
        )
        return result

    @mcp.tool()
    async def enrich_file_hash(hash_value: str) -> dict:
        """Check a file hash (MD5, SHA1, or SHA256) against VirusTotal.

        Requires VIRUSTOTAL_API_KEY in .env.
        """
        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not vt_key:
            return {"error": "VIRUSTOTAL_API_KEY not set in .env"}
        vt_data = await _vt_get(f"files/{hash_value}")
        if not vt_data:
            return {"hash": hash_value, "verdict": "NOT FOUND IN VIRUSTOTAL"}
        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        return {
            "hash": hash_value,
            "malicious_engines": malicious,
            "total_engines": total,
            "detection_ratio": f"{malicious}/{total}",
            "meaningful_name": attrs.get("meaningful_name"),
            "file_type": attrs.get("type_description"),
            "file_size": attrs.get("size"),
            "first_submission": attrs.get("first_submission_date"),
            "threat_label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            "verdict": "MALICIOUS" if malicious > 3 else "SUSPICIOUS" if malicious > 0 else "CLEAN",
        }

    @mcp.tool()
    async def get_threat_intel_status() -> dict:
        """Show daily quota usage and circuit breaker state for VirusTotal and AbuseIPDB.

        Use this to check how many API calls remain before hitting free-tier limits,
        or to diagnose why enrichment is returning 'unavailable'.
        """
        return {
            "quota_and_circuit_status": breaker.status(),
            "limits": {
                "virustotal_daily_limit": int(os.getenv("VIRUSTOTAL_DAILY_LIMIT", "450")),
                "abuseipdb_daily_limit":  int(os.getenv("ABUSEIPDB_DAILY_LIMIT",  "900")),
                "circuit_fail_threshold": int(os.getenv("TI_CIRCUIT_FAIL_THRESHOLD", "5")),
                "circuit_reset_seconds":  int(os.getenv("TI_CIRCUIT_RESET_SECONDS", "300")),
            },
        }

    @mcp.tool()
    async def enrich_ip_geo(ips: list) -> dict:
        """Look up geolocation for up to 10 IP addresses.

        Returns country, city, ISP, and ASN for each. Uses ip-api.com — no API key required.
        Skips private/RFC1918 addresses automatically.
        """
        tasks = [_geoip_lookup(ip) for ip in ips[:10]]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return {"results": list(results)}
