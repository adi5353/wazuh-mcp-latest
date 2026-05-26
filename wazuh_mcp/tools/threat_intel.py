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
    async def enrich_domain(domain: str) -> dict:
        """Check a domain name against VirusTotal for reputation and threat data.

        Returns detection stats, creation date, registrar, categories, and a
        KNOWN MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN verdict.
        Requires VIRUSTOTAL_API_KEY in .env.
        """
        import re
        # Basic domain validation — no URLs, just hostname
        domain = domain.strip().lstrip("https://").lstrip("http://").split("/")[0]
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
            return {"error": f"'{domain}' does not look like a valid domain name."}

        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not vt_key:
            return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

        vt_data = await _vt_get(f"domains/{domain}")
        if not vt_data:
            return {"domain": domain, "verdict": "LOOKUP FAILED — check VIRUSTOTAL_API_KEY"}

        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return {
            "domain": domain,
            "virustotal": {
                "malicious_votes":  malicious,
                "suspicious_votes": suspicious,
                "harmless_votes":   stats.get("harmless", 0),
                "creation_date":    attrs.get("creation_date"),
                "last_update_date": attrs.get("last_update_date"),
                "registrar":        attrs.get("registrar"),
                "reputation":       attrs.get("reputation"),
                "categories":       attrs.get("categories", {}),
                "tags":             attrs.get("tags", []),
                "whois_date":       attrs.get("whois_date"),
            },
            "verdict": (
                "KNOWN MALICIOUS" if malicious > 5
                else "SUSPICIOUS" if malicious > 0 or suspicious > 3
                else "CLEAN"
            ),
        }

    @mcp.tool()
    async def enrich_url(url: str) -> dict:
        """Check a URL against VirusTotal for reputation and phishing/malware signals.

        Returns detection stats, final URL after redirects, HTTP response code,
        and a KNOWN MALICIOUS / SUSPICIOUS / CLEAN verdict.
        Requires VIRUSTOTAL_API_KEY in .env.

        url: full URL including scheme (e.g. https://example.com/path)
        """
        import base64

        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not vt_key:
            return {"error": "VIRUSTOTAL_API_KEY not set in .env"}
        if not url.startswith(("http://", "https://")):
            return {"error": "URL must start with http:// or https://"}
        if len(url) > 2000:
            return {"error": "URL too long (max 2000 characters)"}

        # VT expects a URL-safe base64 encoding of the URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        vt_data = await _vt_get(f"urls/{url_id}")
        if not vt_data:
            return {"url": url, "verdict": "LOOKUP FAILED — check VIRUSTOTAL_API_KEY"}

        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return {
            "url": url,
            "virustotal": {
                "malicious_votes":  malicious,
                "suspicious_votes": suspicious,
                "harmless_votes":   stats.get("harmless", 0),
                "final_url":        attrs.get("last_final_url", url),
                "http_response_code": attrs.get("last_http_response_code"),
                "title":            attrs.get("title"),
                "categories":       attrs.get("categories", {}),
                "tags":             attrs.get("tags", []),
                "reputation":       attrs.get("reputation"),
            },
            "verdict": (
                "KNOWN MALICIOUS" if malicious > 5
                else "SUSPICIOUS" if malicious > 0 or suspicious > 2
                else "CLEAN"
            ),
        }

    @mcp.tool()
    async def bulk_enrich_iocs(
        iocs: list,
        ioc_type: str = "auto",
    ) -> dict:
        """Enrich a batch of IOCs (IPs, domains, hashes, URLs) in one call.

        Up to 20 IOCs per call. Each IOC is enriched against VirusTotal and
        AbuseIPDB (IPs only). Results are returned with a per-IOC verdict.

        iocs:     list of IOC strings (IPs, domains, SHA256/MD5 hashes, or URLs)
        ioc_type: 'auto' to detect type automatically, or 'ip' | 'domain' | 'hash' | 'url'

        Requires VIRUSTOTAL_API_KEY in .env. AbuseIPDB used for IPs if key present.
        """
        import re
        import asyncio as _asyncio

        if not iocs:
            return {"error": "iocs list is empty"}
        if len(iocs) > 20:
            return {"error": "Maximum 20 IOCs per call to stay within API rate limits"}

        _IP_RE     = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
        _HASH_RE   = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
        _URL_RE    = re.compile(r'^https?://')
        _DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')

        def _detect_type(ioc: str) -> str:
            ioc = ioc.strip()
            if _IP_RE.match(ioc):     return "ip"
            if _HASH_RE.match(ioc):   return "hash"
            if _URL_RE.match(ioc):    return "url"
            if _DOMAIN_RE.match(ioc): return "domain"
            return "unknown"

        # Build coroutine list
        async def _enrich_one(ioc: str) -> dict:
            ioc = ioc.strip()
            t = ioc_type if ioc_type != "auto" else _detect_type(ioc)
            try:
                if t == "ip":
                    vt, abuse = await asyncio.gather(_vt_get(f"ip_addresses/{ioc}"), _abuse_get(ioc))
                    vt_attrs = (vt or {}).get("data", {}).get("attributes", {})
                    vt_stats = vt_attrs.get("last_analysis_stats", {})
                    mal = vt_stats.get("malicious", 0)
                    ab_score = (abuse or {}).get("abuseConfidenceScore", 0)
                    return {
                        "ioc": ioc, "type": "ip",
                        "malicious_votes": mal,
                        "abuse_score": ab_score,
                        "country": vt_attrs.get("country") or (abuse or {}).get("countryCode"),
                        "verdict": (
                            "KNOWN MALICIOUS" if mal > 5 or ab_score > 50
                            else "SUSPICIOUS" if mal > 0 or ab_score > 10
                            else "CLEAN" if (vt or abuse) else "UNKNOWN"
                        ),
                    }
                elif t == "hash":
                    vt = await _vt_get(f"files/{ioc}")
                    attrs = (vt or {}).get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    return {
                        "ioc": ioc, "type": "hash",
                        "malicious_engines": mal,
                        "total_engines": sum(stats.values()),
                        "threat_label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
                        "verdict": "MALICIOUS" if mal > 3 else "SUSPICIOUS" if mal > 0 else "CLEAN",
                    }
                elif t == "domain":
                    vt = await _vt_get(f"domains/{ioc}")
                    attrs = (vt or {}).get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    return {
                        "ioc": ioc, "type": "domain",
                        "malicious_votes": mal,
                        "suspicious_votes": stats.get("suspicious", 0),
                        "registrar": attrs.get("registrar"),
                        "verdict": "KNOWN MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal > 0 else "CLEAN",
                    }
                elif t == "url":
                    import base64
                    url_id = base64.urlsafe_b64encode(ioc.encode()).rstrip(b"=").decode()
                    vt = await _vt_get(f"urls/{url_id}")
                    attrs = (vt or {}).get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    return {
                        "ioc": ioc, "type": "url",
                        "malicious_votes": mal,
                        "final_url": attrs.get("last_final_url", ioc),
                        "verdict": "KNOWN MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal > 0 else "CLEAN",
                    }
                else:
                    return {"ioc": ioc, "type": "unknown", "verdict": "UNRECOGNIZED IOC TYPE"}
            except Exception as exc:
                return {"ioc": ioc, "type": t, "verdict": "ERROR", "error": str(exc)}

        results = await _asyncio.gather(*[_enrich_one(ioc) for ioc in iocs])

        malicious_count  = sum(1 for r in results if "MALICIOUS" in r.get("verdict", ""))
        suspicious_count = sum(1 for r in results if r.get("verdict") == "SUSPICIOUS")

        return {
            "total": len(results),
            "malicious":  malicious_count,
            "suspicious": suspicious_count,
            "clean":      len(results) - malicious_count - suspicious_count,
            "results":    list(results),
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
