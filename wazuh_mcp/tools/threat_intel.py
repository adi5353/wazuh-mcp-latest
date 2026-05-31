"""Threat intelligence enrichment — IP reputation, file hash lookup, and geo lookup."""
from __future__ import annotations
from ..tool_context import ToolContext

import asyncio
import logging
import os

import httpx

from ..circuit_breaker import breaker
import time

log = logging.getLogger("wazuh-mcp")

# IOC result cache (Fix 1) — prevents repeated external API calls for same indicator
_IOC_CACHE: dict[str, tuple[dict, float]] = {}
_CACHE_TTL_IP    = int(os.getenv("WAZUH_IOC_CACHE_TTL_IP",    "3600"))   # 1h
_CACHE_TTL_HASH  = int(os.getenv("WAZUH_IOC_CACHE_TTL_HASH",  "86400"))  # 24h
_CACHE_TTL_OTHER = int(os.getenv("WAZUH_IOC_CACHE_TTL_OTHER", "7200"))   # 2h


def _cache_get(key: str) -> dict | None:
    entry = _IOC_CACHE.get(key)
    if entry and time.monotonic() < entry[1]:
        return entry[0]
    _IOC_CACHE.pop(key, None)
    return None


_CACHE_MAX_SIZE = 2000
_CACHE_EVICT_N  = 200   # entries removed per eviction pass

def _cache_set(key: str, value: dict | None, ttl: int) -> None:
    if value is None:
        return
    _IOC_CACHE[key] = (value, time.monotonic() + ttl)
    if len(_IOC_CACHE) > _CACHE_MAX_SIZE:
        now = time.monotonic()
        # Pass 1: remove expired entries.
        stale = [k for k, (_, exp) in _IOC_CACHE.items() if exp < now]
        for k in stale[:_CACHE_EVICT_N]:
            _IOC_CACHE.pop(k, None)
        # Pass 2: if still over limit, evict the soonest-to-expire entries.
        if len(_IOC_CACHE) > _CACHE_MAX_SIZE:
            oldest = sorted(_IOC_CACHE, key=lambda k: _IOC_CACHE[k][1])
            for k in oldest[:_CACHE_EVICT_N]:
                _IOC_CACHE.pop(k, None)

# Shared connection pools — one TLS handshake per host, reused across all calls.
# Closed on server shutdown via close_shared_ti_clients() called from server.py lifespan.
_VT_CLIENT: httpx.AsyncClient | None = None
_ABUSE_CLIENT: httpx.AsyncClient | None = None


def _get_vt_client() -> httpx.AsyncClient:
    global _VT_CLIENT
    if _VT_CLIENT is None or _VT_CLIENT.is_closed:
        _VT_CLIENT = httpx.AsyncClient(
            base_url="https://www.virustotal.com",
            timeout=15,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _VT_CLIENT


def _get_abuse_client() -> httpx.AsyncClient:
    global _ABUSE_CLIENT
    if _ABUSE_CLIENT is None or _ABUSE_CLIENT.is_closed:
        _ABUSE_CLIENT = httpx.AsyncClient(
            base_url="https://api.abuseipdb.com",
            timeout=15,
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=3),
        )
    return _ABUSE_CLIENT


async def close_shared_ti_clients() -> None:
    """Close shared httpx clients on server shutdown."""
    global _VT_CLIENT, _ABUSE_CLIENT
    for client in (_VT_CLIENT, _ABUSE_CLIENT):
        if client and not client.is_closed:
            try:
                await client.aclose()
            except Exception:
                pass
    _VT_CLIENT = None
    _ABUSE_CLIENT = None


async def _vt_get(path: str) -> dict | None:
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return None
    # Fix 1: cache before hitting API
    _ck = f"vt:{path}"
    _hit = _cache_get(_ck)
    if _hit is not None:
        return _hit
    if not breaker.allow("virustotal"):
        st = breaker.status("virustotal")
        reason = "circuit open" if st["circuit_open"] else "daily quota exhausted"
        log.warning("VirusTotal skipped — %s (%s/%s used today)",
                    reason, st["requests_today"], st["daily_limit"])
        return None
    try:
        r = await _get_vt_client().get(
            f"/api/v3/{path}",
            headers={"x-apikey": vt_key},
        )
        if r.status_code == 200:
            breaker.record_success("virustotal")
            _res = r.json()
            _ttl = (_CACHE_TTL_HASH if "/files/" in path else _CACHE_TTL_IP if "/ip_addresses/" in path else _CACHE_TTL_OTHER)
            _cache_set(_ck, _res, _ttl)
            return _res
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
    # Fix 1: cache before hitting API
    _ck2 = f"abuse:{ip}"
    _hit2 = _cache_get(_ck2)
    if _hit2 is not None:
        return _hit2
    if not breaker.allow("abuseipdb"):
        st = breaker.status("abuseipdb")
        reason = "circuit open" if st["circuit_open"] else "daily quota exhausted"
        log.warning("AbuseIPDB skipped — %s (%s/%s used today)",
                    reason, st["requests_today"], st["daily_limit"])
        return None
    try:
        r = await _get_abuse_client().get(
            "/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": abuse_key, "Accept": "application/json"},
        )
        if r.status_code == 200:
            breaker.record_success("abuseipdb")
            _res2 = r.json().get("data")
            _cache_set(_ck2, _res2, _CACHE_TTL_IP)
            return _res2
        breaker.record_failure("abuseipdb")
        return None
    except Exception as e:
        log.warning("AbuseIPDB error: %s", e)
        breaker.record_failure("abuseipdb")
        return None


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _geoip_lookup = ctx.geoip_lookup

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
        # Basic domain validation — strip any scheme + path, keep the hostname.
        # NB: use a prefix regex, not str.lstrip("https://"), which strips a
        # *character set* and would mangle hosts like "stackoverflow.com".
        domain = re.sub(r"^https?://", "", domain.strip(), flags=re.IGNORECASE).split("/")[0]
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

        def _defang(ioc: str) -> str:
            """Normalize defanged IOCs: 1[.]1[.]1[.]1->1.1.1.1, hxxp->http."""
            return (ioc.strip()
                    .replace("[.]", ".").replace("(.)", ".")
                    .replace("[:]", ":").replace("hxxp", "http")
                    .replace("hXXp", "http").replace("hxxps", "https")
                    .replace("hXXps", "https"))

        def _detect_type(ioc: str) -> str:
            import socket
            ioc = _defang(ioc)
            try:
                socket.inet_pton(socket.AF_INET6, ioc)
                return "ip"
            except (OSError, AttributeError):
                pass
            if _IP_RE.match(ioc):     return "ip"
            if _HASH_RE.match(ioc):   return "hash"
            if _URL_RE.match(ioc):    return "url"
            if _DOMAIN_RE.match(ioc): return "domain"
            return "unknown"

        # Build coroutine list
        async def _enrich_one(ioc: str) -> dict:
            ioc = _defang(ioc.strip())
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

    @mcp.tool()
    async def enrich_email(email: str) -> dict:
        """Enrich an email address with breach and deliverability intelligence.

        Checks HaveIBeenPwned (k-anonymity, no key required) for known data breaches
        and Hunter.io (optional HUNTER_API_KEY) for domain deliverability / MX info.

        Returns:
          - breach_count, breaches list (name, domain, date, data_classes)
          - hunter_score, mx_records (if HUNTER_API_KEY set)
          - verdict: BREACHED / CLEAN / UNKNOWN
        """
        import base64
        import hashlib

        result: dict = {"email": email, "breaches": [], "breach_count": 0}

        # ── HaveIBeenPwned email lookup ────────────────────────────────────────
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                         base_url="https://haveibeenpwned.com") as c:
                hibp_headers = {
                    "User-Agent": "wazuh-mcp-security-tool",
                    "hibp-api-key": os.getenv("HIBP_API_KEY", ""),
                }
                # Remove empty header values
                hibp_headers = {k: v for k, v in hibp_headers.items() if v}
                r = await c.get(
                    f"/api/v3/breachedaccount/{email}?truncateResponse=false",
                    headers=hibp_headers,
                )
                if r.status_code == 200:
                    breaches = r.json()
                    result["breach_count"] = len(breaches)
                    result["breaches"] = [
                        {
                            "name": b.get("Name"),
                            "domain": b.get("Domain"),
                            "breach_date": b.get("BreachDate"),
                            "data_classes": b.get("DataClasses", []),
                            "pwn_count": b.get("PwnCount", 0),
                        }
                        for b in breaches
                    ]
                elif r.status_code == 404:
                    result["breach_count"] = 0  # Not found = clean
                elif r.status_code == 401:
                    result["hibp_note"] = "HIBP API key required for email lookup — set HIBP_API_KEY"
                else:
                    result["hibp_note"] = f"HIBP returned HTTP {r.status_code}"
        except Exception as e:
            result["hibp_note"] = f"HIBP lookup failed: {e}"

        # ── Hunter.io domain/email verification (optional) ─────────────────────
        hunter_key = os.getenv("HUNTER_API_KEY")
        if hunter_key and "@" in email:
            domain = email.split("@", 1)[1]
            try:
                async with httpx.AsyncClient(timeout=15,
                                             base_url="https://api.hunter.io") as c:
                    # Email verification endpoint
                    r = await c.get(
                        "/v2/email-verifier",
                        params={"email": email, "api_key": hunter_key},
                    )
                    if r.status_code == 200:
                        data = r.json().get("data", {})
                        result["hunter_score"] = data.get("score")
                        result["hunter_status"] = data.get("status")  # valid/risky/invalid
                        result["mx_records"] = data.get("mx_records", False)
                        result["disposable"] = data.get("disposable", False)
                        result["webmail"] = data.get("webmail", False)
            except Exception as e:
                result["hunter_note"] = f"Hunter.io lookup failed: {e}"
        elif not hunter_key:
            result["hunter_note"] = "Set HUNTER_API_KEY for email deliverability scoring"

        # ── Verdict ────────────────────────────────────────────────────────────
        if result["breach_count"] > 0:
            result["verdict"] = "BREACHED"
            result["risk_level"] = "HIGH" if result["breach_count"] >= 3 else "MEDIUM"
        elif "hibp_note" in result and "key required" in result.get("hibp_note", ""):
            result["verdict"] = "UNKNOWN"
            result["risk_level"] = "UNKNOWN"
        else:
            result["verdict"] = "CLEAN"
            result["risk_level"] = "LOW"

        return result

    @mcp.tool()
    async def ioc_to_alert_match(
        iocs: list,
        time_range: str = "7d",
        limit: int = 200,
    ) -> dict:
        """Scan recent Wazuh alerts for matches against a list of known IOCs.

        Searches alert fields: data.srcip, data.win.eventdata.ipAddress, data.dstip,
        data.url, data.hostname, data.md5, data.sha256, data.sha1.

        Args:
            iocs:       List of IOC strings (IPs, domains, hashes, URLs — mixed OK)
            time_range: Look-back window, e.g. "24h", "7d", "30d"
            limit:      Maximum alerts to return per IOC match

        Returns:
            matched_iocs, total_matches, alerts grouped by IOC, unmatched_iocs
        """
        if not iocs:
            return {"error": "iocs list is empty"}

        iocs = [str(i).strip() for i in iocs[:100]]  # cap at 100 IOCs

        # Build time range
        _range_map = {"1h": "now-1h", "4h": "now-4h", "24h": "now-24h",
                      "7d": "now-7d", "14d": "now-14d", "30d": "now-30d"}
        gte = _range_map.get(time_range, f"now-{time_range}")

        # Fields to search for IOC matches
        _ioc_fields = [
            "data.srcip", "data.dstip", "data.win.eventdata.ipAddress",
            "data.win.eventdata.destinationIp",
            "data.url", "data.http.url",
            "data.hostname", "data.win.eventdata.hostName",
            "data.md5", "data.sha256", "data.sha1",
            "data.win.eventdata.hashes",
        ]

        should_clauses = []
        for ioc in iocs:
            for field in _ioc_fields:
                should_clauses.append({"term": {field: ioc}})
            # Also try wildcard for URL/domain partial matches
            if "." in ioc and not ioc.replace(".", "").isdigit():
                should_clauses.append({"wildcard": {"data.url": f"*{ioc}*"}})

        body = {
            "query": {
                "bool": {
                    "must": [{"range": {"@timestamp": {"gte": gte}}}],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": min(limit, 500),
            "_source": [
                "@timestamp", "rule.id", "rule.description", "rule.level",
                "agent.id", "agent.name",
                "data.srcip", "data.dstip", "data.url",
                "data.hostname", "data.md5", "data.sha256",
            ],
        }

        try:
            resp = await idx.search(body, index=cfg.get("alerts_index", "wazuh-alerts-*"))
        except Exception as e:
            return {"error": f"Index search failed: {e}"}

        hits = resp.get("hits", {}).get("hits", [])

        # Group matched alerts by the IOC that triggered the match
        ioc_set = set(ioc.lower() for ioc in iocs)
        grouped: dict[str, list] = {}

        for hit in hits:
            src = hit.get("_source", {})
            # Find which IOC matched this alert
            matched_ioc = None
            for field in _ioc_fields:
                val = src
                for part in field.split("."):
                    val = val.get(part, {}) if isinstance(val, dict) else None
                if val and str(val).lower() in ioc_set:
                    matched_ioc = str(val).lower()
                    break
                # Check wildcard/partial matches for URLs
                if val and isinstance(val, str):
                    for ioc in iocs:
                        if "." in ioc and ioc.lower() in val.lower():
                            matched_ioc = ioc.lower()
                            break
                if matched_ioc:
                    break

            if matched_ioc:
                if matched_ioc not in grouped:
                    grouped[matched_ioc] = []
                grouped[matched_ioc].append({
                    "timestamp": src.get("@timestamp"),
                    "rule_id": src.get("rule", {}).get("id"),
                    "rule_description": src.get("rule", {}).get("description"),
                    "rule_level": src.get("rule", {}).get("level"),
                    "agent_id": src.get("agent", {}).get("id"),
                    "agent_name": src.get("agent", {}).get("name"),
                    "src_ip": src.get("data", {}).get("srcip"),
                    "dst_ip": src.get("data", {}).get("dstip"),
                    "url": src.get("data", {}).get("url"),
                })

        matched_iocs = list(grouped.keys())
        unmatched = [ioc for ioc in iocs if ioc.lower() not in set(matched_iocs)]
        total_matches = sum(len(v) for v in grouped.values())

        return {
            "time_range": time_range,
            "iocs_checked": len(iocs),
            "matched_iocs": matched_iocs,
            "matched_ioc_count": len(matched_iocs),
            "unmatched_iocs": unmatched,
            "total_alert_matches": total_matches,
            "matches_by_ioc": {
                ioc: {
                    "alert_count": len(alerts),
                    "alerts": alerts[:20],  # cap per-IOC to 20
                }
                for ioc, alerts in grouped.items()
            },
            "verdict": "ACTIVE_THREATS_DETECTED" if matched_iocs else "NO_MATCHES",
        }
