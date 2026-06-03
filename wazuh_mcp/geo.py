"""GeoIP enrichment helper.

Provider priority:
  1. ipinfo.io  — HTTPS, set IPINFO_TOKEN for higher rate limits (50k/mo free tier)
  2. ip-api.com — HTTPS fallback, 45 req/min unauthenticated

Override with env var: WAZUH_GEOIP_PROVIDER=ipinfo|ip-api

Performance
-----------
A single httpx.AsyncClient is shared across all lookups (created lazily) instead
of being built per call — building a client per lookup churns the connection
pool and TLS handshakes, which is costly when enriching a batch of alerts.

Results are cached per IP for WAZUH_GEOIP_CACHE_TTL_SECONDS (default 1h): geo
data is effectively static, and a batch of alerts typically shares a handful of
source IPs, so this collapses N identical lookups into one. (The shared
``@cached`` decorator keys only on kwargs and ``geoip_lookup`` is called
positionally, so a dedicated IP-keyed cache is used here instead.)
"""
from __future__ import annotations

import ipaddress
import os
import time

import httpx

# ── Shared client (lazy singleton) ────────────────────────────────────────────
_GEO_CLIENT: httpx.AsyncClient | None = None


def _get_geo_client() -> httpx.AsyncClient:
    global _GEO_CLIENT
    if _GEO_CLIENT is None or _GEO_CLIENT.is_closed:
        _GEO_CLIENT = httpx.AsyncClient(
            timeout=3.0,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _GEO_CLIENT


async def close_geo_client() -> None:
    """Close the shared GeoIP client on server shutdown."""
    global _GEO_CLIENT
    if _GEO_CLIENT and not _GEO_CLIENT.is_closed:
        try:
            await _GEO_CLIENT.aclose()
        except Exception:
            pass
    _GEO_CLIENT = None


# ── IP-keyed TTL cache ─────────────────────────────────────────────────────────
_CACHE_TTL: int = int(os.getenv("WAZUH_GEOIP_CACHE_TTL_SECONDS", "3600"))
_CACHE_MAX: int = int(os.getenv("WAZUH_GEOIP_CACHE_MAX_ENTRIES", "5000"))
# ip → (expire_monotonic, result)
_geo_cache: dict[str, tuple[float, dict]] = {}


def _cache_get(ip: str) -> dict | None:
    if _CACHE_TTL <= 0:
        return None
    entry = _geo_cache.get(ip)
    if entry is None:
        return None
    expire_at, value = entry
    if time.monotonic() > expire_at:
        _geo_cache.pop(ip, None)
        return None
    return value


def _cache_put(ip: str, value: dict) -> None:
    if _CACHE_TTL <= 0:
        return
    if len(_geo_cache) >= _CACHE_MAX:
        # Drop expired first, then oldest-inserted (FIFO) until under the cap.
        now = time.monotonic()
        for k in [k for k, (exp, _) in _geo_cache.items() if exp <= now]:
            _geo_cache.pop(k, None)
        while len(_geo_cache) >= _CACHE_MAX:
            _geo_cache.pop(next(iter(_geo_cache)), None)
    _geo_cache[ip] = (time.monotonic() + _CACHE_TTL, value)


async def geoip_lookup(ip: str) -> dict:
    """Return GeoIP data for a single IP address.

    Returns a dict with keys: ip, country, city, isp, asn.
    Private/loopback IPs return {"ip": ip, "geo": "private/local"}.
    On lookup failure returns {"ip": ip, "geo": "lookup_failed"}.

    Successful and definitive results are cached per IP; transient
    ``lookup_failed`` results are not cached so a later retry can succeed.
    """
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback:
            return {"ip": ip, "geo": "private/local"}
    except ValueError:
        return {"ip": ip, "geo": "invalid_ip"}

    cached = _cache_get(ip)
    if cached is not None:
        return cached

    provider = os.getenv("WAZUH_GEOIP_PROVIDER", "ipinfo").lower()
    client = _get_geo_client()

    try:
        if provider != "ip-api":
            token = os.getenv("IPINFO_TOKEN", "")
            url = f"https://ipinfo.io/{ip}/json"
            params = {"token": token} if token else {}
            r = await client.get(url, params=params)
            if r.status_code == 200:
                data = r.json()
                if "bogon" not in data:
                    result = {
                        "ip": ip,
                        "country": data.get("country", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("org", ""),
                        "asn": data.get("org", ""),
                    }
                    _cache_put(ip, result)
                    return result

        # HTTPS fallback
        r = await client.get(
            f"https://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,isp,as"},
        )
        data = r.json()
        if data.get("status") == "success":
            result = {
                "ip": ip,
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "asn": data.get("as", ""),
            }
            _cache_put(ip, result)
            return result
    except Exception:
        pass

    return {"ip": ip, "geo": "lookup_failed"}


async def geoip_batch(ips: list[str], max_concurrent: int = 10) -> list[dict]:
    """Enrich a list of IPs concurrently, bounded by max_concurrent."""
    import asyncio

    sem = asyncio.Semaphore(max_concurrent)

    async def bounded(ip: str) -> dict:
        async with sem:
            return await geoip_lookup(ip)

    return await asyncio.gather(*[bounded(ip) for ip in ips])
