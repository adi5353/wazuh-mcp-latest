"""Extended GeoIP & ASN intelligence — F8.

Supplements threat_intel.py with ASN lookup, hosting-provider classification,
Tor/VPN/datacenter detection, and WHOIS-level org data via ipinfo.io (free tier)
and the existing ip-api.com endpoint.

Tools added:
  enrich_ip_extended          — full ASN + GeoIP + classification
  classify_ip_infrastructure  — fast infrastructure type classification
"""
from __future__ import annotations

import ipaddress
import logging
import os

import httpx

log = logging.getLogger("wazuh-mcp")

# Known cloud/datacenter ASN prefixes (major providers)
_DATACENTER_ORG_KEYWORDS = {
    "amazon", "aws", "google", "microsoft", "azure", "cloudflare",
    "digitalocean", "linode", "akamai", "fastly", "hetzner", "ovh",
    "vultr", "leaseweb", "choopa", "path network", "serverius",
    "m247", "pack et", "quadranet", "psychz", "tzulo",
}

_TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"


async def _ipinfo_get(ip: str) -> dict:
    """Query ipinfo.io for ASN, org, hosting, country, city."""
    token = os.getenv("IPINFO_TOKEN", "")
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token} if token else {}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url, params=params)
            if r.status_code == 200:
                return r.json()
    except Exception as exc:
        log.debug("ipinfo.io error for %s: %s", ip, exc)
    return {}


async def _ip_api_get(ip: str) -> dict:
    """Query ip-api.com for GeoIP data via HTTPS (pro key required for HTTPS; falls back gracefully)."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"https://ip-api.com/json/{ip}",
                params={"fields": "status,country,regionName,city,isp,org,as,hosting,proxy,mobile"},
            )
            if r.status_code == 200:
                return r.json()
    except Exception as exc:
        log.debug("ip-api.com error for %s: %s", ip, exc)
    return {}


async def _is_tor_exit(ip: str) -> bool:
    """Check Tor Project's bulk exit list (cached in memory for session)."""
    cache = _is_tor_exit.__dict__.setdefault("_cache", None)
    if cache is None:
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(_TOR_EXIT_LIST_URL)
                if r.status_code == 200:
                    _is_tor_exit.__dict__["_cache"] = set(r.text.splitlines())
                else:
                    _is_tor_exit.__dict__["_cache"] = set()
        except Exception:
            _is_tor_exit.__dict__["_cache"] = set()
        cache = _is_tor_exit.__dict__["_cache"]
    return ip in cache


def _classify_infra(ipinfo: dict, ipapi: dict) -> str:
    """Return infrastructure classification string."""
    # ip-api.com has a hosting flag
    if ipapi.get("hosting"):
        return "datacenter/hosting"
    if ipapi.get("proxy"):
        return "proxy/vpn"
    if ipapi.get("mobile"):
        return "mobile"

    org = (ipinfo.get("org") or ipapi.get("org") or "").lower()
    for kw in _DATACENTER_ORG_KEYWORDS:
        if kw in org:
            return "datacenter/hosting"

    # ipinfo.io marks privacy services
    privacy = ipinfo.get("privacy") or {}
    if isinstance(privacy, dict):
        if privacy.get("tor"):
            return "tor-exit-node"
        if privacy.get("vpn"):
            return "vpn"
        if privacy.get("hosting"):
            return "datacenter/hosting"
        if privacy.get("proxy"):
            return "proxy"
        if privacy.get("relay"):
            return "relay"

    return "residential/isp"


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def register(mcp, wz, idx, cfg):

    @mcp.tool()
    async def enrich_ip_extended(ip: str) -> dict:
        """Full IP enrichment: ASN, GeoIP, org, hosting classification, Tor check.

        Combines ipinfo.io (ASN + privacy flags) with ip-api.com (GeoIP + ISP)
        to give a complete picture of who owns the IP and what infrastructure
        it runs on.  No API key required; ipinfo.io token is optional
        (set IPINFO_TOKEN env var for higher rate limits).
        """
        if _is_private(ip):
            return {"ip": ip, "classification": "private/rfc1918", "summary": "Private/internal address"}

        ipinfo, ipapi, is_tor = {}, {}, False
        import asyncio
        ipinfo, ipapi, is_tor = await asyncio.gather(
            _ipinfo_get(ip),
            _ip_api_get(ip),
            _is_tor_exit(ip),
        )

        classification = _classify_infra(ipinfo, ipapi)
        if is_tor:
            classification = "tor-exit-node"

        asn = ipinfo.get("org", "")  # ipinfo format: "AS12345 ORG NAME"
        country = ipinfo.get("country") or ipapi.get("country", "")
        city = ipinfo.get("city") or ipapi.get("city", "")
        region = ipinfo.get("region") or ipapi.get("regionName", "")
        isp = ipapi.get("isp") or ipapi.get("org") or asn
        hostname = ipinfo.get("hostname", "")

        risk_factors = []
        if is_tor:
            risk_factors.append("Tor exit node — traffic origin concealed")
        if ipapi.get("proxy"):
            risk_factors.append("Proxy/VPN detected")
        if "datacenter" in classification:
            risk_factors.append("Hosted infrastructure — common for C2 servers")
        if not country:
            risk_factors.append("Unable to determine country")

        return {
            "ip": ip,
            "classification": classification,
            "is_tor_exit": is_tor,
            "asn": asn,
            "hostname": hostname,
            "location": {"country": country, "region": region, "city": city},
            "isp": isp,
            "risk_factors": risk_factors,
            "risk_level": "high" if (is_tor or ipapi.get("proxy")) else
                          "medium" if "datacenter" in classification else "low",
            "raw": {"ipinfo": ipinfo, "ipapi": ipapi},
        }

    @mcp.tool()
    async def classify_ip_infrastructure(ip: str) -> dict:
        """Fast classification of IP infrastructure type.

        Returns one of: residential/isp, datacenter/hosting, proxy/vpn,
        tor-exit-node, mobile, relay, private/rfc1918.

        Useful for bulk triage — call this first, then enrich_ip_extended
        only for suspicious classifications.
        """
        if _is_private(ip):
            return {"ip": ip, "classification": "private/rfc1918",
                    "action_recommended": "investigate internal source"}

        import asyncio
        ipinfo, ipapi = await asyncio.gather(_ipinfo_get(ip), _ip_api_get(ip))
        classification = _classify_infra(ipinfo, ipapi)

        action_map = {
            "tor-exit-node": "block immediately — origin concealed",
            "proxy/vpn": "investigate — potential evasion",
            "datacenter/hosting": "correlate with threat feeds — common C2 hosting",
            "residential/isp": "standard triage",
            "mobile": "standard triage",
            "relay": "investigate — Apple/Cloudflare relay node",
        }

        return {
            "ip": ip,
            "classification": classification,
            "asn": ipinfo.get("org", ipapi.get("as", "")),
            "country": ipinfo.get("country") or ipapi.get("country", ""),
            "action_recommended": action_map.get(classification, "standard triage"),
        }
