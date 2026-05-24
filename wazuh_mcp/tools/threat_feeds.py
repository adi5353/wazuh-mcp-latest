"""Threat feed integration — F10.

Pulls IOC lists from free public feeds (Feodo Tracker, URLhaus, Tor exit nodes)
and populates Wazuh CDB lists. Correlates active alerts against feed IOCs.

Tools: sync_threat_feed, list_threat_feeds, correlate_alerts_with_feed
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import httpx

from ..rbac import responder_only

log = logging.getLogger("wazuh-mcp")

_FEEDS = {
    "feodo": {
        "name": "Feodo Tracker C2 IPs",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv",
        "description": "Botnet C2 IPs — abuse.ch Feodo Tracker",
        "ioc_type": "ip",
        "cdb_list": "threat-feed-feodo",
    },
    "urlhaus": {
        "name": "URLhaus Malicious Domains",
        "url": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "description": "Active malicious domains — abuse.ch URLhaus",
        "ioc_type": "domain",
        "cdb_list": "threat-feed-urlhaus",
    },
    "torstats": {
        "name": "Tor Exit Nodes",
        "url": "https://check.torproject.org/torbulkexitlist",
        "description": "Tor Project bulk exit node list",
        "ioc_type": "ip",
        "cdb_list": "threat-feed-tor",
    },
}

_FEED_CACHE: dict[str, dict] = {}


def _parse_feodo_csv(text: str) -> list[str]:
    ips = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        ip = parts[0].strip().strip('"')
        if ip:
            ips.append(ip)
    return ips


def _parse_urlhaus_csv(text: str) -> list[str]:
    domains = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split('","')
        if len(parts) >= 2:
            url = parts[1].strip('"').strip()
            if url.startswith("http"):
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc
                    if domain:
                        domains.append(domain)
                except Exception:
                    pass
    return list(set(domains))


def _parse_tor_list(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.startswith("#")]


async def _fetch_feed(feed_id: str) -> tuple[list[str], str]:
    feed = _FEEDS[feed_id]
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            r = await c.get(feed["url"])
            r.raise_for_status()
            text = r.text
    except Exception as exc:
        return [], str(exc)
    if feed_id == "feodo":
        return _parse_feodo_csv(text), ""
    if feed_id == "urlhaus":
        return _parse_urlhaus_csv(text), ""
    if feed_id == "torstats":
        return _parse_tor_list(text), ""
    return [], "unknown feed"


def register(mcp, wz, idx, cfg, _require_writes):

    @mcp.tool()
    async def sync_threat_feed(feed_id: str, dry_run: bool = True) -> dict:
        """Pull a threat feed and populate the corresponding Wazuh CDB list.

        feed_id: 'feodo' (botnet C2 IPs), 'urlhaus' (malicious domains),
                 or 'torstats' (Tor exit nodes).
        dry_run: if True (default) preview only — no write. Set False with
                 WAZUH_ALLOW_WRITES=true to actually sync. Requires: responder.
        """
        if feed_id not in _FEEDS:
            return {"error": "Unknown feed. Valid: " + str(list(_FEEDS.keys()))}

        iocs, err = await _fetch_feed(feed_id)
        if err:
            return {"error": "Failed to fetch feed: " + err}

        meta = _FEEDS[feed_id]
        _FEED_CACHE[feed_id] = {
            "iocs": set(iocs),
            "synced_at": time.time(),
            "count": len(iocs),
        }

        if dry_run:
            return {
                "feed": feed_id,
                "feed_name": meta["name"],
                "ioc_type": meta["ioc_type"],
                "ioc_count": len(iocs),
                "target_cdb_list": meta["cdb_list"],
                "sample_iocs": iocs[:10],
                "dry_run": True,
                "message": "Preview only. Set dry_run=false + WAZUH_ALLOW_WRITES=true to write.",
            }

        err_rbac = responder_only()
        if err_rbac:
            return err_rbac
        blocked = _require_writes()
        if blocked:
            return blocked

        cdb_content = "\n".join(f"{ioc}:{feed_id}" for ioc in iocs) + "\n"
        try:
            await wz.upload_xml_file(
                "/lists/files/" + meta["cdb_list"], cdb_content,
                content_type="application/octet-stream",
            )
            return {
                "feed": feed_id,
                "feed_name": meta["name"],
                "ioc_count": len(iocs),
                "cdb_list": meta["cdb_list"],
                "synced_at": datetime.now(timezone.utc).isoformat(),
                "status": "synced",
                "sample_iocs": iocs[:10],
            }
        except Exception as exc:
            return {"error": "CDB write failed: " + str(exc), "ioc_count": len(iocs)}

    @mcp.tool()
    async def list_threat_feeds() -> dict:
        """Show available threat feeds with sync status and IOC counts."""
        feeds_status = []
        for fid, meta in _FEEDS.items():
            cache = _FEED_CACHE.get(fid)
            feeds_status.append({
                "feed_id": fid,
                "name": meta["name"],
                "description": meta["description"],
                "ioc_type": meta["ioc_type"],
                "cdb_list": meta["cdb_list"],
                "cached_in_memory": cache is not None,
                "ioc_count": cache["count"] if cache else 0,
                "last_synced": (
                    datetime.fromtimestamp(cache["synced_at"], tz=timezone.utc).isoformat()
                    if cache else "never"
                ),
            })
        return {
            "feeds": feeds_status,
            "total_cached_iocs": sum(c["count"] for c in _FEED_CACHE.values()),
            "tip": "Run sync_threat_feed(feed_id, dry_run=True) to preview.",
        }

    @mcp.tool()
    async def correlate_alerts_with_feed(
        feed_id: str = "feodo",
        hours: int = 24,
        max_alerts: int = 500,
    ) -> dict:
        """Cross-reference recent alerts against a loaded threat feed.

        Feed must be loaded first via sync_threat_feed (dry_run=True caches
        IOCs in memory without writing to CDB). Checks srcip, dstip, url fields.
        """
        if feed_id not in _FEEDS:
            return {"error": "Unknown feed. Valid: " + str(list(_FEEDS.keys()))}
        cache = _FEED_CACHE.get(feed_id)
        if not cache:
            return {"error": "Feed not loaded. Run sync_threat_feed first."}

        from datetime import timedelta
        now = datetime.now(timezone.utc)
        gte = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            "query": {"range": {"@timestamp": {"gte": gte}}},
            "size": max_alerts,
            "_source": ["@timestamp", "agent", "data.srcip", "data.dstip",
                        "data.url", "rule"],
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        try:
            raw = await idx.search(query, index="wazuh-alerts-*")
        except Exception as exc:
            return {"error": "Indexer query failed: " + str(exc)}

        hits = (raw.get("hits") or {}).get("hits") or []
        ioc_set = cache["iocs"]
        matches = []
        for hit in hits:
            src = hit.get("_source") or {}
            data = src.get("data") or {}
            candidates = [
                data.get("srcip", ""),
                data.get("dstip", ""),
                data.get("url", ""),
            ]
            matched = [c for c in candidates if c and c in ioc_set]
            if matched:
                matches.append({
                    "timestamp": src.get("@timestamp"),
                    "agent": src.get("agent", {}),
                    "matched_iocs": matched,
                    "rule": src.get("rule", {}),
                })

        return {
            "feed": feed_id,
            "feed_name": _FEEDS[feed_id]["name"],
            "time_window_hours": hours,
            "alerts_scanned": len(hits),
            "matches_found": len(matches),
            "matches": matches[:50],
            "ioc_cache_count": cache["count"],
            "severity": "critical" if matches else "none",
            "recommendation": (
                "WARNING: " + str(len(matches)) + " alerts matched feed IOCs"
                if matches else "No matches found"
            ),
        }
