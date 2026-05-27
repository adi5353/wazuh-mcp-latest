"""Alert enrichment pipeline.

Augments a raw Wazuh alert dict with contextual data from multiple sources.
Each enricher is a small async function that adds a key to the alert.
The pipeline runs enrichers concurrently where possible.

Enrichers (all optional — skipped on error):
  1. geo        — GeoIP country/city/ISP for src_ip
  2. reputation — VirusTotal + AbuseIPDB verdict for external IPs
  3. mitre      — technique name + tactic from the MITRE map
  4. agent      — agent OS, group, last-seen from the Manager API
  5. frequency  — how noisy is this rule? alert count over last 7d
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

log = logging.getLogger("wazuh-mcp.enrichment")

# ── Helpers ────────────────────────────────────────────────────────────────────

def _src_ip(alert: dict) -> str | None:
    data = alert.get("data", {})
    return (
        data.get("srcip")
        or data.get("src_ip")
        or alert.get("_source", {}).get("data", {}).get("srcip")
    )


def _rule_id(alert: dict) -> str | None:
    rule = alert.get("rule", {})
    return str(rule.get("id", "")) or None


def _technique_ids(alert: dict) -> list[str]:
    rule = alert.get("rule", {})
    mitre = rule.get("mitre", {})
    ids = mitre.get("id", [])
    return ids if isinstance(ids, list) else ([ids] if ids else [])


# ── Individual enrichers ───────────────────────────────────────────────────────

async def _enrich_geo(alert: dict, **_: Any) -> None:
    ip = _src_ip(alert)
    if not ip:
        return
    try:
        from ..geo import geoip_lookup
        geo = await geoip_lookup(ip)
        alert.setdefault("enrichment", {})["geo"] = geo
    except Exception as exc:
        log.debug("geo enricher failed for %s: %s", ip, exc)


async def _enrich_reputation(alert: dict, wz: Any = None, idx: Any = None, cfg: Any = None, **_: Any) -> None:
    ip = _src_ip(alert)
    if not ip or not cfg:
        return
    import ipaddress
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback:
            return
    except ValueError:
        return
    try:
        from ..tools.threat_intel import _vt_get, _abuse_get
        _rep_results: list[Any] = list(await asyncio.gather(
            _vt_get(f"ip_addresses/{ip}"),
            _abuse_get(ip),
            return_exceptions=True,
        ))
        vt, abuse = _rep_results[0], _rep_results[1]
        alert.setdefault("enrichment", {})["reputation"] = {
            "virustotal": vt if not isinstance(vt, Exception) else {"error": str(vt)},
            "abuseipdb": abuse if not isinstance(abuse, Exception) else {"error": str(abuse)},
        }
    except Exception as exc:
        log.debug("reputation enricher failed for %s: %s", ip, exc)


async def _enrich_mitre(alert: dict, **_: Any) -> None:
    tids = _technique_ids(alert)
    if not tids:
        return
    try:
        from ..mitre_data import enrich_mitre_ids
        alert.setdefault("enrichment", {})["mitre"] = enrich_mitre_ids(tids)
    except Exception as exc:
        log.debug("mitre enricher failed: %s", exc)


async def _enrich_agent_context(alert: dict, wz: Any = None, **_: Any) -> None:
    if not wz:
        return
    agent_id = alert.get("agent", {}).get("id")
    if not agent_id or agent_id == "000":
        return
    try:
        resp = await wz.request("GET", f"/agents/{agent_id}")
        agent_data = (resp.get("data", {}).get("affected_items") or [{}])[0]
        alert.setdefault("enrichment", {})["agent"] = {
            "name": agent_data.get("name"),
            "os": agent_data.get("os", {}).get("name"),
            "group": (agent_data.get("group") or [""])[0],
            "last_keep_alive": agent_data.get("lastKeepAlive"),
            "status": agent_data.get("status"),
        }
    except Exception as exc:
        log.debug("agent enricher failed for agent %s: %s", agent_id, exc)


async def _enrich_frequency(alert: dict, idx: Any = None, cfg: Any = None, **_: Any) -> None:
    if not idx or not cfg:
        return
    rid = _rule_id(alert)
    if not rid:
        return
    try:
        count = await idx.count(
            query={"bool": {"filter": [
                {"term": {"rule.id": rid}},
                {"range": {"timestamp": {"gte": "now-7d/d"}}},
            ]}},
        )
        alert.setdefault("enrichment", {})["frequency"] = {
            "rule_id": rid,
            "count_7d": count,
            "noisy": count > 100,
        }
    except Exception as exc:
        log.debug("frequency enricher failed for rule %s: %s", rid, exc)


# ── Pipeline ───────────────────────────────────────────────────────────────────

_ALL_ENRICHERS = [
    _enrich_geo,
    _enrich_mitre,
    _enrich_agent_context,
    _enrich_frequency,
    _enrich_reputation,   # last — slowest (external VT/AbuseIPDB calls)
]


class EnrichmentPipeline:
    """Runs a configurable set of enrichers concurrently against a single alert dict."""

    def __init__(
        self,
        *,
        wz: Any = None,
        idx: Any = None,
        cfg: Any = None,
        enrichers: list | None = None,
    ) -> None:
        self._wz = wz
        self._idx = idx
        self._cfg = cfg
        self._enrichers = enrichers if enrichers is not None else _ALL_ENRICHERS

    async def run(self, alert: dict) -> dict:
        """Enrich a single alert in-place and return it."""
        await asyncio.gather(
            *[e(alert, wz=self._wz, idx=self._idx, cfg=self._cfg) for e in self._enrichers],
            return_exceptions=True,
        )
        return alert

    async def run_batch(self, alerts: list[dict], max_concurrent: int = 5) -> list[dict]:
        """Enrich a list of alerts with bounded concurrency."""
        sem = asyncio.Semaphore(max_concurrent)

        async def bounded(a: dict) -> dict:
            async with sem:
                return await self.run(a)

        return list(await asyncio.gather(*[bounded(a) for a in alerts]))


# ── Module-level convenience functions ────────────────────────────────────────

async def enrich_alert(
    alert: dict,
    *,
    wz: Any = None,
    idx: Any = None,
    cfg: Any = None,
) -> dict:
    return await EnrichmentPipeline(wz=wz, idx=idx, cfg=cfg).run(alert)


async def enrich_alerts_batch(
    alerts: list[dict],
    *,
    wz: Any = None,
    idx: Any = None,
    cfg: Any = None,
    max_concurrent: int = 5,
) -> list[dict]:
    return await EnrichmentPipeline(wz=wz, idx=idx, cfg=cfg).run_batch(
        alerts, max_concurrent=max_concurrent
    )
