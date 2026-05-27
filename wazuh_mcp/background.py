"""Background pre-computation worker for critical alerts.

Polls OpenSearch every 60 seconds for level-12+ alerts and caches compact
summaries so explain_alert and get_precomputed_summary can return instantly
instead of making 5+ live API calls.

Usage (HTTP mode — wired into Starlette lifespan in server.py):
    from .background import init_precomputer
    pc = init_precomputer(idx_proxy, cfg)
    pc.start()   # on startup
    pc.stop()    # on shutdown
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

log = logging.getLogger(__name__)

_MAX_CACHE_SIZE = 500   # evict oldest when exceeded
_POLL_INTERVAL  = 60    # seconds between polls
_ALERT_WINDOW   = "1h"  # look-back window for critical alerts


class AlertPrecomputer:
    """Background asyncio task that pre-computes summaries for critical alerts."""

    def __init__(self, idx: Any, cfg: Any) -> None:
        self._idx  = idx
        self._cfg  = cfg
        self._cache: dict[str, dict] = {}   # alert_id → summary
        self._task: asyncio.Task | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._task = asyncio.create_task(self._poll_loop(), name="alert-precomputer")
        log.info("AlertPrecomputer started (poll_interval=%ds window=%s)", _POLL_INTERVAL, _ALERT_WINDOW)

    def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            log.info("AlertPrecomputer stopped")

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_summary(self, alert_id: str) -> dict | None:
        """Return pre-computed summary for alert_id, or None if not yet cached."""
        return self._cache.get(alert_id)

    def cache_stats(self) -> dict:
        return {"cached_alerts": len(self._cache), "max_cache_size": _MAX_CACHE_SIZE}

    # ── Internal ───────────────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(_POLL_INTERVAL)
                await self._precompute_critical()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("AlertPrecomputer poll error: %s", exc)

    async def _precompute_critical(self) -> None:
        try:
            res = await self._idx.search({
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": f"now-{_ALERT_WINDOW}"}}},
                    {"range": {"rule.level": {"gte": 12}}},
                ]}},
                "_source": ["@timestamp", "rule.id", "rule.level", "rule.description",
                            "rule.mitre", "agent.id", "agent.name", "data.srcip", "full_log"],
            })
        except Exception as exc:
            log.error("AlertPrecomputer indexer query failed: %s", exc)
            return

        hits = res.get("hits", {}).get("hits", [])
        new_ids = 0
        for hit in hits:
            alert_id = hit["_id"]
            if alert_id in self._cache:
                continue
            src   = hit.get("_source", {})
            rule  = src.get("rule", {})
            agent = src.get("agent", {})
            self._cache[alert_id] = {
                "alert_id":         alert_id,
                "timestamp":        src.get("@timestamp"),
                "rule_id":          rule.get("id"),
                "rule_level":       rule.get("level"),
                "rule_description": rule.get("description"),
                "agent_name":       agent.get("name"),
                "agent_id":         agent.get("id"),
                "src_ip":           src.get("data", {}).get("srcip"),
                "mitre":            rule.get("mitre", {}),
                "log_snippet":      (src.get("full_log") or "")[:200],
                "precomputed":      True,
            }
            new_ids += 1

        # Evict oldest entries when cache exceeds limit
        if len(self._cache) > _MAX_CACHE_SIZE:
            evict_n = len(self._cache) - _MAX_CACHE_SIZE
            for old_key in list(self._cache.keys())[:evict_n]:
                del self._cache[old_key]

        if new_ids:
            log.debug("AlertPrecomputer: cached %d new critical alerts", new_ids)


# ── Module-level singleton ─────────────────────────────────────────────────────
# Populated by init_precomputer() in server.py at Starlette startup.
_precomputer: AlertPrecomputer | None = None


def init_precomputer(idx: Any, cfg: Any) -> AlertPrecomputer:
    global _precomputer
    _precomputer = AlertPrecomputer(idx, cfg)
    return _precomputer


def get_precomputer() -> AlertPrecomputer | None:
    return _precomputer
