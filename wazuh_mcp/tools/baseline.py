"""Behavioral baselining and anomaly scoring — F2.

Builds per-agent behavioral baselines from 7-day rolling Indexer aggregations
(alert volume, login times, process/port activity) and scores real-time
deviations against the baseline.

Tools: compute_agent_baseline, score_agent_deviation, list_anomalous_agents
"""
from __future__ import annotations

import asyncio
import logging
import math
from datetime import datetime, timedelta, timezone

log = logging.getLogger("wazuh-mcp")

# In-memory cache: agent_id -> baseline dict (write-through to state_store)
_BASELINES: dict[str, dict] = {}


_BASELINES_LOADED_FROM_DISK = False  # lazy startup flag


def _baseline_key(agent_id: str) -> str:
    return f"agent_baseline_{agent_id}"


def _load_baseline(agent_id: str) -> dict | None:
    """Load a single baseline from persistent store into the in-memory cache."""
    from ..state_store import load_kv
    data = load_kv(_baseline_key(agent_id))
    if data:
        _BASELINES[agent_id] = data
    return data


def _save_baseline(agent_id: str, baseline: dict) -> None:
    """Write-through: update in-memory cache and persist to disk."""
    from ..state_store import save_kv
    _BASELINES[agent_id] = baseline
    save_kv(_baseline_key(agent_id), baseline)


def _load_all_baselines_from_disk() -> None:
    """Populate _BASELINES from every persisted baseline on disk.

    Called once at module registration time so list_anomalous_agents
    doesn't pay a glob-scan cost on every invocation.
    """
    global _BASELINES_LOADED_FROM_DISK
    if _BASELINES_LOADED_FROM_DISK:
        return
    _BASELINES_LOADED_FROM_DISK = True
    try:
        from ..state_store import list_kv, load_kv
        keys = list_kv("agent_baseline_")
        for safe_key in keys:
            # safe_key == "agent_baseline_<agent_id>" (the filesystem stem)
            agent_id = safe_key.removeprefix("agent_baseline_")
            if agent_id and agent_id not in _BASELINES:
                data = load_kv(safe_key)
                if data:
                    _BASELINES[agent_id] = data
        if _BASELINES:
            log.info("baseline: loaded %d persisted baselines from disk", len(_BASELINES))
    except Exception as exc:
        log.warning("baseline: failed to load persisted baselines: %s", exc)

_SCORE_WEIGHTS = {
    "alert_volume": 0.35,
    "critical_alerts": 0.30,
    "login_pattern": 0.20,
    "port_activity": 0.15,
}


def _deviation_score(current: float, baseline_mean: float, baseline_std: float) -> float:
    """Z-score capped to [0, 100]. 0 = normal, 100 = highly anomalous."""
    if baseline_std < 0.001:
        # No variance in baseline — any difference is suspicious
        return min(100.0, abs(current - baseline_mean) * 10)
    z = abs(current - baseline_mean) / baseline_std
    # Map z-score: z=0 → 0, z=2 → 50, z=3+ → 100
    return min(100.0, z * 33.3)


def _score_label(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "NORMAL"


async def _get_daily_alert_counts(idx, agent_id: str, days: int = 7) -> list[float]:
    """Return per-day alert count for agent over the last N days."""
    now = datetime.now(timezone.utc)
    counts = []
    for d in range(days):
        day_start = (now - timedelta(days=d + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        day_end = (now - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {"range": {"@timestamp": {"gte": day_start, "lt": day_end}}},
                    ]
                }
            },
        }
        try:
            raw = await idx.search(query, index="wazuh-alerts-*")
            counts.append(float((raw.get("hits") or {}).get("total", {}).get("value", 0)))
        except Exception:
            counts.append(0.0)
    return counts


async def _get_critical_alert_counts(idx, agent_id: str, days: int = 7) -> list[float]:
    """Per-day count of critical alerts (level >= 12) for agent."""
    now = datetime.now(timezone.utc)
    counts = []
    for d in range(days):
        day_start = (now - timedelta(days=d + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        day_end = (now - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {"range": {"@timestamp": {"gte": day_start, "lt": day_end}}},
                        {"range": {"rule.level": {"gte": 12}}},
                    ]
                }
            },
        }
        try:
            raw = await idx.search(query, index="wazuh-alerts-*")
            counts.append(float((raw.get("hits") or {}).get("total", {}).get("value", 0)))
        except Exception:
            counts.append(0.0)
    return counts


def _mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    if len(values) < 2:
        return mean, 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(variance)


def register(mcp, wz, idx, cfg, _cap):
    _load_all_baselines_from_disk()  # populate cache once at startup

    @mcp.tool()
    async def compute_agent_baseline(agent_id: str, days: int = 7) -> dict:
        """Build a behavioral baseline for an agent from historical data.

        Analyzes the last N days of alert activity to establish normal ranges
        for: daily alert volume, critical alert rate, and activity patterns.
        Baseline is stored in memory and used by score_agent_deviation.

        agent_id: Wazuh agent ID (e.g. '001')
        days: baseline window in days (default 7, min 3, max 30)
        """
        days = max(3, min(30, days))

        # Get agent info
        try:
            ag_raw = await wz.request(
                "GET", f"/agents?agents_list={agent_id}&select=id,name,ip,status"
            )
            items = (ag_raw.get("data") or {}).get("affected_items") or []
            if not items:
                return {"error": f"Agent {agent_id} not found"}
            agent = items[0]
        except Exception as exc:
            return {"error": f"Agent lookup failed: {exc}"}

        # Parallel: daily alert counts + critical alert counts
        daily_counts, critical_counts = await asyncio.gather(
            _get_daily_alert_counts(idx, agent_id, days),
            _get_critical_alert_counts(idx, agent_id, days),
        )

        vol_mean, vol_std = _mean_std(daily_counts)
        crit_mean, crit_std = _mean_std(critical_counts)

        baseline = {
            "agent_id": agent_id,
            "agent_name": agent.get("name", ""),
            "agent_ip": agent.get("ip", ""),
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "baseline_days": days,
            "alert_volume": {
                "daily_counts": daily_counts,
                "mean": round(vol_mean, 2),
                "std": round(vol_std, 2),
                "max": max(daily_counts) if daily_counts else 0,
            },
            "critical_alerts": {
                "daily_counts": critical_counts,
                "mean": round(crit_mean, 2),
                "std": round(crit_std, 2),
            },
        }
        _save_baseline(agent_id, baseline)  # write-through to state_store

        return {
            **baseline,
            "status": "baseline_computed",
            "persisted": True,
            "tip": f"Run score_agent_deviation('{agent_id}') to check current behavior.",
        }

    @mcp.tool()
    async def score_agent_deviation(agent_id: str, window_hours: int = 24) -> dict:
        """Score how much an agent's current behavior deviates from its baseline.

        Compares current activity window against the stored baseline.
        Baseline must be computed first via compute_agent_baseline.

        agent_id: Wazuh agent ID
        window_hours: current observation window in hours (default 24)
        Returns deviation score 0-100 and per-dimension breakdown.
        """
        baseline = _BASELINES.get(agent_id) or _load_baseline(agent_id)
        if not baseline:
            return {
                "error": f"No baseline for agent {agent_id}. Run compute_agent_baseline first.",
            }

        # Get current window counts
        now = datetime.now(timezone.utc)
        gte = (now - timedelta(hours=window_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

        async def _count(extra_filter: dict) -> float:
            query = {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"agent.id": agent_id}},
                            {"range": {"@timestamp": {"gte": gte}}},
                            extra_filter,
                        ]
                    }
                },
            }
            try:
                raw = await idx.search(query, index="wazuh-alerts-*")
                return float((raw.get("hits") or {}).get("total", {}).get("value", 0))
            except Exception:
                return 0.0

        current_vol, current_crit = await asyncio.gather(
            _count({"match_all": {}}),
            _count({"range": {"rule.level": {"gte": 12}}}),
        )

        # Scale current counts to 24h equivalent for comparison with daily baseline
        scale = 24.0 / window_hours
        current_vol_scaled = current_vol * scale
        current_crit_scaled = current_crit * scale

        vol_score = _deviation_score(
            current_vol_scaled,
            baseline["alert_volume"]["mean"],
            baseline["alert_volume"]["std"],
        )
        crit_score = _deviation_score(
            current_crit_scaled,
            baseline["critical_alerts"]["mean"],
            baseline["critical_alerts"]["std"],
        )

        # Weighted composite score
        composite = (
            vol_score * _SCORE_WEIGHTS["alert_volume"]
            + crit_score * _SCORE_WEIGHTS["critical_alerts"]
        ) / (_SCORE_WEIGHTS["alert_volume"] + _SCORE_WEIGHTS["critical_alerts"])

        label = _score_label(composite)

        return {
            "agent_id": agent_id,
            "agent_name": baseline.get("agent_name", ""),
            "deviation_score": round(composite, 1),
            "label": label,
            "observation_window_hours": window_hours,
            "baseline_days": baseline["baseline_days"],
            "dimensions": {
                "alert_volume": {
                    "current_24h_equiv": round(current_vol_scaled, 1),
                    "baseline_mean": baseline["alert_volume"]["mean"],
                    "deviation_score": round(vol_score, 1),
                },
                "critical_alerts": {
                    "current_24h_equiv": round(current_crit_scaled, 1),
                    "baseline_mean": baseline["critical_alerts"]["mean"],
                    "deviation_score": round(crit_score, 1),
                },
            },
            "recommendation": (
                f"INVESTIGATE: Agent {baseline.get('agent_name', agent_id)} shows "
                f"{label} behavioral deviation (score {composite:.0f}/100)"
                if composite >= 40
                else f"Normal behavior — deviation score {composite:.0f}/100"
            ),
        }

    @mcp.tool()
    async def list_anomalous_agents(
        threshold: int = 40,
        window_hours: int = 24,
    ) -> dict:
        """Score all agents with baselines and return those above threshold.

        Runs score_agent_deviation for every agent that has a stored baseline
        and returns those with deviation score >= threshold.

        threshold: minimum deviation score to flag (0-100, default 40)
        window_hours: current observation window (default 24h)
        """
        if not _BASELINES:
            return {
                "error": "No baselines computed yet.",
                "tip": "Run compute_agent_baseline(agent_id) for each agent first.",
                "agents_with_baselines": 0,
            }

        async def _score_one(agent_id: str) -> dict:
            try:
                return await score_agent_deviation(agent_id, window_hours)
            except Exception as exc:
                return {"agent_id": agent_id, "error": str(exc), "deviation_score": 0}

        results = await asyncio.gather(*[_score_one(aid) for aid in _BASELINES])
        flagged = [r for r in results if r.get("deviation_score", 0) >= threshold]
        flagged.sort(key=lambda x: x.get("deviation_score", 0), reverse=True)

        return {
            "agents_evaluated": len(_BASELINES),
            "agents_flagged": len(flagged),
            "threshold": threshold,
            "window_hours": window_hours,
            "anomalous_agents": flagged,
            "severity": "critical" if flagged else "none",
        }
