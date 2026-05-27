"""ROI reporting tools — measure and report analyst time saved by Wazuh MCP.

Tools:
  generate_roi_report   — time-saved summary for the last N days
  roi_session_start     — mark the start of a timed investigation session
  roi_session_end       — close a session and get per-session savings
"""
from __future__ import annotations
from ..tool_context import ToolContext

import uuid
from datetime import datetime, timezone


def register(ctx: ToolContext) -> None:
    mcp = ctx.mcp
    wz = ctx.wz
    idx = ctx.idx
    cfg = ctx.cfg
    _cap = ctx.cap
    _truncate = ctx.truncate

    @mcp.tool()
    async def generate_roi_report(days: int = 7) -> dict:
        """Generate an ROI report showing analyst time saved by Wazuh MCP.

        Compares actual MCP tool call durations against industry-baseline manual
        analyst time for equivalent tasks. Use this to demonstrate value to
        management or in sales conversations.

        Args:
            days: Look-back window in days (default 7, max 90).

        Returns:
            Total sessions, tool calls, hours saved, top tools by usage,
            and a formatted summary narrative.
        """
        days = max(1, min(days, 90))
        from ..core.roi_tracker import get_roi_summary, BASELINE_MINUTES
        summary = get_roi_summary(days=days)

        # Build plain-text narrative
        saved_h = summary["time_saved_hours"]
        calls   = summary["tool_calls"]
        sessions = summary["sessions"]
        ratio   = summary["efficiency_ratio"]

        if saved_h >= 40:
            verdict = f"Equivalent to a full analyst work-week ({saved_h:.0f}h saved)."
        elif saved_h >= 8:
            verdict = f"Equivalent to {saved_h:.0f} analyst hours — roughly {saved_h/8:.1f} work-days saved."
        elif saved_h >= 1:
            verdict = f"{saved_h:.1f} analyst hours saved across {sessions} sessions."
        else:
            verdict = f"{summary['time_saved_minutes']:.0f} minutes saved. More sessions needed for a meaningful baseline."

        top_tool_lines = "\n".join(
            f"  • {t['tool']}: {t['calls']} calls, {t['saved_minutes']:.0f} min saved"
            for t in summary["top_tools"][:5]
        )

        narrative = (
            f"ROI Report — last {days} days\n"
            f"{'─' * 40}\n"
            f"Sessions:          {sessions}\n"
            f"Tool calls:        {calls}\n"
            f"Time saved:        {saved_h:.1f} hours\n"
            f"Efficiency ratio:  {ratio}× faster than manual\n"
            f"\n{verdict}\n"
            f"\nTop tools by savings:\n{top_tool_lines}\n"
            f"\nLifetime: {summary['lifetime_calls']} calls, "
            f"{summary['lifetime_saved_minutes']/60:.1f}h saved total."
        )

        return {
            **summary,
            "narrative": narrative,
            "note": (
                "Baseline times sourced from SOC efficiency benchmarks. "
                "Actual savings depend on alert complexity and analyst experience."
            ),
        }

    @mcp.tool()
    async def roi_session_start(label: str = "") -> dict:
        """Start a timed ROI session for a named investigation.

        Call this at the beginning of an investigation to track exactly how much
        time this session saves vs. manual analysis. End with roi_session_end().

        Args:
            label: Optional human-readable label (e.g. 'brute-force-2026-05-26').
        """
        from ..core.roi_tracker import session_start
        session_id = str(uuid.uuid4())[:8]
        if label:
            session_id = f"{label}-{session_id}"
        session_start(session_id)
        return {
            "status": "started",
            "session_id": session_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "message": (
                f"ROI session '{session_id}' started. "
                "Run your investigation, then call roi_session_end() to see time saved."
            ),
        }

    @mcp.tool()
    async def roi_session_end() -> dict:
        """End the current ROI session and return per-session time-saved summary.

        Returns tool call count, total saved minutes vs. analyst baseline,
        and a per-tool breakdown for this investigation.
        """
        from ..core.roi_tracker import session_end
        sess = session_end()
        if not sess:
            return {
                "error": "No active ROI session. Call roi_session_start() first.",
            }

        saved_min = sess.get("saved_minutes", 0.0)
        call_count = sess.get("call_count", len(sess.get("calls", [])))

        top_calls = sorted(
            sess.get("calls", []),
            key=lambda c: -c.get("saved_min", 0),
        )[:5]

        return {
            "session_id": sess["session_id"],
            "started_at": sess.get("started_at"),
            "ended_at": sess.get("ended_at"),
            "call_count": call_count,
            "saved_minutes": saved_min,
            "saved_hours": round(saved_min / 60, 2),
            "actual_time_seconds": sess.get("actual_seconds", 0.0),
            "top_savings": [
                {
                    "tool": c["tool"],
                    "baseline_min": c["baseline_min"],
                    "actual_s": c["duration_s"],
                    "saved_min": c["saved_min"],
                }
                for c in top_calls
            ],
            "summary": (
                f"This investigation: {call_count} tool calls, "
                f"{saved_min:.0f} min saved vs. manual analysis "
                f"({saved_min/60:.1f}h)."
            ),
        }
