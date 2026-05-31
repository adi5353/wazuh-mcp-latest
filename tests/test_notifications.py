"""Tests for Slack/Teams/email notification tools.

The module captures Slack/SMTP/Teams settings from the environment at
``register()`` time, so each test sets the env first, then registers the module
against a context whose ``shared`` dict carries the report-generator callables
the notification tools depend on.
"""
from __future__ import annotations

import asyncio
import importlib
from unittest.mock import AsyncMock, MagicMock

import pytest


def _run(coro):
    return asyncio.run(coro)


class _Resp:
    def __init__(self, data=None):
        self._data = data if data is not None else {"ok": True, "ts": "1.2"}
        self.status_code = 200

    def json(self):
        return self._data

    def raise_for_status(self):
        return None


class _FakeClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        return _Resp()


def _make_notif_env(shared=None):
    from wazuh_mcp.tool_context import ToolContext
    tools: dict = {}
    mcp = MagicMock()
    mcp.tool = lambda *a, **k: (lambda fn: tools.__setitem__(fn.__name__, fn) or fn)
    ctx = ToolContext(
        mcp=mcp, wz=AsyncMock(), idx=AsyncMock(), cfg=MagicMock(),
        cap=lambda n: n, require_writes=lambda: None,
        truncate=lambda s, n=300: s,
        enrich_mitre_ids=lambda ids: [{"id": i} for i in (ids or [])],
        geoip_lookup=AsyncMock(return_value={}),
        incident_recommendations=lambda *a, **k: [],
        tool_registry={},
        shared=shared or {},
    )
    mod = importlib.import_module("wazuh_mcp.tools.notifications")
    mod.register(ctx)
    return tools, mod


@pytest.fixture
def patched_httpx(monkeypatch):
    mod = importlib.import_module("wazuh_mcp.tools.notifications")
    monkeypatch.setattr(mod.httpx, "AsyncClient", lambda *a, **k: _FakeClient())
    return mod


class TestSlack:
    def test_not_configured(self, monkeypatch):
        for k in ("SLACK_WEBHOOK_URL", "SLACK_BOT_TOKEN"):
            monkeypatch.delenv(k, raising=False)
        tools, _ = _make_notif_env()
        out = _run(tools["send_alert_to_slack"](message="hi"))
        assert "error" in out

    def test_send_alert_webhook(self, monkeypatch, patched_httpx):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/xxx")
        tools, _ = _make_notif_env()
        out = _run(tools["send_alert_to_slack"](
            message="boom", title="Alert", severity="critical",
            fields={"agent": "host1"}, ticket_url="http://t"))
        assert out["status"] == "ok" and out["method"] == "webhook"

    def test_send_critical_alert(self, monkeypatch, patched_httpx):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/xxx")
        tools, _ = _make_notif_env()
        out = _run(tools["send_critical_alert_notify"](
            alert_id="a1", rule_id="5710", rule_description="brute force",
            agent_name="web01", severity_level=13, source_ip="8.8.8.8",
            ticket_url="http://jira/1"))
        assert out["severity_tier"] == "CRITICAL" and out["status"] == "ok"

    def test_shift_handover(self, monkeypatch, patched_httpx):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/xxx")
        report = {
            "alert_overview": {"total_alerts": 42, "trend": {"direction": "up"},
                               "top_rules": [{"rule_id": "5710", "count": 7, "description": "ssh"}]},
            "shift_handover": {"attention_items": ["host1 noisy"]},
            "volume_vs_baseline": {"delta_pct": 12.5},
        }
        shared = {"generate_shift_handover": AsyncMock(return_value=report)}
        tools, _ = _make_notif_env(shared)
        out = _run(tools["send_shift_handover_to_slack"](analyst_name="Sam"))
        assert out["status"] == "ok" and out["analyst"] == "Sam"

    def test_weekly_summary(self, monkeypatch, patched_httpx):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/xxx")
        report = {
            "alert_counts": {"this_week": 100, "trend_pct": -5.0, "trend_direction": "down"},
            "top_rules": [{"rule": "ssh brute", "count": 9}],
            "top_mitre_techniques": [{"id": "T1110", "name": "Brute Force", "count": 4}],
        }
        shared = {"generate_weekly_summary": AsyncMock(return_value=report)}
        tools, _ = _make_notif_env(shared)
        out = _run(tools["send_weekly_summary_to_slack"](week_offset=1))
        assert out["status"] == "ok" and out["week_offset"] == 1


class TestEmail:
    def test_smtp_not_configured(self, monkeypatch):
        monkeypatch.delenv("SMTP_USER", raising=False)
        monkeypatch.delenv("SMTP_PASS", raising=False)
        tools, _ = _make_notif_env()
        out = _run(tools["email_compliance_report"]())
        assert "error" in out

    def test_no_recipients(self, monkeypatch):
        monkeypatch.setenv("SMTP_USER", "soc@example.com")
        monkeypatch.setenv("SMTP_PASS", "pw")
        monkeypatch.delenv("REPORT_EMAIL_TO", raising=False)
        tools, _ = _make_notif_env()
        out = _run(tools["email_compliance_report"]())
        assert "error" in out and "recipient" in out["error"].lower()

    def test_email_sends(self, monkeypatch):
        monkeypatch.setenv("SMTP_USER", "soc@example.com")
        monkeypatch.setenv("SMTP_PASS", "pw")
        monkeypatch.setenv("REPORT_EMAIL_TO", "ciso@example.com")
        report = {
            "controls": [{"control": "1.1", "total_alerts": 3, "status": "FAILING",
                          "top_agents": ["h1"]},
                         {"control": "1.2", "total_alerts": 0, "status": "PASSING",
                          "top_agents": []}],
            "failing_controls_count": 1,
            "total_alerts": 3,
        }
        shared = {"generate_compliance_report": AsyncMock(return_value=report)}
        tools, mod = _make_notif_env(shared)

        sent = {"called": False}

        class _SMTP:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def ehlo(self):
                pass

            def starttls(self):
                pass

            def login(self, *a):
                pass

            def sendmail(self, *a):
                sent["called"] = True

        monkeypatch.setattr(mod.smtplib, "SMTP", _SMTP)
        out = _run(tools["email_compliance_report"](framework="pci_dss"))
        assert out["status"] == "ok" and sent["called"]

    def test_email_report_error_propagates(self, monkeypatch):
        monkeypatch.setenv("SMTP_USER", "soc@example.com")
        monkeypatch.setenv("SMTP_PASS", "pw")
        monkeypatch.setenv("REPORT_EMAIL_TO", "ciso@example.com")
        shared = {"generate_compliance_report": AsyncMock(return_value={"error": "no data"})}
        tools, _ = _make_notif_env(shared)
        out = _run(tools["email_compliance_report"]())
        assert out == {"error": "no data"}


def _required_args(fn) -> dict:
    """Fill a tool's required (no-default) parameters with plausible values."""
    import inspect
    defaults = {
        "message": "hello", "title": "Alert", "alert_id": "a1", "rule_id": "5710",
        "rule_description": "brute force", "agent_name": "host1",
        "severity_level": 12, "framework": "pci_dss", "source_ip": "8.8.8.8",
    }
    kwargs: dict = {}
    for pname, p in inspect.signature(fn).parameters.items():
        if p.default is inspect.Parameter.empty and pname not in ("self",):
            kwargs[pname] = defaults.get(pname, "x")
    return kwargs


class TestTeams:
    def test_teams_not_configured(self, monkeypatch):
        monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
        tools, _ = _make_notif_env()
        teams_tools = [n for n in tools if "teams" in n]
        assert teams_tools  # the module exposes Teams notification tools
        for name in teams_tools:
            out = _run(tools[name](**_required_args(tools[name])))
            assert "error" in out

    def test_teams_send_ok(self, monkeypatch, patched_httpx):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/x")
        tools, _ = _make_notif_env()
        name = "send_alert_to_teams"
        if name in tools:
            out = _run(tools[name](**_required_args(tools[name])))
            assert "error" not in out or out.get("status") == "ok"
