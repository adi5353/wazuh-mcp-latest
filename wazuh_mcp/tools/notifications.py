"""Notification tools — Slack alerts, shift handover delivery, weekly summary delivery, email compliance report."""
from __future__ import annotations

import datetime
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

log = logging.getLogger("wazuh-mcp")

_SOAR_TIMEOUT = 15


def register(
    mcp, wz, idx, cfg,
    generate_shift_handover,
    generate_weekly_summary,
    generate_compliance_report,
):

    _SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL", "")
    _SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
    _SLACK_CHANNEL   = os.getenv("SLACK_DEFAULT_CHANNEL", "#soc-alerts")
    _SLACK_SOC_CHANNEL  = os.getenv("SLACK_SOC_CHANNEL", _SLACK_CHANNEL)
    _SLACK_MGMT_CHANNEL = os.getenv("SLACK_MGMT_CHANNEL", "#security-mgmt")
    _SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    _SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    _SMTP_USER = os.getenv("SMTP_USER", "")
    _SMTP_PASS = os.getenv("SMTP_PASS", "")
    _EMAIL_FROM = os.getenv("REPORT_EMAIL_FROM", _SMTP_USER)
    _EMAIL_TO   = os.getenv("REPORT_EMAIL_TO", "")

    async def _post_slack_blocks(channel: str, blocks: list, fallback: str) -> dict:
        if _SLACK_WEBHOOK:
            try:
                async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                    r = await client.post(
                        _SLACK_WEBHOOK,
                        json={"blocks": blocks, "text": fallback},
                    )
                r.raise_for_status()
                return {"status": "ok", "method": "webhook"}
            except Exception as e:
                return {"error": str(e)}

        if _SLACK_BOT_TOKEN:
            try:
                async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                    r = await client.post(
                        "https://slack.com/api/chat.postMessage",
                        json={"channel": channel, "blocks": blocks, "text": fallback},
                        headers={
                            "Authorization": f"Bearer {_SLACK_BOT_TOKEN}",
                            "Content-Type":  "application/json",
                        },
                    )
                data = r.json()
                if not data.get("ok"):
                    return {"error": f"Slack: {data.get('error')}"}
                return {"status": "ok", "method": "bot_token", "ts": data.get("ts")}
            except Exception as e:
                return {"error": str(e)}

        return {"error": "Slack not configured. Add SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN to .env."}

    @mcp.tool()
    async def send_alert_to_slack(
        message: str,
        title: str | None = None,
        severity: str = "info",
        channel: str | None = None,
        fields: dict | None = None,
        ticket_url: str | None = None,
    ) -> dict:
        """Push a formatted message to a Slack channel.

        Use for ad-hoc notifications, critical alert escalations, or sharing reports.
        severity: info | warning | critical  (controls attachment colour)
        channel: override default channel (e.g. '#incident-response')
        fields: dict of key→value pairs shown as Slack attachment fields
        ticket_url: link to Jira/TheHive ticket if already created
        Requires SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN in .env.
        """
        if not _SLACK_WEBHOOK and not _SLACK_BOT_TOKEN:
            return {
                "error": "Slack not configured. Add SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN to .env."
            }

        color_map = {"critical": "#ff0000", "warning": "#ffaa00", "info": "#36a64f"}
        color = color_map.get(severity.lower(), "#36a64f")

        attachment: dict = {"color": color, "text": message, "mrkdwn_in": ["text", "fields"]}
        if title:
            attachment["title"] = title
        if ticket_url:
            attachment["title_link"] = ticket_url
            attachment["footer"] = "Wazuh MCP"
        if fields:
            attachment["fields"] = [
                {"title": k, "value": str(v), "short": len(str(v)) < 40}
                for k, v in fields.items()
            ]

        target_channel = channel or _SLACK_CHANNEL

        if _SLACK_WEBHOOK:
            try:
                async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                    r = await client.post(_SLACK_WEBHOOK, json={"attachments": [attachment]})
                r.raise_for_status()
                log.info("Slack message sent via webhook severity=%s", severity)
                return {"status": "ok", "method": "webhook", "message": "Sent to Slack."}
            except Exception as e:
                return {"error": f"Slack webhook failed: {e}"}

        try:
            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                r = await client.post(
                    "https://slack.com/api/chat.postMessage",
                    json={"channel": target_channel, "attachments": [attachment]},
                    headers={
                        "Authorization": f"Bearer {_SLACK_BOT_TOKEN}",
                        "Content-Type":  "application/json",
                    },
                )
            data = r.json()
            if not data.get("ok"):
                return {"error": f"Slack API error: {data.get('error')}"}
            log.info("Slack message sent via bot token to %s", target_channel)
            return {"status": "ok", "method": "bot_token", "channel": target_channel}
        except Exception as e:
            return {"error": str(e)}

    @mcp.tool()
    async def send_shift_handover_to_slack(
        analyst_name: str = "SOC Analyst",
        shift_duration: str = "8h",
        channel: str | None = None,
    ) -> dict:
        """Generate a shift handover report and push it to Slack immediately.

        shift_duration: '6h', '8h', '12h', '24h'
        Requires SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN in .env.
        """
        if not _SLACK_WEBHOOK and not _SLACK_BOT_TOKEN:
            return {"error": "Slack not configured. Add SLACK_WEBHOOK_URL to .env."}

        report = await generate_shift_handover(
            shift_duration=shift_duration,
            analyst_name=analyst_name,
        )

        ts_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        target = channel or _SLACK_SOC_CHANNEL

        overview = report.get("alert_overview") or {}
        total_alerts = overview.get("total_alerts", "N/A")
        trend = (overview.get("trend") or {}).get("direction", "?")

        attention_items = (report.get("shift_handover") or {}).get("attention_items", [])
        attention_text  = "\n".join(f"• {item}" for item in attention_items[:5])

        top_rules = overview.get("top_rules", [])[:5]
        rules_text = "\n".join(
            f"• Rule {r.get('rule_id')} — {r.get('count')} alerts ({r.get('description', '')[:50]})"
            for r in top_rules
        ) or "_No significant rules_"

        volume_data = report.get("volume_vs_baseline") or {}
        delta_pct   = volume_data.get("delta_pct")
        volume_text = f"{delta_pct:+.1f}% vs prior period" if isinstance(delta_pct, (int, float)) else "N/A"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"Wazuh Shift Handover — {ts_str}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Outgoing analyst:*\n{analyst_name}"},
                    {"type": "mrkdwn", "text": f"*Shift:*\n{shift_duration}"},
                    {"type": "mrkdwn", "text": f"*Total alerts:*\n{total_alerts} {trend}"},
                    {"type": "mrkdwn", "text": f"*Volume vs baseline:*\n{volume_text}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Attention items*\n{attention_text or 'Clean handover — no anomalies.'}",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top rules this shift*\n{rules_text}"},
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "Posted by Wazuh MCP"}],
            },
        ]

        result = await _post_slack_blocks(target, blocks, f"Wazuh Shift Handover — {ts_str}")
        return {**result, "channel": target, "analyst": analyst_name, "shift_duration": shift_duration}

    @mcp.tool()
    async def send_weekly_summary_to_slack(
        week_offset: int = 0,
        channel: str | None = None,
    ) -> dict:
        """Generate the weekly security summary and push it to Slack.

        week_offset: 0 = current week, 1 = last week.
        Requires SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN in .env.
        """
        if not _SLACK_WEBHOOK and not _SLACK_BOT_TOKEN:
            return {"error": "Slack not configured. Add SLACK_WEBHOOK_URL to .env."}

        report = await generate_weekly_summary(week_offset=week_offset)

        ts_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        label  = "This week" if week_offset == 0 else "Last week"
        target = channel or _SLACK_MGMT_CHANNEL

        counts  = report.get("alert_counts") or {}
        total   = counts.get("this_week", "N/A")
        delta   = counts.get("trend_pct")
        trend   = counts.get("trend_direction", "?")
        delta_s = f"{delta:+.1f}%" if isinstance(delta, (int, float)) else "N/A"

        top_rules = report.get("top_rules", [])[:5]
        rules_text = "\n".join(
            f"• {r.get('rule')} — {r.get('count')} alerts" for r in top_rules
        ) or "_No significant rules_"

        top_mitre = report.get("top_mitre_techniques", [])[:3]
        mitre_text = "\n".join(
            f"• {t.get('id')} {t.get('name', '')} ({t.get('count', 0)})" for t in top_mitre
        ) or "_None observed_"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"Weekly Security Summary — {label} ({ts_str})"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total alerts:*\n{total} {trend}"},
                    {"type": "mrkdwn", "text": f"*Week-on-week:*\n{delta_s}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top rules*\n{rules_text}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top MITRE techniques*\n{mitre_text}"},
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "Posted by Wazuh MCP"}],
            },
        ]

        result = await _post_slack_blocks(target, blocks, f"Wazuh Weekly Summary — {ts_str}")
        return {**result, "channel": target, "week_offset": week_offset}

    @mcp.tool()
    async def send_critical_alert_notify(
        alert_id: str,
        rule_id: str,
        rule_description: str,
        agent_name: str,
        severity_level: int,
        source_ip: str | None = None,
        channel: str | None = None,
        ticket_url: str | None = None,
    ) -> dict:
        """Fire an instant Slack notification for a critical alert.

        severity_level >= 12 → CRITICAL (red), 9-11 → HIGH (orange), <9 → MEDIUM (yellow).
        ticket_url: link to Jira/TheHive ticket if already created.
        Requires SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN in .env.
        """
        if not _SLACK_WEBHOOK and not _SLACK_BOT_TOKEN:
            return {"error": "Slack not configured. Add SLACK_WEBHOOK_URL to .env."}

        ts_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        target = channel or _SLACK_SOC_CHANNEL

        if severity_level >= 12:
            tier = "CRITICAL"; color = "#ff0000"
        elif severity_level >= 9:
            tier = "HIGH";     color = "#ff6600"
        else:
            tier = "MEDIUM";   color = "#ffaa00"

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"[{tier}] Alert — {ts_str}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Rule:* `{rule_id}`"},
                    {"type": "mrkdwn", "text": f"*Level:* {severity_level}"},
                    {"type": "mrkdwn", "text": f"*Agent:* {agent_name}"},
                    {"type": "mrkdwn", "text": f"*Source IP:* {source_ip or 'N/A'}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{rule_description}*"},
            },
        ]

        if ticket_url:
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type":  "button",
                    "text":  {"type": "plain_text", "text": "View Ticket"},
                    "url":   ticket_url,
                    "style": "danger",
                }],
            })

        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Alert ID: `{alert_id}` | Wazuh MCP"},
            ],
        })

        result = await _post_slack_blocks(
            target, blocks,
            f"[{tier}] Rule {rule_id} on {agent_name}: {rule_description}",
        )
        return {**result, "channel": target, "severity_tier": tier, "alert_id": alert_id}

    @mcp.tool()
    async def email_compliance_report(
        framework: str = "pci_dss",
        time_range: str = "168h",
        recipients: list | None = None,
    ) -> dict:
        """Generate a compliance report and email it as formatted HTML.

        framework: pci_dss | hipaa | gdpr | nist_800_53 | tsc
        time_range: reporting window (168h = 7 days)
        recipients: list of email addresses (overrides REPORT_EMAIL_TO env var)
        Requires SMTP_USER, SMTP_PASS, REPORT_EMAIL_TO in .env.
        """
        if not _SMTP_USER or not _SMTP_PASS:
            return {"error": "SMTP not configured. Add SMTP_USER and SMTP_PASS to .env."}

        to_addresses = recipients or [r.strip() for r in _EMAIL_TO.split(",") if r.strip()]
        if not to_addresses:
            return {
                "error": "No recipients. Set REPORT_EMAIL_TO in .env or pass recipients list."
            }

        report = await generate_compliance_report(framework=framework, time_range=time_range)
        if "error" in report:
            return report

        ts_str  = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        subject = f"[Wazuh SOC] {framework.upper()} Compliance Report — {ts_str}"

        controls     = report.get("controls", [])
        failing_cnt  = report.get("failing_controls_count", 0)
        total_alerts = report.get("total_alerts", 0)

        rows_html = ""
        for ctrl in controls[:30]:
            color = "#d32f2f" if ctrl.get("status") == "FAILING" else (
                    "#f57c00" if ctrl.get("status") == "WARNING" else "#388e3c")
            rows_html += (
                f"<tr>"
                f"<td style='padding:5px 8px;border-bottom:1px solid #eee'>{ctrl.get('control','')}</td>"
                f"<td style='padding:5px 8px;border-bottom:1px solid #eee'>{ctrl.get('total_alerts',0)}</td>"
                f"<td style='padding:5px 8px;border-bottom:1px solid #eee;color:{color};font-weight:bold'>"
                f"{ctrl.get('status','')}</td>"
                f"<td style='padding:5px 8px;border-bottom:1px solid #eee;font-size:12px'>"
                f"{', '.join(ctrl.get('top_agents',[])[:3])}</td>"
                f"</tr>"
            )

        html = f"""<!DOCTYPE html>
<html><body style='font-family:Arial,sans-serif;color:#222;max-width:820px;margin:auto'>
<h2 style='background:#1a237e;color:#fff;padding:14px 18px;border-radius:4px;margin:0'>
  {framework.upper()} Compliance Report &mdash; {ts_str}
</h2>
<p style='color:#555;margin:12px 0'>
  Reporting window: <strong>{time_range}</strong> &nbsp;|&nbsp;
  Generated by: <strong>Wazuh MCP</strong>
</p>
<table style='width:100%;border-collapse:collapse;margin-bottom:20px'>
  <tr>
    <td style='background:#e8eaf6;padding:12px;border-radius:4px;text-align:center;width:33%'>
      <div style='font-size:26px;font-weight:bold'>{total_alerts}</div>
      <div style='color:#555;font-size:13px'>Total alerts</div>
    </td>
    <td style='width:2%'></td>
    <td style='background:#fce4ec;padding:12px;border-radius:4px;text-align:center;width:33%'>
      <div style='font-size:26px;font-weight:bold;color:#c62828'>{failing_cnt}</div>
      <div style='color:#555;font-size:13px'>Failing controls</div>
    </td>
    <td style='width:2%'></td>
    <td style='background:#e8f5e9;padding:12px;border-radius:4px;text-align:center;width:30%'>
      <div style='font-size:26px;font-weight:bold;color:#2e7d32'>
        {len(controls) - failing_cnt}
      </div>
      <div style='color:#555;font-size:13px'>Passing controls</div>
    </td>
  </tr>
</table>
<table style='width:100%;border-collapse:collapse;font-size:13px'>
  <tr style='background:#f5f5f5;font-weight:bold'>
    <th style='padding:6px 8px;text-align:left'>Control</th>
    <th style='padding:6px 8px;text-align:left'>Alerts</th>
    <th style='padding:6px 8px;text-align:left'>Status</th>
    <th style='padding:6px 8px;text-align:left'>Top agents</th>
  </tr>
  {rows_html}
</table>
<p style='color:#aaa;font-size:11px;margin-top:24px'>
  Auto-generated by Wazuh MCP. Do not reply to this email.
</p>
</body></html>"""

        try:
            msg = MIMEMultipart("alternative")
            msg["From"]    = _EMAIL_FROM
            msg["To"]      = ", ".join(to_addresses)
            msg["Subject"] = subject
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.login(_SMTP_USER, _SMTP_PASS)
                smtp.sendmail(_EMAIL_FROM, to_addresses, msg.as_string())

            log.info("Compliance report emailed to %s", to_addresses)
            return {
                "status":     "ok",
                "framework":  framework,
                "recipients": to_addresses,
                "subject":    subject,
                "message":    f"{framework.upper()} report sent to {', '.join(to_addresses)}.",
            }
        except smtplib.SMTPException as e:
            return {"error": f"SMTP error: {e}"}
        except Exception as e:
            return {"error": str(e)}

    # ── Microsoft Teams notifications ────────────────────────────────────────────
    _TEAMS_WEBHOOK = os.getenv("TEAMS_WEBHOOK_URL", "")

    async def _post_teams_card(card: dict) -> dict:
        """Post an Adaptive Card payload to a Teams incoming webhook."""
        if not _TEAMS_WEBHOOK:
            return {"error": "Teams not configured. Add TEAMS_WEBHOOK_URL to .env."}
        try:
            async with httpx.AsyncClient(timeout=_SOAR_TIMEOUT) as client:
                r = await client.post(
                    _TEAMS_WEBHOOK,
                    json=card,
                    headers={"Content-Type": "application/json"},
                )
            r.raise_for_status()
            return {"status": "ok", "method": "teams_webhook"}
        except Exception as e:
            return {"error": f"Teams webhook failed: {e}"}

    @mcp.tool()
    async def send_alert_to_teams(
        message: str,
        title: str | None = None,
        severity: str = "info",
        fields: dict | None = None,
        ticket_url: str | None = None,
    ) -> dict:
        """Push a formatted message to Microsoft Teams via an incoming webhook.

        Uses Adaptive Cards format for rich formatting.
        severity: info | warning | critical  (controls accent colour)
        fields:   dict of key→value pairs shown as a facts table
        ticket_url: link to Jira/TheHive ticket if already created

        Requires TEAMS_WEBHOOK_URL in .env.
        Set via: Teams channel → Connectors → Incoming Webhook → copy URL.
        """
        if not _TEAMS_WEBHOOK:
            return {"error": "Teams not configured. Add TEAMS_WEBHOOK_URL to .env."}

        color_map = {"critical": "attention", "warning": "warning", "info": "good"}
        accent = color_map.get(severity.lower(), "good")

        body_items: list[dict] = [
            {"type": "TextBlock", "text": message, "wrap": True, "size": "Small"},
        ]

        if fields:
            facts = [{"title": str(k), "value": str(v)} for k, v in fields.items()]
            body_items.append({"type": "FactSet", "facts": facts})

        actions: list[dict] = []
        if ticket_url:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "View Ticket",
                "url": ticket_url,
            })

        card: dict = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": title or "Wazuh Security Alert",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": accent,
                        },
                        *body_items,
                    ],
                    **({"actions": actions} if actions else {}),
                },
            }],
        }

        result = await _post_teams_card(card)
        log.info("Teams message sent severity=%s", severity)
        return result

    @mcp.tool()
    async def send_critical_alert_to_teams(
        alert_id: str,
        rule_id: str,
        rule_description: str,
        agent_name: str,
        severity_level: int,
        source_ip: str | None = None,
        ticket_url: str | None = None,
    ) -> dict:
        """Fire an instant Teams notification for a critical Wazuh alert.

        Posts a rich Adaptive Card with alert details, severity badge, and
        optional ticket link. severity_level >= 12 → CRITICAL, 9-11 → HIGH.

        Requires TEAMS_WEBHOOK_URL in .env.
        """
        if not _TEAMS_WEBHOOK:
            return {"error": "Teams not configured. Add TEAMS_WEBHOOK_URL to .env."}

        ts_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        if severity_level >= 12:
            tier = "CRITICAL"; color = "attention"
        elif severity_level >= 9:
            tier = "HIGH";     color = "warning"
        else:
            tier = "MEDIUM";   color = "accent"

        facts = [
            {"title": "Rule ID",   "value": str(rule_id)},
            {"title": "Level",     "value": str(severity_level)},
            {"title": "Agent",     "value": agent_name},
            {"title": "Source IP", "value": source_ip or "N/A"},
            {"title": "Alert ID",  "value": alert_id},
            {"title": "Time",      "value": ts_str},
        ]
        actions: list[dict] = []
        if ticket_url:
            actions.append({"type": "Action.OpenUrl", "title": "View Ticket", "url": ticket_url})

        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"[{tier}] Wazuh Alert — {ts_str}",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": color,
                        },
                        {
                            "type": "TextBlock",
                            "text": rule_description,
                            "wrap": True,
                            "size": "Small",
                        },
                        {"type": "FactSet", "facts": facts},
                    ],
                    **({"actions": actions} if actions else {}),
                },
            }],
        }

        result = await _post_teams_card(card)
        return {**result, "severity_tier": tier, "alert_id": alert_id}

    @mcp.tool()
    async def send_weekly_summary_to_teams(
        week_offset: int = 0,
    ) -> dict:
        """Generate the weekly security summary and push it to Microsoft Teams.

        week_offset: 0 = current week, 1 = last week.
        Requires TEAMS_WEBHOOK_URL in .env.
        """
        if not _TEAMS_WEBHOOK:
            return {"error": "Teams not configured. Add TEAMS_WEBHOOK_URL to .env."}

        report = await generate_weekly_summary(week_offset=week_offset)
        ts_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        label = "This week" if week_offset == 0 else "Last week"

        counts = report.get("alert_counts") or {}
        total  = counts.get("this_week", "N/A")
        delta  = counts.get("trend_pct")
        delta_s = f"{delta:+.1f}%" if isinstance(delta, (int, float)) else "N/A"

        top_rules = report.get("top_rules", [])[:5]
        rules_text = "\n".join(
            f"• Rule {r.get('rule')} — {r.get('count')} alerts" for r in top_rules
        ) or "No significant rules"

        top_mitre = report.get("top_mitre_techniques", [])[:3]
        mitre_text = "\n".join(
            f"• {t.get('id')} {t.get('name', '')} ({t.get('count', 0)})" for t in top_mitre
        ) or "None observed"

        facts = [
            {"title": "Total alerts",    "value": str(total)},
            {"title": "Week-on-week",    "value": delta_s},
            {"title": "Top rules",       "value": rules_text},
            {"title": "Top MITRE",       "value": mitre_text},
        ]

        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"Weekly Security Summary — {label} ({ts_str})",
                            "weight": "Bolder",
                            "size": "Medium",
                        },
                        {"type": "FactSet", "facts": facts},
                        {
                            "type": "TextBlock",
                            "text": "Posted by Wazuh MCP",
                            "size": "Small",
                            "color": "Default",
                            "isSubtle": True,
                        },
                    ],
                },
            }],
        }

        result = await _post_teams_card(card)
        return {**result, "week_offset": week_offset, "label": label}
