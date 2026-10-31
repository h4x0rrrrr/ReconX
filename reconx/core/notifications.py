"""Webhook Notifications & Push Alerts.

Supports Discord, Slack, and Telegram notifications for high-risk findings
and scan completions.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from reconx.utils.logger import debug, info, warn

def send_scan_notification(
    findings: Any,
    out_dir: str,
    webhook_url: str | None = None,
) -> bool:
    """Send formatted scan summary to configured webhooks."""
    webhook = webhook_url or os.environ.get("DISCORD_WEBHOOK") or os.environ.get("SLACK_WEBHOOK")
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    tg_chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not webhook and not (tg_token and tg_chat_id):
        return False

    target = findings.target
    mode = findings.mode
    data = findings.data
    flags = findings.flags

    high_flags = [f["note"] for f in flags if f.get("severity") == "high"]
    subs_count = len(data.get("subdomains", []))
    services_count = len(data.get("network_services", []))
    cves_count = len(data.get("vulnerabilities", []))
    origins_count = len(data.get("origin_ips", []))

    summary_text = (
        f"🎯 ReconX Scan Completed: **{target}** ({mode})\n"
        f"• Subdomains: {subs_count} | Services: {services_count} | CVEs: {cves_count}\n"
    )
    if origins_count:
        summary_text += f"• 🛡️ Unmasked Origin IPs: {origins_count}\n"
    if high_flags:
        summary_text += f"⚠️ **High-Risk Alerts ({len(high_flags)}):**\n"
        for note in high_flags[:4]:
            summary_text += f"  - {note}\n"
    summary_text += f"📁 Report Saved: `{out_dir}/report.html`"

    # Discord Webhook
    if webhook and "discord.com" in webhook:
        payload = {
            "username": "ReconX Intelligence",
            "content": summary_text,
        }
        _post_json(webhook, payload)
        return True

    # Slack Webhook
    if webhook and "hooks.slack.com" in webhook:
        payload = {
            "text": summary_text.replace("**", "*"),
        }
        _post_json(webhook, payload)
        return True

    # Generic Webhook
    if webhook:
        payload = {
            "event": "scan_complete",
            "target": target,
            "mode": mode,
            "high_flags_count": len(high_flags),
            "summary": summary_text,
            "output_directory": out_dir,
        }
        _post_json(webhook, payload)
        return True

    # Telegram Bot
    if tg_token and tg_chat_id:
        tg_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
        tg_payload = {
            "chat_id": tg_chat_id,
            "text": summary_text.replace("**", ""),
        }
        _post_json(tg_url, tg_payload)
        return True

    return False

def _post_json(url: str, data: dict[str, Any]) -> None:
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "ReconX-Alert/0.3.3"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            debug(f"Webhook delivered: HTTP {resp.status}")
    except Exception as exc:
        debug(f"Webhook delivery failed: {exc}")
