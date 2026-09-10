#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
notifier.py — Sends new findings to Discord via webhook.

Discord webhooks need no bot setup: Server Settings -> Integrations ->
Webhooks -> New Webhook -> Copy URL. Paste that URL into config.json.
"""

import requests
import logging

logger = logging.getLogger(__name__)

SEVERITY_COLOR = {
    "CRITICAL": 0xE02424, "HIGH": 0xF97316, "MEDIUM": 0xFACC15,
    "LOW": 0x60A5FA, "INFO": 0x9CA3AF,
}


def send_discord_alert(webhook_url: str, target: str, category: str,
                        severity: str, summary: str, details: dict) -> bool:
    if not webhook_url:
        logger.warning("No Discord webhook configured — skipping alert.")
        return False

    field_lines = []
    for k, v in list(details.items())[:8]:
        field_lines.append(f"**{k}**: `{v}`")

    embed = {
        "title": f"🛰️ New finding — {target}",
        "description": f"**Category:** {category}\n**Summary:** {summary}",
        "color": SEVERITY_COLOR.get(severity, 0x9CA3AF),
        "fields": [{"name": "Details", "value": "\n".join(field_lines) or "—", "inline": False}],
        "footer": {"text": "MHZALY Autonomous SOC"},
    }

    try:
        resp = requests.post(webhook_url, json={"embeds": [embed]}, timeout=10)
        return resp.status_code in (200, 204)
    except Exception as e:
        logger.warning(f"Discord send failed: {e}")
        return False


def send_discord_text(webhook_url: str, message: str) -> bool:
    """Plain-text message (used for scan-cycle summaries / errors)."""
    if not webhook_url:
        return False
    try:
        resp = requests.post(webhook_url, json={"content": message}, timeout=10)
        return resp.status_code in (200, 204)
    except Exception as e:
        logger.warning(f"Discord send failed: {e}")
        return False
