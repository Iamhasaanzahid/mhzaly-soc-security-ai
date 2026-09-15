#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
notifier.py — Sends new findings to Discord via webhook.

Discord webhooks need no bot setup: Server Settings -> Integrations ->
Webhooks -> New Webhook -> Copy URL. Paste that URL into config.json.

v2 changes:
    - Retries once on connection/timeout errors instead of dropping the alert.
    - Handles Discord's 429 rate-limit response by sleeping for the
      `retry_after` it returns, then retrying once — Discord webhooks throttle
      hard (roughly 30 requests/minute per webhook), and a noisy scan cycle
      with many new findings could otherwise silently lose alerts.
"""

import time
import requests
import logging

logger = logging.getLogger(__name__)

SEVERITY_COLOR = {
    "CRITICAL": 0xE02424, "HIGH": 0xF97316, "MEDIUM": 0xFACC15,
    "LOW": 0x60A5FA, "INFO": 0x9CA3AF,
}


def _post_with_rate_limit_retry(webhook_url: str, payload: dict, timeout: int = 10) -> bool:
    for attempt in range(2):
        try:
            resp = requests.post(webhook_url, json=payload, timeout=timeout)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            logger.warning(f"Discord send attempt {attempt + 1} failed: {e}")
            time.sleep(1.5)
            continue

        if resp.status_code in (200, 204):
            return True
        if resp.status_code == 429:
            try:
                retry_after = float(resp.json().get("retry_after", 1.0))
            except Exception:
                retry_after = 1.0
            logger.warning(f"Discord rate limit hit — retrying in {retry_after:.1f}s")
            time.sleep(retry_after)
            continue
        logger.warning(f"Discord send failed: HTTP {resp.status_code} — {resp.text[:200]}")
        return False
    return False


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

    return _post_with_rate_limit_retry(webhook_url, {"embeds": [embed]})


def send_discord_text(webhook_url: str, message: str) -> bool:
    """Plain-text message (used for scan-cycle summaries / errors)."""
    if not webhook_url:
        return False
    return _post_with_rate_limit_retry(webhook_url, {"content": message})
