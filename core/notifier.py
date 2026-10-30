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

v3 changes (pipeline hardening):
    - Webhook URLs are validated before any request is attempted. A malformed
      value (a leftover placeholder such as "***", a pasted token, a typo'd
      scheme) now produces a warning instead of a requests.InvalidSchema
      exception raised in the middle of a scan cycle.
    - ALL requests-level failures are caught via requests.RequestException
      (InvalidSchema, MissingSchema, InvalidURL, ConnectionError, Timeout, ...).
      Previously only ConnectionError/Timeout were handled, so a bad webhook
      URL escaped send_discord_*(), aborted run_scan_cycle(), made the GitHub
      Actions job exit 1 and skipped the "commit the DB" step — one broken
      webhook silently disabled the whole autonomous SOC.
    - send_discord_*() are now guaranteed not to raise: notifications are
      best-effort and must never be part of the scan transaction.
"""

import time
import logging
from typing import Any, Dict
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

SEVERITY_COLOR = {
    "CRITICAL": 0xE02424, "HIGH": 0xF97316, "MEDIUM": 0xFACC15,
    "LOW": 0x60A5FA, "INFO": 0x9CA3AF,
}

# Only these hosts are legitimate Discord webhook endpoints. Keeping the list
# tight means a user-supplied URL can't turn the notifier into a request
# forwarder (SSRF) if config.json or the env var is tampered with.
ALLOWED_WEBHOOK_HOSTS = {
    "discord.com",
    "discordapp.com",
    "ptb.discord.com",
    "canary.discord.com",
}


def is_valid_webhook_url(webhook_url: Any) -> bool:
    """True only for https://<discord-host>/api/webhooks/<id>/<token> URLs."""
    if not webhook_url or not isinstance(webhook_url, str):
        return False
    url = webhook_url.strip()
    # Placeholders like "***" (what GitHub Actions prints for a masked secret)
    # and pasted tokens are not URLs — reject before handing them to requests.
    if not url or any(ch.isspace() for ch in url) or "*" in url:
        return False
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    if (parsed.hostname or "").lower() not in ALLOWED_WEBHOOK_HOSTS:
        return False
    return parsed.path.startswith("/api/webhooks/")


def _post_with_rate_limit_retry(webhook_url: str, payload: dict, timeout: int = 10) -> bool:
    if not is_valid_webhook_url(webhook_url):
        logger.warning(
            "Discord webhook is not configured or is not a valid "
            "https://discord.com/api/webhooks/<id>/<token> URL — skipping "
            "notification (scan results are unaffected)."
        )
        return False

    for attempt in range(2):
        try:
            resp = requests.post(webhook_url, json=payload, timeout=timeout)
        except requests.exceptions.RequestException as e:
            # Deliberately broad: InvalidSchema/MissingSchema/InvalidURL are
            # RequestException subclasses too, not just connection failures.
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
                        severity: str, summary: str, details: Dict[str, Any]) -> bool:
    """Send a finding embed. Returns False on any failure; never raises."""
    if not isinstance(details, dict):
        details = {"detail": details}

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
        return _post_with_rate_limit_retry(webhook_url, {"embeds": [embed]})
    except Exception as e:  # belt and braces — notifications are best-effort
        logger.warning(f"Discord alert construction failed: {e}")
        return False


def send_discord_text(webhook_url: str, message: str) -> bool:
    """Plain-text message (used for scan-cycle summaries / errors). Never raises."""
    try:
        return _post_with_rate_limit_retry(webhook_url, {"content": message})
    except Exception as e:
        logger.warning(f"Discord text notification failed: {e}")
        return False
