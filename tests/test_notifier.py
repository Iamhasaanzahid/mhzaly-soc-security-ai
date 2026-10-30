"""Notifier tests — a bad webhook must never raise into a scan cycle.

Regression guard for the outage where DISCORD_WEBHOOK_URL held a non-URL
value ("***") and requests.InvalidSchema aborted the whole autonomous scan.
"""
import pytest
import requests

from core import notifier


@pytest.mark.parametrize("url", [
    "https://discord.com/api/webhooks/123456789/abcdef",
    "https://discordapp.com/api/webhooks/1/tok",
    "https://canary.discord.com/api/webhooks/1/tok",
])
def test_accepts_real_discord_webhooks(url):
    assert notifier.is_valid_webhook_url(url) is True


@pytest.mark.parametrize("url", [
    None, "", "***", "not-a-url", "http://discord.com/api/webhooks/1/t",
    "https://evil.example.com/api/webhooks/1/t",
    "https://discord.com/not-a-webhook",
    "https://discord.com/api/webhooks/1/tok extra",
])
def test_rejects_placeholders_and_foreign_hosts(url):
    assert notifier.is_valid_webhook_url(url) is False


def test_invalid_webhook_returns_false_without_network(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("no HTTP request should be made for an invalid URL")

    monkeypatch.setattr(notifier.requests, "post", explode)
    assert notifier.send_discord_text("***", "hello") is False
    assert notifier.send_discord_alert("***", "t", "c", "INFO", "s", {}) is False


def test_request_level_errors_are_swallowed(monkeypatch):
    """InvalidSchema is a RequestException, not a ConnectionError."""

    def raise_invalid_schema(*args, **kwargs):
        raise requests.exceptions.InvalidSchema("no adapter")

    monkeypatch.setattr(notifier.requests, "post", raise_invalid_schema)
    monkeypatch.setattr(notifier.time, "sleep", lambda *_a, **_k: None)

    assert notifier.send_discord_text(
        "https://discord.com/api/webhooks/1/tok", "hello") is False


def test_success_and_429_retry_paths(monkeypatch):
    class Resp:
        def __init__(self, status, payload=None):
            self.status_code = status
            self._payload = payload or {}
            self.text = ""

        def json(self):
            return self._payload

    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append(url)
        if len(calls) == 1:
            return Resp(429, {"retry_after": 0.01})
        return Resp(204)

    monkeypatch.setattr(notifier.requests, "post", fake_post)
    monkeypatch.setattr(notifier.time, "sleep", lambda *_a, **_k: None)

    assert notifier.send_discord_text(
        "https://discord.com/api/webhooks/1/tok", "hi") is True
    assert len(calls) == 2
