"""Scheduler tests — config precedence and "notifications never abort a scan"."""
import json

import pytest

from core import db, scheduler


@pytest.fixture()
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "soc.db"))
    db.init_db()
    return tmp_path


def test_load_config_creates_default_file(workdir):
    cfg = scheduler.load_config()
    assert workdir.joinpath("config.json").exists()
    assert cfg["strict_cve_matching"] is True
    assert cfg["discord_webhook_url"] == ""


def test_env_overrides_file_values(workdir, monkeypatch):
    workdir.joinpath("config.json").write_text(json.dumps({
        "discord_webhook_url": "https://discord.com/api/webhooks/file/from-file",
        "poll_interval_seconds": 5,
    }))
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1/from-env")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")

    cfg = scheduler.load_config()
    assert cfg["discord_webhook_url"].endswith("from-env")
    assert cfg["virustotal_api_key"] == "vt-key"
    assert cfg["poll_interval_seconds"] == 5  # untouched file value survives


def test_safe_notify_alert_never_raises(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("discord is down")

    monkeypatch.setattr(scheduler.notifier, "send_discord_alert", boom)
    # must not raise
    scheduler.safe_notify_alert({}, "example.com", "Open Port", "MEDIUM", "443", {})
    scheduler.safe_notify_text({}, "summary")


def test_run_all_once_with_no_targets_exits_clean(workdir, monkeypatch):
    monkeypatch.setattr("sys.argv", ["scheduler.py", "run-all-once"])
    assert scheduler.main() == 0


def test_one_failing_target_does_not_stop_the_others(workdir, monkeypatch):
    db.add_target("bad.example.com")
    db.add_target("good.example.com")
    seen = []

    def fake_cycle(target, target_id, cfg):
        seen.append(target)
        if target == "bad.example.com":
            raise RuntimeError("boom")

    monkeypatch.setattr(scheduler, "run_scan_cycle", fake_cycle)
    monkeypatch.setattr("sys.argv", ["scheduler.py", "run-all-once"])

    assert scheduler.main() == 0
    assert set(seen) == {"bad.example.com", "good.example.com"}
