"""Persistence-layer tests — fingerprints must dedupe, schema must be stable."""
import sqlite3

import pytest

from core import db


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    path = tmp_path / "soc_test.db"
    monkeypatch.setattr(db, "DB_PATH", str(path))
    db.init_db()
    return path


def test_init_db_creates_all_tables(temp_db):
    conn = sqlite3.connect(temp_db)
    tables = {row[0] for row in conn.execute(
        "select name from sqlite_master where type='table'")}
    conn.close()
    assert {"targets", "scan_runs", "findings", "forensics_artifacts"} <= tables


def test_add_target_is_idempotent(temp_db):
    assert db.add_target("example.com", 30) is True
    assert db.add_target("example.com", 30) is False
    targets = db.list_targets()
    assert len(targets) == 1
    assert targets[0]["target"] == "example.com"
    assert targets[0]["scan_interval_minutes"] == 30


def test_deactivate_target_keeps_history(temp_db):
    db.add_target("example.com")
    target_id = db.list_targets()[0]["id"]
    db.deactivate_target(target_id)
    assert db.list_targets(active_only=True) == []
    assert len(db.list_targets(active_only=False)) == 1


def test_remove_target_purges_target_and_findings(temp_db):
    db.add_target("example.com")
    target_id = db.list_targets()[0]["id"]
    fp = db.make_fingerprint("example.com", "open_port", "443")
    db.upsert_finding(target_id, "open_port", fp, "Open 443", {"port": 443}, "MEDIUM")
    db.remove_target(target_id)
    assert db.list_targets(active_only=False) == []
    assert db.recent_findings() == []


def test_fingerprint_is_stable_and_case_insensitive():
    a = db.make_fingerprint("Example.COM", "Open_Port", "443")
    b = db.make_fingerprint(" example.com ", "open_port", " 443 ")
    assert a == b
    assert len(a) == 64


def test_upsert_finding_alerts_only_once(temp_db):
    db.add_target("example.com")
    target_id = db.list_targets()[0]["id"]
    fp = db.make_fingerprint("example.com", "open_port", "443")

    assert db.upsert_finding(target_id, "open_port", fp,
                             "Open port 443", {"port": 443}, "medium") is True
    assert db.upsert_finding(target_id, "open_port", fp,
                             "Open port 443", {"port": 443}, "medium") is False
    assert len(db.recent_findings()) == 1


def test_scan_run_lifecycle(temp_db):
    db.add_target("example.com")
    target_id = db.list_targets()[0]["id"]
    run_id = db.start_scan_run(target_id)
    db.finish_scan_run(run_id, "SUCCESS", 2)

    runs = db.recent_scan_runs()
    assert runs[0]["status"] == "SUCCESS"
    assert runs[0]["new_findings_count"] == 2


def test_forensics_vault_roundtrip(temp_db):
    db.add_forensics_artifact("IP Address", "203.0.113.9", "High", "C2 candidate")
    artifacts = db.get_forensics_artifacts()
    assert len(artifacts) == 1
    assert artifacts[0]["artifact_value"] == "203.0.113.9"


def test_posture_history_roundtrip(temp_db):
    assert db.posture_history() == []
    db.record_posture("run-1", "example.com", {"score": 82, "grade": "B", "verified_count": 3})
    rows = db.posture_history()
    assert len(rows) == 1
    assert rows[0]["score"] == 82 and rows[0]["grade"] == "B"


def test_delta_counters_and_recent_events(temp_db):
    db.store_delta("example.com", "run-1", {
        "summary": {"new": 2, "resolved": 1, "persisting": 0, "escalated": 0, "de_escalated": 0},
        "new_findings": [{"kind": "weak_headers", "marker": "HSTS"}, {"kind": "open_port", "marker": "21"}],
        "resolved_findings": [{"kind": "tls_untrusted", "marker": "chain"}],
    })
    counts = db.delta_counters(days=30)
    assert counts.get("NEW") == 2
    assert counts.get("RESOLVED") == 1
    assert len(db.recent_deltas()) == 3


def test_latest_evidence_run_is_none_when_ledger_empty(temp_db):
    assert db.latest_evidence_run() is None
    db.record_evidence("run-42", "example.com", [{
        "kind": "weak_headers", "marker": "HSTS", "summary": "missing HSTS",
        "severity": "MEDIUM", "confidence": 88, "verified": True, "details": {},
    }])
    assert db.latest_evidence_run() == "run-42"
