"""Evidence ledger: hash chain integrity, fingerprinting, proof pack."""

import json

from core import evidence as ev


def test_fingerprint_is_deterministic():
    a = ev.fingerprint_of("Example.com", "weak_headers", "HSTS", "missing hsts", "MEDIUM")
    b = ev.fingerprint_of("example.com", "weak_headers", "hsts", "missing hsts", "medium")
    assert a == b
    assert len(a) == 64


def test_record_hash_uses_previous_hash(tmp_path):
    ledger = ev.EvidenceLedger(db_path=str(tmp_path / "ev.db"))
    head = ledger.record_run("run-1", "example.com", [{
        "kind": "weak_headers", "severity": "MEDIUM", "confidence": 88,
        "summary": "missing HSTS", "marker": "HSTS", "details": {"missing": ["HSTS"]},
    }])
    assert len(ledger.all_records()) == 1
    assert ledger.verify()["ok"] is True
    assert ledger.verify()["records"] == 1

    # second run chains on top
    ledger.record_run("run-2", "example.com", [{
        "kind": "weak_headers", "severity": "MEDIUM", "confidence": 88,
        "summary": "missing HSTS", "marker": "HSTS", "details": {"missing": ["HSTS"]},
    }])
    v = ledger.verify()
    assert v["ok"] is True and v["records"] == 2

    manifest = ledger.export_proof_pack("run-1", str(tmp_path / "pack.json"))
    assert manifest["run_id"] == "run-1"
    assert manifest["records"][0]["finding_fp"]


def test_tampered_payload_detects_integrity_break(tmp_path):
    ledger = ev.EvidenceLedger(db_path=str(tmp_path / "ev.db"))
    ledger.record_run("run-1", "example.com", [{
        "kind": "weak_headers", "severity": "MEDIUM", "confidence": 88,
        "summary": "missing HSTS", "marker": "HSTS", "details": {},
    }])
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "ev.db"))
    conn.execute("UPDATE evidence_ledger SET payload = '{}' WHERE seq = 1")
    conn.commit()
    conn.close()
    assert ledger.verify()["ok"] is False
    assert ledger.verify()["broken_at"] == 1
