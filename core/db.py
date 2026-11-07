#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db.py — SQLite persistence module for MHZALY Autonomous SOC.
Manages monitored targets, scan runs, findings with fingerprinting, and alert logs.
"""

import sqlite3
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional

from .evidence import EvidenceLedger

DB_PATH = "mhzaly_soc.db"


def _ledger() -> EvidenceLedger:
    """Create the evidence ledger lazily.

    Importing core.db must never open SQLite: on Streamlit Cloud the checkout can
    be read-only at import time, and opening the database there used to take the
    whole console down before a single page rendered.
    """
    return EvidenceLedger(DB_PATH)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the SQLite database schema if it doesn't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    # Monitored targets table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT UNIQUE NOT NULL,
            scan_interval_minutes INTEGER DEFAULT 60,
            last_scanned_at TIMESTAMP,
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Scan runs history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP,
            status TEXT,
            new_findings_count INTEGER DEFAULT 0,
            error TEXT,
            FOREIGN KEY (target_id) REFERENCES targets (id)
        )
    """)

    # Findings table with fingerprinting to prevent alert spam
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            category TEXT,
            fingerprint TEXT UNIQUE,
            summary TEXT,
            details TEXT,
            severity TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets (id)
        )
    """)

    # Migration: confidence/verified columns (added 2026-10). ALTER TABLE is
    # idempotent here because we check PRAGMA first — older databases upgrade
    # in place instead of losing their history.
    existing = {row[1] for row in cursor.execute("PRAGMA table_info(findings)").fetchall()}
    if "confidence" not in existing:
        cursor.execute("ALTER TABLE findings ADD COLUMN confidence INTEGER")
    if "verified" not in existing:
        cursor.execute("ALTER TABLE findings ADD COLUMN verified INTEGER DEFAULT 0")

    # Digital Forensics Artifacts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS forensics_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_type TEXT,
            artifact_value TEXT,
            severity TEXT,
            case_notes TEXT,
            logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Append-only hash-chained evidence ledger (created by core.evidence too,
    # but the path must be explicit here so the module-level API stays consistent).
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_ledger (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at TEXT NOT NULL,
            target TEXT NOT NULL,
            run_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            finding_fp TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            payload TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL
        )
    """)

    # Scan-to-scan change log
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_deltas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            run_id TEXT NOT NULL,
            change_type TEXT NOT NULL,
            finding_fp TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Posture score history — one row per scan run, so the console can show a
    # trend instead of a single snapshot.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posture_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            run_id TEXT NOT NULL,
            score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            verified_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# ── Target Management ────────────────────────────────────────────────────────

def add_target(target: str, interval_minutes: int = 60) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO targets (target, scan_interval_minutes) VALUES (?, ?)",
            (target.strip().lower(), interval_minutes)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def deactivate_target(target_id: int) -> bool:
    """Soft-delete: stop monitoring a target but keep its findings/history."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE targets SET active = 0 WHERE id = ?", (target_id,))
    changed = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return changed


def remove_target(target_id: int):
    """Hard delete: drop the target plus its findings and scan-run history."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings WHERE target_id = ?", (target_id,))
    cursor.execute("DELETE FROM scan_runs WHERE target_id = ?", (target_id,))
    cursor.execute("DELETE FROM targets WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()


def list_targets(active_only: bool = False) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    if active_only:
        cursor.execute("SELECT * FROM targets WHERE active = 1")
    else:
        cursor.execute("SELECT * FROM targets")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def mark_scanned(target_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE targets SET last_scanned_at = ? WHERE id = ?",
        (datetime.utcnow().isoformat(), target_id)
    )
    conn.commit()
    conn.close()


# ── Scan Runs Management ─────────────────────────────────────────────────────

def start_scan_run(target_id: int) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_runs (target_id, status) VALUES (?, ?)",
        (target_id, "RUNNING")
    )
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return run_id


def finish_scan_run(run_id: int, status: str, new_count: int, error: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE scan_runs 
           SET finished_at = ?, status = ?, new_findings_count = ?, error = ? 
           WHERE run_id = ?""",
        (datetime.utcnow().isoformat(), status, new_count, error, run_id)
    )
    conn.commit()
    conn.close()


# ── Fingerprinting & Findings ────────────────────────────────────────────────

def make_fingerprint(target: str, category: str, unique_marker: str) -> str:
    """Generates a unique SHA256 hash for a specific finding to track changes over time."""
    raw = f"{target.strip().lower()}:{category.strip().lower()}:{unique_marker.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def upsert_finding(target_id: int, category: str, fingerprint: str,
                   summary: str, details: dict, severity: str,
                   confidence: Optional[int] = None, verified: bool = False) -> bool:
    """
    Inserts a finding if it's new. If it already exists, updates last_seen.
    Returns True ONLY if it is genuinely brand new (triggering a Discord alert).
    """
    import json
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    details_str = json.dumps(details)

    cursor.execute("SELECT id FROM findings WHERE fingerprint = ?", (fingerprint,))
    row = cursor.fetchone()

    if row:
        # Finding exists, update last_seen
        cursor.execute(
            "UPDATE findings SET last_seen = ? WHERE fingerprint = ?",
            (now, fingerprint)
        )
        conn.commit()
        conn.close()
        return False
    else:
        # Brand new finding
        cursor.execute(
            """INSERT INTO findings
               (target_id, category, fingerprint, summary, details, severity,
                confidence, verified, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (target_id, category, fingerprint, summary, details_str, severity.upper(),
             confidence, 1 if verified else 0, now, now)
        )
        conn.commit()
        conn.close()
        return True


def recent_findings(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.*, t.target 
        FROM findings f 
        JOIN targets t ON f.target_id = t.id 
        ORDER BY f.last_seen DESC 
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def recent_scan_runs(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sr.*, t.target 
        FROM scan_runs sr 
        JOIN targets t ON sr.target_id = t.id 
        ORDER BY sr.started_at DESC 
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def add_forensics_artifact(artifact_type: str, artifact_value: str, severity: str, case_notes: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO forensics_artifacts (artifact_type, artifact_value, severity, case_notes) VALUES (?, ?, ?, ?)",
            (artifact_type, artifact_value, severity.upper(), case_notes)
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def get_forensics_artifacts(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forensics_artifacts ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


# ── Evidence ledger & proof packs ─────────────────────────────────────────────

def record_evidence(run_id, target: str, findings: List[Dict[str, Any]]) -> str:
    """Append one scan run's verified findings to the hash-chained ledger."""
    return _ledger().record_run(str(run_id), target, findings)


def verify_evidence() -> Dict[str, Any]:
    return _ledger().verify()


def export_proof_pack(run_id: str, path: str) -> Dict[str, Any]:
    return _ledger().export_proof_pack(run_id, path)


# ── Findings for a target (used by the delta engine) ─────────────────────────

def findings_for_target(target: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT f.*, t.target
        FROM findings f
        JOIN targets t ON f.target_id = t.id
        WHERE t.target = ?
        ORDER BY f.last_seen DESC
        """,
        (target.strip().lower(),),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ── Scan deltas ─────────────────────────────────────────────────────────────

def store_delta(target: str, run_id: str, delta: Dict[str, Any]) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    summary = delta.get("summary") or {}
    types = (
        ("NEW", summary.get("new", 0)),
        ("RESOLVED", summary.get("resolved", 0)),
        ("ESCALATED", summary.get("escalated", 0)),
        ("DE_ESCALATED", summary.get("de_escalated", 0)),
        ("PERSISTING", summary.get("persisting", 0)),
    )
    ok = True
    for change_type, count in types:
        if not count:
            continue
        for f in delta.get(change_type.lower() + "_findings") or []:
            cursor.execute(
                "INSERT INTO scan_deltas (target, run_id, change_type, finding_fp) VALUES (?, ?, ?, ?)",
                (target, str(run_id), change_type, str(f.get("kind") or "") + ":" + str(f.get("marker") or "")),
            )
    conn.commit()
    conn.close()
    return ok


def get_latest_delta(target: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT * FROM scan_deltas ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


# ── Position history & delta analytics (Proof & Posture console) ────────────

def record_posture(run_id, target: str, posture: Dict[str, Any]) -> bool:
    """Persist one scan run's posture so the console can chart a trend."""
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO posture_history
               (target, run_id, score, grade, verified_count)
               VALUES (?, ?, ?, ?, ?)""",
            (target, str(run_id), int(posture.get("score") or 0),
             str(posture.get("grade") or "?"), int(posture.get("verified_count") or 0)),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def posture_history(limit: int = 120) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM posture_history ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def recent_deltas(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scan_deltas ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delta_counters(days: int = 30) -> Dict[str, int]:
    """Count each change type over the recent window."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT change_type, COUNT(*) AS n FROM scan_deltas "
        "WHERE created_at >= datetime('now', ?) GROUP BY change_type",
        (f"-{int(days)} days",),
    ).fetchall()
    conn.close()
    return {str(r["change_type"]): int(r["n"]) for r in rows}


def latest_evidence_run() -> Optional[str]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT run_id FROM evidence_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    except Exception:
        row = None
    finally:
        conn.close()
    return str(row["run_id"]) if row else None
