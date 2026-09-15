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

DB_PATH = "mhzaly_soc.db"


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


def remove_target(target_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    # Foreign key constraints اور منسلک ریکارڈز کو مدنظر رکھتے ہوئے ٹارगेट کو ہمیشہ کے لیے ڈیلیٹ کریں
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
                   summary: str, details: dict, severity: str) -> bool:
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
               (target_id, category, fingerprint, summary, details, severity, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (target_id, category, fingerprint, summary, details_str, severity.upper(), now, now)
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
