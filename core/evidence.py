#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evidence.py — Append-only, hash-chained evidence ledger.

Every verified finding that survives the confidence gate becomes a chain entry.
The ledger is an append-only hash chain (each record commits to its predecessor
and to a canonical JSON payload), which means:

  * the ordering of evidence can never be rewritten without detection,
  * a payload change is detectable in O(1) with a rehash,
  * the full history can be exported as a proof pack that an auditor can replay.

This is the property that makes a report more than a document: it is a *proof*.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

GENESIS_HASH = "GENESIS"


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint_of(target: str, kind: str, marker: str, summary: str = "", severity: str = "") -> str:
    """Deterministic finding identity across runs."""
    payload = {
        "target": (target or "").strip().lower(),
        "kind": (kind or "").strip().lower(),
        "marker": (marker or "").strip().lower(),
        "summary": (summary or "").strip().lower(),
        "severity": (severity or "").upper(),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _record_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    material = f"{prev_hash}:{_canonical(payload)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class EvidenceLedger:
    def __init__(self, db_path: str = "mhzaly_soc.db") -> None:
        self.db_path = db_path
        self._ensure_schema()

    # -- schema -------------------------------------------------------------
    def _ensure_schema(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
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
            """
        )
        conn.commit()
        conn.close()

    # -- writes -------------------------------------------------------------
    def record_run(self, run_id: str, target: str, findings: List[Dict[str, Any]]) -> str:
        """Append every verified finding of one scan run to the chain.

        Returns the head hash of the chain after this run.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        last = conn.execute(
            "SELECT record_hash FROM evidence_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["record_hash"] if last else GENESIS_HASH
        head = prev_hash
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for f in findings:
            payload = {
                "finding_fp": fingerprint_of(
                    str(f.get("target") or f.get("host") or ""),
                    str(f.get("kind") or ""),
                    str(f.get("marker") or ""),
                    str(f.get("summary") or ""),
                    str(f.get("severity") or ""),
                ),
                "severity": str(f.get("severity") or "INFO").upper(),
                "confidence": int(f.get("confidence") or 0),
                "summary": str(f.get("summary") or ""),
                "details": str(f.get("details") or ""),
            }
            rh = _record_hash(prev_hash, payload)
            conn.execute(
                """INSERT INTO evidence_ledger
                   (recorded_at, target, run_id, kind, finding_fp, severity,
                    confidence, payload, prev_hash, record_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    now, str(f.get("target") or ""), str(run_id), str(f.get("kind") or ""),
                    payload["finding_fp"], payload["severity"], payload["confidence"],
                    _canonical(payload), prev_hash, rh,
                ),
            )
            prev_hash = rh
            head = rh
        conn.commit()
        conn.close()
        return head

    # -- reads / verification -------------------------------------------------
    def all_records(self, limit: int = 10_000) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM evidence_ledger ORDER BY seq ASC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def verify(self) -> Dict[str, Any]:
        rows = self.all_records()
        prev_hash = GENESIS_HASH
        broken_at = None
        for r in rows:
            payload = json.loads(r["payload"]) if r["payload"] else {}
            expected = _record_hash(r["prev_hash"], payload)
            if r["prev_hash"] != prev_hash or r["record_hash"] != expected:
                broken_at = r["seq"]
                break
            prev_hash = r["record_hash"]
        return {
            "ok": broken_at is None,
            "records": len(rows),
            "head": prev_hash if broken_at is None else None,
            "broken_at": broken_at,
        }

    # -- proof pack -----------------------------------------------------------
    def export_proof_pack(self, run_id: str, path: str) -> Dict[str, Any]:
        rows = [r for r in self.all_records() if r["run_id"] == run_id]
        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "chain_head": rows[-1]["record_hash"] if rows else None,
            "records": [
                {
                    "seq": r["seq"],
                    "recorded_at": r["recorded_at"],
                    "target": r["target"],
                    "kind": r["kind"],
                    "finding_fp": r["finding_fp"],
                    "severity": r["severity"],
                    "confidence": r["confidence"],
                    "payload": json.loads(r["payload"]) if r["payload"] else {},
                    "prev_hash": r["prev_hash"],
                    "record_hash": r["record_hash"],
                }
                for r in rows
            ],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        return manifest
