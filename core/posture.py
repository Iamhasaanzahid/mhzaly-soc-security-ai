#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""posture.py — Explainable posture score.

A single 0-100 posture number is only useful if you can defend it. This module
computes one from the verified findings and inventory with an explicit rubric, and
returns the drivers so the score is auditable in a report or a UI panel.

Rubric weights map to finding kinds that indicate risk exposure.
"""

from __future__ import annotations

from typing import Any, Dict, List

RUBRIC: List[Dict[str, Any]] = [
    {"factor": "verified_exposure", "weight": 30, "kinds": ["verified_leak"]},
    {"factor": "headers", "weight": 20, "kinds": ["weak_headers"]},
    {"factor": "transport_security", "weight": 15, "kinds": ["tls_weak_protocol", "tls_untrusted", "tls_expiring", "tls_expired"]},
    {"factor": "cookie_and_cors", "weight": 10, "kinds": ["insecure_cookie", "cors_wildcard"]},
    {"factor": "email_auth", "weight": 10, "kinds": ["email_dmarc_missing", "email_spf_missing"]},
    {"factor": "exposure_surface", "weight": 15, "kinds": ["open_port", "risky_port", "cors_wildcard"]},
]


def _kinds(finding: Dict[str, Any]) -> List[str]:
    return [str(finding.get("kind") or "")]


def posture_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    verified = [f for f in findings or [] if f.get("verified")]
    score = 100.0
    drivers: List[Dict[str, Any]] = []
    seen_kinds = set()
    for f in sorted(verified, key=lambda x: -float(x.get("confidence") or 0)):
        kind = str(f.get("kind") or "")
        weight = 25.0  # worst-case single finding cost when the kind is unmapped
        for entry in RUBRIC:
            if kind in entry["kinds"]:
                weight = float(entry["weight"])
                break
        score -= weight
        if kind not in seen_kinds:
            seen_kinds.add(kind)
            drivers.append({
                "factor": kind,
                "finding": str(f.get("summary") or ""),
                "weight": weight,
                "confidence": f.get("confidence"),
            })
        if score <= 0:
            break
    score = max(0, round(score))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    return {"score": int(score), "grade": grade, "drivers": drivers, "verified_count": len(verified)}
