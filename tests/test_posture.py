"""Posture score: explainable 0-100 risk posture."""

from core import posture as po


def test_no_findings_scores_perfect_posture():
    s = po.posture_score([])
    assert s["score"] == 100 and s["grade"] == "A"


def test_single_verified_leak_lowers_score():
    s = po.posture_score([_f := {
        "kind": "verified_leak", "severity": "HIGH", "confidence": 95, "verified": True,
        "summary": "exposed .env", "marker": ".env", "details": {},
    }])
    assert s["score"] < 100
    assert s["drivers"]


def test_ignores_unverified_findings():
    s = po.posture_score([{"kind": "weak_headers", "severity": "MEDIUM", "confidence": 40, "verified": False, "summary": "x", "marker": "x"}])
    assert s["score"] == 100
