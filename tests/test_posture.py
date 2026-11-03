"""Posture score: explainable 0-100 risk posture."""

from core import posture as po


def test_no_findings_scores_perfect_posture():
    s = po.posture_score([])
    assert s["score"] == 100 and s["grade"] == "A"


def _f(kind, severity="HIGH", confidence=95, verified=True, summary="finding"):
    return {"kind": kind, "severity": severity, "confidence": confidence,
            "verified": verified, "summary": summary, "marker": kind, "details": {}}


def test_single_verified_leak_deducts_rubric_weight_once():
    s = po.posture_score([_f("verified_leak", summary="exposed .env")])
    assert s["score"] == 70
    assert s["drivers"][0]["factor"] == "verified_leak"


def test_rubric_weights_compound():
    s = po.posture_score([_f("verified_leak"), _f("weak_headers", "MEDIUM")])
    assert s["score"] == 50


def test_ignores_unverified_findings():
    s = po.posture_score([_f("weak_headers", "MEDIUM", 40, verified=False)])
    assert s["score"] == 100
