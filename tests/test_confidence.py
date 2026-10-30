"""Precision gate: fewer findings, each one defensible."""

from core import confidence


def test_score_known_kind():
    assert confidence.score_finding("verified_leak") == 95
    assert confidence.score_finding("weak_headers") == 88


def test_unknown_kind_scores_low():
    assert confidence.score_finding("something-new") <= 45


def test_soft_404_is_capped():
    assert confidence.score_finding("verified_leak", {"soft_404": True}) <= 15


def test_protected_is_not_a_leak():
    assert confidence.score_finding("verified_leak", {"protected": True}) <= 25


def test_keyword_cve_is_a_lead_not_a_finding():
    assert confidence.score_finding("cve_cpe", {"match_confidence": "keyword"}) <= 40
    assert confidence.score_finding("cve_cpe", {"match_confidence": "cpe"}) >= 80


def test_evidence_flags_raise_score():
    base = confidence.score_finding("verified_leak")
    assert confidence.score_finding("verified_leak", {"double_checked": True}) > base


def test_normalise_fills_fields():
    f = confidence.normalise({"kind": "open_port", "severity": "medium"})
    assert f["severity"] == "MEDIUM"
    assert isinstance(f["confidence"], int)
    assert f["verified"] is False


def test_dedupe_keeps_strongest():
    findings = [
        {"kind": "weak_headers", "category": "Security Headers", "marker": "h", "confidence": 60},
        {"kind": "weak_headers", "category": "Security Headers", "marker": "h", "confidence": 90},
    ]
    out = confidence.dedupe(findings)
    assert len(out) == 1
    assert out[0]["confidence"] == 90


def test_gate_enforces_confidence_and_severity():
    findings = [
        {"kind": "verified_leak", "category": "Exposed Asset", "marker": "p1",
         "severity": "CRITICAL", "confidence": 95, "verified": True},
        {"kind": "cve_keyword", "category": "CVE", "marker": "cve",
         "severity": "HIGH", "confidence": 35, "verified": False},
        {"kind": "tech", "category": "Inventory", "marker": "t",
         "severity": "INFO", "confidence": 55, "verified": True},
    ]
    kept = confidence.gate(findings)
    assert [f["marker"] for f in kept] == ["p1"]


def test_should_alert_requires_verified_material_finding():
    strong = {"kind": "verified_leak", "category": "x", "marker": "m",
              "severity": "CRITICAL", "confidence": 95, "verified": True}
    weak = {**strong, "confidence": 60}
    unverified = {**strong, "verified": False}
    assert confidence.should_alert(strong) is True
    assert confidence.should_alert(weak) is False
    assert confidence.should_alert(unverified) is False


def test_suppressed_count_bookkeeping():
    findings = [
        {"kind": "verified_leak", "category": "A", "marker": "one", "severity": "HIGH", "confidence": 95},
        {"kind": "cve_keyword", "category": "A", "marker": "two", "severity": "HIGH", "confidence": 30},
        {"kind": "tech", "category": "A", "marker": "three", "severity": "INFO", "confidence": 55},
    ]
    kept = confidence.gate(findings)
    stats = confidence.suppressed_count(findings, kept)
    assert stats["candidates"] == 3
    assert stats["reported"] == 1
    # cve_keyword (30) and tech (55) are both below the confidence floor.
    assert stats["low_confidence"] == 2
    assert stats["low_severity"] == 0
    assert stats["duplicates"] == 0

    # A high-confidence but informational item is dropped on severity alone.
    informational = [{"kind": "tech", "category": "A", "marker": "t",
                      "severity": "INFO", "confidence": 92}]
    stats2 = confidence.suppressed_count(informational, confidence.gate(informational))
    assert stats2["low_severity"] == 1
    assert stats2["reported"] == 0
