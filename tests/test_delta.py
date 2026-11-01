"""Delta engine: what changed between assessments."""

from core import delta as dl


def _f(kind, marker, severity, summary, conf=90):
    return {
        "kind": kind, "marker": marker, "severity": severity, "summary": summary,
        "confidence": conf, "verified": True, "details": {},
    }


def test_delta_detects_new_and_resolved():
    prev = [_f("weak_headers", "HSTS", "MEDIUM", "missing HSTS")]
    curr = [_f("weak_headers", "CSP", "LOW", "missing CSP")]
    d = dl.delta_between(prev, curr, target="example.com")
    assert d["summary"]["new"] == 1
    assert d["summary"]["resolved"] == 1
    assert len(d["new_findings"]) == 1
    assert len(d["resolved_findings"]) == 1


def test_delta_detects_escalation():
    prev = [_f("weak_headers", "HSTS", "LOW", "missing HSTS", conf=70)]
    curr = [_f("weak_headers", "HSTS", "HIGH", "missing HSTS", conf=92)]
    d = dl.delta_between(prev, curr, target="example.com")
    assert d["summary"]["escalated"] == 1


def test_delta_empty_is_clean():
    d = dl.delta_between([], [], target="example.com")
    assert d["summary"] == {"new": 0, "resolved": 0, "persisting": 0, "escalated": 0, "de_escalated": 0}
    assert dl.delta_narrative(d)
