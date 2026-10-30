#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
confidence.py — Precision gate for the MHZALY SOC pipeline.

The old pipeline reported everything a scanner could see: soft-404 pages
counted as "exposed files", keyword CVE matches counted as real
vulnerabilities, and every open port was a separate point. That produces a
report nobody trusts.

This module exists so the platform reports *less* and stands behind all of
it. Every candidate finding is scored 0-100, de-duplicated, and only
findings above a confidence floor (and above a severity floor) are persisted
or alerted on. Anything below the floor is counted, logged, and dropped.
"""

from typing import Any, Dict, Iterable, List, Optional

SEVERITY_RANK: Dict[str, int] = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

#: Nothing below this is reported by default.
DEFAULT_MIN_CONFIDENCE = 70
#: Informational inventory (subdomains, technology hints) is not a "finding".
DEFAULT_MIN_SEVERITY = "MEDIUM"

#: Base score per finding kind. Evidence modifiers are applied on top.
BASE_SCORES: Dict[str, int] = {
    # Verified, signature-matched exposures — these are the ones worth paging on.
    "verified_leak": 95,
    "takeover": 92,
    "dangerous_service": 90,
    # Transport / certificate problems.
    "tls_expired": 96,
    "tls_untrusted": 88,        # self-signed / wrong hostname / unknown CA
    "tls_expiring": 86,         # < 30 days left
    "tls_weak_protocol": 87,
    # Deterministic, directly observable configuration issues.
    "weak_headers": 88,         # consolidated, not one point per header
    "insecure_cookie": 84,
    "cors_wildcard": 86,
    "email_spf_missing": 80,
    "email_dmarc_missing": 82,
    "email_dmarc_weak": 76,
    # Network surface.
    "open_port": 72,
    "risky_port": 78,
    # Intelligence correlation.
    "cve_cpe": 85,
    "cve_keyword": 35,
    "vt_malicious": 90,
    "threat_intel": 84,
    # Inventory — never alert, may be useful in a report appendix.
    "tech": 55,
    "subdomain": 45,
}

#: Modifiers keyed on evidence flags produced by core.hunter / scheduler.
EVIDENCE_MODIFIERS: Dict[str, int] = {
    "verified": 5,
    "double_checked": 5,
    "signature_match": 5,
    "banner_confirmed": 8,
    "fresh_cert": 0,
}


def clamp(value: Any, low: int = 0, high: int = 100) -> int:
    """Clamp an arbitrary value into an integer 0-100."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return low
    return max(low, min(high, v))


def score_finding(kind: str, evidence: Optional[Dict[str, Any]] = None) -> int:
    """Score one candidate finding.

    `kind` selects the base score; `evidence` flags add or remove weight.
    Unknown kinds deliberately score low: an unrecognised finding has not
    been validated by anyone, so it must not reach the report.
    """
    evidence = evidence or {}
    base = BASE_SCORES.get(str(kind or "").strip().lower(), 40)
    for flag, delta in EVIDENCE_MODIFIERS.items():
        if evidence.get(flag):
            base += delta
    # Soft-404 matches are the classic false positive: page exists, file doesn't.
    if evidence.get("soft_404"):
        base = min(base, 15)
    # A 401/403 is a *protected* resource, not an exposure.
    if evidence.get("protected") and kind in {"verified_leak", "takeover"}:
        base = min(base, 25)
    # Keyword-only CVE correlation is a lead, never a finding.
    if evidence.get("match_confidence") == "keyword" and kind.startswith("cve"):
        base = min(base, BASE_SCORES["cve_keyword"])
    return clamp(base)


def normalise(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of `finding` with a numeric confidence and verified flag."""
    out = dict(finding)
    kind = str(out.get("kind") or out.get("category") or "").lower()
    evidence = out.get("evidence") or {}
    if out.get("confidence") is None:
        out["confidence"] = score_finding(kind, evidence)
    else:
        out["confidence"] = clamp(out["confidence"])
    out["severity"] = str(out.get("severity") or "INFO").upper()
    out["verified"] = bool(out.get("verified", evidence.get("verified", False)))
    out["kind"] = kind
    return out


def _dedupe_key(finding: Dict[str, Any]) -> str:
    """Identity used to collapse duplicates of the same fact."""
    marker = finding.get("marker") or finding.get("summary") or finding.get("category") or ""
    return f"{finding.get('category', '')}|{marker}".strip().lower()


def dedupe(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse duplicate findings, keeping the highest-confidence version."""
    best: Dict[str, Dict[str, Any]] = {}
    for raw in findings:
        f = normalise(raw)
        key = _dedupe_key(f)
        current = best.get(key)
        if current is None or f["confidence"] > current["confidence"]:
            best[key] = f
    return sorted(best.values(), key=lambda f: (-f["confidence"], -SEVERITY_RANK.get(f["severity"], 0)))


def gate(
    findings: Iterable[Dict[str, Any]],
    min_confidence: int = DEFAULT_MIN_CONFIDENCE,
    min_severity: str = DEFAULT_MIN_SEVERITY,
) -> List[Dict[str, Any]]:
    """The policy: de-duplicate, then keep only strong, material findings."""
    floor = SEVERITY_RANK.get(str(min_severity).upper(), SEVERITY_RANK[DEFAULT_MIN_SEVERITY])
    kept: List[Dict[str, Any]] = []
    for f in dedupe(findings):
        if f["confidence"] < min_confidence:
            continue
        if SEVERITY_RANK.get(f["severity"], 0) < floor:
            continue
        kept.append(f)
    return kept


def suppressed_count(findings: Iterable[Dict[str, Any]], kept: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """Small bookkeeping record of what the gate threw away, and why."""
    raw = [normalise(f) for f in findings]
    unique = dedupe(raw)
    kept_n = len(list(kept))
    low_conf = sum(1 for f in unique if f["confidence"] < DEFAULT_MIN_CONFIDENCE)
    low_sev = sum(
        1 for f in unique
        if f["confidence"] >= DEFAULT_MIN_CONFIDENCE
        and SEVERITY_RANK.get(f["severity"], 0) < SEVERITY_RANK[DEFAULT_MIN_SEVERITY]
    )
    return {
        "candidates": len(raw),
        "reported": kept_n,
        "low_confidence": low_conf,
        "low_severity": low_sev,
        "duplicates": max(0, len(raw) - len(unique)),
    }


def should_alert(finding: Dict[str, Any], min_confidence: int = 80) -> bool:
    """Only verified, strong, material findings are allowed to page a human."""
    f = normalise(finding)
    return (
        f["verified"]
        and f["confidence"] >= min_confidence
        and SEVERITY_RANK.get(f["severity"], 0) >= SEVERITY_RANK["MEDIUM"]
    )
