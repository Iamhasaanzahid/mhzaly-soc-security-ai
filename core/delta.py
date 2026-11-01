#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""delta.py — Scan-to-scan delta engine.

Compares the set of verified findings between two scans and renders a plain-
language change narrative. The autonomous SOC has always stored findings; what
it did not have was a *story of change* between assessments.

Usage: run A finds X; run B finds X gone, Y appeared → the delta narrative is
"regression" (a previously verified finding stopped being verified/existing),
or "new", or "cleared".
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from .confidence import SEVERITY_RANK
from .evidence import fingerprint_of


def _identity(f: Dict[str, Any], target: str) -> str:
    """Identity for change-tracking: kind + marker + summary. Severity changes
    are reported as escalations, not as new findings."""
    return fingerprint_of(
        target,
        str(f.get("kind") or ""),
        str(f.get("marker") or ""),
        str(f.get("summary") or ""),
        "",
    )


def delta_between(previous: List[Dict[str, Any]], current: List[Dict[str, Any]],
                  target: str = "") -> Dict[str, Any]:
    prev_map: Dict[str, Dict[str, Any]] = {}
    for f in previous or []:
        prev_map[_identity(f, target)] = f
    curr_map: Dict[str, Dict[str, Any]] = {}
    for f in current or []:
        curr_map[_identity(f, target)] = f

    added = [curr_map[k] for k in sorted(set(curr_map) - set(prev_map))]
    resolved = [prev_map[k] for k in sorted(set(prev_map) - set(curr_map))]

    escalated: List[Dict[str, Any]] = []
    de_escalated: List[Dict[str, Any]] = []
    persisting: List[Dict[str, Any]] = []
    for k in sorted(set(prev_map) & set(curr_map)):
        a, b = prev_map[k], curr_map[k]
        if str(a.get("severity", "")).upper() != str(b.get("severity", "")).upper():
            sev_a = str(a.get("severity") or "INFO").upper()
            sev_b = str(b.get("severity") or "INFO").upper()
            if SEVERITY_RANK.get(sev_a, 0) < SEVERITY_RANK.get(sev_b, 0):
                escalated.append(b)
            else:
                de_escalated.append(b)
        else:
            persisting.append(b)

    return {
        "target": target,
        "new_findings": added,
        "resolved_findings": resolved,
        "persisting_findings": persisting,
        "escalated_findings": escalated,
        "de_escalated_findings": de_escalated,
        "summary": {
            "new": len(added),
            "resolved": len(resolved),
            "persisting": len(persisting),
            "escalated": len(escalated),
            "de_escalated": len(de_escalated),
        },
    }


def delta_narrative(delta: Dict[str, Any]) -> str:
    """Human voice: explain what changed since the last assessment."""
    s = delta.get("summary") or {}
    lines = []
    if not s.get("new") and not s.get("resolved") and not s.get("persisting"):
        return "No changes since the last assessment."
    if s.get("new"):
        lines.append(
            f"{s['new']} new finding(s) were verified since the previous assessment. "
            f"The overall exposure picture is not static, and these need engineer attention."
        )
    if s.get("resolved"):
        lines.append(
            f"{s['resolved']} previously verified finding(s) are no longer reported as live — "
            "either the exposure was fixed or it changed shape. This is the part of an "
            "assessment I actually like to read out loud."
        )
    if s.get("escalated"):
        lines.append(
            f"{s['escalated']} existing finding(s) escalated in severity — treat that as a "
            "regression and work the remediation order backwards."
        )
    if s.get("de_escalated"):
        lines.append(
            f"{s['de_escalated']} finding(s) were re-scored down on re-verification; record the "
            "reasoning and re-run the proving check before closing the thread."
        )
    if s.get("persisting"):
        lines.append(
            f"{s['persisting']} finding(s) persisted across the re-scan, which is expected — "
            "they are the standing backlog."
        )
    return " ".join(lines)
