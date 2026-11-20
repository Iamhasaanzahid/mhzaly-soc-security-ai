#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify.py — live re-verification of stored findings.

A scan is a snapshot. Between the scan and the report, the client may have
shipped a fix, a CDN may have been enabled, or a header may have been added.
Reporting a stored finding as if it were still true is how a scanner loses
trust.

`live_facts()` re-checks the target the way a browser would. `reconcile()`
then labels every stored finding as reproduced, resolved, not applicable
(CDN edge / provider-managed DNS) or unverifiable. Reports are built from the
reproduced set, and resolved items are shown explicitly as progress rather
than silently dropped.
"""

from __future__ import annotations

import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

from . import hunter

try:  # pragma: no cover - import cycle guard
    from . import connectors
except Exception:  # pragma: no cover
    connectors = None  # type: ignore


def _lower_headers(resp: Optional[requests.Response]) -> Dict[str, str]:
    if resp is None:
        return {}
    return {str(k).lower(): str(v) for k, v in resp.headers.items()}


def _origin(target: str) -> str:
    return hunter.origin_of(target)


def collect_probe_paths(findings: Iterable[Dict[str, Any]]) -> List[str]:
    """Paths worth re-probing because a stored finding claims they leak."""
    paths: List[str] = []
    for finding in findings or []:
        kind = str(finding.get("kind") or "").lower()
        details = finding.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        path = details.get("path")
        if path and (kind.startswith(("verified_leak", "exposed")) or "path:" in str(finding.get("marker", ""))):
            paths.append(str(path))
    return list(dict.fromkeys(paths))[:8]


def live_facts(target: str, timeout: int = 8, check_ports: bool = True,
               paths: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Collect the current, checkable truth about a target. Never raises."""
    origin = _origin(target)
    host = (urllib.parse.urlparse(origin).hostname or "").strip()
    facts: Dict[str, Any] = {
        "target": target,
        "origin": origin,
        "host": host,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "reachable": False,
        "status": None,
        "final_url": None,
        "headers": {},
        "header_grade": {"score": 0, "grade": "—", "missing": []},
        "cors": {},
        "tls": {},
        "cdn": None,
        "ports": [],
        "email": {},
        "managed_domain": False,
        "robots": {},
        "leaks": {},
        "notes": [],
        "errors": [],
    }
    if not origin or not host:
        facts["errors"].append("target could not be normalised")
        return facts

    session = requests.Session()
    session.headers.update({"User-Agent": hunter.DEFAULT_UA, "Accept": "*/*"})
    resp: Optional[requests.Response] = None
    try:
        resp = session.get(origin, timeout=timeout, allow_redirects=True, verify=True)
    except requests.exceptions.SSLError as exc:
        facts["tls_error"] = str(exc)
        facts["notes"].append("TLS trust failed during the live fetch; the page was still read to grade headers.")
        try:
            resp = session.get(origin, timeout=timeout, allow_redirects=True, verify=False)
        except Exception as exc2:  # pragma: no cover - network dependent
            facts["errors"].append(f"fetch failed: {exc2}")
    except Exception as exc:  # pragma: no cover - network dependent
        facts["errors"].append(f"fetch failed: {exc}")

    if resp is not None:
        facts["reachable"] = True
        facts["status"] = resp.status_code
        facts["final_url"] = resp.url
        facts["headers"] = _lower_headers(resp)
        facts["header_grade"] = hunter.grade_security_headers(facts["headers"])
        facts["cdn"] = hunter.detect_cdn(facts["headers"])
        if facts["cdn"]:
            facts["notes"].append(
                f"{facts['cdn']} edge detected — edge ports and TLS termination belong to "
                "the provider, not the origin server."
            )

    # CORS with a synthetic Origin so reflection is observable.
    try:
        probe = session.get(origin, timeout=timeout, verify=False,
                            headers={"Origin": hunter.CORS_PROBE_ORIGIN})
        facts["cors"] = hunter.assess_cors(_lower_headers(probe))
    except Exception as exc:  # pragma: no cover - network dependent
        facts["cors"] = {"error": str(exc)}

    # Certificate, verified exactly like a browser would.
    try:
        facts["tls"] = hunter.check_tls(host)
    except Exception as exc:  # pragma: no cover - network dependent
        facts["tls"] = {"valid": False, "error": str(exc)}

    # Email authentication, only when the client actually controls the zone.
    facts["managed_domain"] = hunter.is_managed_domain(host)
    if facts["managed_domain"]:
        facts["email"] = {"managed": True, "note": "provider-managed DNS zone"}
        facts["notes"].append(
            "SPF/DMARC are controlled by the hosting platform for this domain and are not "
            "client-actionable."
        )
    else:
        try:
            facts["email"] = hunter.check_email_security(host)
        except Exception as exc:  # pragma: no cover - network dependent
            facts["email"] = {"error": str(exc)}

    # robots.txt must be a real crawler file, not the SPA fallback page.
    try:
        robots = session.get(origin + "/robots.txt", timeout=timeout, verify=False)
        body = robots.text or ""
        ctype = (robots.headers.get("content-type") or "").lower()
        looks_real = bool(
            robots.status_code == 200
            and "<html" not in body[:300].lower()
            and ("text/plain" in ctype or re.search(r"(?mi)^\s*(user-agent|disallow|allow)\s*:", body))
        )
        facts["robots"] = {
            "status": robots.status_code,
            "content_type": ctype,
            "valid": looks_real,
        }
    except Exception as exc:  # pragma: no cover - network dependent
        facts["robots"] = {"error": str(exc)}

    # Ports — skip entirely when the DNS name points at a CDN edge.
    if check_ports:
        if facts["cdn"]:
            facts["notes"].append(
                f"Port sweep skipped: {facts['cdn']} answers on behalf of the origin, so edge "
                "ports (80/443/8080/8443) are not evidence about the customer's server."
            )
        elif connectors is not None:
            try:
                facts["ports"] = connectors.scan_ports(host)
            except Exception as exc:  # pragma: no cover - network dependent
                facts["errors"].append(f"port sweep failed: {exc}")

    # Re-probe only the leak paths a stored finding actually claims.
    wanted = [p for p in (paths or []) if p]
    if wanted and facts["reachable"]:
        probe_session = hunter.make_session(timeout=timeout)
        baseline = hunter.soft_404_baseline(probe_session, origin)
        for path in wanted:
            try:
                facts["leaks"][path] = hunter.verify_sensitive_path(
                    probe_session, origin, path, baseline
                )
            except Exception as exc:  # pragma: no cover - network dependent
                facts["leaks"][path] = {"path": path, "verified": False, "note": str(exc)}

    return facts


# ── reconciliation ──────────────────────────────────────────────────────────

def _status_for(finding: Dict[str, Any], facts: Dict[str, Any]) -> Tuple[str, str]:
    """Return (status, human reason) for one stored finding."""
    kind = str(finding.get("kind") or finding.get("category") or "").lower()
    details = finding.get("details") or {}
    if not isinstance(details, dict):
        details = {}

    if kind in {"weak_headers", "missing_headers", "security_headers", "header_gap"}:
        missing = (facts.get("header_grade") or {}).get("missing") or []
        if missing:
            return "reproduced", "still missing: " + ", ".join(missing)
        if facts.get("reachable"):
            return "resolved", "the live response now carries every graded security header"
        return "unverified", "target was not reachable during re-check"

    if kind in {"cors_wildcard", "cors_reflection", "cors_misconfig"}:
        cors = facts.get("cors") or {}
        if cors.get("risky"):
            return "reproduced", str(cors.get("reason") or "permissive CORS still observed")
        if cors.get("error"):
            return "unverified", str(cors["error"])
        return "resolved", str(cors.get("reason") or "CORS is no longer permissive")

    if kind.startswith("tls_"):
        tls = facts.get("tls") or {}
        if kind == "tls_untrusted" and tls.get("untrusted"):
            return "reproduced", str(tls.get("error") or "certificate still fails trust validation")
        if kind == "tls_expired" and tls.get("expired"):
            return "reproduced", f"certificate expired {abs(int(tls.get('days_left') or 0))} day(s) ago"
        if kind == "tls_expiring" and tls.get("expiring_soon"):
            return "reproduced", f"certificate expires in {tls.get('days_left')} day(s)"
        if tls.get("valid") and not tls.get("expired") and not tls.get("untrusted"):
            return "resolved", "certificate validates against a public trust store"
        return "unverified", str(tls.get("error") or "certificate could not be validated")

    if kind.startswith("email_"):
        if facts.get("managed_domain"):
            return "not_applicable", "provider-managed DNS zone (SPF/DMARC owned by the platform)"
        email = facts.get("email") or {}
        if email.get("error"):
            return "unverified", str(email["error"])
        if kind == "email_spf_missing" and email.get("spf"):
            return "resolved", "SPF record is now published"
        if kind == "email_dmarc_missing" and email.get("dmarc"):
            return "resolved", "DMARC record is now published"
        if kind == "email_dmarc_weak" and email.get("dmarc_policy") in {"quarantine", "reject"}:
            return "resolved", f"DMARC policy is now p={email.get('dmarc_policy')}"
        if kind == "email_spf_missing" and not email.get("spf"):
            return "reproduced", "no SPF record published"
        if kind == "email_dmarc_missing" and not email.get("dmarc"):
            return "reproduced", "no DMARC record published"
        if kind == "email_dmarc_weak":
            return "reproduced", "DMARC policy is still monitor-only"
        return "unverified", "email records could not be re-read"

    if kind in {"open_port", "risky_open_port", "exposed_service"}:
        port = int(details.get("port") or 0)
        if port and facts.get("cdn") and port in hunter.CDN_EDGE_PORTS:
            return "not_applicable", f"{facts['cdn']} edge port — not attributable to the origin"
        live_ports = {int(p.get("port", 0)) for p in (facts.get("ports") or [])}
        if port and facts.get("ports"):
            if port in live_ports:
                return "reproduced", f"TCP/{port} still accepts connections"
            return "resolved", f"TCP/{port} no longer accepts connections"
        return "unverified", "no live port sweep was possible"

    if kind.startswith(("verified_leak", "exposed_asset", "exposed_file")):
        path = str(details.get("path") or "")
        probe = (facts.get("leaks") or {}).get(path)
        if probe is not None:
            if probe.get("verified"):
                return "reproduced", "content signature still matches"
            if probe.get("protected"):
                return "resolved", "path is now protected by authentication"
            return "resolved", str(probe.get("note") or "no longer exposed")
        return "unverified", "path was not re-probed"

    return "unverified", "no live check exists for this finding kind"


def reconcile(findings: Iterable[Dict[str, Any]], facts: Dict[str, Any]) -> Dict[str, Any]:
    """Split stored findings into reproduced / resolved / not-applicable / unverified."""
    fresh: List[Dict[str, Any]] = []
    resolved: List[Dict[str, Any]] = []
    not_applicable: List[Dict[str, Any]] = []
    unverified: List[Dict[str, Any]] = []

    for finding in findings or []:
        status, reason = _status_for(finding, facts)
        enriched = dict(finding)
        enriched["live_status"] = status
        enriched["live_reason"] = reason
        if status == "reproduced":
            fresh.append(enriched)
        elif status == "resolved":
            resolved.append(enriched)
        elif status == "not_applicable":
            not_applicable.append(enriched)
        else:
            unverified.append(enriched)

    return {
        "checked_at": facts.get("checked_at"),
        "facts": facts,
        "fresh": fresh,
        "resolved": resolved,
        "not_applicable": not_applicable,
        "unverified": unverified,
        "counts": {
            "stored": len(fresh) + len(resolved) + len(not_applicable) + len(unverified),
            "reproduced": len(fresh),
            "resolved": len(resolved),
            "not_applicable": len(not_applicable),
            "unverified": len(unverified),
        },
    }


def summary_line(recon: Dict[str, Any]) -> str:
    """One line an operator can trust at a glance."""
    counts = recon.get("counts") or {}
    return (
        f"Live re-check at {recon.get('checked_at', 'unknown')}: "
        f"{counts.get('reproduced', 0)} reproduced, {counts.get('resolved', 0)} resolved, "
        f"{counts.get('not_applicable', 0)} not applicable, "
        f"{counts.get('unverified', 0)} unverifiable."
    )
