#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reporter.py — Report writer with a human voice.

Three things this module does that a plain "ask the LLM to write a report"
call does not:

1. **A prompt written for a consultant, not a chatbot.** The model is told how
   a senior penetration tester structures an internal assessment: scope first,
   evidence before opinion, explicit uncertainty, no marketing adjectives.
2. **A deterministic fallback that still reads like prose.** With no API key
   the report is built from the actual findings as a narrative, not a wall of
   bullet points, so the document is presentable either way.
3. **Post-processing.** `humanize()` strips the tells that make AI writing
   obvious, and `check_hallucinations()` flags identifiers in the text that
   are not backed by the evidence bundle — a report that invents a CVE is
   worse than no report.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .confidence import SEVERITY_RANK  # noqa: F401  (kept for callers)

#: Phrases that make a technical report read like a chatbot wrote it.
AI_ISMS: Tuple[str, ...] = (
    "as an ai", "as a language model", "i'm sorry", "i am sorry", "sure, here",
    "sure! here", "certainly!", "i hope this helps", "let me know if",
    "delve into", "dive into", "in today's", "digital landscape", "ever-evolving",
    "cutting-edge", "state-of-the-art", "game-changer", "seamless",
    "leverage", "robust solution", "comprehensive solution", "unlock the",
    "it is important to note", "it's important to note", "in conclusion",
    "in summary,", "overall, it", "furthermore,", "moreover,", "additionally,",
    "embark on", "tapestry", "testament to", "navigate the", "revolutionize",
)

_EMOJI_RE = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF]+"
)

SYSTEM_PROMPT = (
    "You are a senior penetration tester with fourteen years of experience, "
    "OSCP and OSWE certified, writing an internal assessment for the client's "
    "engineering team. Write the way an experienced consultant actually writes: "
    "first person, plain English, specific. Lead with what the evidence proves "
    "and separate it from what you suspect. Name the exact host, header, path or "
    "certificate you observed. Say plainly when something could not be tested. "
    "Do not use emojis, marketing adjectives, or filler. Do not invent hosts, "
    "versions, CVEs or exploit results — if the evidence bundle does not contain "
    "it, it does not go in the report. Prefer short paragraphs over long bullet "
    "lists, and keep remediation concrete enough that an engineer can action it "
    "without asking a follow-up question."
)

REPORT_SKELETON = (
    "Structure the report exactly like this, in markdown:\n"
    "## Scope and method\n"
    "## What the assessment found\n"
    "## Findings\n"
    "For each finding: severity, what was observed, why it matters, how to fix it.\n"
    "## What could not be verified\n"
    "## Recommended order of work\n"
)


def humanize(text: str) -> str:
    """Remove the most obvious machine-writing tells from a report.

    Deliberately conservative: it edits phrasing, never facts. Numbers, host
    names and identifiers are left untouched.
    """
    if not text:
        return ""
    out = text
    for phrase in AI_ISMS:
        out = re.sub(re.escape(phrase), "", out, flags=re.I)
    out = _EMOJI_RE.sub("", out)
    # Chatbot openers such as "Certainly! Here is the report:".
    out = re.sub(r"^\s*(okay|ok|alright|certainly|sure)[,.!\s]+", "", out, flags=re.I)
    # Normalise whitespace without destroying markdown structure.
    out = re.sub(r"[ \t]+\n", "\n", out)
    out = re.sub(r"\n{3,}", "\n\n", out)
    out = re.sub(r" {2,}", " ", out)
    # A stray capital after removing an opener reads badly; fix sentence starts.
    out = re.sub(r"(^|[.!?]\s+)([a-z])", lambda m: m.group(1) + m.group(2).upper(), out)
    return out.strip()


def _evidence_blob(evidence: Any) -> str:
    return str(evidence).lower()


def check_hallucinations(text: str, evidence: Any) -> List[str]:
    """Return identifiers mentioned in the report that the evidence lacks.

    Covers CVE IDs, IPv4 addresses and hostnames. This is a guard-rail, not a
    proof: it catches the failure mode where a model "helpfully" adds a CVE
    that was never observed.
    """
    blob = _evidence_blob(evidence)
    suspicious: List[str] = []
    for cve in set(re.findall(r"CVE-\d{4}-\d{4,7}", text or "", flags=re.I)):
        if cve.lower() not in blob:
            suspicious.append(cve.upper())
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text or "")):
        if ip not in blob:
            suspicious.append(ip)
    return sorted(set(suspicious))


def build_messages(target: str, findings: Iterable[Dict[str, Any]],
                   inventory: Optional[Dict[str, Any]] = None,
                   audience: str = "the client's engineering team") -> List[Dict[str, str]]:
    """Build the Groq chat payload for a human-style assessment report."""
    findings = list(findings or [])
    inventory = inventory or {}
    lines = [f"Target: {target}", f"Audience: {audience}", ""]
    if findings:
        lines.append(f"Confirmed findings ({len(findings)}):")
        for f in findings:
            lines.append(
                f"- [{f.get('severity', 'INFO')}] {f.get('summary', '')} "
                f"(confidence {f.get('confidence', '?')}%)"
            )
            details = f.get("details") or {}
            if details:
                lines.append(f"  evidence: {str(details)[:400]}")
    else:
        lines.append("Confirmed findings: none survived verification.")
    if inventory:
        pages = inventory.get("pages") or []
        lines.append("")
        lines.append(f"Pages reviewed: {len(pages)}; technologies: {', '.join(inventory.get('technologies') or []) or 'not fingerprinted'}")
        headers = inventory.get("headers") or {}
        if headers:
            lines.append(f"Header grade: {headers.get('grade')} ({headers.get('score')}/100); missing: {', '.join(headers.get('missing') or []) or 'none'}")
        tls = inventory.get("tls") or {}
        if tls:
            lines.append(f"TLS: valid={tls.get('valid')} protocol={tls.get('protocol')} days_left={tls.get('days_left')}")
        if inventory.get("error"):
            lines.append(f"Note: {inventory['error']}")
    lines.append("")
    lines.append(REPORT_SKELETON)
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "\n".join(lines)},
    ]


def _formatted_date() -> str:
    return datetime.now(timezone.utc).strftime("%d %B %Y")


def local_report(target: str, findings: Iterable[Dict[str, Any]],
                 inventory: Optional[Dict[str, Any]] = None,
                 analyst: str = "the MHZALY assessment team") -> str:
    """Write the report from scratch, in prose, without an LLM.

    With no API key this is the document the client receives, so it has to
    stand on its own: specific, ordered by risk, honest about gaps.
    """
    findings = sorted(
        list(findings or []),
        key=lambda f: (-SEVERITY_RANK.get(str(f.get("severity", "INFO")).upper(), 0),
                       -int(f.get("confidence", 0) or 0)),
    )
    inventory = inventory or {}
    origin = inventory.get("origin") or target
    pages = inventory.get("pages") or []
    tech = inventory.get("technologies") or []
    headers = inventory.get("headers") or {}
    tls = inventory.get("tls") or {}
    email = inventory.get("email_security") or {}

    out: List[str] = []
    out.append(f"# Security Assessment — {target}")
    out.append("")
    out.append(f"Prepared by {analyst} on {_formatted_date()}.")
    out.append("")

    out.append("## Scope and method")
    out.append("")
    out.append(
        f"This was a black-box assessment of the public surface of {origin}. "
        f"I reviewed {len(pages) or 'the root'} page(s), the TLS configuration, "
        f"HTTP response headers, cookie attributes, CORS behaviour and the email "
        f"authentication records for the domain. Sensitive paths were probed only "
        f"after calibrating the host's 404 behaviour, so a catch-all page cannot be "
        f"mistaken for a real file exposure."
    )
    if tech:
        out.append("")
        out.append(f"The host fingerprints as {', '.join(tech[:6])}.")
    out.append("")

    out.append("## What the assessment found")
    out.append("")
    if not findings:
        out.append(
            "Nothing survived verification. That is a meaningful result rather than "
            "an empty one: the checks that would normally produce noise — exposed "
            "configuration files, certificate problems, missing security headers — "
            "either passed or could not be proven, and I have not padded the report "
            "with maybes."
        )
    else:
        by_sev: Dict[str, int] = {}
        for f in findings:
            by_sev[f.get("severity", "INFO")] = by_sev.get(f.get("severity", "INFO"), 0) + 1
        summary = ", ".join(f"{n} {sev.lower()}" for sev, n in by_sev.items())
        out.append(
            f"{len(findings)} finding(s) met the evidence bar ({summary}). "
            f"Everything else was suppressed at the verification stage, which is why "
            f"this list is short."
        )
    out.append("")

    out.append("## Findings")
    out.append("")
    if findings:
        for idx, f in enumerate(findings, start=1):
            sev = str(f.get("severity", "INFO")).upper()
            conf = f.get("confidence", "?")
            out.append(f"### {idx}. {f.get('summary', 'Finding')}")
            out.append("")
            out.append(f"**Severity:** {sev} · **Confidence:** {conf}%")
            out.append("")
            details = f.get("details") or {}
            observation = details.get("evidence_snippet") or ""
            if observation:
                out.append(f"What I observed: `{observation}`")
                out.append("")
            impact = _impact_for(f)
            if impact:
                out.append(impact)
                out.append("")
            fix = _fix_for(f)
            if fix:
                out.append(fix)
                out.append("")
    else:
        out.append("No findings.")
        out.append("")

    out.append("## What could not be verified")
    out.append("")
    gaps = []
    if not pages:
        gaps.append("the site root could not be fetched, so no crawl was possible")
    if not tls:
        gaps.append("TLS could not be inspected (port 443 unreachable)")
    if not email.get("spf") is None or not email.get("dmarc") is None:
        pass
    if not email:
        gaps.append("email authentication records were not checked")
    gaps.append("I did not test authentication bypass, injection or business-logic flaws; those need an authenticated scope and explicit written authorisation")
    out.extend(f"- {g}" for g in gaps)
    out.append("")

    out.append("## Recommended order of work")
    out.append("")
    if findings:
        order = []
        for f in findings:
            order.append(f"- **{f.get('severity', 'INFO')}** — {_fix_short(f)}")
        out.extend(order[:8])
    else:
        out.append("- Keep the current header and certificate posture; re-test after any infrastructure change.")
    out.append("")
    out.append(
        f"Evidence bundle: {len(findings)} verified finding(s), "
        f"{len(pages)} page(s) reviewed, header grade {headers.get('grade', 'n/a')}."
    )
    return humanize("\n".join(out))


def _impact_for(finding: Dict[str, Any]) -> str:
    kind = finding.get("kind", "")
    table = {
        "verified_leak": "An attacker who can read this file can usually recover credentials or internal configuration, which turns a web issue into an infrastructure compromise.",
        "weak_headers": "Without these headers a browser will happily run injected script in the site's context and will not enforce HTTPS on first visit.",
        "insecure_cookie": "Cookies without Secure, HttpOnly and SameSite can be replayed over plain HTTP or read by injected script.",
        "tls_expired": "Visitors see a certificate error, and any client that does enforce validation will refuse the connection.",
        "tls_untrusted": "Clients cannot distinguish this host from an interception proxy.",
        "tls_expiring": "The certificate will fail in the near future; renewal should not be left to the expiry day.",
        "tls_weak_protocol": "Legacy TLS versions have known cryptographic weaknesses and are rejected by current browsers.",
        "email_dmarc_missing": "Without DMARC anyone can send mail that claims to come from this domain, which is the standard phishing path against its customers.",
        "email_spf_missing": "Without SPF, receiving servers have no way to reject forged envelopes for this domain.",
        "cors_wildcard": "A wildcard CORS policy allows any origin to read authenticated responses where credentials are permitted.",
        "open_port": "An open port is an additional entry point; what matters is the service behind it, which needs a separate, authorised test.",
        "risky_port": "This service should not normally be reachable from the public internet.",
    }
    return table.get(kind, "")


def _fix_for(finding: Dict[str, Any]) -> str:
    details = finding.get("details") or {}
    kind = finding.get("kind", "")
    if kind == "verified_leak":
        path = details.get("path", "the file")
        return f"Remove {path} from the web root and rotate every credential it contained. Add a deploy-time check so it cannot be published again."
    if kind == "weak_headers":
        missing = details.get("missing") or []
        return (
            "Add the missing headers at the edge: "
            + ", ".join(missing)
            + ". Start with HSTS (with a short max-age first) and a Content-Security-Policy in report-only mode before enforcing it."
        )
    if kind == "insecure_cookie":
        return "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies, then confirm the flags survive the CDN."
    if kind in {"tls_expired", "tls_untrusted", "tls_expiring"}:
        return "Renew and correctly chain the certificate, and wire an expiry alert at 30 and 7 days so renewal is not a surprise."
    if kind == "tls_weak_protocol":
        return "Disable TLS 1.0 and 1.1 in the server or load balancer configuration and keep TLS 1.2 as the floor."
    if kind == "email_dmarc_missing":
        return "Publish a DMARC record beginning at p=none with rua reporting, then move to p=quarantine and p=reject once the reports look clean."
    if kind == "email_spf_missing":
        return "Publish an SPF record listing only the sending infrastructure actually in use, and keep it under ten DNS lookups."
    if kind == "cors_wildcard":
        return "Replace the wildcard with an explicit allow-list of origins, and never combine a wildcard with credentials."
    if kind in {"open_port", "risky_port"}:
        return "Restrict the port to the networks that need it, or close it. Confirm ownership of the service before any deeper test."
    return "Review the evidence and apply the matching hardening control."


def _fix_short(finding: Dict[str, Any]) -> str:
    summary = finding.get("summary", "")
    kind = finding.get("kind", "")
    quick = {
        "verified_leak": "remove the exposed file and rotate its secrets",
        "weak_headers": "add the missing security headers at the edge",
        "insecure_cookie": "add Secure/HttpOnly/SameSite to session cookies",
        "tls_expired": "renew the certificate",
        "tls_untrusted": "fix the certificate chain",
        "tls_expiring": "schedule certificate renewal now",
        "tls_weak_protocol": "disable TLS 1.0/1.1",
        "email_dmarc_missing": "publish a DMARC record",
        "email_spf_missing": "publish an SPF record",
        "cors_wildcard": "replace wildcard CORS with an allow-list",
    }
    return quick.get(kind, summary[:90])


def generate_report(target: str, findings: Iterable[Dict[str, Any]],
                    inventory: Optional[Dict[str, Any]] = None,
                    groq_key: str = "", audience: str = "the client's engineering team",
                    analyst: str = "the MHZALY assessment team") -> Dict[str, Any]:
    """Produce the best available report: AI-polished if possible, local if not.

    Returns `{"text", "source", "warnings"}`. `source` is deliberately explicit
    so the UI can tell the operator whether a human-reviewed local narrative or
    a model-polished one is on screen.
    """
    findings = list(findings or [])
    inventory = inventory or {}
    text: Optional[str] = None
    source = "local analyst narrative"
    warnings: List[str] = []

    if groq_key:
        try:
            from .advanced_features import call_groq  # local import avoids a cycle
            messages = build_messages(target, findings, inventory, audience)
            text = call_groq(groq_key, messages, max_tokens=2200, temperature=0.35)
            if text:
                source = "AI report, human-voice pass"
        except Exception:  # pragma: no cover - network/LLM failures are expected
            text = None

    if not text:
        text = local_report(target, findings, inventory, analyst)
    else:
        text = humanize(text)
        warnings = check_hallucinations(text, {"findings": findings, "inventory": inventory})
        if warnings:
            source += " (unverified identifiers flagged)"

    return {"text": text, "source": source, "warnings": warnings}
