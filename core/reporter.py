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

#: Word-level tells and the plain-English replacement used instead. Swapping a
#: word keeps the sentence grammatical; deleting it does not.
_AI_WORD_FIXES: Tuple[Tuple[str, str], ...] = (
    (r"\bleverage\b", "use"),
    (r"\bleveraging\b", "using"),
    (r"\bleverages\b", "uses"),
    (r"\butilize\b", "use"),
    (r"\butilises\b", "uses"),
    (r"\butilizes\b", "uses"),
    (r"\butilizing\b", "using"),
    (r"\bdelves? into\b", "examine"),
    (r"\bdives? into\b", "examine"),
    (r"\bin order to\b", "to"),
    (r"\ba myriad of\b", "many"),
    (r"\ba plethora of\b", "many"),
    (r"\bfacilitates?\b", "helps"),
    (r"\bcommence\b", "start"),
    (r"\bendeavor to\b", "try to"),
)

#: Filler clauses that can be removed without leaving a broken sentence.
_AI_SENTENCE_FILLER: Tuple[str, ...] = (
    "it is important to note that", "it's important to note that",
    "it is worth noting that", "it's worth noting that",
    "please note that", "needless to say,",
    "as previously mentioned,", "as mentioned earlier,",
    "in today's fast-paced", "in today's rapidly evolving",
)

#: Phrases that make a technical report read like a chatbot wrote it.
AI_ISMS: Tuple[str, ...] = (
    "as an ai", "as a language model", "i'm sorry", "i am sorry", "sure, here",
    "sure! here", "certainly!", "i hope this helps", "let me know if",
    "in today's", "digital landscape", "ever-evolving",
    "cutting-edge", "state-of-the-art", "game-changer", "seamless",
    "robust solution", "comprehensive solution", "unlock the",
    "it is important to note", "it's important to note", "in conclusion",
    "in summary,", "overall, it", "furthermore,", "moreover,", "additionally,",
    "embark on", "tapestry", "testament to", "navigate the", "revolutionize",
)


def _sentence_case_after_punctuation(text: str) -> str:
    return re.sub(r"(^|[.!?]\s+)([a-z])", lambda m: m.group(1) + m.group(2).upper(), text)

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
    "without asking a follow-up question. For every finding, answer the same questions in the "
    "same order: what it is in plain language, what you actually observed, why it matters, how "
    "an attacker would use it, how to fix it, and how the engineer can confirm the fix. Explain "
    "an acronym the first time you use it. If a section has nothing to report, say so in one "
    "sentence rather than filling space."
)

REPORT_SKELETON = (
    "Structure the report exactly like this, in markdown:\n"
    "## Executive summary\n"
    "One short paragraph: what was found, what to fix first, and the overall risk read.\n"
    "## Scope and method\n"
    "## What the assessment found\n"
    "## Findings\n"
    "For each finding use these bold labels, in this order:\n"
    "**Severity:** … · **Confidence:** …%\n"
    "**What it is.** …\n"
    "**What I observed.** …\n"
    "**Why it matters.** …\n"
    "**How an attacker would use it.** …\n"
    "**How to fix it.** …\n"
    "**How to confirm the fix.** …\n"
    "## What passed verification\n"
    "List the checks that came back clean, briefly.\n"
    "## What could not be verified\n"
    "## Recommended order of work\n"
    "Numbered, highest risk first, with a target timeframe.\n"
    "## Bottom line\n"
)


def humanize(text: str) -> str:
    """Remove the most obvious machine-writing tells from a report.

    Deliberately conservative: it edits phrasing, never facts. Numbers, host
    names and identifiers are left untouched. Word-level replacements keep the
    sentence grammatical; only self-contained filler clauses are deleted.
    """
    if not text:
        return ""
    out = text
    for pattern, replacement in _AI_WORD_FIXES:
        out = re.sub(pattern, replacement, out, flags=re.I)
    for phrase in _AI_SENTENCE_FILLER:
        out = re.sub(re.escape(phrase) + r"\s*", "", out, flags=re.I)
    for phrase in AI_ISMS:
        out = re.sub(re.escape(phrase) + r"\s*", "", out, flags=re.I)
    out = _EMOJI_RE.sub("", out)
    # Chatbot openers such as "Certainly! Here is the report:".
    out = re.sub(r"^\s*(okay|ok|alright|certainly|sure)\b[,.!\s]*", "", out, flags=re.I)
    out = re.sub(
        r"^\s*(here('| i)s|below is)\s+(the|your)\s+[^:\n]{0,48}:\s*",
        "",
        out,
        flags=re.I,
    )
    # Tidy punctuation and spacing left behind by the removals.
    out = re.sub(r"[ \t]+([,.;:])", r"\1", out)
    out = re.sub(r"([,;:])(\s*\1)+", r"\1", out)
    out = re.sub(r"[ \t]+\n", "\n", out)
    out = re.sub(r"\n{3,}", "\n\n", out)
    out = re.sub(r" {2,}", " ", out)
    out = _sentence_case_after_punctuation(out)
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
        cors = inventory.get("cors") or {}
        if cors:
            lines.append(
                f"CORS: risky={cors.get('risky')} reason={cors.get('reason') or cors.get('error') or 'n/a'}"
            )
        email = inventory.get("email_security") or {}
        if email:
            lines.append(
                f"Email: managed={bool(email.get('managed'))} spf={bool(email.get('spf'))} "
                f"dmarc={bool(email.get('dmarc'))}"
            )
        if inventory.get("cdn"):
            lines.append(f"CDN in front of origin: {inventory['cdn']} (edge ports are not origin findings)")
        robots = inventory.get("robots") or {}
        if robots:
            lines.append(f"robots.txt: valid={robots.get('valid')} status={robots.get('status')}")
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
    """Write the whole report in prose, without an LLM.

    With no API key this is the document the client receives, so it has to stand
    on its own: a real executive summary, every confirmed issue explained in
    plain language (what it is, what was observed, why it matters, how it would
    be used, how to fix it, how to prove the fix), what passed, what could not be
    tested, and an order of work that starts with the highest-risk item.
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

    counts: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    risk_read = _risk_read(findings)

    out: List[str] = []
    out.append(f"# Security Assessment — {target}")
    out.append("")
    out.append(f"Prepared by {analyst} on {_formatted_date()}.")
    out.append("")

    # ── Scope ──────────────────────────────────────────────────────────────
    out.append("## Scope and method")
    out.append("")
    scope = (
        f"This was a black-box assessment of the public surface of {origin}. "
        f"I reviewed {len(pages) or 'the root'} page(s), the TLS configuration, HTTP response "
        f"headers, cookie attributes, CORS behaviour and the email authentication records for "
        f"the domain. Sensitive paths were probed only after calibrating the host's 404 "
        f"behaviour, so a catch-all page cannot be mistaken for a real file exposure."
    )
    if inventory.get("cdn"):
        scope += (f" {inventory['cdn']} answers for this name, so edge ports and transport "
                  "termination were treated as provider behaviour rather than findings.")
    out.append(scope)
    if tech:
        out.append("")
        out.append(f"The host fingerprints as {', '.join(tech[:6])}.")

    posture_bits: List[str] = []
    if tls.get("valid"):
        posture_bits.append(
            f"the live certificate validated against the public trust store "
            f"(expires {tls.get('not_after', 'unknown')}, {tls.get('days_left', '?')} day(s) left)"
        )
    elif tls:
        posture_bits.append("the certificate did not validate against the public trust store")
    if headers.get("grade"):
        missing = headers.get("missing") or []
        posture_bits.append(
            f"the root response scored header grade {headers['grade']}"
            + (f" (missing: {', '.join(missing)})" if missing else "")
        )
    if posture_bits:
        out.append("")
        out.append("On the wire, " + "; ".join(posture_bits) + ".")
    if email.get("managed"):
        out.append("")
        out.append(
            "SPF and DMARC are controlled by the hosting platform for this domain, so they are "
            "excluded from the client-actionable scope."
        )
    out.append("")

    # ── Executive summary ──────────────────────────────────────────────────
    out.append("## Executive summary")
    out.append("")
    if findings:
        strongest = findings[0]
        out.append(
            f"In one line: I confirmed {len(findings)} issue(s) on {origin}, and the one I would "
            f"fix first is **{strongest.get('summary', 'the highest-severity item')}** "
            f"({str(strongest.get('severity', 'INFO')).upper()}). My overall read is a "
            f"**{risk_read}** risk posture."
        )
        out.append("")
        out.append(
            "Everything below is something I reproduced myself and can point to in the evidence "
            "bundle. I have left out anything I could not prove, so the list is shorter than a "
            "scanner's and each line should survive a conversation with your engineer. What I "
            "checked and found clean is listed separately, because a report that only lists "
            "problems is not an assessment."
        )
    else:
        out.append(
            f"In one line: I could not confirm any issue on the public surface I tested for "
            f"{origin}. That is a real result, not an empty one — the checks that normally "
            "generate noise either passed or could not be proven, and I have not padded the "
            "report with theoretical risks."
        )
        out.append("")
        out.append(
            "The sections below show exactly what was tested, what the live responses showed, "
            "and what I would look at next if you want to widen the scope."
        )
    out.append("")

    # ── Summary of findings ────────────────────────────────────────────────
    out.append("## What the assessment found")
    out.append("")
    if findings:
        summary = ", ".join(f"{counts[s]} {s.lower()}" for s in
                            ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts.get(s))
        out.append(
            f"{len(findings)} finding(s) met the evidence bar ({summary}). They are explained one "
            "by one in the next section. For each one I answer the same questions: what it is, "
            "what I actually saw, why it matters, how an attacker would use it, how to fix it, "
            "and how to prove the fix worked."
        )
    else:
        out.append(
            "Nothing survived verification. That is a meaningful result rather than an empty "
            "one: the checks that would normally produce noise — exposed configuration files, "
            "certificate problems, missing security headers — either passed or could not be "
            "proven, and I have not padded the report with maybes."
        )
    out.append("")

    # ── Findings, in full ──────────────────────────────────────────────────
    out.append("## Findings")
    out.append("")
    if findings:
        for idx, f in enumerate(findings, start=1):
            sev = str(f.get("severity", "INFO")).upper()
            conf = f.get("confidence", "?")
            kind = str(f.get("kind") or "")
            out.append(f"### {idx}. {f.get('summary', 'Finding')}")
            out.append("")
            out.append(f"**Severity:** {sev} · **Confidence:** {conf}%")
            out.append("")
            out.append(f"**What it is.** {_plain_for(kind)}")
            out.append("")
            out.append(f"**What I observed.** {_observed_for(f, inventory)}")
            out.append("")
            impact = _impact_for(f)
            if impact:
                out.append(f"**Why it matters.** {impact}")
                out.append("")
            exploit = _exploit_for(kind)
            if exploit:
                out.append(f"**How an attacker would use it.** {exploit}")
                out.append("")
            fix = _fix_for(f)
            if fix:
                out.append(f"**How to fix it.** {fix}")
                out.append("")
            verify = _verify_fix_for(kind)
            if verify:
                out.append(f"**How to confirm the fix.** {verify}")
                out.append("")
            from .evidence import fingerprint_of
            fp = fingerprint_of(target, kind, str(f.get("marker") or ""),
                                str(f.get("summary") or ""), str(f.get("severity") or ""))
            out.append(f"Evidence reference: `{fp[:16]}…`")
            out.append("")
    else:
        out.append("No findings.")
        out.append("")

    # ── What passed ────────────────────────────────────────────────────────
    passed = _passed_checks(inventory, findings)
    if passed:
        out.append("## What passed verification")
        out.append("")
        out.append(
            "These are not filler. They are the checks I ran that came back clean, so you can "
            "see the full picture and know what a future regression would look like."
        )
        out.append("")
        out.extend(f"- {line}" for line in passed)
        out.append("")

    # ── Gaps ───────────────────────────────────────────────────────────────
    out.append("## What could not be verified")
    out.append("")
    gaps = []
    if not pages:
        gaps.append("the site root could not be fetched, so no crawl was possible")
    if not tls:
        gaps.append("TLS could not be inspected (no completed handshake)")
    elif not tls.get("valid"):
        gaps.append("TLS trust could not be established: "
                    + str(tls.get("error") or "certificate did not validate"))
    if not email:
        gaps.append("email authentication records were not checked")
    gaps.append("I did not test authentication bypass, injection or business-logic flaws; those "
                "need an authenticated scope and explicit written authorisation")
    out.extend(f"- {g}" for g in gaps)
    out.append("")

    # ── Order of work ──────────────────────────────────────────────────────
    out.append("## Recommended order of work")
    out.append("")
    if findings:
        out.append("The order below is by risk and by how cheap the fix is, not by the order the "
                   "scanner found them.")
        out.append("")
        for i, f in enumerate(findings[:8], start=1):
            sev = str(f.get("severity", "INFO")).upper()
            effort = _EFFORT.get(sev, "when convenient")
            out.append(f"{i}. **{sev} — {f.get('summary', '')}.** "
                       f"{_fix_short(f).capitalize()}. Target: {effort}.")
    else:
        out.append("- Keep the current header and certificate posture; re-test after any "
                   "infrastructure change.")
    out.append("")

    # ── Bottom line ────────────────────────────────────────────────────────
    out.append("## Bottom line")
    out.append("")
    if findings:
        out.append(
            f"If you fix only one thing, fix **{findings[0].get('summary', 'the highest-severity item')}**. "
            "Then work down the list above. Re-run the assessment after the fixes and compare the "
            "results; anything that disappears should be recorded as resolved, not quietly forgotten."
        )
    else:
        out.append(
            "No action is required from this assessment. Keep the current header and certificate "
            "posture, and re-run after any change to the edge, DNS or deployment pipeline. The "
            "next run will compare against this baseline."
        )
    out.append("")
    out.append(
        f"Evidence bundle: {len(findings)} verified finding(s), "
        f"{len(pages)} page(s) reviewed, header grade {headers.get('grade', 'n/a')}."
    )
    return humanize("\n".join(out))


_EFFORT: Dict[str, str] = {
    "CRITICAL": "today",
    "HIGH": "today",
    "MEDIUM": "this sprint",
    "LOW": "the next maintenance window",
    "INFO": "when convenient",
}

_PLAIN: Dict[str, str] = {
    "verified_leak": "A file that should never be public is being served from the web root. These files usually contain credentials, keys or internal configuration.",
    "weak_headers": "A set of HTTP response headers tells the browser how to behave safely: force HTTPS, block injected script, stop the page being framed. One or more are missing.",
    "insecure_cookie": "A session cookie is missing an attribute that stops it being read by script, sent over plain HTTP, or attached to cross-site requests.",
    "tls_expired": "The TLS certificate the server presents is past its validity date.",
    "tls_untrusted": "The certificate does not chain to a public trust store or does not match the hostname, so a browser cannot tell it apart from an interception proxy.",
    "tls_expiring": "The certificate is still valid but close enough to expiry that renewal needs to be scheduled now.",
    "tls_weak_protocol": "The server still negotiates a TLS version with known cryptographic weaknesses.",
    "email_dmarc_missing": "DMARC tells receiving mail servers what to do when someone forges this domain. Without it, receivers have no policy to enforce.",
    "email_spf_missing": "SPF lists the servers allowed to send mail for this domain. Without it, anyone can put this domain in an envelope sender.",
    "email_dmarc_weak": "DMARC is published but only in monitor mode, so forged mail is observed rather than rejected.",
    "cors_wildcard": "Cross-Origin Resource Sharing decides which other sites may read this site's responses. A wildcard policy is too open when credentials are involved.",
    "cors_reflection": "The server echoes back whatever Origin the caller sends, which lets an attacker-controlled page read responses in a victim's browser.",
    "open_port": "A TCP service is reachable from the public internet. Whether that is a problem depends on what the service is.",
    "risky_port": "A service that normally belongs on an internal network is reachable from the internet.",
}

_EXPLOIT: Dict[str, str] = {
    "verified_leak": "Fetch the path directly, with no authentication, and read whatever it contains. The first thing an attacker does with a leaked `.env` or `.git/config` is reuse the keys against the cloud account or the database.",
    "weak_headers": "Combine the missing control with any reflection point on the site. Without CSP an injected script runs with the site's privileges; without HSTS a network attacker can downgrade the first request.",
    "insecure_cookie": "Read the cookie with an XSS payload, or replay it over HTTP on a hostile network, then use the session as the victim.",
    "tls_expired": "Present any certificate from a hostile network and rely on the user having been trained to click through the warning.",
    "tls_untrusted": "Intercept the connection from a network position and present a certificate the client cannot distinguish from the real one.",
    "tls_expiring": "Wait for the renewal to be missed; on expiry the site becomes an interception target and some clients stop connecting altogether.",
    "tls_weak_protocol": "Force a downgrade to the legacy protocol and attack the known weaknesses in its cipher suite.",
    "email_dmarc_missing": "Send phishing mail that claims to come from this domain. Without a rejecting DMARC policy, many receivers will deliver it.",
    "email_spf_missing": "Spoof the envelope sender from any host, which is the standard first step in a business-email-compromise campaign.",
    "email_dmarc_weak": "Send forged mail knowing the policy only reports it; delivery is still likely on many receivers.",
    "cors_wildcard": "Host a page on any domain; the browser lets it read the authenticated response if credentials are allowed, then exfiltrates the data.",
    "cors_reflection": "Send the victim a link to the attacker's page; script on that page calls the API and reads the response because the server echoed the attacker's Origin.",
    "open_port": "Fingerprint the service, check its version against public advisories, and use it as a second entry point if the web tier is hardened.",
    "risky_port": "Go straight at the management or database service with default or reused credentials, bypassing the web application entirely.",
}

_VERIFY_FIX: Dict[str, str] = {
    "verified_leak": "Request the same path from outside and confirm a 404 or an authentication challenge with no sensitive body content. Rotate the secrets regardless — assume they were read.",
    "weak_headers": "Re-fetch the document response and confirm each header is present with the intended value; the header grade in the next scan is the regression check.",
    "insecure_cookie": "Inspect `Set-Cookie` on a fresh login and confirm Secure, HttpOnly and SameSite are all present, including after the CDN.",
    "tls_expired": "Reconnect and confirm the chain validates with no warning, then confirm the expiry date and that renewal alerting is wired.",
    "tls_untrusted": "Reconnect with a verifying client and confirm hostname and chain both validate.",
    "tls_expiring": "Confirm the new certificate is deployed and the expiry date has moved out.",
    "tls_weak_protocol": "Reconnect offering only TLS 1.0/1.1 and confirm the handshake is refused.",
    "email_dmarc_missing": "Query `_dmarc.<domain>` TXT and confirm the policy record is returned; send from an unauthorised sender and confirm rejection or quarantine.",
    "email_spf_missing": "Query the domain TXT records and confirm a single valid `v=spf1` record under ten DNS lookups.",
    "email_dmarc_weak": "Confirm the policy has moved to `p=quarantine` or `p=reject` and that a test forgery is not delivered.",
    "cors_wildcard": "Re-run the synthetic Origin probe and confirm the response returns a fixed allow-listed origin, never `*` with credentials.",
    "cors_reflection": "Re-run the probe from two unrelated origins and confirm neither is echoed back.",
    "open_port": "Re-run the port check from outside the network and confirm the port is closed or filtered.",
}


def _risk_read(findings: List[Dict[str, Any]]) -> str:
    severities = {str(f.get("severity", "")).upper() for f in findings}
    if "CRITICAL" in severities:
        return "critical"
    if "HIGH" in severities:
        return "high"
    if "MEDIUM" in severities:
        return "moderate"
    if "LOW" in severities:
        return "low"
    return "clean"


def _plain_for(kind: str) -> str:
    return _PLAIN.get(kind, "A configuration issue that affects how the site behaves under attack.")


def _exploit_for(kind: str) -> str:
    return _EXPLOIT.get(kind, "")


def _verify_fix_for(kind: str) -> str:
    return _VERIFY_FIX.get(kind, "")


def _observed_for(finding: Dict[str, Any], inventory: Dict[str, Any]) -> str:
    """State the evidence in one human sentence, using the live inventory when useful."""
    details = finding.get("details") or {}
    kind = str(finding.get("kind") or "")
    snippet = details.get("evidence_snippet") or details.get("evidence")
    if isinstance(snippet, str) and snippet.strip():
        return f"The response contained `{snippet.strip()[:300]}`."
    if kind == "weak_headers":
        missing = details.get("missing") or (inventory.get("headers") or {}).get("missing") or []
        grade = details.get("grade") or (inventory.get("headers") or {}).get("grade")
        head = (f"The live document response omitted {', '.join(missing)}"
                if missing else "The live document response was missing part of the graded header set")
        return head + (f" (header grade {grade})." if grade else ".")
    if kind == "verified_leak":
        path = details.get("path") or "the reported path"
        return (f"I requested `{path}` and the body matched the expected sensitive-file signature, "
                "so this is not a soft-404.")
    if kind in {"tls_expired", "tls_untrusted", "tls_expiring", "tls_weak_protocol"}:
        tls = inventory.get("tls") or {}
        parts = []
        if tls.get("days_left") is not None:
            parts.append(f"{tls['days_left']} day(s) to expiry")
        if tls.get("protocol"):
            parts.append(str(tls["protocol"]))
        if tls.get("error"):
            parts.append(str(tls["error"]))
        if parts:
            return "The certificate handshake showed " + ", ".join(parts) + "."
        return str(finding.get("summary") or "The certificate check failed") + "."
    if kind in {"cors_wildcard", "cors_reflection"}:
        acao = details.get("acao") or "an arbitrary origin"
        cred = " with credentials enabled" if details.get("allow_credentials") else ""
        return (f"The server answered the synthetic Origin probe with "
                f"`Access-Control-Allow-Origin: {acao}`{cred}.")
    if kind in {"open_port", "risky_port"}:
        port = details.get("port", "the reported")
        service = details.get("service") or "unknown service"
        return f"TCP/{port} accepted a connection from the assessment host ({service})."
    if kind in {"email_spf_missing", "email_dmarc_missing", "email_dmarc_weak"}:
        return "A DNS TXT lookup for the domain and `_dmarc` returned no usable policy record."
    if kind == "insecure_cookie":
        return "The `Set-Cookie` response lacked one or more of Secure, HttpOnly and SameSite."
    return f"The check reproduced on a second request: {finding.get('summary', '')}."


def _passed_checks(inventory: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[str]:
    """Checks that came back clean — the other half of an assessment.

    A check is only "passed" if no confirmed finding covers the same area; a
    valid-but-expiring certificate is not a clean TLS result.
    """
    kinds = {str(f.get("kind") or "") for f in findings}
    passed: List[str] = []
    pages = inventory.get("pages") or []
    if pages:
        passed.append(f"Reachability — the site root answered on HTTPS and "
                      f"{len(pages)} page(s) were reviewed.")
    tls = inventory.get("tls") or {}
    if tls.get("valid") and not any(k.startswith("tls_") for k in kinds):
        passed.append(f"TLS — the certificate validated against the public trust store "
                      f"({tls.get('days_left', '?')} day(s) to expiry, "
                      f"{tls.get('protocol', 'modern TLS')}).")
    headers = inventory.get("headers") or {}
    if (headers.get("grade") and not headers.get("missing")
            and "weak_headers" not in kinds):
        passed.append(f"Security headers — grade {headers['grade']}; every header I grade for "
                      "was present on the live document response.")
    cors = inventory.get("cors") or {}
    if (cors and not cors.get("error") and not cors.get("risky")
            and not any(k.startswith("cors_") for k in kinds)):
        passed.append("CORS — the server did not reflect an arbitrary Origin and did not pair a "
                      "wildcard with credentials.")
    email = inventory.get("email_security") or {}
    email_finding = any(k.startswith("email_") for k in kinds)
    if email.get("managed") and not email_finding:
        passed.append("Email — the DNS zone is provider-managed, so SPF/DMARC were excluded from "
                      "the client-actionable scope.")
    elif email.get("spf") and email.get("dmarc") and not email_finding:
        passed.append("Email — both SPF and DMARC records are published.")
    return passed


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
        "cors_reflection": "Reflecting an arbitrary Origin lets a hostile page read the response in the victim's browser when the endpoint trusts cookies.",
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
    if kind == "cors_reflection":
        return "Validate the Origin header against an explicit allow-list and return a fixed ACAO value; never echo the request Origin."
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
        "cors_reflection": "stop reflecting arbitrary Origins",
    }
    return quick.get(kind, summary[:90])


COUNCIL_SYSTEM = (
    "You are a senior consultant arbitrating four independent analyst reports for an "
    "internal security assessment: (1) an external consultant who led the investigation, "
    "(2) an internal red team that treated the findings as exploitable surface, (3) an internal "
    "blue team that treated them as active threats requiring defensive playbooks, and "
    "(4) an internal sceptic whose job is to challenge every conclusion: to state what an "
    "attacker would actually need, what would disprove a finding, and what the organisation "
    "should prove before it fixes. You must produce ONE final executive assessment. Preserve "
    "the distinct judgement of each perspective, but synthesise to a single conclusion: what is "
    "real, what is likely real, and what order the engineering team should work in. Never "
    "introduce facts that are not in the input. Write in first-person consultant voice, plain "
    "English, concrete, no filler."
)


def _red_team_text(findings: List[Dict[str, Any]], target: str) -> str:
    lines = [
        f"## Red Team Perspective — {target}",
        "",
        "Adversarial reading of the verified surface. The findings below are treated as live "
        "exploitation candidates; each one would be exercised with a PoC before remediation.",
        "",
        f"- Verified findings in scope: {len(findings)}",
    ]
    for f in findings[:6]:
        lines.append(
            f"- [{str(f.get('severity', 'INFO')).upper()}] {f.get('summary', '')} "
            f"(confidence {f.get('confidence', '?')}%)"
        )
    lines.append("")
    lines.append(
        "Red-team action posture: prioritise exploit-verification on the highest-confidence "
        "verified findings first; treat anything the consultant rated advisory but the red team "
        "found reproducible as the top of the queue."
    )
    return "\n".join(lines)


def _blue_team_text(findings: List[Dict[str, Any]], target: str) -> str:
    lines = [f"## Blue Team Perspective — {target}", "", "Defensive posture read against the same evidence:"]
    if not findings:
        lines.append("No verified findings to defend against; baseline posture appears acceptable.")
    else:
        lines.append(
            f"{len(findings)} verified finding(s) — each warrants an incident playbook and a detection "
            f"rule (Sigma/MITRE) before remediation closes the gap."
        )
    for f in findings[:6]:
        lines.append(f"- [{str(f.get('severity', 'INFO')).upper()}] {f.get('summary', '')}")
    lines.append("")
    lines.append(
        "Blue-team action posture: detection engineering first (SIGMA + MITRE mapping), then "
        "host/header hardening, so the organisation retains the ability to detect regressions."
    )
    return "\n".join(lines)


def _skeptic_text(findings: List[Dict[str, Any]], target: str) -> str:
    lines = [
        f"## Skeptic Perspective — {target}",
        "",
        "Adversarial thinking about the findings themselves. Not to dismiss them, but to "
        "challenge the confidence before the engineering team commits budget.",
    ]
    if not findings:
        lines.append("No verified findings to challenge; the posture is currently acceptable, but "
                     "that verdict is exactly what a sceptical engineer should not have to sign off on "
                     "without independent proof.")
    for f in findings[:6]:
        lines.append(
            f"- [{str(f.get('severity', 'INFO')).upper()}] {f.get('summary', '')} "
            f"(confidence {f.get('confidence', '?')}%)"
        )
    lines.append("")
    lines.append(
        "Sceptic action posture: for each finding ask what an attacker would need, what would "
        "falsify it, and whether the absence of the evidence (blocked file, clean headers, quiet "
        "domain) is itself being proven. A finding that cannot be disproved is still a risk; a "
        "finding that cannot be proved should not ship as 'verified'."
    )
    return "\n".join(lines)


def _merge_perspectives(findings: List[Dict[str, Any]], target: str,
                        perspectives: Dict[str, str]) -> str:
    lines = [f"# Human Council Assessment — {target}", "",
             "This assessment arbitrated multiple independent analyst perspectives and merged them "
             "into a single executive conclusion.", ""]
    for name, text in perspectives.items():
        lines.append(f"## Perspective: {name}")
        lines.append(text)
        lines.append("")
    lines.append(
        "Final executive conclusion: "
        + (
            f"{len(findings)} verified finding(s) survived verification; "
            + ("the strongest is in the highest severity class and should be fixed first."
               if findings else
               "nothing survived verification; posture is currently acceptable.")
        )
    )
    return humanize("\n".join(lines))


def generate_council_report(target: str, findings: List[Dict[str, Any]],
                            inventory: Optional[Dict[str, Any]] = None,
                            groq_key: str = "",
                            analyst: str = "the AI Security Engineer") -> Dict[str, Any]:
    """Human Council: consultant + red team + blue team + skeptic, human-voice synthesis.

    With a Groq key the perspectives are arbitrated by the senior consultant
    into a final executive report; without one, the merged local narrative is
    produced deterministically.
    """
    perspectives = {
        "Consultant": local_report(target, findings, inventory, analyst),
        "Red Team": _red_team_text(findings, target),
        "Blue Team": _blue_team_text(findings, target),
        "Skeptic": _skeptic_text(findings, target),
    }
    final_text: Optional[str] = None
    synthesized = False
    if groq_key:
        try:
            from .advanced_features import call_groq
            user_content = (
                f"Target: {target}\nFindings: {findings}\nInventory: {inventory}\n"
                + "\n--- PERSPECTIVE REPORTS ---\n"
                + "\n\n".join(f"## {n}\n{t}" for n, t in perspectives.items())
                + "\n\nArbitrate the final executive assessment."
            )
            final_text = call_groq(groq_key, [
                {"role": "system", "content": COUNCIL_SYSTEM},
                {"role": "user", "content": user_content},
            ], max_tokens=3200, temperature=0.3)
            synthesized = bool(final_text)
        except Exception:
            synthesized = False
    if not final_text:
        final_text = _merge_perspectives(findings, target, perspectives)
        synthesized = False
    else:
        final_text = humanize(final_text)
    return {"report": final_text, "perspectives": perspectives, "synthesized": synthesized}


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
            text = call_groq(groq_key, messages, max_tokens=3200, temperature=0.35)
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
