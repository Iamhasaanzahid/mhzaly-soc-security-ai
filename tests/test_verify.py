"""Evidence-only reporting: CDN, managed zones, CORS grading and live re-checks."""

from core import hunter, verify


# ── platform / CDN detection ────────────────────────────────────────────────

def test_managed_hosting_domains_are_recognised():
    assert hunter.is_managed_domain("app.pages.dev")
    assert hunter.is_managed_domain("site.netlify.app")
    assert hunter.is_managed_domain("demo.vercel.app")
    assert hunter.is_managed_domain("org.github.io")
    assert not hunter.is_managed_domain("example.com")
    assert not hunter.is_managed_domain("pages.dev.example.com")


def test_cdn_detection_from_headers():
    assert hunter.detect_cdn({"cf-ray": "abc", "server": "cloudflare"}) == "Cloudflare"
    assert hunter.detect_cdn({"x-nf-request-id": "123"}) == "Netlify"
    assert hunter.detect_cdn({"x-vercel-cache": "HIT"}) == "Vercel"
    assert hunter.detect_cdn({"x-github-request-id": "abc"}) == "GitHub Pages"
    assert hunter.detect_cdn({"server": "nginx"}) is None


# ── CORS grading: wildcard alone is not a finding ───────────────────────────

def test_wildcard_cors_without_credentials_is_informational():
    result = hunter.assess_cors({"Access-Control-Allow-Origin": "*"})
    assert result["risky"] is False
    assert result["severity"] is None
    assert result["misconfigured"] is False


def test_wildcard_cors_with_credentials_is_high():
    result = hunter.assess_cors({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    assert result["risky"] is True
    assert result["misconfigured"] is True
    assert result["severity"] == "HIGH"


def test_origin_reflection_with_credentials_is_high():
    result = hunter.assess_cors({
        "Access-Control-Allow-Origin": hunter.CORS_PROBE_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    })
    assert result["risky"] is True
    assert result["severity"] == "HIGH"


def test_origin_reflection_without_credentials_is_low():
    result = hunter.assess_cors({"Access-Control-Allow-Origin": hunter.CORS_PROBE_ORIGIN})
    assert result["risky"] is True
    assert result["severity"] == "LOW"


# ── live reconciliation ─────────────────────────────────────────────────────

def _fact_bundle(**overrides):
    facts = {
        "checked_at": "2026-11-20T00:00:00+00:00",
        "reachable": True,
        "header_grade": {"score": 100, "grade": "A", "missing": []},
        "cors": {"risky": False, "severity": None, "reason": "no permissive CORS policy observed"},
        "tls": {"valid": True},
        "managed_domain": False,
        "email": {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "dmarc_policy": "reject"},
        "cdn": None,
        "ports": [],
        "leaks": {},
        "notes": [],
        "errors": [],
    }
    facts.update(overrides)
    return facts


def test_reconcile_marks_fixed_findings_resolved():
    findings = [
        {"kind": "weak_headers", "summary": "Missing HSTS", "details": {}},
        {"kind": "cors_wildcard", "summary": "Wildcard CORS", "details": {}},
        {"kind": "tls_untrusted", "summary": "TLS untrusted", "details": {}},
    ]
    recon = verify.reconcile(findings, _fact_bundle())
    assert recon["counts"]["reproduced"] == 0
    assert recon["counts"]["resolved"] == 3
    assert all(f["live_status"] == "resolved" for f in recon["resolved"])


def test_reconcile_keeps_reproduced_findings():
    facts = _fact_bundle(header_grade={"score": 40, "grade": "D", "missing": ["HSTS"]})
    recon = verify.reconcile(
        [{"kind": "weak_headers", "summary": "Missing HSTS", "details": {}}], facts
    )
    assert recon["counts"]["reproduced"] == 1
    assert "still missing" in recon["fresh"][0]["live_reason"]


def test_reconcile_managed_domain_email_is_not_applicable():
    facts = _fact_bundle(managed_domain=True, email={"managed": True})
    recon = verify.reconcile(
        [{"kind": "email_dmarc_missing", "summary": "Missing DMARC", "details": {}}], facts
    )
    assert recon["counts"]["not_applicable"] == 1


def test_reconcile_cdn_edge_port_is_not_applicable():
    facts = _fact_bundle(cdn="Cloudflare", ports=[])
    recon = verify.reconcile(
        [{"kind": "risky_open_port", "summary": "Port 8080", "details": {"port": 8080}}], facts
    )
    assert recon["counts"]["not_applicable"] == 1


def test_reconcile_origin_port_that_closed_is_resolved():
    facts = _fact_bundle(cdn=None, ports=[{"port": 443}])
    recon = verify.reconcile(
        [{"kind": "open_port", "summary": "Port 8080", "details": {"port": 8080}}], facts
    )
    assert recon["counts"]["resolved"] == 1


def test_reconcile_origin_port_still_open_is_reproduced():
    facts = _fact_bundle(cdn=None, ports=[{"port": 8080}])
    recon = verify.reconcile(
        [{"kind": "open_port", "summary": "Port 8080", "details": {"port": 8080}}], facts
    )
    assert recon["counts"]["reproduced"] == 1


def test_reconcile_leak_reprobe_marks_resolved():
    facts = _fact_bundle(leaks={"/.env": {"path": "/.env", "verified": False,
                                          "note": "no content signature — suppressed"}})
    recon = verify.reconcile(
        [{"kind": "verified_leak", "summary": "Exposed .env", "details": {"path": "/.env"}}],
        facts,
    )
    assert recon["counts"]["resolved"] == 1


def test_reconcile_unknown_kind_stays_unverified():
    recon = verify.reconcile([{"kind": "custom_observation", "summary": "x", "details": {}}],
                             _fact_bundle())
    assert recon["counts"]["unverified"] == 1


def test_collect_probe_paths_only_for_leak_findings():
    findings = [
        {"kind": "verified_leak", "details": {"path": "/.env"}},
        {"kind": "verified_leak", "details": {"path": "/.git/config"}},
        {"kind": "weak_headers", "details": {}},
    ]
    assert verify.collect_probe_paths(findings) == ["/.env", "/.git/config"]


def test_summary_line_reports_every_bucket():
    recon = verify.reconcile([
        {"kind": "weak_headers", "details": {}},
        {"kind": "email_dmarc_missing", "details": {}},
    ], _fact_bundle(managed_domain=True, email={"managed": True}))
    line = verify.summary_line(recon)
    assert "reproduced" in line and "resolved" in line and "not applicable" in line


# ── zero-key report honesty ─────────────────────────────────────────────────

def test_local_report_states_verified_tls_and_grade():
    from core import reporter

    inventory = {
        "origin": "https://example.com",
        "pages": ["https://example.com"],
        "tls": {"valid": True, "not_after": "Feb 17 2027", "days_left": 89},
        "headers": {"grade": "A", "missing": []},
        "email_security": {"managed": True},
    }
    text = reporter.local_report("example.com", [], inventory)
    assert "validated against the public trust store" in text
    assert "header grade A" in text
    assert "TLS could not be inspected" not in text
    assert "email authentication records were not checked" not in text
    assert "controlled by the hosting platform" in text


def test_local_report_names_real_tls_failure():
    from core import reporter

    inventory = {
        "origin": "https://expired.example",
        "pages": ["https://expired.example"],
        "tls": {"valid": False, "error": "certificate has expired"},
    }
    text = reporter.local_report("expired.example", [], inventory)
    assert "certificate has expired" in text
