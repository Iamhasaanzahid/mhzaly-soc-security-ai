"""Report writer: human voice, no invented identifiers."""

from core import reporter


def test_humanize_removes_ai_tells():
    text = "As an AI language model, I will delve into this. In conclusion, it's important to note the result."
    out = reporter.humanize(text)
    low = out.lower()
    assert "as an ai" not in low
    assert "delve into" not in low
    assert "in conclusion" not in low
    assert "it's important to note" not in low


def test_humanize_strips_emoji_and_chat_openers():
    out = reporter.humanize("Certainly! Here is the report 🚀🔥")
    assert "🚀" not in out
    assert not out.lower().startswith("certainly")


def test_humanize_keeps_facts():
    out = reporter.humanize("The certificate expires in 12 days on api.example.com.")
    assert "12 days" in out
    assert "api.example.com" in out


def test_check_hallucinations_flags_invented_cve():
    text = "This matches CVE-2021-44228 and CVE-2099-0001."
    warnings = reporter.check_hallucinations(text, {"findings": [{"cve": "CVE-2021-44228"}]})
    assert "CVE-2099-0001" in warnings
    assert "CVE-2021-44228" not in warnings


def test_check_hallucinations_flags_invented_ip():
    assert "10.1.2.3" in reporter.check_hallucinations("Host 10.1.2.3", "")


def test_local_report_has_all_sections():
    findings = [{
        "kind": "weak_headers", "category": "Security Headers", "severity": "MEDIUM",
        "summary": "Security headers grade F — missing: HSTS, CSP",
        "confidence": 88, "verified": True,
        "details": {"missing": ["HSTS", "CSP"], "grade": "F", "score": 10},
    }]
    inventory = {
        "origin": "https://example.com",
        "pages": ["https://example.com"],
        "technologies": ["nginx"],
        "headers": {"grade": "F", "score": 10, "missing": ["HSTS", "CSP"]},
        "tls": {"valid": True, "protocol": "TLSv1.3", "days_left": 120},
        "email_security": {"spf": "v=spf1 -all", "dmarc": None},
    }
    text = reporter.local_report("example.com", findings, inventory)
    for section in ("## Scope and method", "## What the assessment found",
                    "## Findings", "## What could not be verified",
                    "## Recommended order of work"):
        assert section in text
    assert "HSTS" in text
    assert "CVE-" not in text  # no invented vulnerability ids


def test_local_report_no_findings_is_honest_not_padded():
    text = reporter.local_report("clean.example", [], {"origin": "https://clean.example", "pages": ["https://clean.example"]})
    assert "Nothing survived verification" in text
    assert "No findings." in text


def test_build_messages_shape():
    msgs = reporter.build_messages("example.com", [], {})
    assert msgs[0]["role"] == "system"
    assert "penetration tester" in msgs[0]["content"].lower()
    assert msgs[1]["role"] == "user"
    assert "example.com" in msgs[1]["content"]


def test_generate_report_without_key_uses_local_narrative():
    result = reporter.generate_report("example.com", [], {"origin": "https://example.com"})
    assert result["source"] == "local analyst narrative"
    assert result["text"]


def test_fix_short_covers_known_kinds():
    assert reporter._fix_short({"kind": "verified_leak", "summary": "x"})
    assert reporter._fix_short({"kind": "unknown-kind", "summary": "do the thing"}) == "do the thing"


def test_council_report_merges_perspectives_locally():
    result = reporter.generate_council_report(
        "example.com",
        [{"kind": "weak_headers", "category": "Security Headers", "severity": "MEDIUM",
          "summary": "Security headers grade F", "confidence": 88, "verified": True, "details": {}}],
        {"origin": "https://example.com", "pages": ["https://example.com"], "technologies": []},
    )
    assert result["synthesized"] is False
    assert "Human Council Assessment" in result["report"]
    assert set(result["perspectives"]) >= {"Consultant", "Red Team", "Blue Team"}
    assert result["report"]
