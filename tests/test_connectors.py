"""Regression tests for the recon/scanning connectors.

The hostname validator exists because crt.sh returns dirty data — see the
docstring of core.connectors.is_valid_hostname. These tests pin that
behaviour so the "zero false positive" promise can't silently regress.
"""
import pytest

from core import connectors as c


@pytest.mark.parametrize("name,parent,expected", [
    # real hosts / subdomains
    ("example.com", "example.com", True),
    ("www.example.com", "example.com", True),
    ("deep.sub.example.com", "example.com", True),
    ("example.com.", "example.com", True),
    # unrelated domain that only shares a character suffix
    ("m.testexample.com", "example.com", False),
    ("notexample.com", "example.com", False),
    ("example.com.evil.io", "example.com", False),
    # crt.sh garbage: email SANs, CA CNs, wildcards, SRV records
    ("user@example.com", "example.com", False),
    ("subjectname@example.com", "example.com", False),
    ("as207960 test intermediate", "example.com", False),
    ("*.example.com", "example.com", False),
    ("_dmarc.example.com", "example.com", False),
    # syntactically broken labels
    ("-bad.example.com", "example.com", False),
    ("bad-.example.com", "example.com", False),
    ("exa mple.com", "example.com", False),
    ("", "example.com", False),
    ("localhost", "", False),
    ("1.2.3.4", "", False),
    ("x" * 64 + ".example.com", "example.com", False),
])
def test_is_valid_hostname(name, parent, expected):
    assert c.is_valid_hostname(name, parent) is expected


@pytest.mark.parametrize("raw,expected", [
    ("https://Example.COM/path?q=1", "example.com"),
    ("http://example.com", "example.com"),
    ("example.com/foo/bar", "example.com"),
    ("  EXAMPLE.com  ", "example.com"),
    ("", ""),
])
def test_clean_host(raw, expected):
    assert c.clean_host(raw) == expected


@pytest.mark.parametrize("host", [
    "127.0.0.1",
    "::1",
    "10.0.0.5",
    "192.168.1.1",
    "169.254.169.254",
    "0.0.0.0",
])
def test_ssrf_guard_blocks_internal_targets(host):
    with pytest.raises(c.ScopeViolation):
        c.assert_public_host(host)


def test_ssrf_guard_allows_public_ip():
    c.assert_public_host("93.184.215.14")  # example.com, public
