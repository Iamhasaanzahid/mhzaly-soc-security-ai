#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
connectors.py — The core external intelligence & utility connector module.
Provides SSRF guards, host normalization, DNS resolution, port scanning,
subdomain enumeration, endpoint fuzzing, and threat-intel API wrappers.
"""

import requests
import logging
import re
import socket
import ssl
import ipaddress
import dns.resolver
import urllib.parse
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings()


class ScopeViolation(Exception):
    """Raised when a target resolves to a disallowed internal/metadata address."""
    pass


def clean_host(target: str) -> str:
    """Normalizes a user-supplied target domain, URL, or IP into a clean hostname."""
    if not target:
        return ""
    clean = target.strip()
    if clean.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(clean)
        clean = parsed.hostname or clean
    return clean.split("/")[0].lower()


def assert_public_host(hostname: str) -> None:
    """SSRF guard: blocks internal, loopback, link-local, and cloud metadata IPs."""
    clean = clean_host(hostname)
    try:
        infos = socket.getaddrinfo(clean, None)
    except socket.gaierror as e:
        raise ScopeViolation(f"Could not resolve host {clean}: {e}")

    for family, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ScopeViolation(f"Target '{clean}' resolves to non-public address ({ip_str}).")
        if ip_str == "169.254.169.254":
            raise ScopeViolation("Refusing to scan cloud metadata endpoint.")


# A DNS label: 1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen.
_HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def is_valid_hostname(name: str, parent: str = "") -> bool:
    """Strict hostname validation, optionally scoped to a parent domain.

    Certificate Transparency logs (crt.sh) are dirty: `name_value` entries
    contain email SANs ("user@example.com"), human-readable CA CNs
    ("as207960 test intermediate"), wildcards, and unrelated domains that
    merely *end* with the same characters ("m.testexample.com" vs
    "example.com"). `str.endswith()` alone accepted all of those and wrote
    them into the findings DB as "discovered subdomains".

    This requires a real dot-boundary match (`name == parent` or
    `name.endswith("." + parent)`) plus syntactically valid DNS labels.
    """
    if not name or len(name) > 253:
        return False
    name = name.strip().rstrip(".").lower()
    if not name or any(ch.isspace() for ch in name):
        return False
    # Emails (crt.sh SANs), wildcards and SRV-style underscore records are not
    # A/AAAA hostnames — drop them instead of reporting them as subdomains.
    if "@" in name or "*" in name or "_" in name:
        return False
    labels = name.split(".")
    if len(labels) < 2:
        return False
    if any(not _HOST_LABEL_RE.match(label) for label in labels):
        return False
    # TLD must not be numeric (that would be an IPv4 address, not a hostname).
    if labels[-1].isdigit():
        return False
    if parent:
        parent = parent.strip().rstrip(".").lower()
        if name != parent and not name.endswith("." + parent):
            return False
    return True


def verify_api_connection(service_name: str, endpoint: str, headers: dict = None) -> bool:
    """Helper utility to check connectivity and validity for platform connectors."""
    try:
        resp = requests.get(endpoint, headers=headers, timeout=5)
        return resp.status_code in [200, 401, 403, 429]
    except Exception as e:
        logger.warning(f"Connection check failed for {service_name}: {e}")
        return False


def check_dns(domain: str) -> Dict[str, List[str]]:
    """Resolves standard authoritative DNS records for a domain."""
    clean = clean_host(domain)
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
        try:
            answers = dns.resolver.resolve(clean, rtype)
            records[rtype] = list(set([str(r) for r in answers]))
        except Exception:
            records[rtype] = []
    return records


def scan_ports(domain: str) -> List[Dict[str, Any]]:
    """Performs a fast multi-threaded TCP connect sweep on common critical ports."""
    clean = clean_host(domain)
    assert_public_host(clean)
    common_ports = [21, 22, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9200]
    open_ports = []

    def _test_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.6)
            res = sock.connect_ex((clean, port))
            sock.close()
            if res == 0:
                sname = {
                    21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                    110: 'POP3', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL',
                    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
                    8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
                }.get(port, 'Unknown')
                return {'port': port, 'service': sname, 'status': 'OPEN'}
        except Exception:
            pass
        return None

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_test_port, p) for p in common_ports]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports, key=lambda x: x['port'])


def _days_until(not_after: str) -> int:
    """Days until a certificate expires (negative when already expired)."""
    from datetime import datetime, timezone
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return 0
    return (expiry - datetime.now(timezone.utc)).days


def check_ssl(domain: str) -> Dict[str, Any]:
    """Inspect the certificate the way a browser would.

    The old implementation disabled both hostname checking and verification,
    so an expired or self-signed certificate was returned as valid. This one
    uses the default verifying context; a second non-verifying handshake is
    only used to describe *why* trust failed.
    """
    clean = clean_host(domain)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                return {
                    'valid': True,
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'not_after': not_after,
                    'days_left': _days_until(not_after) if not_after else None,
                    'protocol': ssock.version(),
                }
    except ssl.SSLCertVerificationError as e:
        detail = {'valid': False, 'untrusted': True, 'error': str(e)}
        try:
            raw_ctx = ssl.create_default_context()
            raw_ctx.check_hostname = False
            raw_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((clean, 443), timeout=4) as sock:
                with raw_ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter")
                    detail['not_after'] = not_after
                    detail['days_left'] = _days_until(not_after) if not_after else None
                    detail['protocol'] = ssock.version()
        except Exception:
            pass
        return detail
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def crtsh_subdomains(domain: str) -> List[str]:
    """Free-tier subdomain enumeration via crt.sh Certificate Transparency logs."""
    clean = clean_host(domain)
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{clean}&output=json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            names = set()
            for entry in data:
                for name in str(entry.get('name_value', '')).split('\n'):
                    name = name.strip().lower()
                    if is_valid_hostname(name, clean):
                        names.add(name)
            return sorted(names)
    except Exception as e:
        logger.warning(f"crt.sh lookup failed: {e}")
    return []


def fuzz_endpoints(base_url: str) -> List[Dict[str, Any]]:
    """Probe well-known sensitive paths, calibrated against soft-404 pages.

    A catch-all site answers 200 for every URL. Without the baseline probe
    those responses were logged as "exposed endpoints". The baseline is taken
    first and any response whose status and body size match it is dropped.
    This is a coarse filter; `core.hunter.verify_sensitive_path()` adds the
    content-signature check that the scheduler actually relies on.
    """
    fuzz_paths = [
        '/.env', '/robots.txt', '/git/config', '/.git/config',
        '/backup.zip', '/swagger.json', '/phpinfo.php',
        '/.DS_Store', '/server-status', '/actuator/env', '/openapi.json',
    ]
    exposed = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    baseline = None
    try:
        probe = requests.get(origin + "/mhzaly-probe-404", timeout=3, verify=False)
        baseline = (probe.status_code, len(probe.text or ""))
    except Exception:
        baseline = None

    for path in fuzz_paths:
        try:
            resp = requests.get(origin + path, timeout=3, verify=False)
            body = resp.text or ""
            if resp.status_code not in (200, 401, 403) or len(body) <= 15:
                continue
            if baseline and resp.status_code == baseline[0] and abs(len(body) - baseline[1]) <= max(64, baseline[1] // 10):
                continue  # soft-404 / catch-all page
            if any(err in body.lower() for err in ["not found", "404 page", "does not exist"]):
                continue
            exposed.append({'path': path, 'status': resp.status_code, 'size': len(body)})
        except Exception:
            continue
    return exposed


def virustotal_check(indicator: str, vt_key: str) -> Dict[str, Any]:
    """Queries VirusTotal API v3 for threat reputation metrics."""
    if not vt_key:
        return {'malicious': 0, 'error': 'API key missing'}
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        headers = {'x-apikey': vt_key}
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 200:
            stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {'malicious': stats.get('malicious', 0), 'suspicious': stats.get('suspicious', 0)}
    except Exception as e:
        logger.warning(f"VirusTotal query failed: {e}")
    return {'malicious': 0}


def _cve_cpes(cve: Dict[str, Any]) -> List[str]:
    """Extract the CPE criteria attached to a CVE configuration block."""
    cpes: List[str] = []
    for configuration in cve.get("configurations", []) or []:
        for node in configuration.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if criteria:
                    cpes.append(str(criteria).lower())
    return cpes


def nvd_search(keyword: str, nvd_key: str, strict: bool = True) -> List[Dict[str, Any]]:
    """Search NIST NVD v2.0 and only claim a CPE match when one exists.

    The previous version set `match_confidence: 'cpe' if strict else 'keyword'`
    whenever *any* result scored >= 4.0 — the flag described the caller's
    setting, not the evidence. In strict mode a result is now kept only if a
    CPE entry in the CVE's configuration block contains a keyword token.
    """
    vulnerabilities: List[Dict[str, Any]] = []
    tokens = [t for t in re.split(r"[^a-z0-9]+", (keyword or "").lower()) if len(t) >= 3]
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'keywordSearch': keyword, 'resultsPerPage': 5}
        headers = {'apiKey': nvd_key} if nvd_key else {}
        resp = requests.get(url, params=params, headers=headers, timeout=12)
        if resp.status_code != 200:
            return []
        for item in resp.json().get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', 'UNKNOWN')
            desc = cve.get('descriptions', [{}])[0].get('value', 'No description.')
            metrics = cve.get('metrics', {})
            score, severity = 0.0, 'UNKNOWN'
            for block in ('cvssMetricV31', 'cvssMetricV30'):
                if block in metrics and metrics[block]:
                    data = metrics[block][0].get('cvssData', {})
                    score = float(data.get('baseScore', 0.0))
                    severity = data.get('baseSeverity', 'UNKNOWN')
                    break

            cpes = _cve_cpes(cve)
            cpe_hit = bool(tokens) and any(tok in cpe for cpe in cpes for tok in tokens)
            if strict and not cpe_hit:
                continue
            if score < 4.0:
                continue
            vulnerabilities.append({
                'cve_id': cve_id,
                'description': desc,
                'score': score,
                'severity': severity.upper(),
                'match_confidence': 'cpe' if cpe_hit else 'keyword',
                'cpe': next((c for c in cpes if any(tok in c for tok in tokens)), '') if cpe_hit else '',
            })
    except Exception as e:
        logger.warning(f"NVD search failed: {e}")
    return vulnerabilities


def zoomeye_search(domain: str, zoomeye_key: str) -> List[Dict[str, Any]]:
    """Stub wrapper for ZoomEye exposed asset intelligence."""
    return []
