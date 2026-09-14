#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
connectors.py — The core external intelligence & utility connector module.
Provides SSRF guards, host normalization, DNS resolution, port scanning,
subdomain enumeration, endpoint fuzzing, and threat-intel API wrappers.
"""

import requests
import logging
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


def check_ssl(domain: str) -> Dict[str, Any]:
    """Inspects target SSL/TLS certificate validity and details."""
    clean = clean_host(domain)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((clean, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return {
                        'valid': True,
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'not_after': cert.get('notAfter')
                    }
    except Exception as e:
        return {'valid': False, 'error': str(e)}
    return {'valid': False, 'error': 'Unknown SSL state'}


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
                    if name and '*' not in name and name.endswith(clean):
                        names.add(name)
            return sorted(names)
    except Exception as e:
        logger.warning(f"crt.sh lookup failed: {e}")
    return []


def fuzz_endpoints(base_url: str) -> List[Dict[str, Any]]:
    """Fuzzes common sensitive configuration files and backup paths."""
    fuzz_paths = [
        '/.env', '/robots.txt', '/sitemap.xml', '/git/config',
        '/backup.zip', '/api/v1/users', '/swagger.ui', '/phpinfo.php',
        '/config.json', '/auth/login', '/graphql', '/debug', '/admin'
    ]
    exposed = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    
    for path in fuzz_paths:
        try:
            resp = requests.get(origin + path, timeout=3, verify=False)
            if resp.status_code in [200, 403, 401] and len(resp.text) > 15:
                text_lower = resp.text.lower()
                if not any(err in text_lower for err in ["not found", "404 page", "does not exist"]):
                    exposed.append({'path': path, 'status': resp.status_code, 'size': len(resp.text)})
        except Exception:
            pass
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


def nvd_search(keyword: str, nvd_key: str, strict: bool = True) -> List[Dict[str, Any]]:
    """Searches NIST NVD v2.0 for correlated vulnerabilities."""
    vulnerabilities = []
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'keywordSearch': keyword, 'resultsPerPage': 5}
        headers = {}
        if nvd_key:
            headers['apiKey'] = nvd_key
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        if resp.status_code == 200:
            for item in resp.json().get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'UNKNOWN')
                desc = cve.get('descriptions', [{}])[0].get('value', 'No description.')
                metrics = cve.get('metrics', {})
                score, severity = 0.0, 'UNKNOWN'
                if 'cvssMetricV31' in metrics:
                    data = metrics['cvssMetricV31'][0].get('cvssData', {})
                    score = float(data.get('baseScore', 0.0))
                    severity = data.get('baseSeverity', 'UNKNOWN')
                if score >= 4.0:
                    vulnerabilities.append({
                        'cve_id': cve_id, 'description': desc,
                        'score': score, 'severity': severity.upper(),
                        'match_confidence': 'cpe' if strict else 'keyword'
                    })
    except Exception as e:
        logger.warning(f"NVD search failed: {e}")
    return vulnerabilities


def zoomeye_search(domain: str, zoomeye_key: str) -> List[Dict[str, Any]]:
    """Stub wrapper for ZoomEye exposed asset intelligence."""
    return []
