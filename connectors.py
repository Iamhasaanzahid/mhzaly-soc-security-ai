#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
connectors.py — All external data-source integrations for MHZALY Autonomous SOC.

Each function takes a target and returns a plain dict of what it found.
The scheduler calls these, then hands the combined dict to db.upsert_finding()
for each discrete "thing" worth tracking. Keeping every source in its own
function means adding a new API later is a 10-line addition, not a rewrite.

APIs wired up here:
  - NVD (nvd.nist.gov)            free, official, key optional (raises rate limit)
  - VirusTotal                    free tier, key required
  - AbuseIPDB                     free tier, key required
  - crt.sh                        free, NO key needed (certificate transparency)
  - ZoomEye (Knownsec, China)     free tier, key required
  - urlscan.io (Norway)           free tier, key optional for search
  - ip-api.com                    free, NO key needed (geolocation/ISP)

v2 changes:
  - assert_public_host() SSRF guard before any direct socket/HTTP touch of the
    target host (scan_ports, check_ssl, fuzz_endpoints). This runs unattended
    24/7 against whatever's in the DB, so it's the thing most exposed if a bad
    target ever gets added — internal IP, localhost, or cloud metadata address.
  - with_retry() wraps flaky calls (timeouts/connection errors) with backoff.
  - nvd_search() now does CPE-aware matching (same fix as app.py v18.0) and
    defaults to strict/confirmed matches only, since this path alerts to
    Discord with no human review before it fires.
"""

import ipaddress
import requests
import socket
import ssl
import time
import dns.resolver
import urllib.parse
import logging
from typing import Dict, List, Any, Callable

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MHZALY-SOC/2.0"


class ScopeViolation(Exception):
    """Raised when a target resolves to a disallowed internal/metadata address."""
    pass


def assert_public_host(hostname: str) -> None:
    """SSRF guard — see module docstring. Call before any direct connection to
    a user/DB-supplied target host."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ScopeViolation(f"Could not resolve host: {e}")

    for family, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ScopeViolation(
                f"Target '{hostname}' resolves to a non-public address ({ip_str}). "
                f"Refusing to connect to internal/reserved network space."
            )


def with_retry(fn: Callable, *args, retries: int = 2, backoff: float = 1.5, **kwargs):
    """Retry with exponential backoff for flaky/rate-limited HTTP calls."""
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return fn(*args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff ** attempt)
    raise last_exc


def clean_host(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].strip()


# ── crt.sh — certificate transparency, free, no key ─────────────────────────
# Note: this queries crt.sh's own index of the domain, not the target host
# directly, so it isn't an SSRF vector — no guard needed here.

def crtsh_subdomains(domain: str) -> List[str]:
    """Pulls subdomains seen in public SSL certs. Great for catching new
    subdomains someone spun up (a common bug-bounty and shadow-IT signal)."""
    host = clean_host(domain)
    found = set()
    try:
        resp = with_retry(requests.get, f"https://crt.sh/?q=%25.{host}&output=json", timeout=15)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name:
                        found.add(name)
    except Exception as e:
        logger.warning(f"crt.sh error for {host}: {e}")
    return sorted(found)


# ── ip-api.com — free geolocation/ISP, no key ───────────────────────────────

def ip_geolocation(ip_or_host: str) -> Dict[str, Any]:
    try:
        resp = with_retry(requests.get, f"http://ip-api.com/json/{ip_or_host}", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": data.get("query"), "country": data.get("country"),
                    "region": data.get("regionName"), "city": data.get("city"),
                    "isp": data.get("isp"), "org": data.get("org"), "as": data.get("as"),
                }
    except Exception as e:
        logger.warning(f"ip-api error for {ip_or_host}: {e}")
    return {}


# ── ZoomEye — Chinese (Knownsec 404 team) exposed-service search ───────────
# Queries ZoomEye's own index, not the target directly — no SSRF guard needed.

def zoomeye_search(target: str, api_key: str) -> List[Dict[str, Any]]:
    """Free tier gives limited results/month. Returns exposed services/banners
    ZoomEye has already indexed for this host — often surfaces things your
    own scanner would time out on (IoT, old panels, forgotten services)."""
    if not api_key:
        return []
    host = clean_host(target)
    try:
        headers = {"API-KEY": api_key}
        resp = with_retry(
            requests.get,
            f"https://api.zoomeye.org/host/search?query=hostname:{host}",
            headers=headers, timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            out = []
            for m in data.get("matches", [])[:10]:
                out.append({
                    "ip": m.get("ip"), "port": m.get("portinfo", {}).get("port"),
                    "service": m.get("portinfo", {}).get("service"),
                    "product": m.get("portinfo", {}).get("product"),
                })
            return out
    except Exception as e:
        logger.warning(f"ZoomEye error for {host}: {e}")
    return []


# ── urlscan.io — Norway-based page scanning ─────────────────────────────────
# Queries urlscan.io's own scan history — no SSRF guard needed.

def urlscan_lookup(target: str, api_key: str = "") -> Dict[str, Any]:
    """Searches urlscan.io's existing scan history for this domain — flags if
    someone else already scanned it as suspicious/phishing, plus tech stack."""
    host = clean_host(target)
    try:
        headers = {"API-Key": api_key} if api_key else {}
        resp = with_retry(
            requests.get,
            f"https://urlscan.io/api/v1/search/?q=domain:{host}",
            headers=headers, timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if results:
                top = results[0]
                return {
                    "total_scans": data.get("total", 0),
                    "last_scan_url": top.get("result"),
                    "malicious_flagged": top.get("page", {}).get("status") == "malicious"
                    if isinstance(top.get("page"), dict) else False,
                }
    except Exception as e:
        logger.warning(f"urlscan error for {host}: {e}")
    return {}


# ── Port scan + SSL + headers (deterministic, no API — direct-connect, guarded) ─

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9200]
PORT_NAMES = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
              443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
              5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch"}


def scan_ports(host: str) -> List[Dict[str, Any]]:
    import concurrent.futures

    try:
        assert_public_host(host)
    except ScopeViolation as e:
        logger.warning(f"scan_ports blocked: {e}")
        return []

    open_ports = []

    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            r = s.connect_ex((host, port))
            s.close()
            if r == 0:
                return {"port": port, "service": PORT_NAMES.get(port, "Unknown")}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for res in ex.map(check, COMMON_PORTS):
            if res:
                open_ports.append(res)
    return sorted(open_ports, key=lambda x: x["port"])


def check_ssl(host: str) -> Dict[str, Any]:
    try:
        assert_public_host(host)
    except ScopeViolation as e:
        return {"valid": False, "error": str(e)}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return {"valid": True, "not_after": cert.get("notAfter"),
                            "issuer": dict(x[0] for x in cert.get("issuer", []))}
    except Exception as e:
        return {"valid": False, "error": str(e)}
    return {"valid": False}


def check_dns(host: str) -> Dict[str, List[str]]:
    out = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS"]:
        try:
            out[rtype] = [str(r) for r in dns.resolver.resolve(host, rtype)]
        except Exception:
            out[rtype] = []
    return out


# ── NVD, VirusTotal, AbuseIPDB ───────────────────────────────────────────────

def _cpe_matches_keyword(cve_item: Dict[str, Any], keyword: str) -> bool:
    """Checks the CVE's structured CPE match data for the keyword as an actual
    vendor/product token, rather than trusting a raw description substring hit.
    This is the fix for the false-positive class (e.g. 'React' matching
    unrelated hardware CVEs) seen in earlier report runs."""
    kw = keyword.lower().strip()
    if not kw:
        return False
    for config in cve_item.get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                criteria = match.get('criteria', '').lower()
                parts = criteria.split(':')
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    if kw == vendor or kw == product or kw in product:
                        return True
    return False


def nvd_search(keyword: str, api_key: str = "", max_results: int = 8,
               strict: bool = True) -> List[Dict[str, Any]]:
    """
    strict=True (default): only return CVEs where the keyword is confirmed
    against the CVE's own structured product/vendor data (CPE match). This
    runs unattended and posts straight to Discord, so precision matters more
    than recall here — set strict=False only for interactive/manual lookups.
    """
    try:
        headers = {"apiKey": api_key} if api_key else {}
        resp = with_retry(
            requests.get,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=headers, timeout=15,
        )
        out = []
        if resp.status_code == 200:
            for item in resp.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                score, severity = 0.0, "UNKNOWN"
                for key in ["cvssMetricV31", "cvssMetricV30"]:
                    if metrics.get(key):
                        d = metrics[key][0]["cvssData"]
                        score, severity = float(d.get("baseScore", 0)), d.get("baseSeverity", "UNKNOWN")
                        break
                if score < 4.0:
                    continue
                confidence = "cpe" if _cpe_matches_keyword(cve, keyword) else "keyword"
                if strict and confidence != "cpe":
                    continue
                out.append({"cve_id": cve.get("id"), "score": score, "severity": severity,
                            "published": str(cve.get("published", ""))[:10],
                            "match_confidence": confidence})
        return out
    except Exception as e:
        logger.warning(f"NVD error for {keyword}: {e}")
        return []


def virustotal_check(indicator: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {}
    try:
        is_ip = bool(__import__("re").match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator))
        url = (f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}" if is_ip
               else f"https://www.virustotal.com/api/v3/domains/{indicator}")
        resp = with_retry(requests.get, url, headers={"x-apikey": api_key}, timeout=12)
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                    "reputation": attrs.get("reputation", 0)}
        elif resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit (429).")
    except Exception as e:
        logger.warning(f"VT error for {indicator}: {e}")
    return {}


def abuseipdb_check(ip: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {}
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        resp = with_retry(
            requests.get, "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {"score": d.get("abuseConfidenceScore", 0), "reports": d.get("totalReports", 0),
                    "country": d.get("countryCode")}
        elif resp.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit (429).")
    except Exception as e:
        logger.warning(f"AbuseIPDB error for {ip}: {e}")
    return {}


# ── Sensitive endpoint fuzzing (deterministic, direct-connect, guarded) ─────

FUZZ_PATHS = ["/.env", "/.git/config", "/backup.zip", "/api/v1/users", "/swagger.json",
              "/config.json", "/.aws/credentials", "/wp-config.php.bak", "/.DS_Store",
              "/server-status", "/actuator/env", "/debug"]


def fuzz_endpoints(target_url: str) -> List[Dict[str, Any]]:
    host = clean_host(target_url)
    try:
        assert_public_host(host)
    except ScopeViolation as e:
        logger.warning(f"fuzz_endpoints blocked: {e}")
        return []

    found = []
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    for path in FUZZ_PATHS:
        try:
            r = with_retry(session.get, target_url.rstrip("/") + path, timeout=4, verify=False, retries=1)
            if r.status_code in (200, 401, 403) and len(r.text) > 10:
                low = r.text.lower()
                if any(x in low for x in ["not found", "404", "does not exist"]):
                    continue
                found.append({"path": path, "status": r.status_code})
        except Exception:
            pass
    return found
