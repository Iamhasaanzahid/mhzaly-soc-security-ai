#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hunter.py — Verified web-surface hunter for the MHZALY SOC platform.

Design rule: a finding only survives if it can be proven twice.
* Soft-404 calibration before any sensitive-path probe, so a catch-all page
  that returns 200 for every URL is never reported as an "exposed .env".
* Content signatures (what a real .env / .git/config / phpinfo page looks
  like) on top of the status code.
* Certificate checks use the default verifying context; an expired or
  self-signed certificate is never reported as valid.
* One consolidated finding per category (headers, cookies, TLS, email)
  instead of six separate "points".

Network calls are best-effort and time-boxed: a single unreachable endpoint
must never abort a scan cycle.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

try:  # dnspython is a hard requirement of the platform, but stay importable.
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None  # type: ignore

logger = logging.getLogger(__name__)

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0 Safari/537.36 MHZALY-SOC/2.0 (+responsible-disclosure)"
)

SENSITIVE_PATHS: Tuple[str, ...] = (
    "/.env", "/.env.local", "/.git/config", "/config.json", "/phpinfo.php",
    "/actuator/env", "/swagger.json", "/openapi.json", "/backup.zip",
    "/.DS_Store", "/server-status", "/debug", "/graphql",
)

# Expected security headers. The value is (points, human explanation).
SECURITY_HEADERS: Dict[str, Tuple[int, str]] = {
    "strict-transport-security": (30, "HSTS"),
    "content-security-policy": (30, "Content-Security-Policy"),
    "x-frame-options": (15, "X-Frame-Options"),
    "x-content-type-options": (10, "X-Content-Type-Options"),
    "referrer-policy": (10, "Referrer-Policy"),
    "permissions-policy": (5, "Permissions-Policy"),
}

#: Bodies that look like an exposed file. Each entry: path -> (regex, label).
LEAK_SIGNATURES: Dict[str, Tuple[str, str]] = {
    "/.env": (r"(?m)^\s*[A-Z0-9_]{3,}\s*=\s*\S+", "environment file with KEY=VALUE pairs"),
    "/.env.local": (r"(?m)^\s*[A-Z0-9_]{3,}\s*=\s*\S+", "environment file with KEY=VALUE pairs"),
    "/.git/config": (r"(?m)^\[core\]|^\s*repositoryformatversion\s*=", "Git repository config"),
    "/phpinfo.php": (r"phpinfo\(\)|<title>phpinfo\(\)", "phpinfo() output page"),
    "/actuator/env": (r'"propertySources"|"activeProfiles"', "Spring Boot actuator environment"),
    "/swagger.json": (r'"swagger"\s*:\s*"2\.|"openapi"\s*:\s*"3\.', "Swagger/OpenAPI document"),
    "/openapi.json": (r'"openapi"\s*:\s*"3\.', "OpenAPI document"),
    "/config.json": (r'(?s)^\s*\{\s*"[^"]+"\s*:', "JSON configuration object"),
    "/.DS_Store": (r"Bud1|\x00\x00\x00\x01Bud1", "macOS .DS_Store metadata"),
    "/server-status": (r"Apache Server Status|Server Version:", "Apache server-status page"),
}


# ── HTTP helpers ─────────────────────────────────────────────────────────────

def make_session(timeout: int = 8) -> requests.Session:
    """A browser-like session with bounded retries and no redirect loops."""
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA, "Accept": "*/*"})
    adapter = requests.adapters.HTTPAdapter(max_retries=2, pool_connections=8, pool_maxsize=8)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.request_timeout = timeout  # type: ignore[attr-defined]
    return s


def _get(session: requests.Session, url: str, timeout: int = 8) -> Optional[requests.Response]:
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, verify=False)
    except requests.RequestException:
        return None


def origin_of(target: str) -> str:
    """Normalise a target into a scheme://host origin."""
    raw = (target or "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if not parsed.hostname:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


# ── Pure analysis helpers (unit-tested, no network) ──────────────────────────

def grade_security_headers(headers: Iterable[Tuple[str, str]] | Dict[str, str]) -> Dict[str, Any]:
    """Score the security headers present on a response.

    Returns score/grade plus the exact missing headers so the report can name
    them. CSP may substitute for X-Frame-Options via frame-ancestors.
    """
    if isinstance(headers, dict):
        lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    else:
        lowered = {str(k).lower(): str(v) for k, v in headers}

    present: Dict[str, str] = {}
    missing: List[str] = []
    score = 0
    for name, (points, label) in SECURITY_HEADERS.items():
        if name in lowered and lowered[name].strip():
            present[label] = lowered[name][:120]
            score += points
        else:
            missing.append(label)

    # CSP frame-ancestors covers clickjacking even without X-Frame-Options.
    csp = lowered.get("content-security-policy", "").lower()
    if "frame-ancestors" in csp and "X-Frame-Options" in missing:
        missing.remove("X-Frame-Options")
        score += SECURITY_HEADERS["x-frame-options"][0]

    score = min(100, score)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"score": score, "grade": grade, "present": present, "missing": missing}


def analyse_cookies(set_cookie_headers: Iterable[str]) -> List[Dict[str, Any]]:
    """Return cookies that are missing Secure / HttpOnly / SameSite."""
    issues: List[Dict[str, Any]] = []
    for raw in set_cookie_headers:
        if not raw:
            continue
        name = raw.split("=", 1)[0].strip()
        lowered = raw.lower()
        problems = []
        if "secure" not in lowered:
            problems.append("Secure flag missing")
        if "httponly" not in lowered:
            problems.append("HttpOnly flag missing")
        if "samesite" not in lowered:
            problems.append("SameSite attribute missing")
        if problems:
            issues.append({"name": name, "issues": problems})
    return issues


def parse_surface(html: str, base_url: str) -> Dict[str, Any]:
    """Extract links, forms, scripts, query parameters and comments from a page.

    Purely static analysis of the HTML that was already fetched. Bounded so a
    pathological page cannot blow up memory.
    """
    base = urllib.parse.urlparse(base_url)
    base_origin = f"{base.scheme}://{base.netloc}" if base.netloc else ""
    html = html or ""

    hrefs = re.findall(r'href=["\']([^"\'#]+)["\']', html, flags=re.I)[:300]
    srcs = re.findall(r'src=["\']([^"\']+)["\']', html, flags=re.I)[:200]
    forms = re.findall(r"<form\b[^>]*>", html, flags=re.I)[:50]
    actions = re.findall(r'action=["\']([^"\']*)["\']', html, flags=re.I)[:50]
    comments = re.findall(r"<!--(.*?)-->", html, flags=re.S)[:50]
    params = set()
    for link in hrefs:
        query = urllib.parse.urlparse(link).query
        if query:
            params.update(urllib.parse.parse_qs(query).keys())

    def same_origin(url: str) -> bool:
        absolute = urllib.parse.urljoin(base_url, url)
        parsed = urllib.parse.urlparse(absolute)
        return bool(parsed.netloc) and f"{parsed.scheme}://{parsed.netloc}" == base_origin

    links = []
    seen = set()
    for href in hrefs:
        if href.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urllib.parse.urljoin(base_url, href.split("#")[0])
        if absolute not in seen and same_origin(href):
            seen.add(absolute)
            links.append(absolute)

    return {
        "links": links[:150],
        "scripts": [urllib.parse.urljoin(base_url, s) for s in srcs][:100],
        "forms": len(forms),
        "form_actions": [urllib.parse.urljoin(base_url, a) for a in actions if a],
        "param_names": sorted(params)[:50],
        "comments": [c.strip()[:200] for c in comments if c.strip()][:10],
        "external_hosts": sorted({
            urllib.parse.urlparse(urllib.parse.urljoin(base_url, s)).netloc
            for s in srcs if urllib.parse.urlparse(urllib.parse.urljoin(base_url, s)).netloc
            and urllib.parse.urlparse(urllib.parse.urljoin(base_url, s)).netloc != base.netloc
        })[:30],
    }


def leak_signature(path: str, body: str) -> Optional[str]:
    """Return the matched signature label for a truly exposed file, else None."""
    spec = LEAK_SIGNATURES.get(path)
    if not spec:
        return None
    pattern, label = spec
    try:
        if re.search(pattern, body or "", flags=re.I):
            return label
    except re.error:  # pragma: no cover - defensive
        return None
    return None


def is_soft_404(status: int, body: str, baseline: Dict[str, Any], title: str = "") -> bool:
    """Detect catch-all pages: same status, near-identical size, same title."""
    if not baseline:
        return False
    base_status = baseline.get("status")
    base_size = baseline.get("size") or 0
    size = len(body or "")
    if base_status is not None and status != base_status:
        return False
    if base_size and abs(size - base_size) <= max(64, int(base_size * 0.10)):
        return True
    base_title = (baseline.get("title") or "").strip().lower()
    return bool(base_title and title.strip().lower() == base_title)


def fingerprint_technologies(status_headers: Dict[str, str], body: str) -> List[str]:
    """Lightweight stack fingerprint from headers and HTML markers."""
    tech: List[str] = []
    hay_h = {str(k).lower(): str(v) for k, v in (status_headers or {}).items()}
    server = hay_h.get("server", "")
    powered = hay_h.get("x-powered-by", "")
    if server:
        tech.append(server.split("/")[0])
    if "wordpress" in (body or "").lower() or "wp-content" in (body or ""):
        tech.append("WordPress")
    markers = {
        "__NEXT_DATA__": "Next.js",
        "drupal": "Drupal",
        "laravel_session": "Laravel",
        "csrfmiddlewaretoken": "Django",
        "react": "React",
        "vue": "Vue",
        "_wpnonce": "WordPress",
        "shopify": "Shopify",
    }
    low = (body or "").lower()
    for marker, name in markers.items():
        if marker.lower() in low:
            tech.append(name)
    if powered:
        tech.append(powered.split("/")[0])
    return sorted({t for t in tech if t})


def _finding(kind: str, category: str, severity: str, summary: str,
             marker: str, details: Dict[str, Any], evidence: Dict[str, Any],
             verified: bool) -> Dict[str, Any]:
    return {
        "kind": kind,
        "category": category,
        "severity": severity.upper(),
        "summary": summary,
        "marker": marker,
        "details": details,
        "evidence": evidence,
        "verified": verified,
    }


# ── Network probes ──────────────────────────────────────────────────────────

def check_tls(host: str, port: int = 443) -> Dict[str, Any]:
    """Verify the certificate the way a browser would.

    The previous implementation disabled verification entirely, so an expired
    or self-signed certificate was reported as `valid: True`. Here the default
    verifying context decides trust; a second non-verifying connection is only
    used to *describe* the failure.
    """
    host = (host or "").strip()
    result: Dict[str, Any] = {"host": host, "valid": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result.update({
                    "valid": True,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "not_after": cert.get("notAfter"),
                    "protocol": ssock.version(),
                    "cipher": (ssock.cipher() or [None])[0],
                })
    except ssl.SSLCertVerificationError as exc:
        result.update({"valid": False, "error": str(exc), "untrusted": True})
        # Describe the certificate anyway (expiry, self-signed) without trusting it.
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["not_after"] = cert.get("notAfter")
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        except Exception:  # pragma: no cover - best effort only
            pass
    except (OSError, ssl.SSLError) as exc:
        result.update({"valid": False, "error": str(exc)})

    days = _days_until(result.get("not_after"))
    if days is not None:
        result["days_left"] = days
        result["expired"] = days < 0
        result["expiring_soon"] = 0 <= days < 30
    return result


def _days_until(not_after: Optional[str]) -> Optional[int]:
    if not not_after:
        return None
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (expiry - datetime.now(timezone.utc)).days


def soft_404_baseline(session: requests.Session, origin: str) -> Dict[str, Any]:
    """Calibrate what a non-existent path looks like on this host."""
    for candidate in ("/mhzaly-probe-404-a1", "/.mhzaly-probe-404-b2"):
        resp = _get(session, origin + candidate)
        if resp is None:
            continue
        title = ""
        match = re.search(r"<title[^>]*>(.*?)</title>", resp.text or "", flags=re.I | re.S)
        if match:
            title = re.sub(r"\s+", " ", match.group(1)).strip()[:120]
        return {"status": resp.status_code, "size": len(resp.text or ""), "title": title}
    return {}


def verify_sensitive_path(session: requests.Session, origin: str, path: str,
                          baseline: Dict[str, Any]) -> Dict[str, Any]:
    """Probe one path and decide, with evidence, whether it is really exposed."""
    resp = _get(session, origin + path)
    if resp is None:
        return {"path": path, "status": None, "verified": False, "confidence_hint": 0,
                "note": "unreachable"}

    body = resp.text or ""
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:120] if title_match else ""

    if resp.status_code in (401, 403):
        return {"path": path, "status": resp.status_code, "verified": False, "protected": True,
                "note": "protected — authentication required, not a leak"}

    soft = is_soft_404(resp.status_code, body, baseline, title)
    signature = leak_signature(path, body)
    verified = bool(resp.status_code == 200 and signature and not soft)
    return {
        "path": path,
        "status": resp.status_code,
        "size": len(body),
        "title": title,
        "signature": signature,
        "soft_404": soft,
        "verified": verified,
        "evidence_snippet": body.strip()[:280].replace("\n", " ") if verified else "",
        "note": ("verified signature match" if verified
                 else "soft-404 / catch-all response" if soft
                 else "no content signature — suppressed"),
    }


def check_email_security(domain: str) -> Dict[str, Any]:
    """SPF + DMARC presence and policy strength (single consolidated finding)."""
    out: Dict[str, Any] = {"domain": domain, "spf": None, "dmarc": None}
    if dns is None:
        return out
    try:
        txt = [str(r).strip('"') for r in dns.resolver.resolve(domain, "TXT", lifetime=6)]
        out["spf"] = next((r for r in txt if r.lower().startswith("v=spf1")), None)
    except Exception:
        pass
    try:
        dmarc_txt = [str(r).strip('"') for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=6)]
        dmarc = next((r for r in dmarc_txt if r.lower().startswith("v=dmarc1")), None)
        out["dmarc"] = dmarc
        if dmarc:
            policy = re.search(r"\bp\s*=\s*(none|quarantine|reject)", dmarc, flags=re.I)
            out["dmarc_policy"] = policy.group(1).lower() if policy else "none"
    except Exception:
        pass
    return out


TAKEOVER_FINGERPRINTS: Dict[str, str] = {
    "s3.amazonaws.com": "NoSuchBucket",
    "cloudfront.net": "Bad request",
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "azurewebsites.net": "404 Web Site not found",
    "trafficmanager.net": "404",
    "fastly.net": "Fastly error: unknown domain",
    "pantheonsite.io": "The gods are wise",
}


def check_takeover(subdomain: str, session: Optional[requests.Session] = None) -> Optional[Dict[str, Any]]:
    """Real dangling-CNAME detection instead of 'DNS does not resolve'."""
    session = session or make_session()
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=5) if dns else []
        target = str(answers[0]).rstrip(".") if answers else ""
    except Exception:
        return None  # NXDOMAIN alone is not a takeover.
    if not target:
        return None
    for provider, marker in TAKEOVER_FINGERPRINTS.items():
        if target.lower().endswith(provider):
            resp = _get(session, f"http://{subdomain}")
            body = (resp.text if resp else "")[:4000]
            if resp is not None and marker.lower() in body.lower():
                return {
                    "subdomain": subdomain,
                    "cname": target,
                    "provider": provider,
                    "verified": True,
                    "evidence": body.strip()[:200].replace("\n", " "),
                }
    return None


def crawl(origin: str, session: requests.Session, max_pages: int = 15,
          max_depth: int = 2) -> Dict[str, Any]:
    """Bounded same-origin crawl that builds the attack-surface inventory."""
    start = _get(session, origin)
    inventory: Dict[str, Any] = {
        "pages": [], "links": set(), "scripts": set(), "params": set(),
        "form_actions": set(), "comments": [], "external_hosts": set(),
        "technologies": [], "errors": [],
    }
    if start is None:
        inventory["errors"].append("homepage unreachable")
        return _freeze_inventory(inventory)

    inventory["technologies"] = fingerprint_technologies(dict(start.headers), start.text or "")
    surface = parse_surface(start.text or "", origin)
    inventory["links"].update(surface["links"])
    inventory["scripts"].update(surface["scripts"])
    inventory["params"].update(surface["param_names"])
    inventory["form_actions"].update(surface["form_actions"])
    inventory["comments"].extend(surface["comments"])
    inventory["external_hosts"].update(surface["external_hosts"])
    inventory["pages"].append(origin)

    queue = [(u, 1) for u in surface["links"]]
    visited = {origin}
    while queue and len(inventory["pages"]) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        resp = _get(session, url)
        if resp is None:
            continue
        inventory["pages"].append(url)
        page_static = parse_surface(resp.text or "", url)
        inventory["links"].update(page_static["links"])
        inventory["scripts"].update(page_static["scripts"])
        inventory["params"].update(page_static["param_names"])
        inventory["form_actions"].update(page_static["form_actions"])
        inventory["comments"].extend(page_static["comments"])
        inventory["external_hosts"].update(page_static["external_hosts"])
        if depth < max_depth:
            queue.extend((u, depth + 1) for u in page_static["links"][:30])
    return _freeze_inventory(inventory)


def _freeze_inventory(inv: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pages": inv["pages"][:40],
        "links": sorted(inv["links"])[:200],
        "scripts": sorted(inv["scripts"])[:100],
        "params": sorted(inv["params"])[:60],
        "form_actions": sorted(inv["form_actions"])[:60],
        "comments": inv["comments"][:10],
        "external_hosts": sorted(inv["external_hosts"])[:40],
        "technologies": inv["technologies"],
        "errors": inv["errors"],
    }


def well_known_paths(session: requests.Session, origin: str) -> List[str]:
    """Mine robots.txt and sitemap.xml for real, hinted paths."""
    paths: List[str] = []
    robots = _get(session, origin + "/robots.txt")
    if robots is not None and robots.status_code == 200:
        for line in (robots.text or "").splitlines():
            if line.lower().startswith(("disallow:", "allow:")):
                value = line.split(":", 1)[1].strip()
                if value and value != "/" and not value.startswith("*"):
                    paths.append(value if value.startswith("/") else "/" + value)
    sitemap = _get(session, origin + "/sitemap.xml")
    if sitemap is not None and sitemap.status_code == 200:
        paths.extend(re.findall(r"<loc>([^<]+)</loc>", sitemap.text or "")[:50])
    return list(dict.fromkeys(paths))[:50]


# ── Orchestrator ────────────────────────────────────────────────────────────

def scan_web(host: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run the full verified web assessment for one host.

    Returns `findings` (candidates with an `evidence` block for the confidence
    gate) plus an `inventory` used by the report writer. Never raises.
    """
    options = options or {}
    origin = origin_of(host)
    findings: List[Dict[str, Any]] = []
    inventory: Dict[str, Any] = {"origin": origin, "pages": [], "technologies": []}
    if not origin:
        return {"findings": findings, "inventory": inventory}

    session = make_session()

    # 1. Transport
    tls = check_tls(host)
    inventory["tls"] = tls
    if tls.get("expired"):
        findings.append(_finding("tls_expired", "TLS Certificate", "CRITICAL",
                                 f"TLS certificate for {host} expired {abs(tls.get('days_left', 0))} day(s) ago",
                                 "tls-expired", {"host": host, "days_left": tls.get("days_left")},
                                 {"verified": True}, True))
    elif tls.get("expiring_soon"):
        findings.append(_finding("tls_expiring", "TLS Certificate", "HIGH",
                                 f"TLS certificate for {host} expires in {tls.get('days_left')} day(s)",
                                 "tls-expiring", {"host": host, "days_left": tls.get("days_left")},
                                 {"verified": True}, True))
    elif tls.get("untrusted"):
        findings.append(_finding("tls_untrusted", "TLS Certificate", "HIGH",
                                 f"TLS certificate for {host} failed trust validation",
                                 "tls-untrusted", {"host": host, "error": tls.get("error")},
                                 {"verified": True}, True))
    if tls.get("valid") and tls.get("protocol") in {"TLSv1", "TLSv1.1"}:
        findings.append(_finding("tls_weak_protocol", "TLS Configuration", "HIGH",
                                 f"{host} negotiated legacy {tls.get('protocol')}",
                                 "tls-weak-protocol", {"protocol": tls.get("protocol")},
                                 {"verified": True}, True))

    # 2. HTTP surface
    home = _get(session, origin)
    if home is None and origin.startswith("https://"):
        origin = "http://" + origin.split("://", 1)[1]
        home = _get(session, origin)
    if home is None:
        inventory["error"] = "homepage unreachable"
        return {"findings": findings, "inventory": inventory}

    inventory["origin"] = origin
    headers = dict(home.headers)
    header_analysis = grade_security_headers(headers)
    inventory["headers"] = header_analysis
    inventory["technologies"] = fingerprint_technologies(headers, home.text or "")

    if header_analysis["score"] < 60 and header_analysis["missing"]:
        findings.append(_finding(
            "weak_headers", "Security Headers", "MEDIUM",
            f"Security headers grade {header_analysis['grade']} — missing: {', '.join(header_analysis['missing'])}",
            "headers:" + ",".join(header_analysis["missing"]),
            {"score": header_analysis["score"], "grade": header_analysis["grade"],
             "missing": header_analysis["missing"]},
            {"verified": True, "double_checked": True}, True,
        ))

    # 3. Cookies (one consolidated finding)
    raw_cookies: List[str] = []
    for resp in (home,):
        try:
            raw_cookies.extend(resp.raw.headers.getlist("Set-Cookie"))
        except Exception:
            raw_cookies.extend([v for k, v in resp.headers.items() if k.lower() == "set-cookie"])
    cookie_issues = analyse_cookies(raw_cookies)
    if cookie_issues:
        names = ", ".join(sorted({c["name"] for c in cookie_issues}))[:160]
        findings.append(_finding(
            "insecure_cookie", "Cookie Security", "MEDIUM",
            f"Cookie(s) without full protective flags: {names}",
            "cookies:" + ",".join(sorted({c["name"] for c in cookie_issues})),
            {"cookies": cookie_issues},
            {"verified": True}, True,
        ))

    # 4. CORS
    if headers.get("access-control-allow-origin") == "*":
        findings.append(_finding("cors_wildcard", "CORS", "MEDIUM",
                                 "Access-Control-Allow-Origin is a wildcard",
                                 "cors:*", {"value": "*"}, {"verified": True}, True))

    # 5. Sensitive paths, calibrated against soft-404 behaviour
    baseline = soft_404_baseline(session, origin)
    inventory["soft_404_baseline"] = baseline
    for path in SENSITIVE_PATHS:
        probe = verify_sensitive_path(session, origin, path, baseline)
        if probe.get("verified"):
            findings.append(_finding(
                "verified_leak", "Exposed Asset", "CRITICAL" if path in {"/.env", "/.git/config"} else "HIGH",
                f"{path} is publicly readable ({probe.get('signature')})",
                "path:" + path,
                probe,
                {"verified": True, "signature_match": True, "double_checked": True}, True,
            ))

    # 6. Crawl + inventory (feeds the "what I tested" section of reports)
    inventory.update(crawl(origin, session, max_pages=int(options.get("max_pages", 15))))
    inventory["hinted_paths"] = well_known_paths(session, origin)

    # 7. Email security (single consolidated finding)
    domain = urllib.parse.urlparse(origin).hostname or host
    email = check_email_security(domain)
    inventory["email_security"] = email
    if not email.get("spf") or not email.get("dmarc"):
        missing = []
        if not email.get("spf"):
            missing.append("SPF")
        if not email.get("dmarc"):
            missing.append("DMARC")
        findings.append(_finding(
            "email_dmarc_missing" if not email.get("dmarc") else "email_spf_missing",
            "Email Authentication", "MEDIUM",
            f"Missing email authentication record(s): {', '.join(missing)}",
            "email:" + ",".join(missing),
            {"spf": email.get("spf"), "dmarc": email.get("dmarc")},
            {"verified": True}, True,
        ))
    elif email.get("dmarc_policy") == "none":
        findings.append(_finding("email_dmarc_weak", "Email Authentication", "LOW",
                                 "DMARC exists but policy is p=none (monitor only)",
                                 "email:dmarc-none",
                                 {"dmarc": email.get("dmarc")}, {"verified": True}, True))

    return {"findings": findings, "inventory": inventory}
