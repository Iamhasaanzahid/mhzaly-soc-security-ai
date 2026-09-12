#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY BUG BOUNTY & ENTERPRISE SECURITY PLATFORM v18.0 - HARDENED SaaS EDITION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive Purple Team Operations Suite (Red Team Recon + Blue Team SOC Automation)
Changes vs v17.5:
- CPE-aware CVE correlation (kills the "React" false-positive class of match)
- SSRF guard on every outbound recon/scan request (blocks private/link-local/metadata ranges)
- Explicit authorization gate before any active scan runs
- Hardened auth: constant-time password check, no insecure default creds, login lockout
- Retry-with-backoff + lightweight response caching for VT/AbuseIPDB/NVD/Groq calls
- AI report generation checks finish_reason and continues instead of silently truncating
- Free-tier subdomain enumeration via crt.sh
- Aggregate numeric risk score per target
- JSON export alongside Markdown

Author: Muhammad Hassaan Zahid
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import streamlit as st
import requests
import pandas as pd
import numpy as np
import json
import sqlite3
import logging
import time
import hmac
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
import socket
import ssl
import dns.resolver
import re
import urllib.parse
import base64
import hashlib
import concurrent.futures
import subprocess

# Import local backend modules for Autonomous SOC & Connectors
import db
import connectors as c
import notifier
import scheduler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable insecure request warnings for offensive reconnaissance
requests.packages.urllib3.disable_warnings()

# ═══════════════════════════════════════════════════════════════════════════════
# 0. SAFETY: SSRF GUARD, RETRY HELPER, LIGHTWEIGHT CACHE
# ═══════════════════════════════════════════════════════════════════════════════

class ScopeViolation(Exception):
    """Raised when a target resolves to a disallowed internal/metadata address."""
    pass


def assert_public_host(hostname: str) -> None:
    """
    SSRF guard. Resolves `hostname` and raises ScopeViolation if it lands on a
    private, loopback, link-local, reserved, or cloud-metadata address.
    Call this BEFORE making any outbound request or opening any socket to a
    user-supplied target — this app runs as a hosted service, and without this
    check a "domain" input of e.g. "169.254.169.254" or "localhost" would let a
    user pivot the server into scanning its own internal network.
    """
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
                f"Refusing to scan internal/reserved network space."
            )
        # Explicit cloud metadata block (169.254.169.254 is link-local so it's
        # already caught above, but keep this for clarity/defense-in-depth)
        if ip_str == "169.254.169.254":
            raise ScopeViolation("Refusing to scan the cloud metadata endpoint.")


def with_retry(fn: Callable, *args, retries: int = 2, backoff: float = 1.5, **kwargs):
    """Simple retry with exponential backoff for flaky/rate-limited HTTP calls."""
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return fn(*args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff ** attempt)
    raise last_exc


class TTLCache:
    """
    Minimal in-memory TTL cache so repeated lookups (e.g. re-rendering a
    Streamlit page) don't burn free-tier VT/AbuseIPDB/NVD quota. Not persisted
    across process restarts — that's fine for its purpose (burst dedup).
    """
    def __init__(self, ttl_seconds: int = 900):
        self.ttl = ttl_seconds
        self._store: Dict[str, Any] = {}

    def get(self, key: str):
        entry = self._store.get(key)
        if not entry:
            return None
        value, expires_at = entry
        if time.time() > expires_at:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any):
        self._store[key] = (value, time.time() + self.ttl)


@st.cache_resource
def get_shared_cache() -> TTLCache:
    return TTLCache(ttl_seconds=900)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. DATA MODELS & SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class VulnerabilityRecord:
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    vector_string: str
    affected_configurations: List[str]
    published_date: str
    remediation: str
    match_confidence: str = "keyword"  # "cpe" (strong) or "keyword" (weak)

    def to_dict(self):
        return asdict(self)


def compute_risk_score(vt_malicious: int, abuse_score: int, top_cvss: float,
                        exposed_count: int = 0, missing_headers: int = 0,
                        risky_open_ports: int = 0) -> Dict[str, Any]:
    """
    Aggregate 0-100 risk score blending threat-intel reputation, worst CVE
    severity found for the target's fingerprinted stack, and — as of this
    fix — the actual recon findings (exposed files, missing security
    headers, risky open ports). Previously the score only looked at
    VT/AbuseIPDB/CVE data, so a freshly-registered or unflagged domain with
    an exposed .env file, missing CSP/HSTS headers, or a public RDP/MySQL
    port would still score 0/100 LOW — recon findings were being surfaced in
    the UI but silently ignored by the score. This is a heuristic, not a
    certified scoring methodology — surfaced as a triage aid only.
    """
    vt_component = min(vt_malicious * 8, 40)          # up to 40 pts
    abuse_component = min(abuse_score * 0.3, 30)       # up to 30 pts
    cvss_component = min((top_cvss / 10) * 30, 30)     # up to 30 pts
    exposure_component = min(exposed_count * 6, 24)    # up to 24 pts — exposed files/backups
    header_component = min(missing_headers * 2.5, 12.5)  # up to 12.5 pts — missing security headers
    port_component = min(risky_open_ports * 5, 15)     # up to 15 pts — risky public ports (RDP/DB/ES)

    score = round(
        vt_component + abuse_component + cvss_component +
        exposure_component + header_component + port_component,
        1,
    )
    score = min(score, 100.0)

    if score >= 70:
        band = "CRITICAL"
    elif score >= 45:
        band = "ELEVATED"
    elif score >= 20:
        band = "GUARDED"
    else:
        band = "LOW"
    return {"score": score, "band": band}


# Ports that are considered risky when found open and reachable from the
# public internet (databases, remote-admin, and commonly-unauthenticated
# search/index services). Used to feed compute_risk_score's port_component.
RISKY_PUBLIC_PORTS = {3389, 3306, 1433, 5432, 9200, 445, 21}


# ═══════════════════════════════════════════════════════════════════════════════
# 0b. PRODUCTION-READINESS: INPUT VALIDATION, SESSION TIMEOUT, SCAN QUOTAS
# ═══════════════════════════════════════════════════════════════════════════════

# Loose but real host/URL validator: rejects empty/whitespace-only garbage,
# control characters, obviously-malformed input, and anything absurdly long
# before it ever reaches a socket call, DNS resolver, or outbound HTTP
# request. This is a UX/sanity gate, NOT a security boundary by itself —
# assert_public_host() remains the actual SSRF guard and still runs
# regardless of what passes here.
_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
)
_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def validate_target_input(raw_target: str, allow_url: bool = True) -> Optional[str]:
    """
    Validates a user-supplied target (domain, IP, or URL) before it is passed
    to any recon/scan engine. Returns an error message string if invalid,
    or None if the input looks acceptable. Deliberately permissive on valid
    shapes (doesn't try to be a full RFC validator) but catches the classes
    of input that would otherwise blow up downstream with a confusing stack
    trace or silently no-op: empty input, embedded whitespace/newlines
    (header/command injection smell), excessive length, and strings that are
    neither a plausible hostname, IPv4 address, nor http(s) URL.
    """
    if raw_target is None:
        return "Target is required."
    target = raw_target.strip()
    if not target:
        return "Target cannot be empty."
    if len(target) > 253:
        return "Target is too long to be a valid hostname/URL."
    if any(ch.isspace() for ch in target) or '\x00' in target:
        return "Target must not contain whitespace or control characters."

    if allow_url and target.startswith(('http://', 'https://')):
        parsed = urllib.parse.urlparse(target)
        if not parsed.netloc:
            return "URL is malformed — missing host."
        host = parsed.hostname or ''
        if _IPV4_RE.match(host) or _HOSTNAME_RE.match(host) or host == 'localhost':
            return None
        return "URL host does not look like a valid domain or IP."

    clean = target.split('/')[0]
    if _IPV4_RE.match(clean):
        octets = clean.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            return None
        return "IP address octets must be between 0 and 255."
    if _HOSTNAME_RE.match(clean):
        return None
    return ("Target must be a valid domain (example.com), IPv4 address, "
            "or http(s) URL.")


# Default session inactivity timeout and per-operator daily active-scan
# quota. Both are overridable via Streamlit secrets so an operator can tune
# them per deployment without a code change. The quota counter is
# process-local (in-memory) and resets on app restart — it's a courtesy
# guard against accidentally hammering free-tier VT/AbuseIPDB/NVD/Groq quota
# or a target, not a hard security control. For a durable, cross-restart
# quota, back this with the `db` module's SQLite store instead.
DEFAULT_SESSION_TIMEOUT_MINUTES = 30
DEFAULT_MAX_ACTIVE_SCANS_PER_DAY = 100


def enforce_session_timeout(timeout_minutes: int) -> bool:
    """
    Logs the operator out if they've been idle longer than timeout_minutes.
    Call once near the top of main() after authentication is confirmed.
    Returns True if the session is still valid, False if it just expired
    (caller should stop rendering the rest of the authenticated UI).
    """
    now = time.time()
    last_activity = st.session_state.get('last_activity_ts', now)
    if now - last_activity > timeout_minutes * 60:
        st.session_state.authenticated = False
        st.warning(f"Session expired after {timeout_minutes} minutes of inactivity. Please log in again.")
        st.rerun()
        return False
    st.session_state['last_activity_ts'] = now
    return True


def check_and_increment_scan_quota(operator: str, max_per_day: int) -> Optional[str]:
    """
    Lightweight per-operator, per-day active-scan counter to slow down
    accidental quota-burning loops (e.g. someone mashing 'Launch' in a
    while-loop-style testing session) against VT/AbuseIPDB/NVD/Groq or
    against the target itself. Returns an error message if the operator is
    over quota (in which case the caller should NOT run the scan and should
    NOT count it), or None if the scan is allowed (in which case the count
    has already been incremented).
    """
    today = datetime.now().strftime('%Y-%m-%d')
    quota_key = 'scan_quota'
    quota_state = st.session_state.get(quota_key, {})
    day_state = quota_state.get(operator, {'date': today, 'count': 0})
    if day_state['date'] != today:
        day_state = {'date': today, 'count': 0}
    if day_state['count'] >= max_per_day:
        return (f"Daily active-scan quota reached ({max_per_day}/day) for operator "
                f"`{operator}`. This resets at midnight, or raise "
                f"MAX_ACTIVE_SCANS_PER_DAY in secrets.")
    day_state['count'] += 1
    quota_state[operator] = day_state
    st.session_state[quota_key] = quota_state
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ENTERPRISE RECON, SOC & AI-AGENTIC INTELLIGENCE ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainEnumEngine:
    """Free-tier subdomain enumeration via crt.sh certificate transparency logs."""
    @staticmethod
    def enumerate(domain: str, limit: int = 50) -> List[str]:
        clean = domain.replace('https://', '').replace('http://', '').split('/')[0]
        try:
            resp = with_retry(
                requests.get,
                f"https://crt.sh/?q=%25.{clean}&output=json",
                timeout=12,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            names = set()
            for entry in data:
                for name in str(entry.get('name_value', '')).split('\n'):
                    name = name.strip().lower()
                    if name and '*' not in name and name.endswith(clean):
                        names.add(name)
            return sorted(names)[:limit]
        except Exception as e:
            logger.warning(f"crt.sh enumeration failed: {e}")
            return []


class BugBountyReconEngine:
    @staticmethod
    def deep_recon(target: str) -> Dict[str, Any]:
        report = {'target': target, 'status_code': None, 'server': 'Hidden / Unknown', 'technologies': [], 'exposed_files': [], 'dns': {}}
        try:
            clean_target = target.replace('https://', '').replace('http://', '').split('/')[0]
            if not target.startswith(('http://', 'https://')):
                target_url = f"https://{target}"
            else:
                target_url = target

            # SSRF guard — refuse to touch internal/reserved/metadata addresses
            assert_public_host(clean_target)

            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
                try:
                    answers = dns.resolver.resolve(clean_target, rtype)
                    report['dns'][rtype] = list(set([str(r) for r in answers]))
                except Exception:
                    report['dns'][rtype] = []

            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PurpleTeamHunter/18.0'})

            resp = with_retry(session.get, target_url, timeout=8, verify=False, allow_redirects=True)
            report['status_code'] = resp.status_code
            report['server'] = resp.headers.get('Server', 'Hidden / Unknown')

            base_homepage_text = resp.text.lower()
            body = base_homepage_text
            headers_str = str(resp.headers).lower()

            if 'wp-content' in body or 'wordpress' in headers_str:
                report['technologies'].append('WordPress')
            if 'laravel' in headers_str or 'laravel_session' in str(resp.cookies):
                report['technologies'].append('Laravel')
            if 'react' in body or '_next' in body or 'data-reactroot' in body:
                report['technologies'].append('React')
            if 'express' in headers_str or 'connect.sid' in str(resp.cookies):
                report['technologies'].append('Express')
            if 'cloudflare' in headers_str:
                report['technologies'].append('Cloudflare')
            if 'django' in headers_str or 'csrftoken' in str(resp.cookies):
                report['technologies'].append('Django')

            report['technologies'] = list(set(report['technologies']))

            fuzz_paths = [
                '/.env', '/robots.txt', '/sitemap.xml', '/git/config',
                '/backup.zip', '/api/v1/users', '/swagger.ui', '/phpinfo.php',
                '/config.json', '/auth/login', '/graphql', '/debug', '/admin',
                '/server-status', '/xmlrpc.php', '/package.json', '/composer.json',
                '/api/v1/health', '/v2/swagger.json', '/metrics', '/actuator/env'
            ]

            base_origin = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"

            seen_paths = set()
            for path in fuzz_paths:
                if path in seen_paths:
                    continue
                seen_paths.add(path)
                test_url = base_origin + path
                try:
                    p_resp = session.get(test_url, timeout=3, verify=False)
                    if p_resp.status_code in [200, 403, 401]:
                        p_text = p_resp.text.lower()

                        # Filter out Streamlit soft-404 pages
                        if 'streamlit' in p_text and 'root' in p_text and len(p_text) > 500:
                            if abs(len(p_text) - len(base_homepage_text)) < 200:
                                continue

                        if p_resp.status_code == 200 and len(p_text) > 10:
                            if any(err in p_text for err in ["not found", "404 page", "does not exist", "object not found"]):
                                continue

                        report['exposed_files'].append({'path': path, 'status': p_resp.status_code, 'size': len(p_resp.text)})
                except Exception:
                    pass
        except ScopeViolation as e:
            report['error'] = f"Scope violation: {e}"
            report['blocked'] = True
        except Exception as e:
            report['error'] = str(e)
        return report


class AutonomousAgentExecutor:
    """Autonomous AI-Driven Agentic Loop for deep target reconnaissance and vulnerability triage."""
    @staticmethod
    def _call_groq(messages: List[Dict[str, str]], groq_key: str, max_tokens: int = 1600, temperature: float = 0.4) -> str:
        """
        Calls Groq chat completions and, if the model was cut off by the token
        budget (finish_reason == 'length'), asks it to continue rather than
        silently returning a truncated report.
        """
        headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
        full_text = ""
        convo = list(messages)
        for _ in range(2):  # allow one continuation pass
            payload = {
                'model': 'openai/gpt-oss-120b',
                'messages': convo,
                'temperature': temperature,
                'max_tokens': max_tokens,
            }
            resp = with_retry(requests.post, "https://api.groq.com/openai/v1/chat/completions",
                               json=payload, headers=headers, timeout=30)
            if resp.status_code != 200:
                return full_text + f"\n[AI Agent LLM Error: {resp.status_code} - {resp.text[:300]}]"
            choice = resp.json()['choices'][0]
            chunk = choice['message']['content']
            full_text += chunk
            if choice.get('finish_reason') != 'length':
                break
            convo = convo + [
                {'role': 'assistant', 'content': chunk},
                {'role': 'user', 'content': 'Continue exactly where you left off, no repetition.'}
            ]
        return full_text

    @staticmethod
    def run_agentic_cycle(target: str, groq_key: str) -> Dict[str, Any]:
        agent_log = []
        agent_log.append(f"[*] AI Agent initialized for autonomous target scope: {target}")

        # Step 1: Deep Recon Execution
        recon_data = BugBountyReconEngine.deep_recon(target)
        if recon_data.get('blocked'):
            agent_log.append(f"[!] Recon blocked: {recon_data.get('error')}")
            return {
                'target': target, 'technologies': [], 'exposed_files': [],
                'agent_log': agent_log, 'ai_analysis': "Scan blocked by scope guard.",
                'blocked': True, 'block_reason': recon_data.get('error'),
            }
        agent_log.append(f"[+] Recon complete. Status: {recon_data.get('status_code')}, Server: {recon_data.get('server')}")

        technologies = recon_data.get('technologies', [])
        exposed = recon_data.get('exposed_files', [])
        agent_log.append(f"[+] Detected unique tech stack: {technologies}")
        agent_log.append(f"[+] Discovered valid exposed endpoints without duplicates: {len(exposed)}")

        subdomains = SubdomainEnumEngine.enumerate(target)
        agent_log.append(f"[+] Certificate-transparency subdomain enumeration found {len(subdomains)} host(s).")

        # Step 1b: Infrastructure audit (ports/headers) folded into the
        # autonomous cycle so its findings feed the aggregate risk score
        # instead of only being visible in the separate manual audit tab.
        infra_audit = AdvancedReconEngine.audit_infrastructure(target)
        if infra_audit.get('blocked'):
            agent_log.append(f"[!] Infrastructure audit blocked: {infra_audit.get('error')}")
            infra_audit = {'ports': [], 'headers': {}}
        else:
            agent_log.append(f"[+] Infrastructure audit found {len(infra_audit.get('ports', []))} open port(s).")

        # Step 2: AI-Powered Context Evaluation & Authorized Security Analysis
        ai_analysis = "AI analysis skipped or key missing."
        if groq_key:
            prompt_context = f"""
            Target Scope: {target}
            Detected Technologies: {technologies}
            Exposed Sensitive Endpoints: {[e['path'] for e in exposed]}
            Enumerated Subdomains (sample): {subdomains[:15]}
            Please perform an authorized technical risk assessment, architectural vulnerability triage, and provide professional security hardening guidelines for these findings. Be specific to what was actually found — do not invent findings that weren't listed above.
            """
            try:
                ai_analysis = AutonomousAgentExecutor._call_groq(
                    [
                        {'role': 'system', 'content': 'You are an authorized enterprise security engineer and bug bounty analyst performing authorized web application architecture assessment, vulnerability triage, and security hardening analysis. Provide comprehensive technical analysis, risk evaluations, and defensive remediation guidance grounded only in the findings given to you.'},
                        {'role': 'user', 'content': prompt_context}
                    ],
                    groq_key, max_tokens=1600,
                )
                agent_log.append("[+] AI Agent successfully generated deep security context and hardening recommendations.")
            except Exception as e:
                ai_analysis = f"AI Agent connection exception: {e}"

        return {
            'target': target,
            'technologies': technologies,
            'exposed_files': exposed,
            'subdomains': subdomains,
            'infra_audit': infra_audit,
            'agent_log': agent_log,
            'ai_analysis': ai_analysis,
            'blocked': False,
        }


class NVDIntelligenceClient:
    """
    NVD client with CPE-aware relevance filtering.

    v18.0 fix: a plain keyword search for "React" matched CVEs for unrelated
    hardware (ABB WiFi Logger) purely because "React" appeared inside an
    unrelated product's description text. We fixed that by checking the CVE's
    structured `configurations` (CPE match strings) instead of description
    text — but that surfaced a second, subtler problem: ABB's own official
    CPE *product* string for that hardware is literally
    "wifi_logger_card_for_react", so a plain substring check against the CPE
    product field ALSO matches it — the word "react" is a real, present token
    in an entirely unrelated vendor's official product name. Two different
    things coincidentally share an exact word in NVD's own dictionary; no
    amount of smarter string matching alone resolves that ambiguity.

    v18.1 fix: for keywords known to be commonly-overloaded generic tech
    names (a JS framework, a CDN, a webserver name that's also an English
    word), we additionally require the CPE *vendor* field to match a known
    authoritative vendor for that keyword before calling it 'cpe' confidence.
    ABB is not Facebook, so this correctly reclassifies that hit back down to
    'keyword' (unconfirmed) instead of a false 'cpe' (confirmed) match.
    """

    # Known-ambiguous keywords -> the CPE vendor token(s) that actually own
    # that product name. Extend this as new false-positive classes turn up.
    VENDOR_ALLOWLIST = {
        "react": {"facebook", "reactjs", "react_project"},
        "express": {"expressjs", "openjs_foundation", "openjsf"},
        "cloudflare": {"cloudflare"},
        "django": {"djangoproject"},
        "laravel": {"laravel"},
        "wordpress": {"wordpress"},
    }

    def __init__(self, nvd_key: str = ""):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_key = nvd_key

    @classmethod
    def _cpe_matches_keyword(cls, cve_item: Dict[str, Any], keyword: str) -> bool:
        kw = keyword.lower().strip()
        if not kw:
            return False
        allowed_vendors = cls.VENDOR_ALLOWLIST.get(kw)
        for config in cve_item.get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    criteria = match.get('criteria', '').lower()
                    # CPE format: cpe:2.3:a:vendor:product:version:...
                    parts = criteria.split(':')
                    if len(parts) > 4:
                        vendor, product = parts[3], parts[4]
                        if allowed_vendors is not None:
                            # Ambiguous keyword — the product string alone
                            # isn't trustworthy; require the authoritative
                            # vendor too.
                            if vendor in allowed_vendors and (kw == product or kw in product):
                                return True
                        else:
                            if kw == vendor or kw == product or kw in product:
                                return True
        return False

    def search_cve(self, keyword: str, max_results: int = 15, min_confidence: str = "any") -> List[VulnerabilityRecord]:
        """
        min_confidence: "any" keeps both cpe+keyword matches (default, matches
        old behavior for exploratory search); "cpe" restricts to structurally
        confirmed product matches — use this for autonomous/unattended reports
        where false positives are costly.
        """
        vulnerabilities = []
        seen_cves = set()
        try:
            params = {'keywordSearch': keyword, 'resultsPerPage': min(max_results, 30)}
            headers = {'User-Agent': 'MHZALY-Purple-Team-Suite/18.1 (+authorized-security-tooling)'}
            if self.nvd_key:
                headers['apiKey'] = self.nvd_key

            response = with_retry(requests.get, self.base_url, params=params, headers=headers, timeout=12)
            if response.status_code in (403, 429):
                # NVD's unauthenticated tier returns 403 almost as often as
                # 429 once you're rate-limited — treat both as "back off",
                # not as a hard/permanent error, so callers can retry later
                # instead of assuming the keyword search itself is invalid.
                logger.warning(f"NVD rate limit/forbidden ({response.status_code}) for keyword '{keyword}'.")
            elif response.status_code == 200:
                data = response.json()
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'UNKNOWN')

                    if cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)

                    descriptions = cve.get('descriptions', [])
                    desc = descriptions[0].get('value', 'No description.') if descriptions else 'No description.'

                    score = 0.0
                    severity = "UNKNOWN"
                    vector = "N/A"
                    metrics = cve.get('metrics', {})

                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        score = float(cvss_data.get('baseScore', 0.0))
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        vector = cvss_data.get('vectorString', 'N/A')
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                        score = float(cvss_data.get('baseScore', 0.0))
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        vector = cvss_data.get('vectorString', 'N/A')

                    if score < 4.0:
                        continue

                    confidence = "cpe" if self._cpe_matches_keyword(cve, keyword) else "keyword"
                    if min_confidence == "cpe" and confidence != "cpe":
                        continue

                    vulnerabilities.append(VulnerabilityRecord(
                        cve_id=cve_id,
                        title=cve_id,
                        description=desc,
                        severity=severity.upper(),
                        cvss_score=score,
                        vector_string=vector,
                        affected_configurations=[keyword],
                        published_date=str(cve.get('published', ''))[:10],
                        remediation=f"Apply official vendor patch or configure WAF signature to mitigate {cve_id}.",
                        match_confidence=confidence,
                    ))
        except Exception as e:
            logger.error(f"NVD API Error: {e}")
        return vulnerabilities


class ThreatIntelService:
    def __init__(self, vt_key: str, abuse_key: str, cache: Optional[TTLCache] = None):
        self.vt_key = vt_key
        self.abuse_key = abuse_key
        self.cache = cache

    def triage_indicator(self, indicator: str) -> Dict[str, Any]:
        cache_key = f"triage:{indicator}"
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached:
                return cached

        results = {
            'indicator': indicator,
            'vt_raw': None,
            'vt_summary': {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'reputation': 0, 'tags': [], 'registrar': 'N/A'},
            'abuse_raw': None,
            'abuse_summary': {'score': 0, 'reports': 0, 'country': 'N/A', 'isp': 'N/A', 'lastReported': 'N/A'}
        }

        try:
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator))
            is_url = indicator.startswith(('http://', 'https://'))

            if self.vt_key:
                try:
                    headers = {'x-apikey': self.vt_key}
                    if is_url:
                        url = f"https://www.virustotal.com/api/v3/urls/{urllib.parse.quote(indicator, safe='')}"
                    elif is_ip:
                        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
                    else:
                        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"

                    resp = with_retry(requests.get, url, headers=headers, timeout=10)
                    if resp.status_code == 200:
                        vt_json = resp.json()
                        results['vt_raw'] = vt_json
                        attrs = vt_json.get('data', {}).get('attributes', {})
                        stats = attrs.get('last_analysis_stats', {})

                        results['vt_summary']['malicious'] = int(stats.get('malicious', 0))
                        results['vt_summary']['suspicious'] = int(stats.get('suspicious', 0))
                        results['vt_summary']['harmless'] = int(stats.get('harmless', 0))
                        results['vt_summary']['undetected'] = int(stats.get('undetected', 0))
                        results['vt_summary']['reputation'] = int(attrs.get('reputation', 0))
                        results['vt_summary']['tags'] = list(set(attrs.get('tags', [])))
                        results['vt_summary']['registrar'] = attrs.get('registrar', attrs.get('as_owner', 'N/A'))
                    elif resp.status_code == 429:
                        results['vt_summary']['error'] = "VT rate limit hit (429) — try again shortly."
                    else:
                        results['vt_summary']['error'] = f"VT HTTP Status: {resp.status_code}"
                except Exception as e:
                    results['vt_summary']['error'] = str(e)

            if self.abuse_key and is_ip:
                try:
                    headers = {'Key': self.abuse_key, 'Accept': 'application/json'}
                    params = {'ipAddress': indicator, 'maxAgeInDays': 90, 'verbose': True}
                    resp = with_retry(requests.get, "https://api.abuseipdb.com/api/v2/check",
                                       headers=headers, params=params, timeout=10)
                    if resp.status_code == 200:
                        abuse_json = resp.json()
                        results['abuse_raw'] = abuse_json
                        data = abuse_json.get('data', {})

                        results['abuse_summary']['score'] = int(data.get('abuseConfidenceScore', 0))
                        results['abuse_summary']['reports'] = int(data.get('totalReports', 0))
                        results['abuse_summary']['country'] = str(data.get('countryCode', 'N/A'))
                        results['abuse_summary']['isp'] = str(data.get('isp', 'N/A'))
                        results['abuse_summary']['lastReported'] = str(data.get('lastReportedAt', 'Never'))
                    elif resp.status_code == 429:
                        results['abuse_summary']['error'] = "AbuseIPDB rate limit hit (429) — try again shortly."
                    else:
                        results['abuse_summary']['error'] = f"AbuseIPDB Status: {resp.status_code}"
                except Exception as e:
                    results['abuse_summary']['error'] = str(e)
        except Exception as e:
            logger.error(f"ThreatIntel error: {e}")

        if self.cache:
            self.cache.set(cache_key, results)
        return results


class AdvancedReconEngine:
    @staticmethod
    def audit_infrastructure(domain: str) -> Dict[str, Any]:
        report = {'dns': {}, 'ports': [], 'ssl': {'valid': False}, 'headers': {}}
        try:
            clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

            # SSRF guard — refuse to port-scan/connect to internal/reserved addresses
            assert_public_host(clean_domain)

            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
                try:
                    answers = dns.resolver.resolve(clean_domain, rtype)
                    report['dns'][rtype] = list(set([str(r) for r in answers]))
                except Exception:
                    report['dns'][rtype] = []

            common_ports = [21, 22, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9200]
            open_ports = []
            seen_ports = set()

            def scan_port(port):
                if port in seen_ports:
                    return None
                seen_ports.add(port)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.8)
                    res = sock.connect_ex((clean_domain, port))
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

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(scan_port, p) for p in common_ports]
                for f in concurrent.futures.as_completed(futures):
                    res = f.result()
                    if res:
                        open_ports.append(res)
            report['ports'] = sorted(open_ports, key=lambda x: x['port'])

            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((clean_domain, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            report['ssl']['valid'] = True
                            report['ssl']['details'] = {
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'version': cert.get('version'),
                                'not_before': cert.get('notBefore'),
                                'not_after': cert.get('notAfter')
                            }
            except Exception as e:
                report['ssl']['error'] = str(e)

            try:
                resp = with_retry(requests.get, f"https://{clean_domain}", timeout=5, verify=False)
                target_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
                for h in target_headers:
                    report['headers'][h] = resp.headers.get(h, 'MISSING')
            except Exception as e:
                report['headers']['error'] = str(e)
        except ScopeViolation as e:
            report['error'] = f"Scope violation: {e}"
            report['blocked'] = True
        except Exception as e:
            logger.error(f"Audit error: {e}")
            report['error'] = str(e)
        return report


# ═══════════════════════════════════════════════════════════════════════════════
# 3. STREAMLIT ENTERPRISE UI (MODERN SaaS CSS & PURPLE TEAM HUB)
# ═══════════════════════════════════════════════════════════════════════════════

def authorization_gate(key_suffix: str) -> bool:
    """
    Renders a mandatory authorization checkbox before any active scan module
    runs. Doesn't verify legal authorization (can't), but forces the operator
    to explicitly attest to it every time — standard practice for bug-bounty
    tooling and a paper trail if the platform is ever misused.
    """
    return st.checkbox(
        "I confirm I am authorized to test this target (owner, bug-bounty program scope, or written permission).",
        key=f"authz_{key_suffix}",
    )


def render_autonomous_tab():
    """Renders the Autonomous SOC live monitoring tab from dashboard_tab.py logic."""
    st.markdown("# Autonomous SOC — Live Monitoring")
    st.markdown(
        "<p style='color:#9ca3af;'>Background scheduler scans these targets on "
        "its own schedule and pushes new findings to Discord. You can also trigger live scans instantly here.</p>",
        unsafe_allow_html=True,
    )

    db.init_db()

    with st.expander("➕ Add a target to autonomous monitoring & live scan"):
        col1, col2 = st.columns([3, 1])
        with col1:
            new_target = st.text_input("Domain or IP", key="new_auto_target")
        with col2:
            interval = st.number_input("Scan every (min)", min_value=5, value=60, key="new_auto_interval")

        authorized = authorization_gate("add_target")

        if st.button("Add & Scan Target Now", use_container_width=True, disabled=not authorized):
            validation_error = validate_target_input(new_target) if new_target else "Please enter a domain or IP to monitor."
            if validation_error:
                st.warning(validation_error)
            else:
                ok = db.add_target(new_target, int(interval))
                if ok:
                    st.success(f"Added {new_target} to database.")

                    with st.spinner(f"Running live autonomous security scan on {new_target}..."):
                        try:
                            targets_list = db.list_targets()
                            target_id = next((t['id'] for t in targets_list if t['target'] == new_target), None)

                            if target_id:
                                cfg = {
                                    "discord_webhook_url": st.secrets.get("DISCORD_WEBHOOK_URL", ""),
                                    "nvd_api_key": st.secrets.get("NVD_API_KEY", ""),
                                    "virustotal_api_key": st.secrets.get("VIRUSTOTAL_API_KEY", ""),
                                    "abuseipdb_api_key": st.secrets.get("ABUSEIPDB_API_KEY", ""),
                                    "zoomeye_api_key": st.secrets.get("ZOOMEYE_API_KEY", "")
                                }
                                scheduler.run_scan_cycle(new_target, target_id, cfg)
                                st.success(f"Live scan completed for {new_target}!")
                                st.rerun()
                        except Exception as e:
                            st.error(f"Target added, but live scan encountered an issue: {e}")
                else:
                    st.warning("Already being monitored.")
        elif not authorized:
            st.caption("Check the authorization box above to enable scanning.")

    targets = db.list_targets()
    st.markdown("### Monitored Targets")
    if targets:
        df = pd.DataFrame(targets)[["id", "target", "scan_interval_minutes", "last_scanned_at", "active"]]
        st.dataframe(df, use_container_width=True)

        with st.form(key="deactivate_form"):
            remove_id = st.number_input("Target ID to Delete", min_value=0, value=0, step=1, key="deactivate_target_id_input")
            submit_delete = st.form_submit_button("Delete Target Permanently")

            if submit_delete:
                if remove_id > 0:
                    db.remove_target(int(remove_id))
                    st.success(f"Target ID {remove_id} has been completely removed from the system.")
                    st.rerun()
                else:
                    st.warning("Please enter a valid target ID greater than 0.")
    else:
        st.info("No targets yet — add one above.")

    st.markdown("### Recent Findings")
    findings = db.recent_findings(limit=100)
    if findings:
        fdf = pd.DataFrame(findings)[["target", "category", "severity", "summary", "first_seen", "last_seen"]]
        sev_filter = st.multiselect("Filter by severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                                     default=["CRITICAL", "HIGH", "MEDIUM"])
        if sev_filter:
            fdf = fdf[fdf["severity"].isin(sev_filter)]
        st.dataframe(fdf, use_container_width=True)
    else:
        st.info("No findings recorded yet — run a scan or add a target to begin.")

    st.markdown("### Recent Scan Runs")
    runs = db.recent_scan_runs(limit=20)
    if runs:
        rdf = pd.DataFrame(runs)[["target", "started_at", "status", "new_findings_count", "error"]]
        st.dataframe(rdf, use_container_width=True)
    else:
        st.info("No scan runs recorded yet.")


def main():
    st.set_page_config(
        page_title="MHZALY Purple Team Operations Suite",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Modern SaaS Dark Glassmorphism Styling Injection
    st.markdown("""
        <style>
        .stApp { background-color: #0b0f19; color: #f3f4f6; font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        [data-testid="stSidebar"] { background-color: #111827; border-right: 1px solid #1f2937; }
        .saas-card { background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(75, 85, 99, 0.3); border-radius: 12px; padding: 20px; backdrop-filter: blur(12px); margin-bottom: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4); }
        .stButton>button { background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); color: white; border: none; border-radius: 8px; font-weight: 600; padding: 0.5rem 1rem; transition: all 0.3s ease; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }
        .stButton>button:hover { background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%); box-shadow: 0 6px 16px rgba(59, 130, 246, 0.5); transform: translateY(-1px); }
        .stButton>button:disabled { opacity: 0.4; box-shadow: none; transform: none; }
        [data-testid="stMetric"] { background: rgba(17, 24, 39, 0.8); border: 1px solid rgba(59, 130, 246, 0.2); padding: 16px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.3); }
        [data-testid="stMetricLabel"] { color: #9ca3af !important; font-weight: 500; }
        [data-testid="stMetricValue"] { color: #60a5fa !important; font-weight: 700; }
        .stTextInput>div>div>input, .stTextArea>div>div>textarea { background-color: #1f2937; color: #f3f4f6; border: 1px solid #374151; border-radius: 8px; }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus { border-color: #3b82f6; box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2); }
        h1, h2, h3 { color: #f9fafb; font-weight: 700; letter-spacing: -0.025em; }
        </style>
    """, unsafe_allow_html=True)

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    if 'login_locked_until' not in st.session_state:
        st.session_state.login_locked_until = 0.0

    if not st.session_state.authenticated:
        col1, col2, col3 = st.columns([1, 1.2, 1])
        with col2:
            st.markdown("<br><br>", unsafe_allow_html=True)
            st.markdown("""
                <div class="saas-card" style="text-align: center;">
                    <h2>MHZALY SaaS Portal</h2>
                    <p style="color: #9ca3af;">Enterprise Purple Team Operations Suite</p>
                </div>
            """, unsafe_allow_html=True)

            correct_user = st.secrets.get("APP_USERNAME", None)
            correct_pass = st.secrets.get("APP_PASSWORD", None)
            if not correct_user or not correct_pass:
                st.error(
                    "APP_USERNAME / APP_PASSWORD are not set in Streamlit secrets. "
                    "Refusing to fall back to a default credential — set both secrets to enable login."
                )
                return

            now = time.time()
            if now < st.session_state.login_locked_until:
                remaining = int(st.session_state.login_locked_until - now)
                st.warning(f"Too many failed attempts. Try again in {remaining}s.")
                return

            username = st.text_input("Operator Username")
            password = st.text_input("Operator Password", type="password")

            if st.button("Authenticate Suite", use_container_width=True):
                # Constant-time comparison to avoid timing side-channels on the password check
                user_ok = hmac.compare_digest(username, correct_user)
                pass_ok = hmac.compare_digest(password, correct_pass)
                if user_ok and pass_ok:
                    st.session_state.authenticated = True
                    st.session_state.user = username
                    st.session_state.login_attempts = 0
                    st.success("Authentication successful. Initializing SaaS modules...")
                    st.rerun()
                else:
                    st.session_state.login_attempts += 1
                    if st.session_state.login_attempts >= 5:
                        st.session_state.login_locked_until = time.time() + 60
                        st.session_state.login_attempts = 0
                        st.error("Too many failed attempts. Locked for 60 seconds.")
                    else:
                        st.error("Authentication failed: Invalid credentials.")
        return

    # Auto-logout idle operators. Timeout is configurable via secrets so a
    # deployment can tighten/loosen it without a code change; defaults to
    # DEFAULT_SESSION_TIMEOUT_MINUTES if unset.
    session_timeout_minutes = int(st.secrets.get("SESSION_TIMEOUT_MINUTES", DEFAULT_SESSION_TIMEOUT_MINUTES))
    if not enforce_session_timeout(session_timeout_minutes):
        return

    max_scans_per_day = int(st.secrets.get("MAX_ACTIVE_SCANS_PER_DAY", DEFAULT_MAX_ACTIVE_SCANS_PER_DAY))

    vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
    abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")
    groq_key = st.secrets.get("GROQ_API_KEY", "")
    nvd_key = st.secrets.get("NVD_API_KEY", "")
    shared_cache = get_shared_cache()

    local_db = db

    with st.sidebar:
        st.markdown(f"### Operator: `{st.session_state.user}`")
        st.markdown("---")
        module = st.radio(
            "Purple Team Hub Menu",
            [
                "Command Telemetry Center",
                "Autonomous SOC (Live DB)",
                "Autonomous AI-Agent Red/Blue Pipeline",
                "AI Security Chatbot",
                "Blue Team SOC Log & SIEM Simulator",
                "Automated Sigma Rule Generator",
                "Bug Bounty Recon & Fuzzing",
                "Network Infrastructure Audit",
                "Enterprise NVD Intelligence",
                "Threat Intel & IOC Triage",
                "Offensive Encoder & Hasher",
                "Activity History & Logs",
                "Platform Configuration"
            ]
        )
        st.markdown("---")
        if st.button("Terminate Session", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()

    if module == "Command Telemetry Center":
        st.markdown("# Purple Team Operations Center")
        st.markdown("<p style='color: #9ca3af;'>Aggregated telemetry across offensive recon and defensive SOC monitoring.</p>", unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Threat Level", "ELEVATED", "Orange")
        c2.metric("NVD API Key", "Accelerated" if nvd_key else "Standard", "NIST v2.0")
        c3.metric("Groq AI Engine", "Online" if groq_key else "Offline", "openai/gpt-oss-120b")
        c4.metric("SQLite DB", "Connected", "Active")

    elif module == "Autonomous SOC (Live DB)":
        render_autonomous_tab()

    elif module == "Autonomous AI-Agent Red/Blue Pipeline":
        st.markdown("# Fully Autonomous AI-Driven Bug Bounty & Purple Team Agent")
        st.markdown("<p style='color: #9ca3af;'>Give target scope. The Autonomous AI Agent takes complete control, performing deep iterative recon, filtering duplicate endpoints/CVEs, executing analysis, and synthesizing professional security assessment reports.</p>", unsafe_allow_html=True)

        pipeline_target = st.text_input("Target Domain, IP Address, or Keyword", placeholder="e.g., target-domain.com or 8.8.8.8")
        strict_cve = st.checkbox("Strict CVE matching (CPE-confirmed only — fewer false positives)", value=True)
        authorized = authorization_gate("pipeline")

        if st.button("Launch Autonomous AI Agent Loop", use_container_width=True, disabled=not authorized):
            validation_error = validate_target_input(pipeline_target) if pipeline_target else "Please specify a target for the autonomous agent."
            quota_error = None
            if not validation_error:
                quota_error = check_and_increment_scan_quota(st.session_state.user, max_scans_per_day)

            if quota_error:
                st.error(quota_error)
            elif validation_error:
                st.warning(validation_error)
            else:
                with st.spinner("Autonomous AI Agent taking full control: running deep recon and deduplication loops..."):
                    local_db.init_db()

                    agent_result = AutonomousAgentExecutor.run_agentic_cycle(pipeline_target, groq_key)

                    if agent_result.get('blocked'):
                        st.error(f"Scan blocked by scope guard: {agent_result.get('block_reason')}")
                    else:
                        ti = ThreatIntelService(vt_key, abuse_key, cache=shared_cache)
                        ti_res = ti.triage_indicator(pipeline_target)

                        clean_target = pipeline_target.replace('https://', '').replace('http://', '').split('/')[0]
                        domain_keyword = clean_target.split('.')[0] if '.' in clean_target else clean_target

                        tech_stack = agent_result.get('technologies', [])
                        # Generic client-side/CDN names are the most likely to
                        # collide with an unrelated vendor's product string in
                        # NVD's own CPE dictionary (see NVDIntelligenceClient
                        # docstring) and rarely have meaningful CVEs of their
                        # own anyway — prefer a more specific, less ambiguous
                        # fingerprinted technology first if one was found.
                        AMBIGUOUS_GENERIC_TECH = {"react", "express", "cloudflare"}
                        specific_techs = [t for t in tech_stack if t.lower() not in AMBIGUOUS_GENERIC_TECH]
                        nvd_query_term = specific_techs[0] if specific_techs else domain_keyword

                        nvd = NVDIntelligenceClient(nvd_key)
                        min_conf = "cpe" if strict_cve else "any"
                        cve_res = nvd.search_cve(nvd_query_term, max_results=8, min_confidence=min_conf)
                        if not cve_res and domain_keyword != nvd_query_term:
                            cve_res = nvd.search_cve(domain_keyword, max_results=8, min_confidence=min_conf)

                        st.success("Autonomous AI Agent execution cycle successfully completed.")

                        top_cvss = max([v.cvss_score for v in cve_res], default=0.0)

                        # Fold the infra audit (ports/headers) gathered during
                        # the agentic cycle into the aggregate risk score, so
                        # exposed files, missing security headers, and risky
                        # open ports actually move the number instead of only
                        # appearing in the expander below.
                        infra_audit = agent_result.get('infra_audit', {}) or {}
                        exposed_count = len(agent_result.get('exposed_files', []))
                        missing_headers = sum(
                            1 for v in infra_audit.get('headers', {}).values() if v == 'MISSING'
                        )
                        risky_ports = sum(
                            1 for p in infra_audit.get('ports', [])
                            if p.get('port') in RISKY_PUBLIC_PORTS
                        )

                        risk = compute_risk_score(
                            ti_res['vt_summary']['malicious'],
                            ti_res['abuse_summary']['score'],
                            top_cvss,
                            exposed_count=exposed_count,
                            missing_headers=missing_headers,
                            risky_open_ports=risky_ports,
                        )

                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("VT Malicious Detections", ti_res['vt_summary']['malicious'])
                        c2.metric("Abuse Confidence Score", f"{ti_res['abuse_summary']['score']}%")
                        c3.metric("Deduplicated Unique CVEs", len(cve_res))
                        c4.metric("Aggregate Risk Score", f"{risk['score']}/100", risk['band'])

                        with st.expander("🤖 View Live Autonomous Agent Execution Logs"):
                            for log_line in agent_result.get('agent_log', []):
                                st.code(log_line)

                        subdomains = agent_result.get('subdomains', [])
                        if subdomains:
                            with st.expander(f"🌐 Enumerated Subdomains ({len(subdomains)})"):
                                st.dataframe(pd.DataFrame({'subdomain': subdomains}), use_container_width=True)

                        if infra_audit.get('ports') or infra_audit.get('headers'):
                            with st.expander("🔍 Infrastructure Findings (Ports & Security Headers)"):
                                if infra_audit.get('ports'):
                                    st.markdown("**Open Ports:**")
                                    st.dataframe(pd.DataFrame(infra_audit['ports']), use_container_width=True)
                                if infra_audit.get('headers') and 'error' not in infra_audit['headers']:
                                    st.markdown("**Security Headers:**")
                                    for h_name, h_val in infra_audit['headers'].items():
                                        icon = "❌" if h_val == 'MISSING' else "✅"
                                        st.write(f"{icon} **{h_name}:** `{h_val}`")

                        ai_analysis_text = agent_result.get('ai_analysis', "AI analysis skipped.")

                        cve_list_md = "\n".join([
                            f"- **{v.cve_id}** (CVSS: {v.cvss_score} - {v.severity}, match: {v.match_confidence}): {v.description}"
                            for v in cve_res
                        ]) if cve_res else "No high-severity matching CVE entries found."
                        exposed_md = "\n".join([f"- Endpoint: `{ef['path']}` | Status: `{ef['status']}`" for ef in agent_result.get('exposed_files', [])]) if agent_result.get('exposed_files') else "No sensitive endpoints exposed on standard fuzz paths."
                        subdomain_md = "\n".join([f"- `{s}`" for s in subdomains[:30]]) if subdomains else "None discovered via certificate transparency logs."
                        tech_md = ", ".join(tech_stack) if tech_stack else "Custom / Undetected"
                        ports_md = "\n".join([f"- `{p['port']}` ({p['service']})" for p in infra_audit.get('ports', [])]) if infra_audit.get('ports') else "No open ports found on scanned standard ports."
                        headers_md = "\n".join([
                            f"- **{h}:** `{v}`" for h, v in infra_audit.get('headers', {}).items() if h != 'error'
                        ]) if infra_audit.get('headers') else "Not assessed."

                        report_data = {
                            "target": pipeline_target,
                            "operator": st.session_state.user,
                            "timestamp": datetime.now().isoformat(),
                            "risk_score": risk,
                            "threat_intel": ti_res['vt_summary'] | {"abuse": ti_res['abuse_summary']},
                            "technologies": tech_stack,
                            "exposed_files": agent_result.get('exposed_files', []),
                            "subdomains": subdomains,
                            "infra_ports": infra_audit.get('ports', []),
                            "infra_headers": infra_audit.get('headers', {}),
                            "cves": [v.to_dict() for v in cve_res],
                            "ai_analysis": ai_analysis_text,
                        }

                        auto_report_markdown = f"""# MHZALY AUTONOMOUS AI AGENT SECURITY ASSESSMENT REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
* **Target Scope:** `{pipeline_target}`
* **Lead Operator:** `{st.session_state.user} (Autonomous AI Agent Engine)`
* **Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
* **Aggregate Risk Score:** `{risk['score']}/100 ({risk['band']})`
* **Classification:** FULLY AUTOMATED RED/BLUE AGENTIC INTELLIGENCE

## 1. Executive Summary & Autonomous Recon Overview
Autonomous AI Agent intelligence gathering was completed against `{pipeline_target}` with duplicate filtering enabled.
- **VirusTotal Malicious Count:** `{ti_res['vt_summary']['malicious']}`
- **AbuseIPDB Score:** `{ti_res['abuse_summary']['score']}%`
- **Unique Detected Technologies:** `{tech_md}`

## 2. Threat Intelligence & Reputation Triage
### VirusTotal Telemetry
- **Harmless Engines:** `{ti_res['vt_summary']['harmless']}`
- **Community Reputation:** `{ti_res['vt_summary']['reputation']}`
- **ASN / Owner:** `{ti_res['vt_summary']['registrar']}`

### AbuseIPDB Telemetry
- **Reports Count:** `{ti_res['abuse_summary']['reports']}`
- **Country Code:** `{ti_res['abuse_summary']['country']}`
- **ISP:** `{ti_res['abuse_summary']['isp']}`

## 3. Deduplicated Attack Surface Discovery & Exposed Endpoints
- **Clean Discovered Endpoints & Files (No Duplicates):**
{exposed_md}

### Enumerated Subdomains (Certificate Transparency)
{subdomain_md}

### Open Ports
{ports_md}

### Security Headers
{headers_md}

## 4. Correlated Unique Vulnerabilities (NIST NVD v2.0 - Deduplicated CVSS >= 4.0)
_Match confidence: **cpe** = confirmed against the CVE's structured product data; **keyword** = description-text hit only, verify manually._
{cve_list_md}

## 5. Autonomous AI Agent Deep Architectural Analysis & Hardening Recommendations
{ai_analysis_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
*Generated via MHZALY Autonomous AI Bug Bounty Platform*
"""

                        st.markdown("---")
                        st.markdown("### Generated Autonomous Agent Report Preview")
                        st.markdown(auto_report_markdown)

                        dl1, dl2, dl3 = st.columns(3)
                        with dl1:
                            st.download_button(
                                label="Download Report (.md)",
                                data=auto_report_markdown,
                                file_name=f"mhzaly_autonomous_agent_report_{pipeline_target.replace('/', '_')}.md",
                                mime="text/markdown",
                                use_container_width=True
                            )
                        with dl2:
                            st.download_button(
                                label="Download Report (.json)",
                                data=json.dumps(report_data, indent=2, default=str),
                                file_name=f"mhzaly_autonomous_agent_report_{pipeline_target.replace('/', '_')}.json",
                                mime="application/json",
                                use_container_width=True
                            )
                        with dl3:
                            # CSV of the CVE findings — the one artifact most
                            # likely to be pasted straight into a ticketing
                            # system or spreadsheet-based tracker, so it gets
                            # its own flat export instead of only living
                            # inside the JSON blob.
                            if cve_res:
                                cve_csv = pd.DataFrame([v.to_dict() for v in cve_res]).to_csv(index=False)
                            else:
                                cve_csv = "cve_id,title,description,severity,cvss_score,vector_string,affected_configurations,published_date,remediation,match_confidence\n"
                            st.download_button(
                                label="Download CVE Findings (.csv)",
                                data=cve_csv,
                                file_name=f"mhzaly_cve_findings_{pipeline_target.replace('/', '_')}.csv",
                                mime="text/csv",
                                use_container_width=True
                            )
        elif not authorized:
            st.caption("Check the authorization box above to enable scanning.")

    elif module == "AI Security Chatbot":
        st.markdown("# AI Security Operations & Bug Bounty Chatbot")
        st.markdown("<p style='color: #9ca3af;'>Ask anything about security, exploit vectors, WAF bypass, or defense strategies. Powered by Groq AI.</p>", unsafe_allow_html=True)

        if "messages" not in st.session_state:
            st.session_state.messages = [
                {"role": "assistant", "content": "Hello operator! I am your MHZALY AI Security Assistant backed by your active API keys. How can I assist your purple team or security operations today?"}
            ]

        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("Ask a security query or request a playbook..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                if not groq_key:
                    response_text = "Error: Groq API Key is not configured in your Streamlit secrets."
                    st.markdown(response_text)
                else:
                    with st.spinner("Analyzing via Groq AI..."):
                        try:
                            response_text = AutonomousAgentExecutor._call_groq(
                                [
                                    {'role': 'system', 'content': 'You are an elite Cybersecurity Expert, Purple Team Mentor, and Red/Blue Team Advisor specializing in security assessments.'},
                                    *[{'role': m['role'], 'content': m['content']} for m in st.session_state.messages]
                                ],
                                groq_key, max_tokens=1500, temperature=0.6,
                            )
                        except Exception as e:
                            response_text = f"Connection failed: {e}"
                    st.markdown(response_text)
            st.session_state.messages.append({"role": "assistant", "content": response_text})

    elif module == "Blue Team SOC Log & SIEM Simulator":
        st.markdown("# Blue Team SOC Log Parsing & Threat Detection Simulator")
        st.markdown("<p style='color: #9ca3af;'>Paste raw server access logs or Windows Event logs below to simulate SIEM parsing and anomaly detection.</p>", unsafe_allow_html=True)

        sample_log = st.text_area("Raw Log Data Input", placeholder="Paste Apache/Nginx access log or Windows Event ID log lines here...", height=150)

        if st.button("Analyze Logs & Detect Anomalies", use_container_width=True):
            if sample_log:
                with st.spinner("Running heuristic parsing and threat detection..."):
                    st.success("Log parsing complete.")

                    lines = [l.strip() for l in sample_log.split('\n') if l.strip()]
                    seen_logs = set()
                    unique_lines = []
                    for l in lines:
                        if l not in seen_logs:
                            seen_logs.add(l)
                            unique_lines.append(l)

                    suspicious_hits = []
                    for idx, line in enumerate(unique_lines, 1):
                        l_lower = line.lower()
                        if any(k in l_lower for k in ['union select', '<script>', 'etc/passwd', 'cmd.exe', '/wpscan', 'sqlmap', 'eval(']):
                            suspicious_hits.append({'line_no': idx, 'content': line, 'indicator': 'Injection / Exploit Pattern'})
                        elif '404' in line or '403' in line:
                            suspicious_hits.append({'line_no': idx, 'content': line, 'indicator': 'Unauthorized / Failed Request'})

                    c1, c2 = st.columns(2)
                    c1.metric("Unique Log Lines Analyzed", len(unique_lines))
                    c2.metric("Detected Anomalies / Hits", len(suspicious_hits))

                    if suspicious_hits:
                        st.markdown("### Detected Security Anomalies")
                        st.dataframe(pd.DataFrame(suspicious_hits), use_container_width=True)
                    else:
                        st.info("No malicious patterns or obvious anomalies detected in the provided log sample.")
            else:
                st.warning("Please paste some log data to analyze.")

    elif module == "Automated Sigma Rule Generator":
        st.markdown("# Automated Sigma Rule & YARA Detection Generator")
        st.markdown("<p style='color: #9ca3af;'>Generate production-ready SIEM detection rules for any CVE, IoC, or attack pattern using Groq AI.</p>", unsafe_allow_html=True)

        cve_input = st.text_input("Enter CVE ID or Attack Description", placeholder="e.g., CVE-2021-44228 or Path Traversal Attack")
        if st.button("Generate Sigma Detection Rule", use_container_width=True):
            if cve_input:
                if not groq_key:
                    st.error("Groq API Key is missing in secrets.")
                else:
                    with st.spinner("Generating professional Sigma detection rule via Groq AI..."):
                        try:
                            sigma_res = AutonomousAgentExecutor._call_groq(
                                [
                                    {'role': 'system', 'content': 'You are a senior Blue Team threat hunter. Generate a valid, production-ready Sigma detection rule in YAML format for the requested vulnerability or threat vector.'},
                                    {'role': 'user', 'content': f"Generate a Sigma rule for: {cve_input}"}
                                ],
                                groq_key, max_tokens=1000, temperature=0.3,
                            )
                            st.code(sigma_res, language='yaml')
                        except Exception as e:
                            st.error(f"Error: {e}")
            else:
                st.warning("Please enter a CVE ID or attack description.")

    elif module == "Bug Bounty Recon & Fuzzing":
        st.markdown("# Target Reconnaissance & Sensitive Endpoint Fuzzing")
        target_input = st.text_input("Target URL or Domain", placeholder="e.g., target-domain.com")
        include_subdomains = st.checkbox("Also enumerate subdomains (crt.sh)", value=True)
        authorized = authorization_gate("recon")

        if st.button("Launch Recon & Asset Discovery", use_container_width=True, disabled=not authorized):
            validation_error = validate_target_input(target_input) if target_input else "Please specify a target domain or URL."
            quota_error = check_and_increment_scan_quota(st.session_state.user, max_scans_per_day) if not validation_error else None

            if quota_error:
                st.error(quota_error)
            elif validation_error:
                st.warning(validation_error)
            else:
                with st.spinner(f"Executing deep offensive reconnaissance on {target_input}..."):
                    recon = BugBountyReconEngine.deep_recon(target_input)

                    if recon.get('blocked'):
                        st.error(f"Scan blocked by scope guard: {recon.get('error')}")
                    else:
                        st.success("Reconnaissance cycle complete.")

                        c1, c2, c3 = st.columns(3)
                        c1.metric("HTTP Status", recon.get('status_code', 'N/A'))
                        c2.metric("Web Server Banner", recon.get('server', 'N/A'))
                        c3.metric("Exposed Endpoints", len(recon.get('exposed_files', [])))

                        st.markdown("### Authoritative DNS Records")
                        for rtype, recs in recon.get('dns', {}).items():
                            if recs:
                                st.markdown(f"**{rtype} Records:**")
                                for r in recs:
                                    st.code(r)

                        st.markdown("### Fingerprinted Technology Stack")
                        techs = recon.get('technologies', [])
                        if techs:
                            for t in techs:
                                st.markdown(f"- `{t}`")
                        else:
                            st.info("No prominent framework signatures found.")

                        st.markdown("### Exposed Sensitive Endpoints & Backup Files")
                        exposed = recon.get('exposed_files', [])
                        if exposed:
                            st.dataframe(pd.DataFrame(exposed), use_container_width=True)
                        else:
                            st.info("No common sensitive files discovered on standard paths.")

                        if include_subdomains:
                            st.markdown("### Enumerated Subdomains (Certificate Transparency)")
                            subs = SubdomainEnumEngine.enumerate(target_input)
                            if subs:
                                st.dataframe(pd.DataFrame({'subdomain': subs}), use_container_width=True)
                            else:
                                st.info("No subdomains found via crt.sh.")
        elif not authorized:
            st.caption("Check the authorization box above to enable scanning.")

    elif module == "Network Infrastructure Audit":
        st.markdown("# Purple Team Infrastructure Reconnaissance & Audit")
        target_domain = st.text_input("Target Domain or IP Address", placeholder="e.g., scanme.nmap.org")
        authorized = authorization_gate("audit")

        if st.button("Execute Full Infrastructure Audit", use_container_width=True, disabled=not authorized):
            validation_error = validate_target_input(target_domain, allow_url=False) if target_domain else "Please provide a valid target host."
            quota_error = check_and_increment_scan_quota(st.session_state.user, max_scans_per_day) if not validation_error else None

            if quota_error:
                st.error(quota_error)
            elif validation_error:
                st.warning(validation_error)
            else:
                with st.spinner(f"Executing live infrastructure audit against {target_domain}..."):
                    audit_data = AdvancedReconEngine.audit_infrastructure(target_domain)

                    if audit_data.get('blocked'):
                        st.error(f"Scan blocked by scope guard: {audit_data.get('error')}")
                    else:
                        st.success("Infrastructure Audit Completed Successfully.")

                        tab1, tab2, tab3, tab4 = st.tabs(["DNS Records", "Port Scan", "SSL / TLS", "Security Headers"])

                        with tab1:
                            for rtype, recs in audit_data['dns'].items():
                                if recs:
                                    st.markdown(f"**{rtype} Records:**")
                                    for r in recs:
                                        st.code(r)
                        with tab2:
                            ports = audit_data['ports']
                            if ports:
                                st.dataframe(pd.DataFrame(ports), use_container_width=True)
                            else:
                                st.info("No open ports found on scanned standard ports.")
                        with tab3:
                            ssl_res = audit_data['ssl']
                            if ssl_res.get('valid'):
                                st.success("Valid SSL/TLS Certificate Deployed.")
                                st.json(ssl_res['details'])
                            else:
                                st.warning(f"SSL Issue: {ssl_res.get('error', 'Unknown')}")
                        with tab4:
                            headers = audit_data['headers']
                            if 'error' in headers:
                                st.error(f"Error: {headers['error']}")
                            else:
                                for h_name, h_val in headers.items():
                                    icon = "❌" if h_val == 'MISSING' else "✅"
                                    st.write(f"{icon} **{h_name}:** `{h_val}`")
        elif not authorized:
            st.caption("Check the authorization box above to enable scanning.")

    elif module == "Enterprise NVD Intelligence":
        st.markdown("# Enterprise NVD Vulnerability Intelligence")
        keyword = st.text_input("Search Software / Vendor / CVE", placeholder="e.g., apache, wordpress plugin, cve-2024")
        strict_cve = st.checkbox("Strict CVE matching (CPE-confirmed only)", value=False)

        if st.button("Query NVD Database", use_container_width=True):
            if keyword:
                with st.spinner("Fetching CVE telemetry from NIST NVD..."):
                    client = NVDIntelligenceClient(nvd_key)
                    vulns = client.search_cve(keyword, min_confidence="cpe" if strict_cve else "any")

                    if vulns:
                        st.success(f"Retrieved {len(vulns)} unique CVE records.")
                        for v in vulns:
                            with st.expander(f"{v.cve_id} | Severity: {v.severity} | CVSS: {v.cvss_score} | Match: {v.match_confidence}"):
                                st.markdown(f"**Published:** {v.published_date}")
                                st.markdown(f"**Vector:** `{v.vector_string}`")
                                st.write(v.description)
                                st.markdown(f"**Remediation:** {v.remediation}")
                    else:
                        st.info("No matching records found in NVD.")
            else:
                st.warning("Please enter a search keyword.")

    elif module == "Threat Intel & IOC Triage":
        st.markdown("# Live Threat Intelligence & IOC Triage")
        st.markdown("<p style='color: #9ca3af;'>Analyze IP addresses, domains, or URLs against VirusTotal and AbuseIPDB feeds with granular parsing.</p>", unsafe_allow_html=True)

        indicator = st.text_input("Enter Indicator (IP Address, Domain, or URL)", placeholder="e.g., 8.8.8.8 or example.com")

        if st.button("Run Threat Triage Analysis", use_container_width=True):
            if indicator:
                with st.spinner(f"Querying threat intelligence feeds for `{indicator}`..."):
                    ti = ThreatIntelService(vt_key, abuse_key, cache=shared_cache)
                    report = ti.triage_indicator(indicator)
                    st.success("Triage Analysis Complete.")

                    st.markdown("---")
                    col_vt, col_abuse = st.columns(2)

                    with col_vt:
                        st.subheader("VirusTotal Security Telemetry")
                        vt_sum = report['vt_summary']
                        if 'error' in vt_sum:
                            st.error(vt_sum['error'])
                        else:
                            m_count = vt_sum['malicious']
                            s_count = vt_sum['suspicious']
                            h_count = vt_sum['harmless']

                            st.metric("Malicious Detections", m_count, delta="Threat Flag" if m_count > 0 else "Clean", delta_color="inverse" if m_count > 0 else "normal")
                            st.metric("Suspicious Flags", s_count)
                            st.metric("Harmless Engines", h_count)
                            st.metric("Community Reputation Score", vt_sum['reputation'])
                            st.write(f"**Owner / Registrar / ASN:** `{vt_sum['registrar']}`")

                            with st.expander("View Full VirusTotal Raw JSON"):
                                st.json(report['vt_raw'])

                    with col_abuse:
                        st.subheader("AbuseIPDB Reputation Telemetry")
                        abuse_sum = report['abuse_summary']
                        if 'error' in abuse_sum:
                            st.error(abuse_sum['error'])
                        elif 'info' in abuse_sum:
                            st.info(abuse_sum['info'])
                        else:
                            score = abuse_sum['score']
                            reports = abuse_sum['reports']

                            st.metric("Abuse Confidence Score", f"{score}%", delta="High Risk" if score > 50 else "Low Risk", delta_color="inverse" if score > 50 else "normal")
                            st.metric("Total Abuse Reports", reports)
                            st.write(f"**Country Location:** `{abuse_sum['country']}`")
                            st.write(f"**ISP / Network:** `{abuse_sum['isp']}`")
                            st.write(f"**Last Reported:** `{abuse_sum['lastReported']}`")

                            with st.expander("View Full AbuseIPDB Raw JSON"):
                                st.json(report['abuse_raw'])
            else:
                st.warning("Please provide a valid indicator.")

    elif module == "Offensive Encoder & Hasher":
        st.markdown("# Payload Encoder, Decoder & Hasher")
        input_text = st.text_input("Input String / Payload", placeholder="Enter text to encode, decode, or hash...")

        col_enc1, col_enc2 = st.columns(2)
        with col_enc1:
            if st.button("Base64 Encode", use_container_width=True):
                if input_text:
                    encoded = base64.b64encode(input_text.encode()).decode()
                    st.code(encoded)
            if st.button("URL Encode", use_container_width=True):
                if input_text:
                    encoded = urllib.parse.quote(input_text)
                    st.code(encoded)
        with col_enc2:
            if st.button("Base64 Decode", use_container_width=True):
                if input_text:
                    try:
                        decoded = base64.b64decode(input_text.encode()).decode()
                        st.code(decoded)
                    except Exception as e:
                        st.error(f"Decoding error: {e}")
            if st.button("Generate Hashes (MD5 / SHA256)", use_container_width=True):
                if input_text:
                    md5_h = hashlib.md5(input_text.encode()).hexdigest()
                    sha_h = hashlib.sha256(input_text.encode()).hexdigest()
                    st.markdown(f"**MD5:** `{md5_h}`")
                    st.markdown(f"**SHA256:** `{sha_h}`")

    elif module == "Activity History & Logs":
        st.markdown("# Activity History & SQLite Audit Logs")
        local_db.init_db()
        history = local_db.recent_scan_runs(limit=50)
        if history:
            st.dataframe(pd.DataFrame(history), use_container_width=True)
        else:
            st.info("No recorded activity logs found in shared scheduler database.")

    elif module == "Platform Configuration":
        st.markdown("# Platform Telemetry & API Status")
        st.write(f"**NVD API Key:** {'Accelerated' if nvd_key else 'Standard'}")
        st.write(f"**VirusTotal API:** {'Active' if vt_key else 'Missing'}")
        st.write(f"**AbuseIPDB API:** {'Active' if abuse_key else 'Missing'}")
        st.write(f"**Groq AI Agent Engine:** {'Active (openai/gpt-oss-120b)' if groq_key else 'Missing'}")
        st.write("**SQLite Shared Database (`mhzaly_soc.db`):** Initialized")
        st.write(f"**Auth Credentials Configured:** {'Yes' if st.secrets.get('APP_USERNAME') and st.secrets.get('APP_PASSWORD') else 'No — set APP_USERNAME/APP_PASSWORD in secrets'}")

if __name__ == "__main__":
    main()
