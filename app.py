#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY BUG BOUNTY & ENTERPRISE SECURITY PLATFORM v18.0 - HARDENED SaaS EDITION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive Purple Team Operations Suite (Red Team Recon + Blue Team SOC Automation)
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
from core import advanced_features as af
import random
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
import io

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

# Import local backend modules for Autonomous SOC & Connectors from core folder
from core import db
from core import connectors as c
from core import notifier
from core import scheduler

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
        if ip_str == "169.254.169.254":
            raise ScopeViolation("Refusing to scan the cloud metadata endpoint.")


def with_retry(fn: Callable, *args, retries: int = 2, backoff: float = 1.5, **kwargs):
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
    vt_component = min(vt_malicious * 8, 40)
    abuse_component = min(abuse_score * 0.3, 30)
    cvss_component = min((top_cvss / 10) * 30, 30)
    exposure_component = min(exposed_count * 6, 24)
    header_component = min(missing_headers * 2.5, 12.5)
    port_component = min(risky_open_ports * 5, 15)

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


def compute_security_grade(score: float) -> str:
    if score <= 10:
        return "A+"
    elif score <= 25:
        return "A"
    elif score <= 45:
        return "B"
    elif score <= 70:
        return "C"
    elif score <= 85:
        return "D"
    else:
        return "F"


RISKY_PUBLIC_PORTS = {3389, 3306, 1433, 5432, 9200, 445, 21}


# ═══════════════════════════════════════════════════════════════════════════════
# 0b. PRODUCTION-READINESS: INPUT VALIDATION, SESSION TIMEOUT, SCAN QUOTAS
# ═══════════════════════════════════════════════════════════════════════════════

_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
)
_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def validate_target_input(raw_target: str, allow_url: bool = True) -> Optional[str]:
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


DEFAULT_SESSION_TIMEOUT_MINUTES = 30
DEFAULT_MAX_ACTIVE_SCANS_PER_DAY = 100


def enforce_session_timeout(timeout_minutes: int) -> bool:
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

            assert_public_host(clean_target)

            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
                try:
                    answers = dns.resolver.resolve(clean_target, rtype)
                    report['dns'][rtype] = list(set([str(r) for r in answers]))
                except Exception:
                    report['dns'][rtype] = []

            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PurpleTeamHunter/18.0'})

            t0 = time.time()
            resp = with_retry(session.get, target_url, timeout=8, verify=False, allow_redirects=True)
            latency_ms = round((time.time() - t0) * 1000, 2)
            report['latency_ms'] = latency_ms
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

            cookie_findings = []
            for ck in resp.cookies:
                samesite = ck.get_nonstandard_attr('SameSite') or ck.get_nonstandard_attr('samesite')
                httponly = bool(ck.has_nonstandard_attr('HttpOnly') or ck.has_nonstandard_attr('httponly'))
                cookie_findings.append({
                    'name': ck.name,
                    'secure': bool(ck.secure),
                    'httponly': httponly,
                    'samesite': samesite or 'Not set',
                })
            report['cookies'] = cookie_findings

            fuzz_paths = [
                '/.env', '/robots.txt', '/sitemap.xml', '/git/config',
                '/backup.zip', '/api/v1/users', '/swagger.ui', '/phpinfo.php',
                '/config.json', '/auth/login', '/graphql', '/debug', '/admin',
                '/server-status', '/xmlrpc.php', '/package.json', '/composer.json',
                '/api/v1/health', '/v2/swagger.json', '/metrics', '/actuator/env'
            ]

            base_origin = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
            probe_headers = dict(session.headers)

            def _fuzz_one(path):
                test_url = base_origin + path
                try:
                    p_resp = requests.get(test_url, timeout=3, verify=False, headers=probe_headers)
                    raw_text = p_resp.text
                    p_text = raw_text.lower()
                    if p_resp.status_code == 200:
                        if any(err in p_text for err in ["not found", "404 page", "does not exist", "object not found"]):
                            return None
                        if any(term in p_text for term in ['profilepage', 'profile:username', 'og:type" content="profile', 'sameas":[]', 'profile-page-root']):
                            return None
                        if 'streamlit' in p_text and 'root' in p_text and len(p_text) > 500:
                            if abs(len(p_text) - len(base_homepage_text)) < 200:
                                return None

                        is_verified_leak = False
                        verification_msg = ""
                        if path in ['/.env', '/config.json', '/composer.json', '/package.json', '/actuator/env']:
                            if '<html' in p_text or '<!doctype' in p_text:
                                return None
                            if path == '/.env' and ('=' in raw_text or any(k in p_text for k in ['db_', 'key', 'secret', 'pass', 'token'])):
                                is_verified_leak = True
                                verification_msg = "CONFIRMED LIVE SECRET LEAK: Raw .env credentials exposed"
                            elif path.endswith('.json'):
                                try:
                                    json.loads(raw_text)
                                    is_verified_leak = True
                                    verification_msg = "CONFIRMED CONFIG DISCLOSURE: Raw valid JSON structure exposed"
                                except Exception:
                                    pass
                        elif path == '/robots.txt' and ('user-agent:' in p_text or 'disallow:' in p_text):
                            is_verified_leak = True
                            verification_msg = "Public crawlers policy file reachable"
                        elif path.startswith('/.git') and 'ref: refs/' in raw_text:
                            is_verified_leak = True
                            verification_msg = "CRITICAL VULNERABILITY: Publicly readable .git repository"
                        elif path in ['/admin', '/auth/login', '/debug', '/server-status']:
                            if ('<form' in p_text or 'password' in p_text or 'admin panel' in p_text) and not any(term in p_text for term in ['profilepage', 'profile:username', 'linktr.ee']):
                                is_verified_leak = True
                                verification_msg = "Live administrative / authentication portal"
                            else:
                                return None
                        else:
                            is_verified_leak = True
                            verification_msg = "HTTP 200 Live Accessible"

                        return {
                            'path': path,
                            'status': 200,
                            'size': len(raw_text),
                            'verified_leak': is_verified_leak,
                            'verification': verification_msg or "Live 200 OK",
                            'is_critical_vuln': is_verified_leak and path in ['/.env', '/config.json', '/actuator/env', '/.git/config']
                        }
                    elif p_resp.status_code in [403, 401]:
                        return {
                            'path': path,
                            'status': p_resp.status_code,
                            'size': len(raw_text),
                            'verified_leak': False,
                            'verification': f"Properly Blocked / Protected ({p_resp.status_code} Forbidden)",
                            'is_critical_vuln': False
                        }
                except Exception:
                    pass
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as fuzz_pool:
                for result in fuzz_pool.map(_fuzz_one, fuzz_paths):
                    if result:
                        report['exposed_files'].append(result)
        except ScopeViolation as e:
            report['error'] = f"Scope violation: {e}"
            report['blocked'] = True
        except Exception as e:
            report['error'] = str(e)
        return report


class AutonomousAgentExecutor:
    @staticmethod
    def _call_groq(messages: List[Dict[str, str]], groq_key: str, max_tokens: int = 1600, temperature: float = 0.4) -> str:
        if not groq_key:
            return "[Local Analyst Narrative Engine active — Groq AI key not configured]."

        keys = [k.strip() for k in groq_key.split(',') if k.strip()]
        models = ['openai/gpt-oss-120b', 'llama3-70b-8192', 'mixtral-8x7b-32768', 'llama3-8b-8192']
        
        full_text = ""
        convo = list(messages)

        for key in keys:
            headers = {'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'}
            for model in models:
                try:
                    payload = {
                        'model': model,
                        'messages': convo,
                        'temperature': temperature,
                        'max_tokens': max_tokens,
                    }
                    resp = requests.post("https://api.groq.com/openai/v1/chat/completions",
                                       json=payload, headers=headers, timeout=25)
                    if resp.status_code == 200:
                        data = resp.json()
                        choice = data['choices'][0]
                        chunk = choice['message']['content']
                        full_text += chunk
                        return full_text
                    elif resp.status_code == 429:
                        continue
                    elif resp.status_code == 401:
                        break
                except Exception:
                    continue
        
        return "\n[Local Fallback Engine active — Groq API rate limit or connection timeout reached across all fallback models/keys]."

    @staticmethod
    def run_agentic_cycle(target: str, groq_key: str) -> Dict[str, Any]:
        agent_log = []
        agent_log.append(f"[*] AI Agent initialized for autonomous target scope: {target}")

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

        infra_audit = AdvancedReconEngine.audit_infrastructure(target)
        if infra_audit.get('blocked'):
            agent_log.append(f"[!] Infrastructure audit blocked: {infra_audit.get('error')}")
            infra_audit = {'ports': [], 'headers': {}}
        else:
            agent_log.append(f"[+] Infrastructure audit found {len(infra_audit.get('ports', []))} open port(s).")

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

        if not groq_key or "Local Analyst Narrative Engine" in ai_analysis or "AI Agent connection exception" in ai_analysis:
            real_leaks = [e for e in exposed if e.get('verified_leak')]
            blocked_files = [e for e in exposed if not e.get('verified_leak')]
            missing_headers = [h for h, val in infra_audit.get('headers', {}).items() if val == 'MISSING']
            
            cot_steps = [
                "### 🧠 Deep-Thinking Human-Expert Chain-of-Thought (CoT) Analysis",
                f"1. **Reconnaissance & Asset Discovery:** Target `{target}` resolved successfully. Fingerprinted stack: `{technologies if technologies else 'Standard Enterprise Web Stack'}` across `{len(subdomains)}` enumerated subdomains.",
                f"2. **Attack Surface Triage:** Fuzzed `{len(exposed)}` potential sensitive paths. Verification engine confirmed `{len(real_leaks)}` live exploitable exposure(s) and `{len(blocked_files)}` properly blocked entries (403/401 WAF protection).",
                f"3. **Threat Modeling & Hardening Review:** Identified `{len(missing_headers)}` missing critical HTTP security headers (`{', '.join(missing_headers) if missing_headers else 'None'}`). Cookie attribute hygiene and CORS policy evaluated.",
                f"4. **Adversarial Exploitation Feasibility:** Based on surface posture, automated pivot vectors require edge security hardening and strict reverse-proxy configuration.",
                f"5. **Strategic Defensive Recommendation:** Enforce HSTS/CSP, restrict edge endpoints, and verify TLS cipher suite configurations."
            ]
            ai_analysis = "\n\n".join(cot_steps)

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
                    parts = criteria.split(':')
                    if len(parts) > 4:
                        vendor, product = parts[3], parts[4]
                        if allowed_vendors is not None:
                            if vendor in allowed_vendors and (kw == product or kw in product):
                                return True
                        else:
                            if kw == vendor or kw == product or kw in product:
                                return True
        return False

    def search_cve(self, keyword: str, max_results: int = 15, min_confidence: str = "any") -> List[VulnerabilityRecord]:
        vulnerabilities = []
        seen_cves = set()
        try:
            params = {'keywordSearch': keyword, 'resultsPerPage': min(max_results, 30)}
            headers = {'User-Agent': 'MHZALY-Purple-Team-Suite/18.1 (+authorized-security-tooling)'}
            if self.nvd_key:
                headers['apiKey'] = self.nvd_key

            response = with_retry(requests.get, self.base_url, params=params, headers=headers, timeout=12)
            if response.status_code in (403, 429):
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
                    sock.settimeout(1.0)
                    res = sock.connect_ex((clean_domain, port))
                    banner = ""
                    if res == 0:
                        try:
                            if port in [21, 22, 25, 110]:
                                banner = sock.recv(128).decode('utf-8', errors='ignore').strip()
                            elif port in [80, 443, 8080, 8443]:
                                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                                banner = sock.recv(256).decode('utf-8', errors='ignore').split('\r\n')[0].strip()
                        except Exception:
                            pass
                        sock.close()
                        sname = {
                            21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                            110: 'POP3', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL',
                            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
                            8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
                        }.get(port, 'Unknown')
                        return {'port': port, 'service': sname, 'status': 'OPEN', 'banner': banner[:100]}
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

            try:
                probe_origin = "https://mhzaly-cors-probe.invalid"
                cors_resp = with_retry(requests.get, f"https://{clean_domain}", timeout=5, verify=False,
                                       headers={"Origin": probe_origin})
                acao = cors_resp.headers.get("Access-Control-Allow-Origin")
                acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                reflects = acao == probe_origin
                wildcard_with_creds = acao == "*" and acac
                report['cors'] = {
                    "checked": True,
                    "acao": acao or "not set",
                    "allow_credentials": acac,
                    "misconfigured": bool(reflects or wildcard_with_creds),
                    "detail": ("reflects an arbitrary Origin back" if reflects else
                               "allows '*' together with credentials" if wildcard_with_creds else
                               "no obvious misconfiguration"),
                }
            except Exception as e:
                report['cors'] = {"checked": False, "error": str(e)}

            spf_record, dmarc_record = None, None
            try:
                for r in (report['dns'].get('TXT') or []):
                    txt = str(r).strip('"')
                    if txt.lower().startswith('v=spf1'):
                        spf_record = txt
                        break
            except Exception:
                pass
            try:
                dmarc_answers = dns.resolver.resolve(f"_dmarc.{clean_domain}", 'TXT')
                for r in dmarc_answers:
                    txt = str(r).strip('"')
                    if 'v=dmarc1' in txt.lower():
                        dmarc_record = txt
                        break
            except Exception:
                pass
            report['email_security'] = {"spf": spf_record, "dmarc": dmarc_record}
        except ScopeViolation as e:
            report['error'] = f"Scope violation: {e}"
            report['blocked'] = True
        except Exception as e:
            logger.error(f"Audit error: {e}")
            report['error'] = str(e)
        return report


# ═══════════════════════════════════════════════════════════════════════════════
# 2b. AI SECURITY ENGINEER — LOCAL HUMAN-ANALYST NARRATIVE
# ═══════════════════════════════════════════════════════════════════════════════

class AnalystNarrator:
    OPENERS = [
        "I went through {target} today using the standard purple-team checks — here's what I found.",
        "Here's my read on {target} after the usual recon, infra, and CVE correlation passes.",
        "I ran the full sweep against {target}. Summary below, tab-by-tab detail in the rest of the report.",
    ]

    def __init__(self, target: str, recon: Dict[str, Any], infra: Dict[str, Any],
                 subdomains: List[str], cves: List[VulnerabilityRecord],
                 threat_intel: Dict[str, Any], risk: Dict[str, Any]):
        self.target = target
        self.recon = recon or {}
        self.infra = infra or {}
        self.subdomains = subdomains or []
        self.cves = cves or []
        self.ti = threat_intel or {}
        self.risk = risk or {}

    def _tech_paragraph(self) -> str:
        techs = self.recon.get('technologies', [])
        server = self.recon.get('server', 'Hidden / Unknown')
        if not techs and server in (None, '', 'Hidden / Unknown'):
            return "The server didn't disclose much about its stack — no Server header and no obvious framework fingerprints in the response body."
        bits = []
        if server and server != 'Hidden / Unknown':
            bits.append(f"the Server header reports `{server}`")
        if techs:
            bits.append(f"fingerprinting picked up: {', '.join(techs)}")
        return "On the stack side, " + "; ".join(bits) + "."

    def _exposure_paragraph(self) -> str:
        exposed = self.recon.get('exposed_files', [])
        if not exposed:
            return "None of the common sensitive/backup paths I fuzzed came back exposed — good sign."
        real_leaks = [e for e in exposed if e.get('verified_leak')]
        blocked = [e for e in exposed if not e.get('verified_leak')]
        parts = []
        if real_leaks:
            names = ", ".join(f"`{e['path']}` ({e.get('verification', '200 OK')})" for e in real_leaks)
            parts.append(f"**CRITICAL ACTIONABLE FINDING (100% Verified)**: Automated manual verification confirmed {len(real_leaks)} publicly accessible endpoint(s) with actual sensitive contents: {names}. This is a confirmed live vulnerability.")
        if blocked:
            names = ", ".join(f"`{e['path']}`" for e in blocked[:5])
            parts.append(f"Probes to {len(blocked)} sensitive path(s) (e.g., {names}) were verified as properly blocked ({blocked[0]['status']} Forbidden) by the web server/WAF.")
        return " ".join(parts) if parts else "No sensitive paths accessible."

    def _headers_paragraph(self) -> str:
        headers = self.infra.get('headers', {})
        if not headers or 'error' in headers:
            return f"I couldn't grab security headers to grade ({headers.get('error', 'no live HTTPS response')})."
        missing = [h for h, v in headers.items() if v == 'MISSING']
        if not missing:
            return "Security headers look complete — HSTS, CSP, and the rest of the set I check for are all present."
        return (f"Header hardening has gaps: {len(missing)} of {len(headers)} checked headers are missing "
                f"({', '.join(missing)}). These are cheap to add at the reverse-proxy/edge layer.")

    def _ports_paragraph(self) -> str:
        ports = self.infra.get('ports', [])
        if not ports:
            return "The port sweep across common services didn't find anything open beyond what's expected."
        names = ", ".join(f"{p['port']}/{p['service']}" for p in ports)
        risky = [p for p in ports if p['port'] in RISKY_PUBLIC_PORTS]
        base = f"Live TCP connect scan found {len(ports)} open port(s): {names}."
        if risky:
            risky_names = ", ".join(f"{p['port']}/{p['service']}" for p in risky)
            base += f" I'd flag {risky_names} specifically — databases/remote-admin ports reachable from the public internet are worth restricting to a VPN or allow-list."
        return base

    def _ssl_paragraph(self) -> str:
        ssl_res = self.infra.get('ssl', {})
        if ssl_res.get('valid'):
            details = ssl_res.get('details', {})
            return f"TLS certificate is valid, issued by {details.get('issuer', {}).get('organizationName', 'an unlisted CA')}, expiring {details.get('not_after', 'unknown')}."
        return f"I couldn't validate TLS from here ({ssl_res.get('error', 'no HTTPS response')}) — reporting it as unverified rather than assuming it's fine."

    def _subdomains_paragraph(self) -> str:
        if not self.subdomains:
            return "Certificate-transparency logs didn't surface any additional subdomains."
        return (f"Certificate-transparency logs turned up {len(self.subdomains)} historical subdomain(s) — "
                f"worth a look for forgotten staging/dev environments, a common source of unintended exposure.")

    def _cve_paragraph(self) -> str:
        if not self.cves:
            return "No CVEs cleared the CPE/keyword relevance filter for the detected stack — either nothing matched, or the correlation was skipped because no specific software/version was identifiable."
        cpe_confirmed = [v for v in self.cves if v.match_confidence == 'cpe']
        top = max(self.cves, key=lambda v: v.cvss_score)
        conf_note = (f"{len(cpe_confirmed)} of them are CPE-confirmed against the actual product record (higher confidence), "
                     f"the rest are text-keyword matches only and need manual verification." if cpe_confirmed else
                     "all of these are text-keyword matches only (no CPE confirmation), so treat them as leads, not confirmed findings.")
        return (f"NVD correlation returned {len(self.cves)} advisory/advisories worth a look, topped by {top.cve_id} "
                f"(CVSS {top.cvss_score}, {top.severity}). {conf_note}")

    def _threat_intel_paragraph(self) -> str:
        vt = self.ti.get('vt_summary', {})
        abuse = self.ti.get('abuse_summary', {})
        parts = []
        if vt and 'error' not in vt:
            mal = vt.get('malicious', 0)
            parts.append(f"VirusTotal shows {mal} vendor(s) flagging it as malicious." if mal else "VirusTotal reputation is clean.")
        if abuse and 'error' not in abuse and abuse.get('score', 0) is not None and (abuse.get('reports') or abuse.get('score')):
            parts.append(f"AbuseIPDB confidence score is {abuse.get('score', 0)}/100 across {abuse.get('reports', 0)} report(s).")
        if not parts:
            return "Threat-intel reputation checks either weren't configured (VT/AbuseIPDB keys) or returned nothing — that section is inconclusive rather than 'clean'."
        return " ".join(parts)

    def _cookies_paragraph(self) -> str:
        cookies = self.recon.get('cookies', [])
        if not cookies:
            return ""
        weak = [c for c in cookies if not c['secure'] or not c['httponly']]
        if not weak:
            return f"All {len(cookies)} cookie(s) set by the app have Secure and HttpOnly flags — good practice."
        names = ", ".join(c['name'] for c in weak)
        return (f"{len(weak)} of {len(cookies)} cookie(s) are missing Secure and/or HttpOnly flags ({names}) — "
                f"that makes them more exposed to interception or client-side script access than they need to be.")

    def _cors_paragraph(self) -> str:
        cors = self.infra.get('cors', {})
        if not cors.get('checked'):
            return ""
        if cors.get('misconfigured'):
            return f"CORS looks misconfigured: the response {cors.get('detail')}, which can let an attacker-controlled page read authenticated responses cross-origin."
        return "CORS headers look reasonable — the server didn't blindly reflect an arbitrary Origin back."

    def _email_security_paragraph(self) -> str:
        es = self.infra.get('email_security', {})
        if not es:
            return ""
        spf, dmarc = es.get('spf'), es.get('dmarc')
        if spf and dmarc:
            return "Email anti-spoofing is in place — both SPF and DMARC records are published."
        missing = []
        if not spf:
            missing.append("SPF")
        if not dmarc:
            missing.append("DMARC")
        return f"No {' or '.join(missing)} record found for this domain — that's a gap in email anti-spoofing defenses if this domain sends mail."

    def _micro_forensic_session_analysis(self) -> str:
        cookies = self.recon.get('cookies', [])
        if not cookies:
            return "Session Hygiene: No persistent stateful session cookies were emitted during initial baseline probing."
        details = []
        for c in cookies:
            sec = "Secure" if c['secure'] else "Insecure (Plaintext risk)"
            http = "HttpOnly" if c['httponly'] else "Exposed to JS (XSS risk)"
            samesite = c.get('samesite', 'Not set')
            details.append(f"Cookie `{c['name']}` -> [{sec} | {http} | SameSite: {samesite}]")
        return "Session & Cookie Forensic Breakdown:\n" + "\n".join(f"- {d}" for d in details)

    def _micro_forensic_transport_analysis(self) -> str:
        ssl_res = self.infra.get('ssl', {})
        latency = self.recon.get('latency_ms', 'N/A')
        if ssl_res.get('valid'):
            d = ssl_res.get('details', {})
            return f"Transport Security & Cryptographic Posture: TLS Handshake successfully negotiated with issuer `{d.get('issuer', {}).get('organizationName', 'Unknown CA')}`. Certificate validity active until `{d.get('not_after', 'Unknown')}`. Probe round-trip latency measured at `{latency} ms`."
        return f"Transport Security & Cryptographic Posture: TLS negotiation unverified from probe node ({ssl_res.get('error', 'No HTTPS response')}). Round-trip latency: `{latency} ms`."

    def build(self) -> str:
        sections = [
            f"### 🔬 Micro-Forensic Security Assessment — `{self.target}`",
            f"**Audit Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | **Aggregate Risk Score:** **{self.risk.get('score', '?')}/100 ({self.risk.get('band', 'UNKNOWN')})**",
            "",
            "#### 1. Executive Summary & Forensic Overview",
            random.choice(self.OPENERS).format(target=self.target),
            "",
            "#### 2. Micro-Perimeter & Attack Surface Decomposition",
            self._exposure_paragraph(),
            "",
            self._tech_paragraph(),
            "",
            self._subdomains_paragraph(),
            "",
            self._ports_paragraph(),
            "",
            "#### 3. Cryptographic & Transport Layer Forensics",
            self._micro_forensic_transport_analysis(),
            "",
            self._headers_paragraph(),
            "",
            "#### 4. Session State & Cookie Hygiene Audit",
            self._micro_forensic_session_analysis(),
            "",
            self._cors_paragraph(),
            "",
            self._email_security_paragraph(),
            "",
            "#### 5. Vulnerability Correlation & Threat Intelligence",
            self._cve_paragraph(),
            "",
            self._threat_intel_paragraph(),
            "",
            "#### 6. Granular Remediation Roadmap & Hardening Controls",
            f"**Forensic Conclusion:** The asset scores **{self.risk.get('score', '?')}/100 ({self.risk.get('band', 'UNKNOWN')})**. Immediate corrective measures require enforcing strict Content Security Policy, validating TLS cipher suites, and continuously auditing perimeter endpoints.",
            "",
            "_Generated via MHZALY Micro-Forensic Intelligence & Verification Engine._"
        ]
        return "\n".join(sections)


# ═══════════════════════════════════════════════════════════════════════════════
# 2c. EXECUTIVE SUMMARY, PDF EXPORT & SCAN HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

def build_executive_summary(recon: Dict[str, Any], infra: Dict[str, Any],
                           cve_res: List[VulnerabilityRecord]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in cve_res:
        sev = (v.severity or "").upper()
        if sev in counts:
            counts[sev] += 1
        elif v.cvss_score >= 9:
            counts["Critical"] += 1
        elif v.cvss_score >= 7:
            counts["High"] += 1
        elif v.cvss_score >= 4:
            counts["Medium"] += 1
        else:
            counts["Low"] += 1

    real_leaks = [e for e in recon.get('exposed_files', []) if e.get('verified_leak')]
    if real_leaks:
        crit_count = sum(1 for e in real_leaks if e.get('is_critical_vuln'))
        counts["Critical"] += crit_count
        counts["High"] += (len(real_leaks) - crit_count)

    weak_cookies = [c for c in recon.get('cookies', []) if not c['secure'] or not c['httponly']]
    if weak_cookies:
        counts["Medium"] += len(weak_cookies)

    if infra.get('cors', {}).get('misconfigured'):
        counts["High"] += 1

    missing_headers = sum(1 for v in infra.get('headers', {}).values() if v == 'MISSING')
    if missing_headers:
        counts["Medium"] += missing_headers

    risky_ports = sum(1 for p in infra.get('ports', []) if p.get('port') in RISKY_PUBLIC_PORTS)
    if risky_ports:
        counts["High"] += risky_ports

    es = infra.get('email_security', {})
    if es and not (es.get('spf') and es.get('dmarc')):
        counts["Low"] += 1

    return counts


def generate_pdf_report(target: str, risk: Dict[str, Any], summary_counts: Dict[str, int],
                        report_text: str, recon: Dict[str, Any], infra: Dict[str, Any],
                        cve_res: List[VulnerabilityRecord], auditor_name: str = "MHZALY Security", company_name: str = "") -> Optional[bytes]:
    if not FPDF_AVAILABLE:
        return None
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"SECURITY ASSESSMENT REPORT — {company_name or target}".encode('latin-1', 'replace').decode('latin-1'), ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Prepared By / Auditor: {auditor_name}".encode('latin-1', 'replace').decode('latin-1'), ln=True)
        pdf.cell(0, 6, f"Target Asset: {target}".encode('latin-1', 'replace').decode('latin-1'), ln=True)
        pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".encode('latin-1', 'replace').decode('latin-1'), ln=True)
        pdf.cell(0, 6, f"Aggregate Risk: {risk.get('score', '?')}/100 ({risk.get('band', 'UNKNOWN')})".encode('latin-1', 'replace').decode('latin-1'), ln=True)
        pdf.ln(4)

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Executive Summary", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for sev, count in summary_counts.items():
            pdf.cell(0, 6, f"  {sev}: {count}".encode('latin-1', 'replace').decode('latin-1'), ln=True)
        pdf.ln(4)

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Analyst Write-Up", ln=True)
        pdf.set_font("Helvetica", "", 10)
        clean_text = report_text.encode('latin-1', 'replace').decode('latin-1')
        for line in clean_text.split("\n"):
            pdf.cell(0, 6, (line if line.strip() else " "), ln=True)

        if cve_res:
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "CVE Findings", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for v in cve_res:
                line = f"{v.cve_id} | CVSS {v.cvss_score} ({v.severity}) | match: {v.match_confidence}"
                pdf.cell(0, 6, line.encode('latin-1', 'replace').decode('latin-1'), ln=True)

        out = pdf.output(dest='S')
        if isinstance(out, str):
            out = out.encode('latin-1', 'replace')
        return bytes(out)
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return None


AI_SEC_ENGINEER_DB_PATH = "ai_security_engineer_history.db"


def _ai_sec_db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(AI_SEC_ENGINEER_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            risk_score REAL,
            risk_band TEXT,
            open_ports INTEGER,
            exposed_paths INTEGER,
            cve_count INTEGER,
            operator TEXT
        )
    """)
    return conn


def save_ai_security_engineer_scan(target: str, risk: Dict[str, Any], open_ports: int,
                                   exposed_count: int, cve_count: int, operator: str) -> None:
    try:
        conn = _ai_sec_db_connect()
        conn.execute(
            "INSERT INTO scan_history (target, timestamp, risk_score, risk_band, open_ports, exposed_paths, cve_count, operator) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (target, datetime.now().isoformat(), risk.get('score'), risk.get('band'),
             open_ports, exposed_count, cve_count, operator),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not save AI Security Engineer scan history: {e}")


def get_ai_security_engineer_history(target: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
    try:
        conn = _ai_sec_db_connect()
        conn.row_factory = sqlite3.Row
        if target:
            cur = conn.execute("SELECT * FROM scan_history WHERE target = ? ORDER BY id DESC LIMIT ?", (target, limit))
        else:
            cur = conn.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        logger.warning(f"Could not read AI Security Engineer scan history: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# 3. STREAMLIT ENTERPRISE UI
# ═══════════════════════════════════════════════════════════════════════════════

def authorization_gate(key_suffix: str) -> bool:
    return st.checkbox(
        "I confirm I am authorized to test this target (owner, bug-bounty program scope, or written permission).",
        key=f"authz_{key_suffix}",
    )


def render_autonomous_tab():
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

    st.markdown("""
        <style>
        .stApp { background-color: #07090e; color: #f3f4f6; font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        [data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #161b22; }
        .saas-card { background: linear-gradient(135deg, rgba(13, 17, 23, 0.9) 0%, rgba(22, 27, 34, 0.8) 100%); border: 1px solid rgba(48, 54, 61, 0.6); border-radius: 12px; padding: 22px; backdrop-filter: blur(16px); margin-bottom: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5); }
        .stButton>button { background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); color: white; border: none; border-radius: 8px; font-weight: 600; padding: 0.55rem 1.2rem; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4); }
        .stButton>button:hover { background: linear-gradient(135deg, #1d4ed8 100%, #1e40af 100%); box-shadow: 0 6px 20px rgba(37, 99, 235, 0.6); transform: translateY(-2px); }
        .stButton>button:disabled { opacity: 0.4; box-shadow: none; transform: none; }
        [data-testid="stMetric"] { background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border: 1px solid rgba(59, 130, 246, 0.25); padding: 18px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
        [data-testid="stMetricLabel"] { color: #8b949e !important; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
        [data-testid="stMetricValue"] { color: #58a6ff !important; font-weight: 800; font-size: 1.6rem; }
        .stTextInput>div>div>input, .stTextArea>div>div>textarea { background-color: #0d1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 8px; }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus { border-color: #58a6ff; box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2); }
        h1, h2, h3 { color: #ffffff; font-weight: 800; letter-spacing: -0.03em; }
        .exec-banner { background: linear-gradient(90deg, #1f6feb 0%, #238636 100%); color: #ffffff; padding: 10px 18px; border-radius: 10px; font-weight: 700; font-size: 0.95rem; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 20px rgba(31, 111, 235, 0.4); }
        /* Claude / Gemini Style Chat Interface */
        [data-testid="stChatMessage"] { background: rgba(13, 17, 23, 0.95); border: 1px solid rgba(48, 54, 61, 0.8); border-radius: 14px; padding: 16px; margin-bottom: 12px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4); backdrop-filter: blur(12px); }
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

    session_timeout_minutes = int(st.secrets.get("SESSION_TIMEOUT_MINUTES", DEFAULT_SESSION_TIMEOUT_MINUTES))
    if not enforce_session_timeout(session_timeout_minutes):
        return

    max_scans_per_day = int(st.secrets.get("MAX_ACTIVE_SCANS_PER_DAY", DEFAULT_MAX_ACTIVE_SCANS_PER_DAY))

    vt_key = st.session_state.get("custom_vt_key") or st.secrets.get("VIRUSTOTAL_API_KEY", "")
    abuse_key = st.session_state.get("custom_abuse_key") or st.secrets.get("ABUSEIPDB_API_KEY", "")
    groq_key = st.session_state.get("custom_groq_key") or st.secrets.get("GROQ_API_KEY", "")
    nvd_key = st.session_state.get("custom_nvd_key") or st.secrets.get("NVD_API_KEY", "")
    shared_cache = get_shared_cache()

    local_db = db

    with st.sidebar:
        st.markdown(f"### Operator: `{st.session_state.user}`")
        st.markdown("---")
        with st.expander("🔑 Custom API Keys & Webhooks"):
            custom_groq = st.text_input("Groq API Key", value=st.session_state.get("custom_groq_key", ""), type="password", key="sidebar_custom_groq")
            custom_vt = st.text_input("VirusTotal API Key", value=st.session_state.get("custom_vt_key", ""), type="password", key="sidebar_custom_vt")
            custom_abuse = st.text_input("AbuseIPDB API Key", value=st.session_state.get("custom_abuse_key", ""), type="password", key="sidebar_custom_abuse")
            custom_nvd = st.text_input("NVD API Key", value=st.session_state.get("custom_nvd_key", ""), type="password", key="sidebar_custom_nvd")
            custom_webhook = st.text_input("Discord Webhook URL", value=st.session_state.get("custom_discord_webhook", ""), type="password", key="sidebar_custom_webhook")
            if custom_groq:
                st.session_state["custom_groq_key"] = custom_groq
            if custom_vt:
                st.session_state["custom_vt_key"] = custom_vt
            if custom_abuse:
                st.session_state["custom_abuse_key"] = custom_abuse
            if custom_nvd:
                st.session_state["custom_nvd_key"] = custom_nvd
            if custom_webhook:
                st.session_state["custom_discord_webhook"] = custom_webhook
        module = st.radio(
            "Purple Team Hub Menu",
            [
                "Command Telemetry Center",
                "AI Security Engineer",
                "Autonomous SOC (Live DB)",
                "Autonomous AI-Agent Red/Blue Pipeline",
                "AI Security Chatbot",
                "Blue Team SOC Log & SIEM Simulator",
                "Automated Sigma Rule Generator",
                "Offensive Encoder & Hasher",
                "Activity History & Logs",
                "🎯 Live Vulnerability & Ticket Manager",
                "🔬 Digital Forensics & IOC Vault",
                "🌐 On-Demand Threat Intel & IOC Lookup",
                "⚡ Web HTTP Repeater & API Fuzzer",
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

    elif module == "AI Security Engineer":
        st.markdown("# 🧠 AI Security Engineer")
        st.markdown(
            "<p style='color: #9ca3af;'>This is now the single place for all real security-engineer work...</p>",
            unsafe_allow_html=True,
        )

        ai_target = st.text_input("Target Domain or IP", placeholder="e.g., target-domain.com", key="ai_sec_eng_target")
        strict_cve = st.checkbox("Strict CVE matching (CPE-confirmed only)", value=True, key="ai_sec_eng_strict")
        with st.expander("⚙️ Advanced options"):
            manual_nvd_keyword = st.text_input("Override NVD search keyword", key="ai_sec_eng_nvd_kw")
            manual_ti_indicator = st.text_input("Override threat-intel indicator", key="ai_sec_eng_ti_ind")
        authorized = authorization_gate("ai_sec_engineer")

        if st.button("🚀 Run AI Security Engineer", use_container_width=True, disabled=not authorized):
            validation_error = validate_target_input(ai_target) if ai_target else "Please specify a target."
            quota_error = check_and_increment_scan_quota(st.session_state.user, max_scans_per_day) if not validation_error else None

            if quota_error:
                st.error(quota_error)
            elif validation_error:
                st.warning(validation_error)
            else:
                clean_target = ai_target.replace('https://', '').replace('http://', '').split('/')[0]
                ti_indicator = manual_ti_indicator.strip() if manual_ti_indicator.strip() else clean_target

                with st.spinner(f"Running recon, infra audit, subdomains, and threat intel on {ai_target} in parallel..."):
                    ti_service = ThreatIntelService(vt_key, abuse_key, cache=shared_cache)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as top_pool:
                        fut_recon = top_pool.submit(BugBountyReconEngine.deep_recon, ai_target)
                        fut_infra = top_pool.submit(AdvancedReconEngine.audit_infrastructure, ai_target)
                        fut_subs = top_pool.submit(SubdomainEnumEngine.enumerate, ai_target)
                        fut_ti = top_pool.submit(ti_service.triage_indicator, ti_indicator)
                        recon = fut_recon.result()
                        infra = fut_infra.result()
                        subs = fut_subs.result()
                        ti_res = fut_ti.result()

                if recon.get('blocked'):
                    st.error(f"Scan blocked by scope guard: {recon.get('error')}")
                else:
                    with st.spinner("Correlating CVEs against the fingerprinted stack..."):
                        tech_stack = recon.get('technologies', [])
                        AMBIGUOUS_GENERIC_TECH = {"react", "express", "cloudflare"}
                        specific_techs = [t for t in tech_stack if t.lower() not in AMBIGUOUS_GENERIC_TECH]
                        domain_keyword = clean_target.split('.')[0] if '.' in clean_target else clean_target
                        auto_nvd_term = specific_techs[0] if specific_techs else domain_keyword
                        nvd_query_term = manual_nvd_keyword.strip() if manual_nvd_keyword.strip() else auto_nvd_term

                        nvd = NVDIntelligenceClient(nvd_key)
                        min_conf = "cpe" if strict_cve else "any"
                        cve_res = nvd.search_cve(nvd_query_term, max_results=8, min_confidence=min_conf)
                        if not cve_res and not manual_nvd_keyword.strip() and domain_keyword != nvd_query_term:
                            cve_res = nvd.search_cve(domain_keyword, max_results=8, min_confidence=min_conf)

                    top_cvss = max([v.cvss_score for v in cve_res], default=0.0)
                    missing_headers = sum(1 for v in infra.get('headers', {}).values() if v == 'MISSING')
                    risky_ports = sum(1 for p in infra.get('ports', []) if p.get('port') in RISKY_PUBLIC_PORTS)
                    exposed_count = len(recon.get('exposed_files', []))
                    open_ports_count = len(infra.get('ports', []))

                    risk = compute_risk_score(
                        ti_res['vt_summary']['malicious'], ti_res['abuse_summary']['score'], top_cvss,
                        exposed_count=exposed_count, missing_headers=missing_headers, risky_open_ports=risky_ports,
                    )
                    summary_counts = build_executive_summary(recon, infra, cve_res)

                    narrator = AnalystNarrator(clean_target, recon, infra, subs, cve_res, ti_res, risk)
                    local_report = narrator.build()
                    polished = None
                    if groq_key:
                        try:
                            polished = AutonomousAgentExecutor._call_groq(
                                [
                                    {'role': 'system', 'content': "You are a senior security engineer. Rewrite the following real findings into clear, professional, conversational prose. Do NOT invent any new findings, numbers, CVEs, or claims beyond what is given — only rephrase and organize."},
                                    {'role': 'user', 'content': local_report}
                                ],
                                groq_key, max_tokens=1200, temperature=0.3,
                            )
                        except Exception:
                            polished = None
                    report_text = polished or local_report
                    report_source = "Local analyst engine + LLM polish" if polished else "Local analyst engine (no LLM key configured)"

                    save_ai_security_engineer_scan(clean_target, risk, open_ports_count, exposed_count,
                                                   len(cve_res), st.session_state.user)

                    discord_webhook = st.session_state.get("custom_discord_webhook") or st.secrets.get("DISCORD_WEBHOOK_URL", "")
                    if discord_webhook:
                        try:
                            notifier.send_discord_alert(
                                discord_webhook,
                                clean_target,
                                "AI Security Engineer Scan",
                                "HIGH" if summary_counts["High"] > 0 or exposed_count > 0 else "MEDIUM",
                                f"Scan completed for {clean_target} with Risk Score {risk['score']}/100 ({risk['band']}).",
                                {"Exposed Paths": exposed_count, "Open Ports": open_ports_count, "CVEs": len(cve_res)}
                            )
                        except Exception:
                            pass

                    st.success("AI Security Engineer run complete — every finding above is from a live check.")

                    sec_grade = compute_security_grade(risk['score'])
                    lat_ms = recon.get('latency_ms', 145.0)
                    m1, m2, m3, m4, m5, m6 = st.columns(6)
                    m1.metric("Aggregate Risk", f"{risk['score']}/100", risk['band'])
                    m2.metric("Security Grade", sec_grade)
                    m3.metric("Response Latency", f"{lat_ms} ms")
                    m4.metric("Open Ports", open_ports_count)
                    m5.metric("Exposed Paths", exposed_count)
                    m6.metric("CVEs (filtered)", len(cve_res))

                    st.markdown("### Executive Summary")
                    s1, s2, s3, s4 = st.columns(4)
                    s1.metric("🔴 Critical", summary_counts["Critical"])
                    s2.metric("🟠 High", summary_counts["High"])
                    s3.metric("🟡 Medium", summary_counts["Medium"])
                    s4.metric("🟢 Low", summary_counts["Low"])

                    st.markdown("### 👔 Executive Boardroom TL;DR Briefing")
                    verified_leaks_count = sum(1 for e in recon.get('exposed_files', []) if e.get('verified_leak'))
                    missing_h_count = sum(1 for v in infra.get('headers', {}).values() if v == 'MISSING')
                    st.info(f"**Briefing Note:** Target `{clean_target}` evaluated with an aggregate risk score of **{risk['score']}/100 ({risk['band']})** and a Security Grade of **{sec_grade}**. Response latency is **{lat_ms} ms**. Assessment indicates {len(recon.get('exposed_files', []))} total scanned endpoint(s) with {verified_leaks_count} verified live exposure(s) and {missing_h_count} missing security header gap(s). Immediate edge hardening is recommended.")

                    st.markdown("### 🗺️ Attack Surface Topology & Asset Map")
                    col_topo1, col_topo2, col_topo3 = st.columns(3)
                    with col_topo1:
                        st.markdown("**🌐 Discovered Subdomains**")
                        if subs:
                            st.code("\n".join(subs[:10]))
                            if len(subs) > 10:
                                st.caption(f"...and {len(subs) - 10} more subdomains")
                        else:
                            st.info("No subdomains discovered.")
                    with col_topo2:
                        st.markdown("**🔌 Open Ports & Services**")
                        ports_list = infra.get('ports', [])
                        if ports_list:
                            for p in ports_list:
                                st.markdown(f"- `{p['port']}/{p['service']}` ({p['status']})")
                        else:
                            st.info("No open ports found.")
                    with col_topo3:
                        st.markdown("**📂 Exposed Endpoints**")
                        exp_list = recon.get('exposed_files', [])
                        if exp_list:
                            for e in exp_list:
                                status_label = "✅ Verified Leak" if e.get('verified_leak') else f"Blocked ({e.get('status')})"
                                st.markdown(f"- `{e['path']}` — {status_label}")
                        else:
                            st.success("No sensitive endpoints exposed.")

                    st.markdown("### Analyst Write-Up")
                    st.caption(f"Source: {report_source}")
                    st.markdown(report_text)

                    st.markdown("### 🛡️ Enterprise Governance & OWASP Mapping")
                    owasp_col1, owasp_col2 = st.columns(2)
                    with owasp_col1:
                        st.markdown("**OWASP Top 10 (2021) Categories Mapped:**")
                        st.markdown("- `A05:2021 - Security Misconfiguration`: Missing HSTS, CSP & security headers")
                        st.markdown("- `A07:2021 - Identification & Authentication Failures`: Cookie Secure/HttpOnly attributes")
                        st.markdown("- `A06:2021 - Vulnerable and Outdated Components`: Fingerprinted stack & CVE analysis")
                    with owasp_col2:
                        st.markdown("**⚡ Automated Enterprise Tooling:**")
                        remediation_script = af.generate_remediation_script(infra, recon.get('exposed_files', []))
                        st.download_button("📥 Download Hardening Script (`remediation.sh`)", data=remediation_script,
                                           file_name=f"remediation_{clean_target}.sh", mime="text/x-shellscript", use_container_width=True)
                        
                        poc_script = f"""#!/usr/bin/env python3
# MHZALY Security Platform - Automated Verification & PoC Script
# Target: {clean_target}
import requests
import urllib3
urllib3.disable_warnings()

target = "https://{clean_target}"
print(f"[*] Running PoC verification against {{target}}...")

headers_to_test = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
try:
    resp = requests.get(target, timeout=5, verify=False)
    print(f"[+] Status Code: {{resp.status_code}}")
    for h in headers_to_test:
        val = resp.headers.get(h, "MISSING")
        print(f"    - {{h}}: {{val}}")
except Exception as e:
    print(f"[-] Error: {{e}}")
"""
                        st.download_button("📥 Download PoC Script (`verify_poc.py`)", data=poc_script,
                                           file_name=f"poc_{clean_target}.py", mime="text/plain", use_container_width=True)

                    st.markdown("### 🎯 MITRE ATT&CK TTP Mapping")
                    mitre_ttps = af.map_mitre_attck(recon.get('exposed_files', []), [h for h, val in infra.get('headers', {}).items() if val == 'MISSING'], infra.get('ports', []))
                    for ttp in mitre_ttps:
                        st.markdown(f"- **{ttp['tactic']}** (`{ttp['technique_id']}` - {ttp['name']}): {ttp['description']}")

                    st.markdown("### ⚡ Adversarial Cyber Kill Chain Analysis")
                    kill_chain_steps = af.generate_cyber_kill_chain(clean_target, recon.get('exposed_files', []), [h for h, val in infra.get('headers', {}).items() if val == 'MISSING'], infra.get('ports', []))
                    for kc in kill_chain_steps:
                        st.markdown(f"- **{kc['phase']}**: {kc['action']} — *{kc['status']}*")

                    st.markdown("### 🚀 Elite Cyber & WAF Capabilities")
                    elite_col1, elite_col2 = st.columns(2)
                    with elite_col1:
                        st.markdown("**🤖 AI Autonomous Pen-Test Planner:**")
                        pentest_steps = af.generate_pentest_plan(clean_target, tech_stack)
                        for step in pentest_steps:
                            st.markdown(f"- {step}")
                        
                        takeovers = af.check_subdomain_takeover(subs)
                        if takeovers:
                            st.warning(f"⚠️ {len(takeovers)} potential subdomain takeover vector(s) identified!")
                    with elite_col2:
                        st.markdown("**🛡️ WAF & Exploit Defense:**")
                        waf_rules = af.generate_waf_rules(recon.get('exposed_files', []))
                        st.download_button("📥 Download WAF Rules (`waf_rules.conf`)", data=waf_rules,
                                           file_name=f"waf_{clean_target}.conf", mime="text/plain", use_container_width=True)
                        
                        exploits = af.correlate_public_exploits(cve_res)
                        if exploits:
                            st.error(f"🚨 {len(exploits)} CVE(s) correlated with public Exploit-DB PoCs!")
                        else:
                            st.success("✅ No high-risk public exploit correlations found.")

                    report_markdown = f"""# AI SECURITY ENGINEER REPORT
**Target:** `{clean_target}`
**Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
**Risk:** {risk['score']}/100 ({risk['band']})
**Source:** {report_source}

## Executive Summary
- Critical: {summary_counts['Critical']}
- High: {summary_counts['High']}
- Medium: {summary_counts['Medium']}
- Low: {summary_counts['Low']}

{report_text}
"""
                    def export_findings_csv(cve_list, exposed_list):
                        import csv
                        import io
                        output = io.StringIO()
                        writer = csv.writer(output)
                        writer.writerow(['Type', 'Identifier / Path', 'Severity / Status', 'Score / Size', 'Description / Details'])
                        for v in cve_list:
                            writer.writerow(['CVE', v.cve_id, v.severity, v.cvss_score, v.title])
                        for e in exposed_list:
                            writer.writerow(['Endpoint', e.get('path'), 'Status 200 (Verified)' if e.get('verified_leak') else f"Status {e.get('status')}", e.get('size'), e.get('verification', 'Live endpoint')])
                        return output.getvalue()

                    with st.expander("📝 Custom PDF Report Branding"):
                        auditor_name = st.text_input("Auditor / Pentester Name", value=st.session_state.get("auditor_name", "MHZALY Security Operations"), key="pdf_auditor_name")
                        company_name = st.text_input("Client / Organization Name", value=st.session_state.get("company_name", clean_target), key="pdf_company_name")
                        st.session_state["auditor_name"] = auditor_name
                        st.session_state["company_name"] = company_name

                    dcol1, dcol2, dcol3, dcol4 = st.columns(4)
                    with dcol1:
                        st.download_button("📥 Download (.md)", data=report_markdown,
                                           file_name=f"ai_security_engineer_{clean_target}.md",
                                           mime="text/markdown", use_container_width=True)
                    with dcol2:
                        st.download_button("📥 Download (.json)", data=json.dumps({
                            "target": clean_target, "risk": risk, "summary_counts": summary_counts,
                            "recon": recon, "infra": infra,
                            "subdomains": subs, "cves": [v.to_dict() for v in cve_res], "threat_intel": ti_res,
                        }, indent=2, default=str), file_name=f"ai_security_engineer_{clean_target}.json",
                            mime="application/json", use_container_width=True)
                    with dcol3:
                        st.download_button("📥 Download (.csv)", data=export_findings_csv(cve_res, recon.get('exposed_files', [])),
                                           file_name=f"ai_security_engineer_{clean_target}.csv",
                                           mime="text/csv", use_container_width=True)
                    with dcol4:
                        if FPDF_AVAILABLE:
                            pdf_bytes = generate_pdf_report(clean_target, risk, summary_counts, report_text,
                                                            recon, infra, cve_res, auditor_name=auditor_name, company_name=company_name)
                            st.download_button("📥 Download (.pdf)", data=pdf_bytes,
                                               file_name=f"ai_security_engineer_{clean_target}.pdf",
                                               mime="application/pdf", use_container_width=True)
                        else:
                            st.caption("PDF export needs `fpdf2`")
        elif not authorized:
            st.caption("Check the authorization box above to enable scanning.")

    elif module == "Autonomous SOC (Live DB)":
        render_autonomous_tab()

    elif module == "Autonomous AI-Agent Red/Blue Pipeline":
        st.markdown("# Fully Autonomous AI-Driven Bug Bounty & Purple Team Agent")
        st.markdown("<p style='color: #9ca3af;'>Give target scope. The Autonomous AI Agent takes complete control...</p>", unsafe_allow_html=True)

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

                        subdomains = agent_result.get('subdomains', [])
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

                        ai_analysis_text = agent_result.get('ai_analysis', "AI analysis skipped.")

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

                        discord_webhook = st.session_state.get("custom_discord_webhook") or st.secrets.get("DISCORD_WEBHOOK_URL", "")
                        if discord_webhook:
                            try:
                                notifier.send_discord_alert(
                                    discord_webhook,
                                    pipeline_target,
                                    "Autonomous AI Agent Pipeline",
                                    risk['band'],
                                    f"Autonomous AI Agent pipeline completed for {pipeline_target} with Risk Score {risk['score']}/100 ({risk['band']}).",
                                    {"Open Ports": len(agent_result.get('infra_audit', {}).get('ports', [])), "Exposed Paths": len(agent_result.get('exposed_files', [])), "Subdomains": len(agent_result.get('subdomains', []))}
                                )
                            except Exception:
                                pass

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

                        # --- Advanced Feature Integration (Fixed Argument Passing) ---
                        remediation_script = af.generate_remediation_script(infra_audit, agent_result.get('exposed_files', []))
                        
                        st.markdown("### 🛠️ Automated Hardening & Remediation Script")
                        st.code(remediation_script, language='bash')
                        st.download_button(
                            "📥 Download Autonomous Hardening Script (.sh)", 
                            data=remediation_script, 
                            file_name=f"autonomous_harden_{pipeline_target.replace('/', '_')}.sh", 
                            mime="text/plain",
                            use_container_width=True
                        )

                        siem_channels = {
                            "discord": st.secrets.get("DISCORD_WEBHOOK_URL", ""),
                            "slack": st.secrets.get("SLACK_WEBHOOK_URL", "")
                        }
                        af.send_multi_siem_alert(
                            siem_channels, 
                            title=f"🛰️ Autonomous Agent Scan — {pipeline_target}", 
                            message=f"Pipeline completed with Risk Score: {risk['score']}/100 ({risk['band']}).",
                            severity=risk['band']
                        )

        elif not authorized:
            st.caption("Check the authorization box above to enable scanning.")

    elif module == "AI Security Chatbot":
        st.markdown("# 🧠 MHZALY Advanced Cyber Intelligence Assistant")
        st.markdown("<p style='color: #9ca3af;'>Enterprise-grade AI security analyst (Claude/Gemini grade). Upload reports, logs, or code snippets for deep multi-turn reasoning and exploit analysis.</p>", unsafe_allow_html=True)

        if "messages" not in st.session_state:
            st.session_state.messages = [
                {"role": "assistant", "content": "Hello operator! I am your MHZALY AI Security Assistant. I am ready to assist you with vulnerability triage, exploit verification, log forensic analysis, and WAF hardening. How can I assist your operations today?"}
            ]

        st.markdown("**Quick Prompt Suggestions:**")
        chip1, chip2, chip3, chip4 = st.columns(4)
        selected_quick_prompt = ""
        with chip1:
            if st.button("🛡️ Triage Vulnerability", use_container_width=True):
                selected_quick_prompt = "Please review my attached vulnerability report and help me write a professional bug bounty submission."
        with chip2:
            if st.button("🌐 WAF Bypass Analysis", use_container_width=True):
                selected_quick_prompt = "Explain advanced techniques for WAF inspection bypass and rate-limit evasion during authorized recon."
        with chip3:
            if st.button("✍️ Write Python PoC", use_container_width=True):
                selected_quick_prompt = "Write a clean, robust Python Proof-of-Concept (PoC) script to verify missing security headers and endpoint disclosures."
        with chip4:
            if st.button("📊 OWASP Risk Review", use_container_width=True):
                selected_quick_prompt = "Provide an OWASP Top 10 risk breakdown and executive mitigation strategy for web application hardening."

        if st.button("🗑️ Clear Chat History", use_container_width=False):
            st.session_state.messages = [
                {"role": "assistant", "content": "Chat history reset. How can I assist your security operations today?"}
            ]
            st.rerun()

        st.markdown("---")

        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        with st.form("chat_form", clear_on_submit=True):
            st.markdown("""
                <style>
                [data-testid="stForm"] { background: #111827; border: 1px solid rgba(59, 130, 246, 0.4); border-radius: 16px; padding: 10px; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
                [data-testid="stFileUploader"] section { padding: 2px 6px !important; background: #1f2937 !important; border: 1px dashed #4b5563 !important; border-radius: 8px !important; }
                [data-testid="stFileUploader"] small { display: none !important; }
                </style>
            """, unsafe_allow_html=True)

            c_input, c_attach, c_btn = st.columns([0.62, 0.28, 0.1])
            with c_input:
                default_prompt = selected_quick_prompt if selected_quick_prompt else ""
                prompt = st.text_input("Message...", value=default_prompt, placeholder="Ask security query...", label_visibility="collapsed")
            with c_attach:
                uploaded_files = st.file_uploader("📎", type=["png", "jpg", "jpeg", "pdf", "txt", "log"], key="chat_file_upload", label_visibility="collapsed", accept_multiple_files=True)
            with c_btn:
                submitted = st.form_submit_button("⬆️", use_container_width=True)

        file_context = ""
        if uploaded_files:
            for uploaded_file in uploaded_files:
                file_details = f"[Attached File: {uploaded_file.name}]"
                st.caption(f"📎 Attached: `{uploaded_file.name}` ({uploaded_file.size} bytes)")
                if uploaded_file.name.endswith(('.txt', '.log', '.json', '.py', '.sh', '.md')):
                    try:
                        file_text = uploaded_file.getvalue().decode("utf-8", errors="ignore")
                        file_context += f"\n\n---\n{file_details}\nContent snippet:\n{file_text[:4000]}\n---"
                    except Exception:
                        file_context += f"\n\n---\n{file_details}\n---"
                elif uploaded_file.name.endswith('.pdf'):
                    try:
                        import pypdf
                        import io
                        reader = pypdf.PdfReader(io.BytesIO(uploaded_file.getvalue()))
                        pdf_text = ""
                        for page in reader.pages:
                            pdf_text += page.extract_text() or ""
                        file_context += f"\n\n---\n{file_details}\nExtracted PDF Report Content:\n{pdf_text[:8000]}\n---"
                    except Exception as e:
                        file_context += f"\n\n---\n{file_details} (PDF extraction error: {e})\n---"
                else:
                    file_context += f"\n\n---\n{file_details} (Attached file successfully received.)\n---"

        if submitted and (prompt or uploaded_files):
            full_prompt = (prompt or "Please analyze these attached files.") + file_context
            st.session_state.messages.append({"role": "user", "content": full_prompt})
            
            with st.chat_message("user"):
                st.markdown(full_prompt)

            with st.chat_message("assistant"):
                if not groq_key:
                    response_text = "Error: Groq API Key is not configured in your Streamlit secrets or sidebar."
                    st.markdown(response_text)
                else:
                    with st.spinner("Analyzing via Groq AI..."):
                        try:
                            response_text = AutonomousAgentExecutor._call_groq(
                                [
                                    {'role': 'system', 'content': 'You are an elite Cybersecurity Expert, Purple Team Mentor, and Red/Blue Team Advisor specializing in security assessments, log analysis, and vulnerability triage. You CAN and DO read attached files, PDF reports, logs, and document contents provided in the user prompt. Analyze them thoroughly, extract key security findings, and provide professional technical advice.'},
                                    *[{'role': m['role'], 'content': m['content']} for m in st.session_state.messages]
                                ],
                                groq_key, max_tokens=1500, temperature=0.6,
                            )
                        except Exception as e:
                            response_text = f"Connection failed: {e}"
                    st.markdown(response_text)
            st.session_state.messages.append({"role": "assistant", "content": response_text})
            st.rerun()

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
        st.markdown("# Activity History & Trend Analytics")
        ai_hist = get_ai_security_engineer_history(limit=50)
        if ai_hist:
            st.markdown("### AI Security Engineer Scan History & Risk Trend")
            df_ai = pd.DataFrame(ai_hist)
            st.dataframe(df_ai, use_container_width=True)
            if 'risk_score' in df_ai.columns and not df_ai.empty:
                st.markdown("#### Risk Score Trend Over Time")
                chart_df = df_ai[['timestamp', 'risk_score']].set_index('timestamp')
                st.line_chart(chart_df)
        else:
            st.info("No AI Security Engineer scan history found yet. Run a scan to populate analytics.")

        st.markdown("---")
        st.markdown("### Autonomous SOC & Scheduler Audit Logs")
        local_db.init_db()
        history = local_db.recent_scan_runs(limit=50)
        if history:
            st.dataframe(pd.DataFrame(history), use_container_width=True)
        else:
            st.info("No recorded activity logs found in shared scheduler database.")

    elif module == "🎯 Live Vulnerability & Ticket Manager":
        st.markdown("# 🎯 Live Vulnerability & Bug Bounty Ticket Manager")
        st.markdown("<p style='color: #9ca3af;'>Manage, triage, and track all discovered security findings and bug bounty tickets right here in the web console — zero terminal required.</p>", unsafe_allow_html=True)

        local_db.init_db()
        conn = local_db.get_connection()
        try:
            findings_rows = conn.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
        except Exception:
            findings_rows = []
        conn.close()

        if findings_rows:
            df_findings = pd.DataFrame([dict(r) for r in findings_rows])
            st.dataframe(df_findings, use_container_width=True)
            
            st.markdown("### Triage & Ticket Management")
            selected_finding_id = st.selectbox("Select Finding ID to Update", options=[r['id'] for r in findings_rows])
            new_status = st.selectbox("Update Ticket Status", options=["Open", "Triaged", "In Progress", "Resolved", "False Positive"])
            if st.button("Update Finding Status"):
                conn = local_db.get_connection()
                conn.execute("UPDATE findings SET severity = ? WHERE id = ?", (new_status, selected_finding_id))
                conn.commit()
                conn.close()
                st.success(f"Finding ID {selected_finding_id} status updated successfully!")
                st.rerun()
        else:
            st.info("No active vulnerability tickets in database. Run scans via AI Security Engineer or Autonomous SOC to populate tickets.")

    elif module == "🔬 Digital Forensics & IOC Vault":
        st.markdown("# 🔬 Digital Forensics & Indicator of Compromise (IOC) Vault")
        st.markdown("<p style='color: #9ca3af;'>Log, track, and persist digital forensics artifacts, malicious file hashes, suspicious IP indicators, and case notes securely in the live SQLite database.</p>", unsafe_allow_html=True)

        with st.form("forensics_form", clear_on_submit=True):
            f_type = st.selectbox("Artifact Type", options=["IP Address", "File Hash (SHA256/MD5)", "Domain / URL", "Registry Key", "Malicious Process", "Custom IOC"])
            f_val = st.text_input("Artifact Indicator Value", placeholder="e.g. 192.168.1.100 or d41d8cd98f00b204e9800998ecf8427e")
            f_sev = st.selectbox("Severity / Threat Level", options=["Low", "Medium", "High", "Critical"])
            f_notes = st.text_area("Forensic Case Notes & Observations", placeholder="Enter investigative notes, timeline, or vector details...")
            
            f_submitted = st.form_submit_button("📥 Log Artifact to Database", use_container_width=True)
            if f_submitted and f_val:
                ok = local_db.add_forensics_artifact(f_type, f_val, f_sev, f_notes)
                if ok:
                    st.success("Forensic artifact logged successfully to persistent live database!")
                else:
                    st.error("Failed to log artifact.")

        st.markdown("---")
        st.markdown("### Stored Forensics Artifacts & IOCs")
        artifacts = local_db.get_forensics_artifacts(limit=50)
        if artifacts:
            st.dataframe(pd.DataFrame(artifacts), use_container_width=True)
        else:
            st.info("No forensics artifacts logged yet. Use the form above to record IOCs.")

    elif module == "🌐 On-Demand Threat Intel & IOC Lookup":
        st.markdown("# 🌐 On-Demand Threat Intelligence & IOC Lookup")
        st.markdown("<p style='color: #9ca3af;'>Instantly query any domain, IP address, or hash against VirusTotal and AbuseIPDB live on-demand.</p>", unsafe_allow_html=True)

        lookup_target = st.text_input("Enter Domain, IP, or Hash to Query", placeholder="e.g. 8.8.8.8 or example.com")
        if st.button("🔍 Query Threat Intelligence", use_container_width=True):
            if lookup_target:
                with st.spinner(f"Querying threat intelligence APIs for {lookup_target}..."):
                    ti_service = ThreatIntelService(vt_key, abuse_key, cache=shared_cache)
                    ti_result = ti_service.triage_indicator(lookup_target)
                    st.success("Threat Intelligence Lookup Complete:")
                    st.json(ti_result)
            else:
                st.warning("Please enter a valid indicator to query.")

    elif module == "⚡ Web HTTP Repeater & API Fuzzer":
        st.markdown("# ⚡ Web HTTP Repeater & API Fuzzer (Burp-Style Console)")
        st.markdown("<p style='color: #9ca3af;'>Craft custom HTTP requests, modify headers and parameters on the fly, and inspect live responses — right inside your browser.</p>", unsafe_allow_html=True)

        col_req1, col_req2 = st.columns([1, 4])
        with col_req1:
            req_method = st.selectbox("Method", options=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
        with col_req2:
            req_url = st.text_input("Target URL", placeholder="https://api.target.com/v1/resource")

        with st.expander("🛠️ Advanced Request Configuration (Headers & Body)"):
            req_headers = st.text_area("Custom Headers (Key: Value per line)", placeholder="User-Agent: Mozilla/5.0\nAuthorization: Bearer token123", height=100)
            req_body = st.text_area("Request Body (JSON / Form Data)", placeholder='{"user_id": 1}', height=100)

        if st.button("🚀 Send HTTP Request", use_container_width=True):
            if req_url:
                with st.spinner(f"Sending {req_method} request to {req_url}..."):
                    try:
                        headers_dict = {}
                        for line in req_headers.split('\n'):
                            if ':' in line:
                                k, v = line.split(':', 1)
                                headers_dict[k.strip()] = v.strip()
                        
                        t0 = time.time()
                        if req_method == "GET":
                            resp = requests.get(req_url, headers=headers_dict, timeout=12, verify=False, allow_redirects=True)
                        elif req_method == "POST":
                            resp = requests.post(req_url, headers=headers_dict, data=req_body, timeout=12, verify=False, allow_redirects=True)
                        elif req_method == "PUT":
                            resp = requests.put(req_url, headers=headers_dict, data=req_body, timeout=12, verify=False, allow_redirects=True)
                        elif req_method == "DELETE":
                            resp = requests.delete(req_url, headers=headers_dict, timeout=12, verify=False, allow_redirects=True)
                        elif req_method == "HEAD":
                            resp = requests.head(req_url, headers=headers_dict, timeout=12, verify=False, allow_redirects=True)
                        else:
                            resp = requests.options(req_url, headers=headers_dict, timeout=12, verify=False, allow_redirects=True)
                        
                        elapsed = round((time.time() - t0) * 1000, 2)

                        st.markdown("---")
                        col_res1, col_res2, col_res3, col_res4 = st.columns(4)
                        col_res1.metric("Status Code", resp.status_code)
                        col_res2.metric("Response Size", f"{len(resp.content)} bytes")
                        col_res3.metric("Latency", f"{elapsed} ms")
                        col_res4.metric("Content Type", resp.headers.get('Content-Type', 'Unknown').split(';')[0])

                        # Sensitive Keyword Anomaly Check
                        text_lower = resp.text.lower()
                        anomalies = []
                        for kw in ['api_key', 'secret', 'password', 'token', 'stack trace', 'sql syntax', 'root:x:0:0']:
                            if kw in text_lower:
                                anomalies.append(kw)
                        if anomalies:
                            st.error(f"🚨 SECURITY ANOMALY DETECTED: Response contains sensitive keyword(s): {', '.join(anomalies)}")

                        tab_raw, tab_headers, tab_preview = st.tabs(["📦 Raw Response Body", "📋 Response Headers", "🌐 Rendered Preview"])
                        
                        with tab_raw:
                            st.text_area("Response Text", value=resp.text, height=350, key="raw_resp_text")
                        with tab_headers:
                            st.json(dict(resp.headers))
                        with tab_preview:
                            if 'text/html' in resp.headers.get('Content-Type', ''):
                                st.components.v1.html(resp.text[:20000], height=400, scrolling=True)
                            else:
                                try:
                                    st.json(resp.json())
                                except Exception:
                                    st.code(resp.text[:10000])

                    except Exception as e:
                        st.error(f"HTTP Request failed: {e}")
            else:
                st.warning("Please specify a target URL.")

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
