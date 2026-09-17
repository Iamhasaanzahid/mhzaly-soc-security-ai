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
                    if p_resp.status_code in [200, 403, 401]:
                        p_text = p_resp.text.lower()
                        if 'streamlit' in p_text and 'root' in p_text and len(p_text) > 500:
                            if abs(len(p_text) - len(base_homepage_text)) < 200:
                                return None
                        if p_resp.status_code == 200 and len(p_text) > 10:
                            if any(err in p_text for err in ["not found", "404 page", "does not exist", "object not found"]):
                                return None
                        return {'path': path, 'status': p_resp.status_code, 'size': len(p_resp.text)}
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
        headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
        full_text = ""
        convo = list(messages)
        for _ in range(2):
            payload = {
                'model': 'openai/gpt-oss-120b',
                'messages': convo,
                'temperature': temperature,
                'max_tokens': max_tokens,
            }
            resp = with_retry(requests.post, "https://api.groq.com/openai/v1/chat/completions",
                              json=payload, headers=headers, timeout=30)
            if resp.status_code == 401:
                return full_text + "\n[Local Analyst Narrative Engine active — Groq AI key is optional and currently not configured or invalid]."
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
        names = ", ".join(f"`{e['path']}` ({e['status']})" for e in exposed[:8])
        lead = random.choice([
            "This is the part I'd fix first:",
            "Biggest actionable item here:",
        ])
        return f"{lead} {len(exposed)} path(s) responded live: {names}. Worth confirming by hand and locking down access control on these."

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

    def build(self) -> str:
        lines = [random.choice(self.OPENERS).format(target=self.target), ""]
        for para in [self._exposure_paragraph(), self._tech_paragraph(), self._headers_paragraph(),
                     self._cookies_paragraph(), self._cors_paragraph(), self._ssl_paragraph(),
                     self._email_security_paragraph(), self._ports_paragraph(), self._subdomains_paragraph(),
                     self._cve_paragraph(), self._threat_intel_paragraph()]:
            if para:
                lines.append(para)
                lines.append("")
        lines.append(f"**Bottom line:** aggregate risk score is {self.risk.get('score', '?')}/100 ({self.risk.get('band', 'UNKNOWN')}).")
        lines.append("")
        lines.append("_Automated preliminary assessment — verify exposed paths and CVE matches by hand before acting on them, "
                     "and don't treat a clean threat-intel/CVE result as a guarantee of no risk._")
        return "\n".join(lines)


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

    if recon.get('exposed_files'):
        counts["High"] += len(recon['exposed_files'])

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
                        cve_res: List[VulnerabilityRecord]) -> Optional[bytes]:
    if not FPDF_AVAILABLE:
        return None
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "AI Security Engineer - Assessment Report".encode('latin-1', 'replace').decode('latin-1'), ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Target: {target}".encode('latin-1', 'replace').decode('latin-1'), ln=True)
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
                "AI Security Engineer",
                "Autonomous SOC (Live DB)",
                "Autonomous AI-Agent Red/Blue Pipeline",
                "AI Security Chatbot",
                "Blue Team SOC Log & SIEM Simulator",
                "Automated Sigma Rule Generator",
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

                    st.success("AI Security Engineer run complete — every finding above is from a live check.")

                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Aggregate Risk", f"{risk['score']}/100", risk['band'])
                    m2.metric("Open Ports", open_ports_count)
                    m3.metric("Exposed Paths", exposed_count)
                    m4.metric("CVEs (filtered)", len(cve_res))

                    st.markdown("### Executive Summary")
                    s1, s2, s3, s4 = st.columns(4)
                    s1.metric("🔴 Critical", summary_counts["Critical"])
                    s2.metric("🟠 High", summary_counts["High"])
                    s3.metric("🟡 Medium", summary_counts["Medium"])
                    s4.metric("🟢 Low", summary_counts["Low"])

                    st.markdown("### Analyst Write-Up")
                    st.caption(f"Source: {report_source}")
                    st.markdown(report_text)

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
                    dcol1, dcol2, dcol3 = st.columns(3)
                    with dcol1:
                        st.download_button("📥 Download Report (.md)", data=report_markdown,
                                           file_name=f"ai_security_engineer_{clean_target}.md",
                                           mime="text/markdown", use_container_width=True)
                    with dcol2:
                        st.download_button("📥 Download Findings (.json)", data=json.dumps({
                            "target": clean_target, "risk": risk, "summary_counts": summary_counts,
                            "recon": recon, "infra": infra,
                            "subdomains": subs, "cves": [v.to_dict() for v in cve_res], "threat_intel": ti_res,
                        }, indent=2, default=str), file_name=f"ai_security_engineer_{clean_target}.json",
                            mime="application/json", use_container_width=True)
                    with dcol3:
                        if FPDF_AVAILABLE:
                            pdf_bytes = generate_pdf_report(clean_target, risk, summary_counts, report_text,
                                                            recon, infra, cve_res)
                            st.download_button("📥 Download Report (.pdf)", data=pdf_bytes,
                                               file_name=f"ai_security_engineer_{clean_target}.pdf",
                                               mime="application/pdf", use_container_width=True)
                        else:
                            st.caption("PDF export needs `fpdf2` — add it to requirements.txt to enable this button.")
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
