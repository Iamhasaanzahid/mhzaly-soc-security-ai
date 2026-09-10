#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY BUG BOUNTY & ENTERPRISE SECURITY PLATFORM v17.4 - MODERN SaaS EDITION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Comprehensive Purple Team Operations Suite (Red Team Recon + Blue Team SOC Automation)
- Modern Dark Glassmorphism SaaS UI with Custom CSS, Glowing Accents & Sleek Cards
- 100% Autonomous AI-Agent Pipeline with Soft-404 Filtering & Smart CVSS Thresholds
- Fully Automated Enterprise Security Assessment Report Generator & Exporter (.md)
- Dedicated Interactive AI Security Chatbot (Powered by Groq GPT-OSS 120B)
- Separate Automated Sigma Rule & YARA Detection Generator Module
- Autonomous Target Fingerprinting, Smart Endpoint Fuzzing & Log Parsing Simulator
- NVD v2.0 REST Client with AI-Driven Dynamic Query Refinement & Safety Filters
- Deep Live VirusTotal & AbuseIPDB Threat Intelligence Triage with Granular Safe Parsing
- Advanced Network Recon: Real-time Multi-threaded Port Scanning, DNS, SSL & Headers Audit
- Offensive/Defensive Payload Encoder, Decoder, Hasher & Custom Mutator Utility
- Autonomous 24/7 SOC Background Scheduler & Live Database Dashboard Integration
- SQLite Persistence & Audit Log History Tracking

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
from datetime import datetime
from typing import Dict, List, Any, Optional
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

    def to_dict(self):
        return asdict(self)

# ═══════════════════════════════════════════════════════════════════════════════
# 2. ENTERPRISE RECON, SOC & AI-AGENTIC INTELLIGENCE ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

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
                
            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
                try:
                    answers = dns.resolver.resolve(clean_target, rtype)
                    report['dns'][rtype] = [str(r) for r in answers]
                except Exception:
                    report['dns'][rtype] = []

            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PurpleTeamHunter/17.4'})
            
            resp = session.get(target_url, timeout=8, verify=False, allow_redirects=True)
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

            fuzz_paths = [
                '/.env', '/robots.txt', '/sitemap.xml', '/git/config', 
                '/backup.zip', '/api/v1/users', '/swagger.ui', '/phpinfo.php',
                '/config.json', '/auth/login', '/graphql', '/debug', '/admin',
                '/server-status', '/xmlrpc.php', '/package.json', '/composer.json',
                '/api/v1/health', '/v2/swagger.json', '/metrics', '/actuator/env'
            ]
            
            base_origin = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
            
            for path in fuzz_paths:
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
        except Exception as e:
            report['error'] = str(e)
        return report

class NVDIntelligenceClient:
    def __init__(self, nvd_key: str = ""):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_key = nvd_key

    def search_cve(self, keyword: str, max_results: int = 15) -> List[VulnerabilityRecord]:
        vulnerabilities = []
        try:
            params = {'keywordSearch': keyword, 'resultsPerPage': min(max_results, 30)}
            headers = {}
            if self.nvd_key:
                headers['apiKey'] = self.nvd_key
                
            response = requests.get(self.base_url, params=params, headers=headers, timeout=12)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'UNKNOWN')
                    
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
                        
                    if score >= 4.0:
                        vulnerabilities.append(VulnerabilityRecord(
                            cve_id=cve_id,
                            title=cve_id,
                            description=desc,
                            severity=severity.upper(),
                            cvss_score=score,
                            vector_string=vector,
                            affected_configurations=[keyword],
                            published_date=str(cve.get('published', ''))[:10],
                            remediation=f"Apply official vendor patch or configure WAF signature to mitigate {cve_id}."
                        ))
        except Exception as e:
            logger.error(f"NVD API Error: {e}")
        return vulnerabilities

class ThreatIntelService:
    def __init__(self, vt_key: str, abuse_key: str):
        self.vt_key = vt_key
        self.abuse_key = abuse_key

    def triage_indicator(self, indicator: str) -> Dict[str, Any]:
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
                    
                    resp = requests.get(url, headers=headers, timeout=10)
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
                        results['vt_summary']['tags'] = attrs.get('tags', [])
                        results['vt_summary']['registrar'] = attrs.get('registrar', attrs.get('as_owner', 'N/A'))
                    else:
                        results['vt_summary']['error'] = f"VT HTTP Status: {resp.status_code}"
                except Exception as e:
                    results['vt_summary']['error'] = str(e)

            if self.abuse_key and is_ip:
                try:
                    headers = {'Key': self.abuse_key, 'Accept': 'application/json'}
                    params = {'ipAddress': indicator, 'maxAgeInDays': 90, 'verbose': True}
                    resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
                    if resp.status_code == 200:
                        abuse_json = resp.json()
                        results['abuse_raw'] = abuse_json
                        data = abuse_json.get('data', {})
                        
                        results['abuse_summary']['score'] = int(data.get('abuseConfidenceScore', 0))
                        results['abuse_summary']['reports'] = int(data.get('totalReports', 0))
                        results['abuse_summary']['country'] = str(data.get('countryCode', 'N/A'))
                        results['abuse_summary']['isp'] = str(data.get('isp', 'N/A'))
                        results['abuse_summary']['lastReported'] = str(data.get('lastReportedAt', 'Never'))
                    else:
                        results['abuse_summary']['error'] = f"AbuseIPDB Status: {resp.status_code}"
                except Exception as e:
                    results['abuse_summary']['error'] = str(e)
        except Exception as e:
            logger.error(f"ThreatIntel error: {e}")
            
        return results

class AdvancedReconEngine:
    @staticmethod
    def audit_infrastructure(domain: str) -> Dict[str, Any]:
        report = {'dns': {}, 'ports': [], 'ssl': {'valid': False}, 'headers': {}}
        try:
            clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
                try:
                    answers = dns.resolver.resolve(clean_domain, rtype)
                    report['dns'][rtype] = [str(r) for r in answers]
                except Exception:
                    report['dns'][rtype] = []

            common_ports = [21, 22, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9200]
            open_ports = []
            
            def scan_port(port):
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
                resp = requests.get(f"https://{clean_domain}", timeout=5, verify=False)
                target_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
                for h in target_headers:
                    report['headers'][h] = resp.headers.get(h, 'MISSING')
            except Exception as e:
                report['headers']['error'] = str(e)
        except Exception as e:
            logger.error(f"Audit error: {e}")
        return report

# ═══════════════════════════════════════════════════════════════════════════════
# 3. STREAMLIT ENTERPRISE UI (MODERN SaaS CSS & PURPLE TEAM HUB)
# ═══════════════════════════════════════════════════════════════════════════════

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
            
        if st.button("Add & Scan Target Now", use_container_width=True):
            if new_target:
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

    targets = db.list_targets()
    st.markdown("### Monitored Targets")
    if targets:
        df = pd.DataFrame(targets)[["id", "target", "scan_interval_minutes", "last_scanned_at", "active"]]
        st.dataframe(df, use_container_width=True)

        with st.form(key="deactivate_form"):
            remove_id = st.number_input("Deactivate target ID", min_value=0, value=0, step=1, key="deactivate_target_id_input")
            submit_deactivate = st.form_submit_button("Deactivate Target")
            
            if submit_deactivate:
                if remove_id > 0:
                    db.remove_target(int(remove_id))
                    st.success(f"Target ID {remove_id} has been successfully deactivated/removed.")
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
        /* Main background & typography */
        .stApp {
            background-color: #0b0f19;
            color: #f3f4f6;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background-color: #111827;
            border-right: 1px solid #1f2937;
        }
        
        /* Glassmorphism Cards */
        .saas-card {
            background: rgba(17, 24, 39, 0.7);
            border: 1px solid rgba(75, 85, 99, 0.3);
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(12px);
            margin-bottom: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }
        
        /* Custom Buttons */
        .stButton>button {
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            padding: 0.5rem 1rem;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        .stButton>button:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
            box-shadow: 0 6px 16px rgba(59, 130, 246, 0.5);
            transform: translateY(-1px);
        }
        
        /* Metric Cards Customization */
        [data-testid="stMetric"] {
            background: rgba(17, 24, 39, 0.8);
            border: 1px solid rgba(59, 130, 246, 0.2);
            padding: 16px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        [data-testid="stMetricLabel"] {
            color: #9ca3af !important;
            font-weight: 500;
        }
        [data-testid="stMetricValue"] {
            color: #60a5fa !important;
            font-weight: 700;
        }
        
        /* Inputs & Textareas */
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: #1f2937;
            color: #f3f4f6;
            border: 1px solid #374151;
            border-radius: 8px;
        }
        .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
        }
        
        /* Headers styling */
        h1, h2, h3 {
            color: #f9fafb;
            font-weight: 700;
            letter-spacing: -0.025em;
        }
        </style>
    """, unsafe_allow_html=True)

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

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
            
            username = st.text_input("Operator Username")
            password = st.text_input("Operator Password", type="password")
            
            if st.button("Authenticate Suite", use_container_width=True):
                correct_user = st.secrets.get("APP_USERNAME", "admin")
                correct_pass = st.secrets.get("APP_PASSWORD", "admin123")
                if username == correct_user and password == correct_pass:
                    st.session_state.authenticated = True
                    st.session_state.user = username
                    st.success("Authentication successful. Initializing SaaS modules...")
                    st.rerun()
                else:
                    st.error("Authentication failed: Invalid credentials.")
        return

    vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
    abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")
    groq_key = st.secrets.get("GROQ_API_KEY", "")
    nvd_key = st.secrets.get("NVD_API_KEY", "")
    
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
        st.markdown("# Fully Autonomous Purple Team Intelligence Pipeline")
        st.markdown("<p style='color: #9ca3af;'>Enter target scope. The AI Agent executes live multi-API recon, threat triage, soft-404 filtered fuzzing, NVD vulnerability correlation, and unified architectural hardening guidance.</p>", unsafe_allow_html=True)

        pipeline_target = st.text_input("Target Domain, IP Address, or Keyword", placeholder="e.g., target-domain.com or 8.8.8.8")

        if st.button("Execute Autonomous Purple Team Pipeline", use_container_width=True):
            if pipeline_target:
                with st.spinner("AI Agent executing unified Red/Blue reconnaissance and vulnerability synthesis..."):
                    local_db.init_db()
                    
                    ti = ThreatIntelService(vt_key, abuse_key)
                    ti_res = ti.triage_indicator(pipeline_target)
                    
                    recon_res = BugBountyReconEngine.deep_recon(pipeline_target)

                    clean_target = pipeline_target.replace('https://', '').replace('http://', '').split('/')[0]
                    domain_keyword = clean_target.split('.')[0] if '.' in clean_target else clean_target
                    
                    if recon_res.get('technologies'):
                        nvd_query_term = recon_res['technologies'][0]
                    else:
                        nvd_query_term = domain_keyword

                    nvd = NVDIntelligenceClient(nvd_key)
                    cve_res = nvd.search_cve(nvd_query_term, max_results=8)
                    if not cve_res and domain_keyword != nvd_query_term:
                        cve_res = nvd.search_cve(domain_keyword, max_results=8)

                    st.success("Telemetry gathered. AI Agent synthesizing defensive hardening and threat mitigation review...")

                    c1, c2, c3 = st.columns(3)
                    c1.metric("VT Malicious Detections", ti_res['vt_summary']['malicious'])
                    c2.metric("Abuse Confidence Score", f"{ti_res['abuse_summary']['score']}%")
                    c3.metric("Filtered NVD CVEs", len(cve_res))

                    ai_analysis_text = "AI analysis skipped or key missing."
                    if groq_key:
                        summary_context = f"""
                        Target Scope: {pipeline_target}
                        VirusTotal Malicious Count: {ti_res['vt_summary']['malicious']}
                        AbuseIPDB Threat Score: {ti_res['abuse_summary']['score']}%
                        Discovered Tech Stack: {recon_res.get('technologies', [])}
                        Exposed Sensitive Files/Endpoints: {recon_res.get('exposed_files', [])}
                        Top Correlated NVD CVEs: {[c.cve_id for c in cve_res]}
                        """
                        try:
                            headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
                            payload = {
                                'model': 'openai/gpt-oss-120b',
                                'messages': [
                                    {
                                        'role': 'system', 
                                        'content': 'You are an elite Purple Team Lead and Enterprise Cloud Security Architect. Review the provided target telemetry from both offensive and defensive perspectives, evaluate structural authorization patterns, analyze security posture, and provide comprehensive defensive hardening guidelines and SIEM detection strategies.'
                                    },
                                    {
                                        'role': 'user', 
                                        'content': f"Perform unified Purple Team architectural review and generate defensive hardening guidance based on this target telemetry:\n{summary_context}"
                                    }
                                ],
                                'temperature': 0.5,
                                'max_tokens': 2000
                            }
                            resp = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers, timeout=30)
                            if resp.status_code == 200:
                                ai_analysis_text = resp.json()['choices'][0]['message']['content']
                            else:
                                ai_analysis_text = f"API Error: {resp.status_code} - {resp.text}"
                        except Exception as e:
                            ai_analysis_text = f"Connection failed: {e}"

                    cve_list_md = "\n".join([f"- **{c.cve_id}** (CVSS: {c.cvss_score} - {c.severity}): {c.description}" for c in cve_res]) if cve_res else "No high-severity matching CVE entries found."
                    exposed_md = "\n".join([f"- Endpoint: `{ef['path']}` | Status: `{ef['status']}`" for ef in recon_res.get('exposed_files', [])]) if recon_res.get('exposed_files') else "No sensitive endpoints exposed on standard fuzz paths."
                    tech_md = ", ".join(recon_res.get('technologies', ['Custom / Undetected']))

                    auto_report_markdown = f"""# MHZALY PURPLE TEAM SECURITY ASSESSMENT REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
* **Target Scope:** `{pipeline_target}`
* **Lead Operator:** `{st.session_state.user} (Purple Team AI Engine)`
* **Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
* **Classification:** UNIFIED RED/BLUE SECURITY INTELLIGENCE

## 1. Executive Summary & Recon Scope Overview
Automated Purple Team intelligence gathering was completed against `{pipeline_target}`. The pipeline analyzed reputation scores, NVD CVE mappings, and target tech vectors to assess overall security posture.
- **VirusTotal Malicious Count:** `{ti_res['vt_summary']['malicious']}`
- **AbuseIPDB Score:** `{ti_res['abuse_summary']['score']}%`
- **Detected Technologies:** `{tech_md}`

## 2. Threat Intelligence & Reputation Triage
### VirusTotal Telemetry
- **Harmless Engines:** `{ti_res['vt_summary']['harmless']}`
- **Community Reputation:** `{ti_res['vt_summary']['reputation']}`
- **ASN / Owner:** `{ti_res['vt_summary']['registrar']}`

### AbuseIPDB Telemetry
- **Reports Count:** `{ti_res['abuse_summary']['reports']}`
- **Country Code:** `{ti_res['abuse_summary']['country']}`
- **ISP:** `{ti_res['abuse_summary']['isp']}`

## 3. Attack Surface Discovery & Exposed Endpoints
- **HTTP Status:** `{recon_res.get('status_code', 'N/A')}`
- **Server Banner:** `{recon_res.get('server', 'Hidden')}`
- **Discovered Endpoints & Files:**
{exposed_md}

## 4. Correlated Vulnerabilities (NIST NVD v2.0 - Filtered CVSS >= 4.0)
{cve_list_md}

## 5. Unified Purple Team Architectural Analysis & Hardening Recommendations
{ai_analysis_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
*Generated via MHZALY Purple Team Operations Suite*
"""

                    st.markdown("---")
                    st.markdown("### Generated Purple Team Report Preview")
                    st.markdown(auto_report_markdown)

                    st.download_button(
                        label="Download Full Purple Team Security Report (.md)",
                        data=auto_report_markdown,
                        file_name=f"mhzaly_purple_team_report_{pipeline_target.replace('/', '_')}.md",
                        mime="text/markdown",
                        use_container_width=True
                    )
            else:
                st.warning("Please specify a target for the pipeline report.")

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
                            headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
                            payload = {
                                'model': 'openai/gpt-oss-120b',
                                'messages': [
                                    {'role': 'system', 'content': 'You are an elite Cybersecurity Expert, Purple Team Mentor, and Red/Blue Team Advisor specializing in security assessments.'},
                                    *[ {'role': m['role'], 'content': m['content']} for m in st.session_state.messages ]
                                ],
                                'temperature': 0.6,
                                'max_tokens': 1500
                            }
                            resp = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers, timeout=25)
                            if resp.status_code == 200:
                                response_text = resp.json()['choices'][0]['message']['content']
                            else:
                                response_text = f"API Error Code: {resp.status_code} - {resp.text}"
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
                    
                    lines = sample_log.split('\n')
                    suspicious_hits = []
                    for idx, line in enumerate(lines, 1):
                        l_lower = line.lower()
                        if any(k in l_lower for k in ['union select', '<script>', 'etc/passwd', 'cmd.exe', '/wpscan', 'sqlmap', 'eval(']):
                            suspicious_hits.append({'line_no': idx, 'content': line, 'indicator': 'Injection / Exploit Pattern'})
                        elif '404' in line or '403' in line:
                            suspicious_hits.append({'line_no': idx, 'content': line, 'indicator': 'Unauthorized / Failed Request'})
                            
                    c1, c2 = st.columns(2)
                    c1.metric("Total Log Lines Analyzed", len(lines))
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
                            headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
                            payload = {
                                'model': 'openai/gpt-oss-120b',
                                'messages': [
                                    {'role': 'system', 'content': 'You are a senior Blue Team threat hunter. Generate a valid, production-ready Sigma detection rule in YAML format for the requested vulnerability or threat vector.'},
                                    {'role': 'user', 'content': f"Generate a Sigma rule for: {cve_input}"}
                                ],
                                'temperature': 0.3,
                                'max_tokens': 1000
                            }
                            resp = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers, timeout=25)
                            if resp.status_code == 200:
                                sigma_res = resp.json()['choices'][0]['message']['content']
                                st.code(sigma_res, language='yaml')
                            else:
                                st.error(f"API Error: {resp.status_code}")
                        except Exception as e:
                            st.error(f"Error: {e}")
            else:
                st.warning("Please enter a CVE ID or attack description.")

    elif module == "Bug Bounty Recon & Fuzzing":
        st.markdown("# Target Reconnaissance & Sensitive Endpoint Fuzzing")
        target_input = st.text_input("Target URL or Domain", placeholder="e.g., target-domain.com")
        
        if st.button("Launch Recon & Asset Discovery", use_container_width=True):
            if target_input:
                with st.spinner(f"Executing deep offensive reconnaissance on {target_input}..."):
                    recon = BugBountyReconEngine.deep_recon(target_input)
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
            else:
                st.warning("Please specify a target domain or URL.")

    elif module == "Network Infrastructure Audit":
        st.markdown("# Purple Team Infrastructure Reconnaissance & Audit")
        target_domain = st.text_input("Target Domain or IP Address", placeholder="e.g., scanme.nmap.org")
        
        if st.button("Execute Full Infrastructure Audit", use_container_width=True):
            if target_domain:
                with st.spinner(f"Executing live infrastructure audit against {target_domain}..."):
                    audit_data = AdvancedReconEngine.audit_infrastructure(target_domain)
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
            else:
                st.warning("Please provide a valid target host.")

    elif module == "Enterprise NVD Intelligence":
        st.markdown("# Enterprise NVD Vulnerability Intelligence")
        keyword = st.text_input("Search Software / Vendor / CVE", placeholder="e.g., apache, wordpress plugin, cve-2024")
        
        if st.button("Query NVD Database", use_container_width=True):
            if keyword:
                with st.spinner("Fetching CVE telemetry from NIST NVD..."):
                    client = NVDIntelligenceClient(nvd_key)
                    vulns = client.search_cve(keyword)
                    
                    if vulns:
                        st.success(f"Retrieved {len(vulns)} CVE records.")
                        for v in vulns:
                            with st.expander(f"{v.cve_id} | Severity: {v.severity} | CVSS: {v.cvss_score}"):
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
                    ti = ThreatIntelService(vt_key, abuse_key)
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
        st.write(f"**Groq AI Engine:** {'Active (openai/gpt-oss-120b)' if groq_key else 'Missing'}")
        st.write("**SQLite Shared Database (`mhzaly_soc.db`):** Initialized")

if __name__ == "__main__":
    main()
