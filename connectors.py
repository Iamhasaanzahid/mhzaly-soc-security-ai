"""
connectors.py — Real API wrappers for the AI Security Engineer.

4 integrations:
  1. VirusTotal   (IOC reputation)          — needs VT_API_KEY
  2. AbuseIPDB    (IP abuse confidence)      — needs ABUSEIPDB_API_KEY
  3. NVD          (CVE data)                 — NVD_API_KEY optional (higher rate limit if set)
  4. crt.sh       (certificate-transparency subdomain enum) — free, no key needed

Keys are read from environment variables first, then Streamlit secrets
(st.secrets) if running inside Streamlit. Every function fails soft —
returns {"error": "..."} instead of raising, so one dead API never crashes
the whole pipeline.
"""

from __future__ import annotations
import os
import time
import requests

REQUEST_TIMEOUT = 15


def _get_key(name: str) -> str | None:
    val = os.environ.get(name)
    if val:
        return val
    try:
        import streamlit as st
        return st.secrets.get(name)
    except Exception:
        return None


def _get(url: str, **kwargs) -> requests.Response:
    return requests.get(url, timeout=REQUEST_TIMEOUT, **kwargs)


# ---------------------------------------------------------------------------
# 1. VirusTotal
# ---------------------------------------------------------------------------
def query_virustotal(ioc: str) -> dict:
    api_key = _get_key("VT_API_KEY")
    if not api_key:
        return {"error": "VT_API_KEY not configured"}

    is_ip = _looks_like_ip(ioc)
    endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}" if is_ip \
        else f"https://www.virustotal.com/api/v3/domains/{ioc}"

    try:
        resp = _get(endpoint, headers={"x-apikey": api_key})
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit hit"}
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "raw": stats,
        }
    except requests.RequestException as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# 2. AbuseIPDB
# ---------------------------------------------------------------------------
def query_abuseipdb(ip: str) -> dict:
    api_key = _get_key("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured"}
    if not _looks_like_ip(ip):
        return {"error": "AbuseIPDB only accepts IP addresses"}

    try:
        resp = _get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        if resp.status_code == 429:
            return {"error": "AbuseIPDB rate limit hit"}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "totalReports": data.get("totalReports", 0),
            "countryCode": data.get("countryCode"),
            "isTor": data.get("isTor", False),
            "domain": data.get("domain"),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# 3. NVD (CVE data)
# ---------------------------------------------------------------------------
def query_nvd(keyword: str, max_results: int = 10) -> dict:
    api_key = _get_key("NVD_API_KEY")  # optional — raises rate limit from 5/30s to 50/30s
    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = _get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers=headers,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
        )
        if resp.status_code == 403:
            return {"error": "NVD rate limit hit — wait 30s or add NVD_API_KEY"}
        resp.raise_for_status()
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    cvss = metrics[key][0]["cvssData"]["baseScore"]
                    break
            descriptions = cve.get("descriptions", [])
            desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            cves.append({
                "id": cve.get("id"),
                "cvss_score": cvss,
                "description": desc_en[:300],
            })
        return {"count": len(cves), "cves": cves}
    except requests.RequestException as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# 4. crt.sh — certificate transparency subdomain enumeration (free, no key)
# ---------------------------------------------------------------------------
def query_crtsh(domain: str) -> dict:
    try:
        resp = _get(f"https://crt.sh/?q=%25.{domain}&output=json")
        resp.raise_for_status()
        entries = resp.json()
        subdomains = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name:
                    subdomains.add(name)
        return {"domain": domain, "subdomains": sorted(subdomains)}
    except (requests.RequestException, ValueError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
