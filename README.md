# 🛡️ MHZALY Enterprise SOC & Bug Bounty AI Platform v18.1

Comprehensive Purple Team Operations Suite (Red Team Recon + Blue Team SOC Automation & Deep-Thinking AI Intelligence).

---

## 🚀 Key Features & Capabilities

1. **Autonomous AI Security Engineer:** Type any domain/IP and the platform performs deep reconnaissance, tech stack fingerprinting, header auditing, CVE matching, and AI-driven analyst write-ups.
2. **Zero False-Positive Verification Engine:** Automatically filters out `403 Forbidden` or blocked pages, confirming 100% live verified sensitive file leaks (`.env`, `.git`, JSON configs, etc.).
3. **Deep-Thinking Chain-of-Thought (CoT) Engine:** Human-expert level reasoning breaking down targets across a structured 5-phase adversary and defense assessment.
4. **Multimodal AI Security Chatbot:** Claude & Gemini-grade chat assistant supporting multiple file attachments (PDF reports, log files, text logs, screenshots) with instant text extraction via `pypdf`, quick action chips, and a **Clear Chat History** button.
5. **Interactive Attack Surface Topology & Asset Map:** Visualizing discovered subdomains, open TCP ports, and endpoints in real-time.
6. **Automated Enterprise Tooling & Scripts:**
   - **Hardening Script (`remediation.sh`):** Auto-generated Nginx / Apache server hardening script.
   - **PoC Verification Script (`verify_poc.py`):** Ready-to-run Python script to verify headers and endpoint exposure.
   - **WAF Rule Generator (`waf_rules.conf`):** ModSecurity / Cloudflare blocking rules for exposed assets.
7. **Scan History & Trend Analytics Dashboard:** SQLite-backed scan persistence with risk score trend line charts (`st.line_chart`).
8. **Real-Time Discord Webhook Alerts:** Automated Discord embeds dispatched on critical findings and completed scan runs.
9. **MITRE ATT&CK & OWASP Top 10 (2021) Mapping:** Compliance and threat intelligence tagging for professional reporting.
10. **Digital Forensics & IOC Vault:** Persistent storage for malicious hashes, suspicious IPs, and forensic case notes.
11. **On-Demand Threat Intel & IOC Lookup:** Instant VirusTotal & AbuseIPDB queries right from the web console.
12. **Custom PDF Report Branding:** Generate executive PDF reports with custom Auditor Name and Client Organization headers.
13. **Zero Terminal Workflow:** 100% web-based interactive operations dashboard.

---

## 🔑 Configuration & Free API Keys

In your Streamlit Cloud **App settings → Secrets** (or local `.streamlit/secrets.toml`), configure your free API keys:

```toml
APP_USERNAME = "admin"
APP_PASSWORD = "securepassword"

# Optional Live API Keys
GROQ_API_KEY = "your-groq-api-key"
VIRUSTOTAL_API_KEY = "your-virustotal-api-key"
NVD_API_KEY = "your-nvd-api-key"
ABUSEIPDB_API_KEY = "your-abuseipdb-api-key"
DISCORD_WEBHOOK_URL = "your-discord-webhook-url"
```

---

## 🚀 Local Deployment

```bash
git clone https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai.git
cd mhzaly-soc-security-ai
pip install -r requirements.txt
streamlit run app.py
```
