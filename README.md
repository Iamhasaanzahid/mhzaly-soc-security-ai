# 🛡️ MHZALY Enterprise SOC & Bug Bounty AI Platform

**v18.2** — Autonomous purple-team operations suite: red-team reconnaissance, blue-team SOC automation, and AI-assisted analyst reporting — driven from a single Streamlit dashboard.

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/streamlit-1.28%2B-FF4B4B?logo=streamlit&logoColor=white)
![Tests](https://img.shields.io/badge/tests-58%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

> ⚠️ **Authorized use only.** This platform performs active reconnaissance. Only scan assets you own or have explicit written permission to test (bug-bounty scope, client engagement, lab environment). See [SECURITY.md](SECURITY.md).

---

## What it does

| Capability | Detail |
|---|---|
| **Autonomous AI Security Engineer** | Give it a domain/IP → recon, tech fingerprinting, header audit, CVE matching, AI analyst write-up |
| **Interactive Attack Surface Map** | Subdomains, open TCP ports and endpoints visualised live |
| **Zero-False-Positive Verification** | `403`/blocked responses are filtered; sensitive-file hits are content-verified before reporting |
| **Deep-Thinking CoT Engine** | 5-phase adversary/defence assessment written like a human analyst |
| **Multimodal AI Chat** | Chat with PDF reports, logs and screenshots (`pypdf` extraction) |
| **Blue-Team SOC Automation** | Cron-driven monitoring, fingerprint-deduped findings, Discord alerts with 429 back-off |
| **Threat Intelligence** | VirusTotal, AbuseIPDB, NVD (CPE-confirmed CVE matching), ZoomEye |
| **Findings & Ticketing** | SQLite-backed findings, severity, ticket status, trend charts |
| **Forensics & IOC Vault** | Persistent hashes / IPs / case notes |
| **Generated Artefacts** | Hardening script, PoC verifier, WAF rules, branded PDF reports |
| **Burp-style HTTP Repeater** | Craft arbitrary methods/headers/body and inspect raw responses |
| **AI Triage Copilot** | One-click analyst brief per finding: executive summary, candidate Sigma rule, MITRE mapping, containment playbook, remediation |

---

## Architecture

```
                      ┌──────────────────────────────┐
   Browser ────────► │  app.py  (Streamlit UI)      │
                      │  auth · quota · session TTL  │
                      └───────┬──────────────┬───────┘
                              │              │
                 ┌──────────▼───┐   ┌──────▼─────────────┐
                 │ core/        │   │ core/connectors.py │
                 │ advanced_    │   │ SSRF guard, DNS,   │
                 │ features.py  │   │ ports, TLS, crt.sh,│
                 │ SIEM·SOAR·PDF│   │ fuzzing, VT·NVD    │
                 └──────────────┘   └──────┬─────────────┘
                                          │
   GitHub Actions cron ──► core/scheduler.py ─┤
   (every 30 min)          core/notifier.py   │
                          core/db.py ◄────────┘
                              │
                       mhzaly_soc.db  (committed state)
```

Full details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Quick start

### Streamlit Community Cloud (recommended)

1. Point Streamlit Cloud at this repo, main file `app.py`.
2. **App settings → Secrets** and paste:

```toml
APP_USERNAME = "your-operator-name"
APP_PASSWORD = "a-long-random-passphrase"

# Optional integrations
GROQ_API_KEY = ""
VIRUSTOTAL_API_KEY = ""
ABUSEIPDB_API_KEY = ""
NVD_API_KEY = ""
ZOOMEYE_API_KEY = ""
DISCORD_WEBHOOK_URL = ""

SESSION_TIMEOUT_MINUTES = 30
MAX_ACTIVE_SCANS_PER_DAY = 100
```

The app **refuses to start the login screen** if `APP_USERNAME`/`APP_PASSWORD` are missing — there is no default credential.

### Local

```bash
git clone https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai.git
cd mhzaly-soc-security-ai
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mkdir -p .streamlit && cp secrets.toml.example .streamlit/secrets.toml  # then edit it
streamlit run app.py
```

---

## Autonomous SOC (24/7 mode)

The repo ships a scheduled GitHub Actions workflow (`.github/workflows/soc_scan.yml`) that runs every 30 minutes, scans every active target, and commits the updated `mhzaly_soc.db` back to the repo.

Manage targets from the CLI:

```bash
python3 core/scheduler.py add example.com 30   # monitor every 30 minutes
python3 core/scheduler.py list                 # show targets
python3 core/scheduler.py scan-once example.com
python3 core/scheduler.py remove 2             # deactivate (history preserved)
python3 core/scheduler.py run-all-once         # what CI runs
python3 core/scheduler.py run                  # long-lived loop for a VPS
```

Required repository secrets (Settings → Secrets and variables → Actions):

`DISCORD_WEBHOOK_URL`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `NVD_API_KEY`, `ZOOMEYE_API_KEY` — all optional, features degrade gracefully.

**Note:** `mhzaly_soc.db` is tracked in git on purpose — it is the platform's persistent state and the cron job commits it. Don't add it to `.gitignore`.

---

## Repository layout

```
app.py                    Streamlit dashboard (auth, all modules)
core/
  connectors.py           SSRF guard, DNS/TLS/port scanning, crt.sh, CT log parsing, threat intel
  scheduler.py            autonomous scan loop + CLI (used by GitHub Actions)
  db.py                   SQLite persistence, fingerprint dedupe
  notifier.py             Discord alerting with retry / 429 back-off
  advanced_features.py    SIEM fan-out, SOAR, OWASP/MITRE, PDF, email reports
dashboard_tab.py          reusable SOC dashboard snippet
docs/ARCHITECTURE.md      module map, data flow, security controls
tests/                    pytest suite (58 tests)
secrets.toml.example      copy to .streamlit/secrets.toml
```

---

## Quality gates

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest          # 58 tests
ruff check .    # zero findings
```

CI runs both on every push and pull request (`.github/workflows/ci.yml`).

---

## License

MIT — see [LICENSE](LICENSE).
