<div align="center">

# 🛡️ MHZALY — Autonomous SOC & Attack-Surface Intelligence

**Reconnaissance that runs like an operator. Verification that stands like an auditor. Reporting that reads like a senior consultant.**

[![CI](https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai/actions/workflows/codeql.yml/badge.svg)](https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai/actions/workflows/codeql.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Streamlit](https://img.shields.io/badge/streamlit-1.28%2B-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Tests](https://img.shields.io/badge/tests-95%20passing-brightgreen)](tests)
[![Version](https://img.shields.io/badge/version-19.0.0-blueviolet)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

> [!WARNING]
> **Authorized use only.** This platform performs active reconnaissance against systems you nominate.
> Scan only assets you own or have explicit written permission to test. Targets resolving to private,
> loopback, link-local or cloud-metadata addresses are refused at the connector layer. See [SECURITY.md](SECURITY.md).

---

## Why this exists

Most security scanners optimise for volume: hundreds of observations, most of them noise, none of
them defensible in a client report. That output does not survive review, and analysts stop reading it.

This platform optimises for the opposite. Every candidate observation has to earn its place in the
report — it is scored, de-duplicated, and either verified against real evidence or dropped. What
remains is a short list an engineer can act on and a consultant can sign.

| | Conventional scanner | MHZALY |
|---|---|---|
| Finding volume | Hundreds per host | A handful, each with evidence |
| Sensitive-file hits | `200 OK` = reported | Soft-404 calibrated + content signature required |
| Subdomains | Reported as findings | Inventory, not findings |
| TLS | Often trusts everything | Real chain validation, expiry, hostname match |
| Reports | Template bolted onto scanner output | Consultant voice, hallucination-guarded |
| Dismissed findings | Lost silently | Counted and reported as suppressed |

---

## Capabilities

| Area | What it does |
|---|---|
| **AI Security Engineer** | One target in, one verified assessment out: recon, technology fingerprinting, header audit, CPE-confirmed CVE matching, attack-surface map, analyst write-up |
| **Verified Web Surface** | Header grading, cookie-flag analysis, certificate validation, CORS, bounded same-origin crawl, robots/sitemap mining, SPF/DMARC, dangling-CNAME takeover checks |
| **Precision Gate** | Scores every candidate 0–100, de-duplicates across runs, enforces a confidence floor (default 70) and severity floor (default MEDIUM) |
| **Human Council Reports** | Three independent perspectives — consultant, red team, blue team — arbitrated into one executive assessment; deterministic local narrative when no LLM key is configured |
| **Autonomous SOC** | Cron-driven monitoring every 30 minutes, fingerprint-level de-duplication, Discord alerting with 429 back-off, persistent state committed back to the repo |
| **AI Triage Copilot** | Per-finding analyst brief: executive summary, candidate Sigma rule, MITRE ATT&CK mapping, containment playbook, remediation steps |
| **Threat Intelligence** | VirusTotal, AbuseIPDB, NVD (CPE-confirmed matching), ZoomEye — all optional, degrading gracefully when a key is absent |
| **Findings & Ticketing** | SQLite-backed finding lifecycle, severity, ticket state, trend analytics |
| **Forensics & IOC Vault** | Persisted hashes, indicators, case notes |
| **Artefacts** | Hardening script, PoC verifier, WAF rules, branded PDF reports |
| **HTTP Repeater** | Burp-style request crafting for arbitrary methods, headers and bodies |

---

## The precision pipeline

```
  candidate observation
          │
          ▼
  ┌───────────────────┐     no evidence / unverifiable
  │  verification     │ ─────────────────────────────► suppressed
  │  (hunter, TLS,    │                              (counted, not reported)
  │   CPE, signatures)│
  └─────────┬─────────┘
            │ verified
            ▼
  ┌───────────────────┐     score < 70 or severity < MEDIUM
  │  confidence gate  │ ─────────────────────────────► suppressed
  │  score · dedupe   │
  └─────────┬─────────┘
            │
            ▼
     report + alert
  (alerts require confidence ≥ 80)
```

Three rules drive the design:

1. **A status code is not evidence.** Sensitive paths are only reported after a baseline probe
   establishes the host's soft-404 behaviour *and* the response body matches a content signature
   (`.env` → `KEY=VALUE`, `.git/config` → `[core]`, `phpinfo()` markers, and so on).
2. **Inventory is not a finding.** Subdomains, open ports and technologies are context for the
   assessment; they are not vulnerabilities and never inflate the count.
3. **Silence is a result.** If nothing survives verification, the report says so plainly instead of
   padding the page.

---

## Architecture

```
                      ┌──────────────────────────────────┐
   Browser ─────────► │  app.py  (Streamlit UI)          │
                      │  auth · quota · session TTL      │
                      └───────┬───────────────┬──────────┘
                              │               │
                 ┌────────────▼────┐   ┌──────▼──────────────┐
                 │ core/           │   │ core/connectors.py  │
                 │ advanced_       │   │ SSRF guard · DNS    │
                 │ features.py     │   │ ports · TLS · crt.sh│
                 │ SIEM · SOAR ·   │   │ fuzzing · VT · NVD  │
                 │ PDF · triage    │   └──────┬──────────────┘
                 └─────────────────┘          │
                                              │
   GitHub Actions cron ──► core/scheduler.py ─┤
   (every 30 minutes)      core/confidence.py │
                           core/hunter.py     │
                           core/reporter.py   │
                           core/db.py ◄───────┘
                                 │
                          mhzaly_soc.db  (committed state)
```

Full module map and data flow: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Quick start

### Streamlit Community Cloud (recommended)

1. Point Streamlit Cloud at this repository, main file `app.py`.
2. **App settings → Secrets** and paste:

```toml
APP_USERNAME = "your-operator-name"
APP_PASSWORD = "a-long-random-passphrase"

# Optional integrations — features degrade gracefully when empty
GROQ_API_KEY = ""
VIRUSTOTAL_API_KEY = ""
ABUSEIPDB_API_KEY = ""
NVD_API_KEY = ""
ZOOMEYE_API_KEY = ""
DISCORD_WEBHOOK_URL = ""

SESSION_TIMEOUT_MINUTES = 30
MAX_ACTIVE_SCANS_PER_DAY = 100
```

The app will not render a login screen if `APP_USERNAME` / `APP_PASSWORD` are missing — there is no
default credential.

### Local

```bash
git clone https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai.git
cd mhzaly-soc-security-ai
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
mkdir -p .streamlit && cp secrets.toml.example .streamlit/secrets.toml   # then edit it
streamlit run app.py
```

The dashboard ships with a dark theme in `.streamlit/config.toml`, so local and deployed
environments render identically.

---

## 24/7 autonomous SOC

`.github/workflows/soc_scan.yml` runs every 30 minutes, scans every active target, and commits the
updated `mhzaly_soc.db` back to `main`. Findings alert to Discord only when they clear the
verification and confidence gates.

```bash
python -m core.scheduler add example.com 30     # monitor every 30 minutes
python -m core.scheduler list                   # show monitored targets
python -m core.scheduler scan-once example.com  # single scan
python -m core.scheduler run-all-once           # what CI runs
python -m core.scheduler run                    # long-lived loop for a VPS
python -m core.scheduler remove 2               # deactivate (history preserved)
```

Repository secrets (Settings → Secrets and variables → Actions): `DISCORD_WEBHOOK_URL`,
`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `NVD_API_KEY`, `ZOOMEYE_API_KEY` — all optional.

> `mhzaly_soc.db` is tracked in git on purpose: it is the platform's persistent state and the cron job
> commits it. Do not add it to `.gitignore`.

---

## Reports

Reports are written by `core/reporter.py` in a consultant voice, not a scanner voice.

- **With `GROQ_API_KEY`:** the Human Council assembles three perspectives — consultant (evidence-led),
  red team (exploit-first), blue team (detection-first) — and arbitrates them into one executive
  assessment.
- **Without a key:** a deterministic local narrative is produced from the same evidence. No network
  call, no placeholder text, no fabricated identifiers.
- **Every report** passes through `humanize()`, which strips chatbot tells, and
  `check_hallucinations()`, which flags CVE IDs or IPs that do not appear in the evidence bundle.

---

## Quality gates

CI runs exactly these commands on every push and pull request:

```bash
python -m pytest     # 95 tests
ruff check .         # zero findings
```

CodeQL analysis runs on push, pull request, and a weekly schedule. Dependabot keeps Python and
GitHub Actions dependencies current.

---

## Repository layout

```
app.py                    Streamlit dashboard — auth, quota, all modules
core/
  connectors.py           SSRF guard, DNS/TLS/port scanning, crt.sh, threat intelligence
  hunter.py               verified web surface: headers, cookies, TLS, crawl, leak signatures, email auth
  confidence.py           scoring, de-duplication, suppression gate
  reporter.py             human-voice reports, Human Council, hallucination guard
  scheduler.py            autonomous scan loop + CLI (used by GitHub Actions)
  db.py                   SQLite persistence, fingerprint de-duplication, confidence columns
  notifier.py             Discord alerting with retry and 429 back-off
  advanced_features.py    SIEM fan-out, SOAR, OWASP/MITRE, PDF, triage briefs
dashboard_tab.py          reusable SOC dashboard snippet
docs/ARCHITECTURE.md      module map, data flow, security controls
tests/                    pytest suite (95 tests)
.streamlit/config.toml    dark theme and server settings
```

---

## Contributing

Setup, design principles and review expectations are documented in [CONTRIBUTING.md](CONTRIBUTING.md).
Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

Security issues in this project itself must be reported privately — see [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE).
