# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · [SemVer](https://semver.org/).

## [18.3.0] — 2026-10-31

Precision and report-quality release. The platform now reports *fewer* findings
and stands behind all of them.

### Added

- `core/confidence.py` — verification gate. Every candidate finding is scored
  0–100, de-duplicated, and filtered by a confidence floor (default 70) and a
  severity floor (default MEDIUM). Findings below the floor are counted and
  dropped, so the report is short enough to read.
- `core/hunter.py` — verified web-surface hunter: header grading, cookie-flag
  analysis, real certificate validation, CORS check, bounded same-origin crawl
  (links, forms, parameters, comments, technologies), robots/sitemap mining,
  SPF/DMARC review, dangling-CNAME takeover check, and sensitive-path probing
  that calibrates soft-404 behaviour first and requires a content signature
  (`.env` → `KEY=VALUE`, `.git/config` → `[core]`, `phpinfo()` output, etc.).
- `core/reporter.py` — human-voice report writer. Consultant-style system
  prompt, deterministic local narrative when no LLM key is configured, an
  `humanize()` pass that strips chatbot tells, and `check_hallucinations()`
  which flags CVE IDs or IPs in the text that are not in the evidence bundle.
- 36 new tests (94 total) covering scoring, suppression, header grading,
  cookie analysis, surface parsing, leak signatures, soft-404 detection and
  the report writer.

### Fixed

- `scheduler.alert_finding()` called itself as its first statement — every new
  finding raised `RecursionError` and aborted the rest of the scan cycle.
  It now delegates to `safe_notify_alert()`.
- `connectors.check_ssl()` disabled hostname checking *and* verification, so an
  expired or self-signed certificate was returned as `valid: True`. It now uses
  the default verifying context and reports `untrusted`, `expired` and
  `days_left`.
- `connectors.nvd_search()` set `match_confidence: "cpe"` for every keyword hit
  whenever strict mode was on — the flag described the caller's setting rather
  than the evidence. CPE labels are now only emitted when a CPE entry in the
  CVE's configuration block actually matches.
- `connectors.fuzz_endpoints()` treated catch-all / soft-404 pages as exposed
  files. It now takes a baseline probe first and drops near-identical
  responses.

### Changed

- The scheduler runs candidates through the confidence gate before persisting
  or alerting. Alerts require a verified finding with confidence ≥ 80 and
  severity ≥ MEDIUM; everything else is recorded in the run log only.
- Subdomain enumeration is inventory, not findings — the report no longer
  fills up with hundreds of hostnames nobody reads.
- `generate_triage_brief()` and the Streamlit assessment report use the new
  consultant prompt and run their output through `humanize()`.

## [18.2.0] — 2026-10-30

Reliability + data-quality release.

### Fixed

- Autonomous scan pipeline died on a bad Discord webhook (`core/notifier.py` only
  caught `ConnectionError`/`Timeout`, so `requests.InvalidSchema` — raised for the
  invalid webhook value — escaped, aborted `run_scan_cycle()`, made the GitHub Actions
  job exit 1 and skipped the DB commit step).
- Webhook URLs validated (`https://discord.com/api/webhooks/…` allow-list) before use;
  `send_discord_*()` never raise; notifications isolated via `safe_notify_*`.
- `run-all-once` / `run_forever` tolerate per-target failures; `remove` now soft-deletes.

### Fixed

- crt.sh subdomain false positives via `core.connectors.is_valid_hostname()`
  (dot-boundary + label validation). Four junk rows already persisted into
  `mhzaly_soc.db` were removed.

### Changed

- Removed three duplicate app copies; trimmed unused requirements; updated `.gitignore`.

### Added

- 58-test pytest suite + CI workflow (ruff + pytest), LICENSE, SECURITY.md,
  CHANGELOG.md, docs/ARCHITECTURE.md, config.example.json, README.md.

## [18.3.0] — 2026-10-30

### Added
- **AI Triage Copilot** (`core/advanced_features.generate_triage_brief` + new
  `🤖 AI Triage Copilot` Streamlit module): turns any validated finding into a
  structured analyst brief — executive summary, candidate Sigma rule, MITRE ATT&CK
  mapping, containment playbook and remediation steps — via Groq (with fallback).

## [18.1.0]

### Fixed
- CVE matching: ambiguous keywords (`react`, `express`, `django`, `cloudflare`, …)
  now require an authoritative CPE vendor.

## [18.0.0]

### Added
- Hardened SaaS build: operator login, session timeout, scan quota, SSRF guard,
  retry helper, TTL cache.
