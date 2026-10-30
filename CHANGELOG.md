# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · [SemVer](https://semver.org/).

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
