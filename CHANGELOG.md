## [21.3.0] — 2026-11-11

**Real-world front door.** The operations center now reads live data, and the
public site is a full product site instead of a placeholder.

### Added

- **Live Operations Center** — threat level, posture, verified-finding count,
  active targets, evidence records, chain status, last scan and 30-day change
  total, all computed from the shared database. Severity chart, recent findings
  and scan-run tables, and an engine-status row.
- **Product website** in `docs/`: responsive hero with a product preview, five
  workspace cards, proof pipeline, report sample, deployment options, FAQ,
  SEO/OpenGraph metadata, sitemap, robots, favicon, reduced-motion support and
  Netlify security headers (`docs/_headers`).

### Changed

- Version bumped to 21.3.0.

## [21.2.0] — 2026-11-06

**Proof & Posture command centre.** The proof layer is now something an auditor can
read at a glance.

### Added

- Posture history: every autonomous scan stores its score, grade and verified
  count, and the console charts the trend over time.
- Change analytics: 30-day new / resolved / escalated / de-escalated / persisting
  counters as a chart, plus a searchable event log.
- Score drivers table: each factor, the finding behind it, its rubric weight and
  the confidence that produced it.
- One-click proof-pack download (JSON) for the latest evidence-chain run.
- `db.record_posture()`, `db.posture_history()`, `db.recent_deltas()`,
  `db.delta_counters()` and `db.latest_evidence_run()`.

### Changed

- Version bumped to 21.2.0.

## [21.1.0] — 2026-11-03

**Nothing hidden.** Every module is back in the main menu, and the console can no
longer be taken down by a database import.

### Fixed

- `core.db` no longer opens SQLite at import time. The evidence ledger is created
  lazily on first use, so a read-only mount can no longer crash the whole app
  before the first page renders (this is what made the DB and the AI Security
  Engineer appear to disappear on Streamlit Cloud).
- `db.init_db()` now runs once at startup instead of only when the autonomous
  page happens to be opened, so findings, proof and report pages always have
  their schema.

### Changed

- All capabilities are listed in the sidebar again: the fifteen original modules
  plus Client Report Studio and Proof & Posture. No module is buried.
- Version bumped to 21.1.0.

## [21.0.0] — 2026-11-02

**Operator Console.** The platform now has five workspaces, a report studio that
writes like a senior consultant, and a posture score that charges each risk
factor exactly once.

### Added

- **Five workspaces** — Scan & Verify, Findings & Response, AI Reports, Arsenal,
  Proof & Platform. Every capability is grouped under a specific home instead of
  a 17-item menu.
- **Client Report Studio** — a signed, proof-carrying client document built from
  verified findings only: findings-at-a-glance table, analyst narrative,
  remediation order, change-since-last-assessment, evidence-chain statement,
  Markdown and PDF export.
- Deterministic Markdown-to-PDF renderer for client reports.

### Fixed

- `posture_score()` charged each finding twice (a flat 25-point penalty before
  the rubric weight). A single verified exposure now deducts its rubric weight
  exactly once, so the score is explainable and reproducible.
- Dashboard `st.metric` calls no longer pass non-numeric "delta" values, and the
  report studio exposes the posture grade alongside the score.
- Changelog ordering is now strictly newest-first.

### Changed

- Discord/SIEM paging now defaults to **HIGH and above**; MEDIUM findings still
  land in the console and the database but no longer page a human. Override with
  `"discord_min_severity": "MEDIUM"` in config.
- AI Security Engineer now reports from the full verified finding set (exposures,
  missing headers, risky ports) and offers the composed client report as
  Markdown and PDF.
- Chatbot greeting, quick prompts and offline-state copy rewritten in the
  consultant voice.
- Version bumped to 21.0.0 across `pyproject.toml`, the UI, and user agents.

# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · [SemVer](https://semver.org/).

## [20.0.0] — 2026-11-01

**Proof-Carrying SOC.** The platform now ships verifiable evidence instead of
a good-looking report.

### Added

- `core/evidence.py` — append-only, hash-chained evidence ledger. Every
  verified finding of a scan run is committed to a hash chain that commits to its
  predecessor and to a canonical JSON payload; tampering is detectable in O(1).
- Proof-pack export per scan run (`mhzaly_soc.db` ledger + `POST /api/v1/proof-pack`
  style artifact via CLI `python -m core.scheduler export-evidence <run_id> <path>`).
- `core/delta.py` — scan-to-scan change engine: new / resolved / persisting /
  escalated / de-escalated findings with a human-voice narrative.
- `core/posture.py` — explainable 0-100 posture score with per-factor drivers.
- Human Council now includes a fourth perspective, the **Skeptic**, who challenges
  confidence before budget is committed.
- Findings in reports now carry an evidence fingerprint reference.
- New Streamlit module: **🔐 Proof & Posture** (ledger verification, posture score,
  change log).

### Changed

- Version bumped to 20.0.0 across `pyproject.toml`, UI and user agents.

## [19.0.1] — 2026-10-31

Human-voice pass. Every generated surface now goes through the same writer
instead of only the main assessment.

### Changed

- `humanize()` now swaps word-level tells for plain English (`leverage` → `use`,
  `utilize` → `use`, `delve into` → `examine`) instead of deleting them, so
  sentences stay grammatical. Filler clauses (`it is worth noting that`,
  `please note that`) are removed, chat openers and heading emoji are stripped,
  and the pass is idempotent.
- `AutonomousAgentExecutor._call_groq()` applies the human-voice pass to every
  model response before it can reach the UI, a report or a download — this
  covers the chatbot, the Sigma generator and the pipeline analysis in one
  place.
- The autonomous pipeline report is now written by `reporter.generate_report()`
  from verified findings instead of a hand-assembled banner template. The
  robot framing (`━━━` rules, ALL-CAPS classification, generated-by footer) is
  gone.
- The no-key chain-of-thought fallback reads as four short paragraphs an
  engineer would actually write, not five numbered headings with emoji.
- Chat greeting and reset copy rewritten in the same voice.

### Added

- Three regression tests for `humanize()`: grammar-preserving word swaps,
  filler and heading noise removal, and idempotence.

## [19.0.0] — 2026-10-31

Project maturity release. No behaviour change to scanning; this release makes the
platform presentable, maintainable and reviewable by people outside the project.

### Added

- **Human Council reporting** (`core/reporter.py`). Three perspectives are
  generated from the same evidence — consultant, red team, blue team — and
  arbitrated into one executive assessment. With a Groq key the arbitration is
  performed by the model; without one, `_merge_perspectives()` produces a
  deterministic local narrative. The Streamlit assessment reports
  `report_source: "Human Council"` so provenance is never ambiguous.
- **Professional documentation set**: rewritten `README.md` with CI, CodeQL,
  version and test badges; `CONTRIBUTING.md` with the project's four design
  principles; `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- **GitHub collaboration templates**: bug report and feature request issue
  forms, pull request template with an explicit precision checklist.
- **Supply-chain and code scanning**: `.github/workflows/codeql.yml`
  (security-and-quality queries on push, PR and weekly schedule) and
  `.github/dependabot.yml` for `pip` and `github-actions`.
- **Developer ergonomics**: `Makefile` (`install`, `dev`, `test`, `lint`,
  `scan`, `run`), `.pre-commit-config.yaml` (ruff, secret-key detection,
  whitespace and YAML/TOML validation).
- **Consistent rendering**: `.streamlit/config.toml` pins the dark theme and
  server settings so local and deployed builds look identical.
- Sidebar footer showing the running version and the authorized-use reminder.

### Changed

- Version bumped to `19.0.0` across `pyproject.toml`, changelog and UI.
- README now documents the precision pipeline explicitly: verification →
  confidence gate → report/alert, including the suppression path.
- Consolidated the duplicated `18.3.0` changelog section; the AI Triage Copilot
  entry now lives under `18.2.1`.

### Fixed

- Changelog contained two sections numbered `18.3.0`, which made releases
  ambiguous.

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

## [18.2.1] — 2026-10-30

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
