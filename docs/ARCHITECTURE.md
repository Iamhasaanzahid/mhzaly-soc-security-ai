# MHZALY Enterprise SOC & Bug Bounty AI Platform — Architecture

This document maps the codebase as it exists on `main` (v18.2).

## Layers

```
┌─────────────────────────── 1. PRESENTATION ───────────────────────────┐
│ app.py (Streamlit)                                                    │
│   main() → auth gate → module router (st.radio)                     │
│   module tabs delegate to render_* functions / engines               │
└───────────────────────────────────────────────────────────────────────┘
                              │ (calls)
┌─────────────────────────── 2. APPLICATION ───────────────────────────┐
│ core/advanced_features.py   SIEM fan-out, SOAR, OWASP/MITRE, PDF,   │
│                               email reports                            │
│ core/engines (inside app.py)  Recon, threat intel, analyst narrator  │
└───────────────────────────────────────────────────────────────────────┘
                              │ (uses)
┌─────────────────────────── 3. INFRA / DATA ───────────────────────────┐
│ core/connectors.py  → outbound requests (DNS, ports, TLS, ct.sh, VT,  │
│                       NVD, AbuseIPDB, ZoomEye) + SSRF guard            │
│ core/db.py          → SQLite schema, fingerprints, scan runs         │
│ core/notifier.py    → Discord webhook, retry, 429 back-off, URL check │
│ core/scheduler.py   → autonomous loop / CLI / scan cycle              │
└───────────────────────────────────────────────────────────────────────┘
```

## Module map

| Module | Responsibility | Key entry points |
|---|---|---|
| `app.py` | UI shell, auth, quota, session | `main()`, engine classes |
| `core/connectors.py` | All external surface interaction | `assert_public_host`, `clean_host`, `crtsh_subdomains`, `fuzz_endpoints`, threat-intel checkers |
| `core/db.py` | Persistence | `init_db`, `add_target`, `upsert_finding`, `recent_findings`, forensics |
| `core/notifier.py` | Alerts | `send_discord_alert`, `send_discord_text`, `is_valid_webhook_url`, `_post_with_rate_limit_retry` |
| `core/scheduler.py` | Autonomous loop | `run_scan_cycle`, `run_forever`, CLI subcommands, `safe_notify_*` |
| `core/advanced_features.py` | Cross-cutting artifacts | `generate_remediation_script`, `map_owasp_top_10`, `map_mitre_attck`, `generate_waf_rules`, `generate_pentest_plan`, `send_multi_siem_alert` |

## Scan cycle (`run_scan_cycle`)

1. `host = clean_host(target)`
2. `start_scan_run(...)`
3. SSRF guard → `assert_public_host(host)`; blocked → DB status `BLOCKED`, notify, return
4. deterministic steps: DNS, ports, TLS
5. findings → `db.upsert_finding(...)` — only `True` on genuinely new fingerprint → alert
6. crt.sh subdomain → fuzz endpoints → VT → NVD (CPE-confirmed) → ZoomEye
7. `mark_scanned` + `finish_scan_run(status=SUCCESS, new_count=…)`
8. any exception → `finish_scan_run(status=ERROR, error=…)` + best-effort alert (never re-raise into CI)

## Security controls

| Control | Where | Effect |
|---|---|---|
| No default credentials | `secrets.toml.example`, login gate | App refuses to run without operator secrets |
| Password hashing | `hmac.compare_digest` (not `==`) | Login |
| Brute-force lockout | 5 attempts → 60 s lock | Login |
| Session expiry | idle timeout from secrets | Session |
| Scan quota | per operator per day | Courtesy guard |
| SSRF guard | `core/connectors.py::assert_public_host` | Blocks private/loopback/link-local/reserved/metadata IPs |
| Webhook URL allow-list | `core/notifier.py::is_valid_webhook_url` | Blocks placeholders/foreign hosts before request |
| Webhook retry | `core/notifier.py::_post_with_rate_limit_retry` | 2 attempts + Discord 429 back-off |
| Alert isolation | `core/scheduler.py::safe_notify_*` | Notification failure never aborts a scan |
| Input validation | `validate_target_input`, `is_valid_hostname` | Rejects malformed/whitespace/injection-shaped targets |

## Data model (SQLite, `mhzaly_soc.db`)

- `targets` (id, target, interval, last_scanned_at, active, created_at)
- `scan_runs` (run_id, target_id, started_at, finished_at, status, new_findings_count, error)
- `findings` (id, target_id, category, fingerprint UNIQUE, summary, details JSON, severity, first_seen, last_seen)
- `forensics_artifacts` (artifact_type, artifact_value, severity, case_notes, logged_at)

Filenames are **relative** to CWD — `python3 core/scheduler.py …` must run from repo root.

## Known technical debt / roadmap

- `app.py` is 2.4k lines; the recon engines could be split into `core/engines.py`.
- One workflow commit per scan run still floods history (DB blob is binary).
- NVD keyword-matching is deliberately conservative (strict CPE) for unattended alerts.
