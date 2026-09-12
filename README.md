# MHZALY Purple Team Operations Suite — v18.1

Enterprise-style Streamlit SaaS for bug-bounty recon, SOC log triage, threat-intel
lookups, and an autonomous AI-assisted recon → CVE-correlation → report pipeline.

## Setup

```bash
pip install -r requirements.txt
mkdir -p .streamlit
cp secrets.toml.example .streamlit/secrets.toml
# edit .streamlit/secrets.toml with real values, at minimum APP_USERNAME / APP_PASSWORD
streamlit run mhzaly_platform.py
```

This file also expects three sibling modules that are imported but not
included here — `db.py`, `connectors.py`, `notifier.py`, `scheduler.py` —
which back the Autonomous SOC (Live DB) tab and the background scan
scheduler. Wire those up (or stub them) before enabling that tab.

## What changed in v18.1 vs v18.0

**Risk scoring was blind to recon findings.** `compute_risk_score` only
looked at VirusTotal/AbuseIPDB/CVE data, so a target with an exposed
`.env`/`git/config`, missing `Content-Security-Policy`/`HSTS` headers, or a
publicly reachable RDP/MySQL/Elasticsearch port could still score `0/100
LOW` — the findings were visible in the UI but the number ignored them.
Fixed: exposed files, missing headers, and risky open ports now feed the
score directly, and the Autonomous AI-Agent pipeline runs the full
infrastructure audit (not just app-layer recon) so those signals are always
collected, not just in the separate manual "Network Infrastructure Audit"
tab.

**Input validation.** Every active-scan entry point (Autonomous pipeline,
Bug Bounty Recon, Infrastructure Audit, Autonomous SOC target add) now runs
`validate_target_input()` before touching the network — rejects empty
input, embedded whitespace/control characters, and strings that aren't a
plausible domain, IPv4 address, or http(s) URL. This is a sanity/UX gate,
not a security boundary — `assert_public_host()` (the actual SSRF guard)
still runs unconditionally regardless of what passes validation.

**Session inactivity timeout.** Operators are auto-logged-out after
`SESSION_TIMEOUT_MINUTES` (default 30) of inactivity.

**Per-operator daily scan quota.** A soft, in-memory cap
(`MAX_ACTIVE_SCANS_PER_DAY`, default 100) on active-scan button presses per
operator per day, to slow down accidental quota-burning loops against
VT/AbuseIPDB/NVD/Groq or against the target itself. This resets on app
restart — for a durable cross-restart quota, back it with the `db` module's
SQLite store instead.

**NVD client hardening.** Requests now send a `User-Agent`, and `403`
responses (which NVD's unauthenticated tier returns almost as often as
`429` once rate-limited) are treated as a back-off signal instead of a
silent empty result.

**CSV export.** The Autonomous pipeline report now also exports a flat CSV
of CVE findings, in addition to the existing Markdown/JSON downloads.

## Known gaps / suggested next steps

- The per-operator scan quota and session timeout are process-local
  (in-memory). If you run multiple app instances behind a load balancer,
  back both with the `db` SQLite store (or an external cache) so they're
  consistent across instances.
- `db.py`, `connectors.py`, `notifier.py`, `scheduler.py` weren't in scope
  for this pass — worth the same validation/quota treatment if they accept
  user-controlled input anywhere (e.g. the scheduler's background scan
  loop should also run targets through `validate_target_input`).
- Consider persisting an audit trail (operator, target, timestamp, action)
  for every manual scan button press, not just autonomous scheduler runs —
  useful for accountability if the platform is ever misused, and it's a
  natural fit for the existing SQLite `db` module.
