# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 18.2.x  | ✅ |
| < 18.2  | ❌ (earlier builds could write invalid recon data and abort the scan pipeline) |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

- Open a private [security advisory](https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai/security/advisories/new), or
- Contact the maintainer directly on GitHub ([@Iamhasaanzahid](https://github.com/Iamhasaanzahid)).

Include: affected version/commit, reproduction steps, impact, and any suggested fix.

## Scope

In scope:

- `app.py` — authentication, session handling, scan quota, the HTTP repeater
- `core/connectors.py` — SSRF guard, hostname validation, outbound requests
- `core/scheduler.py`, `core/notifier.py`, `core/db.py` — autonomous pipeline
- `.github/workflows/*` — supply-chain / secret exposure in CI

Out of scope: findings that require the operator to intentionally paste secrets into the UI, and vulnerabilities in third-party APIs (VirusTotal, NVD, crt.sh, …).

## Secrets handling

- Real credentials live **only** in Streamlit secrets (`.streamlit/secrets.toml`) or GitHub Actions secrets.
- `config.json`, `.env`, and `.streamlit/secrets.toml` are git-ignored. Never commit them.
- If a token or webhook URL is ever committed or printed in a log, **rotate it** — removing the commit is not enough.
- Actionable-URL fields (webhook targets) are validated against an allow-list so the notifier cannot be pointed at arbitrary hosts.

## Deploying safely

- Always set `APP_USERNAME` / `APP_PASSWORD`; the app refuses to start without them.
- Keep `MAX_ACTIVE_SCANS_PER_DAY` and `SESSION_TIMEOUT_MINUTES` at sane values.
- Only scan assets you are authorized to test. The SSRF guard blocks private, loopback, link-local, reserved and cloud-metadata addresses, but authorization is your responsibility.
