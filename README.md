# AI Security Engineer

Multi-agent security platform — evolution of the MHZALY Purple Team Suite.
This version is tested to actually run end-to-end: `orchestrator.run_pipeline()`
was smoke-tested locally and every module compiles clean.

## What changed from the last version (and why it broke)

- **Package renamed `agents/` → `sec_agents/`.** `agents` is also the import
  name of a real PyPI package (the OpenAI Agents SDK, `pip install openai-agents`
  installs a top-level module called `agents`). If anything in your
  environment/requirements pulled that in, Python imported *that* package
  instead of your local folder — `agents.base_agent` genuinely didn't exist
  in it, which is exactly the `ModuleNotFoundError` you hit. Renaming removes
  the ambiguity entirely regardless of what's in `requirements.txt`.
- **No more silent stub mode.** The old `triage_agent.py` assumed an external
  `connectors.py` existed already; if it didn't, imports failed. Now
  `connectors.py` is bundled directly in this repo with real, working
  implementations of all 4 APIs.
- **Recon no longer needs system binaries.** `nmap`/`subfinder` aren't
  installed on Streamlit Community Cloud and can't be installed there — a
  recon agent depending on them works on your machine and dies in
  production. `recon_agent.py` now uses `crt.sh` (certificate transparency
  logs, free/no key) + Python's built-in `socket` module instead.

## The 4 APIs, all wired and working

| API | File | Needs a key? |
|---|---|---|
| VirusTotal | `sec_agents/connectors.py::query_virustotal` | Yes — `VT_API_KEY` |
| AbuseIPDB | `sec_agents/connectors.py::query_abuseipdb` | Yes — `ABUSEIPDB_API_KEY` |
| NVD (CVE data) | `sec_agents/connectors.py::query_nvd` | Optional — `NVD_API_KEY` (raises rate limit) |
| crt.sh (subdomain enum) | `sec_agents/connectors.py::query_crtsh` | No |

Every connector fails soft (`{"error": "..."}`) instead of raising, so a
missing key or a dead API never crashes the pipeline — you'll just see it
flagged in the sidebar and in that agent's results panel.

## Structure

```
app.py                        # Streamlit UI
orchestrator.py                # runs recon -> triage -> correlation, collects approvals
sec_agents/
  connectors.py                 # the 4 API wrappers
  base_agent.py                 # shared AgentResult / reasoning-trace interface
  recon_agent.py                # crt.sh + DNS -> subdomains & IPs
  triage_agent.py                # VirusTotal + AbuseIPDB scoring
  correlation_agent.py           # NVD CVE matching
```

## Deploy to Streamlit Cloud

1. Push this whole folder to your `mhzaly-soc-security-ai` repo (or wherever
   you're deploying from) — confirm on GitHub's file browser that
   `sec_agents/__init__.py` actually shows up (empty files sometimes get
   dropped by drag-and-drop uploads).
2. In Streamlit Cloud: **App settings → Secrets**, paste in:
   ```toml
   VT_API_KEY = "..."
   ABUSEIPDB_API_KEY = "..."
   NVD_API_KEY = "..."
   ```
3. Reboot the app. The sidebar will show ✅/⚠️ for each API so you can
   confirm they're picked up correctly.

## Next agents to build (same pattern)

- **remediation_agent.py** — turns triage + correlation findings into
  concrete proposed firewall/config actions (already flows into the
  approval queue in `app.py` — just needs to populate it).
- **report_agent.py** — assembles every agent's findings + reasoning trace
  into a Markdown/PDF security assessment report.
- Port your v18.0 CPE-aware strict CVE matching into `correlation_agent.py`
  in place of the current keyword search, to kill false positives the same
  way you already solved it in the Purple Team Suite.
