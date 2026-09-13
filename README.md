# AI Security Engineer

Multi-agent autonomous security platform — evolution of the MHZALY Purple Team Suite.

## What's scaffolded here

- `agents/base_agent.py` — shared interface. Every agent returns an `AgentResult`
  with findings **and** a structured reasoning trace (evidence → interpretation →
  confidence → alternatives considered). This is the "human-like contextual
  reasoning" made concrete and auditable, not just a marketing claim.
- `agents/triage_agent.py` — working example: real-time VirusTotal + AbuseIPDB
  scoring, wired to your existing `connectors.py`.
- `orchestrator.py` — runs agents in sequence, collects any `REVIEW`/`DANGEROUS`
  risk actions into a single approval queue instead of auto-executing them.
- `app.py` — Streamlit control room: run the pipeline, inspect each agent's
  reasoning, approve/reject proposed actions.

## Design principle: propose, don't auto-execute, on real infra changes

Firewall rule changes, blocking IPs, disabling services — these are `REVIEW`
or `DANGEROUS` risk actions. Agents **propose** them with rationale; nothing
touches real infrastructure until a human clicks Approve in the dashboard.
This keeps "autonomous remediation" genuinely useful without the platform
being able to take your own systems offline on a bad heuristic.

## Next agents to build (same pattern as triage_agent.py)

1. **recon_agent.py** — wraps your existing subfinder/DNS/nmap/SSL/Wappalyzer
   layer, outputs `{"ips": [...], "domains": [...], "services": [...]}` for
   triage_agent to consume.
2. **correlation_agent.py** — CPE-aware NVD matching against recon'd services
   (you already solved the false-positive matching problem in v18.0 —
   port that logic in here).
3. **research_agent.py** — searches the web for emerging CVEs/threats tied to
   the target's identified stack; this is the one agent that genuinely needs
   an LLM call (Groq gpt-oss-120b, per your existing setup) to synthesize
   open-ended research rather than deterministic API calls.
4. **remediation_agent.py** — turns triage + correlation findings into
   concrete proposed actions (firewall rule diffs, config hardening steps),
   each tagged with risk level.
5. **report_agent.py** — assembles all agents' findings + reasoning traces
   into a professional Markdown/PDF security assessment report.

## Running it

```bash
pip install streamlit
streamlit run app.py
```

(Wire in your existing `connectors.py`, `db.py`, `notifier.py` from the
Purple Team Suite repo alongside this scaffold — `triage_agent.py` already
expects `connectors.query_virustotal` / `connectors.query_abuseipdb`.)
