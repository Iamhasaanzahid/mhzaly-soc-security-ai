"""
app.py — AI Security Engineer control room (Streamlit).

Run: streamlit run app.py

Required secrets/env vars (set in Streamlit Cloud under Settings > Secrets,
or as environment variables locally):
    VT_API_KEY          — VirusTotal
    ABUSEIPDB_API_KEY   — AbuseIPDB
    NVD_API_KEY         — optional, raises NVD rate limit
crt.sh needs no key.
"""

import streamlit as st
from orchestrator import Orchestrator
from sec_agents import connectors

st.set_page_config(page_title="AI Security Engineer", layout="wide")
st.title("🛡️ AI Security Engineer")
st.caption("Multi-agent platform — recon, triage, correlation, remediation, reporting.")

with st.sidebar:
    st.subheader("API status")
    for name, key in [
        ("VirusTotal", "VT_API_KEY"),
        ("AbuseIPDB", "ABUSEIPDB_API_KEY"),
        ("NVD (optional)", "NVD_API_KEY"),
    ]:
        configured = connectors._get_key(key) is not None
        st.write(("✅ " if configured else "⚠️ ") + name)
    st.write("✅ crt.sh (no key required)")

if "orchestrator" not in st.session_state:
    st.session_state.orchestrator = Orchestrator()
if "last_run" not in st.session_state:
    st.session_state.last_run = None

target = st.text_input("Target domain", placeholder="example.com")
run_clicked = st.button("Run pipeline", type="primary", disabled=not target)

if run_clicked and target:
    with st.spinner("Running recon → triage → correlation..."):
        st.session_state.last_run = st.session_state.orchestrator.run_pipeline(target)

run = st.session_state.last_run
if run:
    st.subheader("Agent results")
    for result in run.results:
        with st.expander(result.summary_line(), expanded=False):
            if result.findings:
                st.write("**Findings**")
                st.json(result.findings)
            if result.reasoning:
                st.write("**Reasoning trace**")
                for step in result.reasoning:
                    st.markdown(
                        f"- **Evidence:** {step.evidence}\n"
                        f"  **Interpretation:** {step.interpretation} (_confidence: {step.confidence.value}_)"
                    )
                    for alt in step.alternatives_considered:
                        st.markdown(f"  - *Alternative considered:* {alt}")
            if result.errors:
                st.warning("\n".join(result.errors))

    st.subheader("⚠️ Pending approvals")
    if not run.pending_approvals:
        st.info("No actions awaiting approval.")
    else:
        for i, action in enumerate(run.pending_approvals):
            with st.container(border=True):
                st.markdown(f"**{action['description']}**  \nRisk: `{action['risk']}` · Agent: `{action['agent']}`")
                if action["command"]:
                    st.code(action["command"], language="bash")
                st.caption(action["rationale"])
                c1, c2 = st.columns(2)
                if c1.button("Approve & execute", key=f"approve_{i}"):
                    st.success(st.session_state.orchestrator.execute_approved_action(action))
                if c2.button("Reject", key=f"reject_{i}"):
                    st.info("Rejected — no action taken.")
