"""
app.py — AI Security Engineer control room (Streamlit).

Run: streamlit run app.py
"""

import streamlit as st
from orchestrator import Orchestrator

st.set_page_config(page_title="AI Security Engineer", layout="wide")
st.title("🛡️ AI Security Engineer")
st.caption("Multi-agent autonomous security platform — recon, triage, correlation, remediation, reporting.")

if "orchestrator" not in st.session_state:
    st.session_state.orchestrator = Orchestrator()
if "last_run" not in st.session_state:
    st.session_state.last_run = None

target = st.text_input("Target (domain / IP)", placeholder="example.com")

col1, col2 = st.columns([1, 3])
with col1:
    run_clicked = st.button("Run pipeline", type="primary", disabled=not target)

if run_clicked and target:
    with st.spinner("Running agent pipeline..."):
        st.session_state.last_run = st.session_state.orchestrator.run_pipeline(target)

run = st.session_state.last_run
if run:
    st.subheader("Agent results")
    for result in run.results:
        with st.expander(result.summary_line(), expanded=False):
            st.write("**Findings**")
            st.json(result.findings)
            st.write("**Reasoning trace**")
            for step in result.reasoning:
                st.markdown(
                    f"- **Evidence:** {step.evidence}\n"
                    f"  **Interpretation:** {step.interpretation} "
                    f"(_confidence: {step.confidence.value}_)"
                )
                if step.alternatives_considered:
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
                st.markdown(f"**{action['description']}**  \n"
                            f"Risk: `{action['risk']}` · Agent: `{action['agent']}`")
                st.code(action["command"] or "", language="bash")
                st.caption(action["rationale"])
                c1, c2 = st.columns(2)
                if c1.button("Approve & execute", key=f"approve_{i}"):
                    outcome = st.session_state.orchestrator.execute_approved_action(action)
                    st.success(outcome)
                if c2.button("Reject", key=f"reject_{i}"):
                    st.info("Rejected — no action taken.")
