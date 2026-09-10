"""
dashboard_tab.py — Paste this module's function into your existing app.py
and add "Autonomous SOC" to the sidebar radio menu, then call
render_autonomous_tab() when that menu item is selected.

This tab is READ-ONLY against the scheduler's SQLite DB (mhzaly_soc.db) —
it never runs scans itself, it just shows what the background scheduler
(scheduler.py, running separately) has already found. That separation is
the whole point: Streamlit stays fast and stateless, scheduler.py does the
24/7 work.
"""

import streamlit as st
import pandas as pd
import db  # the persistence module shared with scheduler.py


def render_autonomous_tab():
    st.markdown("# Autonomous SOC — Live Monitoring")
    st.markdown(
        "<p style='color:#9ca3af;'>Background scheduler scans these targets on "
        "its own schedule and pushes new findings to Discord. This view is read-only.</p>",
        unsafe_allow_html=True,
    )

    db.init_db()

    with st.expander("➕ Add a target to autonomous monitoring"):
        col1, col2 = st.columns([3, 1])
        with col1:
            new_target = st.text_input("Domain or IP", key="new_auto_target")
        with col2:
            interval = st.number_input("Scan every (min)", min_value=5, value=60, key="new_auto_interval")
        if st.button("Add Target", use_container_width=True):
            if new_target:
                ok = db.add_target(new_target, int(interval))
                st.success(f"Added {new_target}.") if ok else st.warning("Already being monitored.")

    targets = db.list_targets()
    st.markdown("### Monitored Targets")
    if targets:
        df = pd.DataFrame(targets)[["id", "target", "scan_interval_minutes", "last_scanned_at", "active"]]
        st.dataframe(df, use_container_width=True)

        remove_id = st.number_input("Deactivate target ID", min_value=0, value=0)
        if st.button("Deactivate") and remove_id > 0:
            db.remove_target(int(remove_id))
            st.rerun()
    else:
        st.info("No targets yet — add one above, or run: `python3 scheduler.py add <domain>`")

    st.markdown("### Recent Findings")
    findings = db.recent_findings(limit=100)
    if findings:
        fdf = pd.DataFrame(findings)[["target", "category", "severity", "summary", "first_seen", "last_seen"]]
        sev_filter = st.multiselect("Filter by severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                                     default=["CRITICAL", "HIGH", "MEDIUM"])
        if sev_filter:
            fdf = fdf[fdf["severity"].isin(sev_filter)]
        st.dataframe(fdf, use_container_width=True)
    else:
        st.info("No findings recorded yet — the scheduler needs at least one scan cycle to complete.")

    st.markdown("### Recent Scan Runs")
    runs = db.recent_scan_runs(limit=20)
    if runs:
        rdf = pd.DataFrame(runs)[["target", "started_at", "status", "new_findings_count", "error"]]
        st.dataframe(rdf, use_container_width=True)
    else:
        st.info("Scheduler hasn't run yet. Start it with: `python3 scheduler.py run`")
