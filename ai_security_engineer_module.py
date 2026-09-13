"""
AI SECURITY ENGINEER MODULE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Paste this function into your existing mhzaly_platform file (the one
that's actually deployed). It reuses your EXISTING classes
(BugBountyReconEngine, ThreatIntelService, NVDIntelligenceClient) —
no new imports, no new files, nothing that can break on import paths.

Then wire it in with 2 small edits (shown at the bottom of this file).
"""

def render_ai_security_engineer(vt_key, abuse_key, nvd_key, groq_key, db):
    st.markdown("# 🤖 AI Security Engineer")
    st.markdown(
        "<p style='color: #9ca3af;'>Autonomous multi-agent pipeline: deep recon → "
        "real-time threat triage → NVD correlation → AI-driven remediation strategy "
        "→ professional assessment report. Every recommendation is proposed with "
        "reasoning and confidence — nothing is auto-executed without your approval.</p>",
        unsafe_allow_html=True,
    )

    target = st.text_input("Target Domain or IP", placeholder="e.g., target-domain.com", key="ase_target")

    if st.button("Run AI Security Engineer Pipeline", use_container_width=True, key="ase_run"):
        if not target:
            st.warning("Please specify a target.")
            return

        db.log_activity("AI Security Engineer", target, "Initiated")

        # ── Agent 1: Recon (reuses your existing engine) ──────────────────
        with st.spinner("Agent 1/4 — Recon: mapping attack surface..."):
            recon_res = BugBountyReconEngine.deep_recon(target)

        # ── Agent 2: Triage (reuses your existing VT/AbuseIPDB service) ───
        with st.spinner("Agent 2/4 — Triage: querying VirusTotal + AbuseIPDB..."):
            ti = ThreatIntelService(vt_key, abuse_key)
            ti_res = ti.triage_indicator(target)

        # ── Agent 3: Correlation (reuses your existing NVD client) ────────
        with st.spinner("Agent 3/4 — Correlation: matching NVD CVE data..."):
            clean_target = target.replace('https://', '').replace('http://', '').split('/')[0]
            domain_keyword = clean_target.split('.')[0] if '.' in clean_target else clean_target
            nvd_query_term = recon_res.get('technologies', [None])[0] or domain_keyword
            nvd = NVDIntelligenceClient(nvd_key)
            cve_res = nvd.search_cve(nvd_query_term, max_results=8)
            if not cve_res and domain_keyword != nvd_query_term:
                cve_res = nvd.search_cve(domain_keyword, max_results=8)

        st.success("Recon, triage, and correlation complete. Synthesizing analysis...")

        c1, c2, c3 = st.columns(3)
        c1.metric("VT Malicious Detections", ti_res['vt_summary']['malicious'])
        c2.metric("Abuse Confidence Score", f"{ti_res['abuse_summary']['score']}%")
        c3.metric("Correlated High-Sev CVEs", len([c for c in cve_res if c.cvss_score >= 7.0]))

        # ── Agent 4: AI reasoning + proactive remediation (Groq) ──────────
        reasoning_trace = []
        proposed_actions = []
        executive_summary = "AI synthesis unavailable — GROQ_API_KEY not configured."

        if groq_key:
            with st.spinner("Agent 4/4 — AI Engineer: reasoning about findings & drafting remediation..."):
                context = f"""
Target: {target}
VirusTotal malicious detections: {ti_res['vt_summary']['malicious']} / reputation: {ti_res['vt_summary']['reputation']}
AbuseIPDB confidence score: {ti_res['abuse_summary']['score']}% / reports: {ti_res['abuse_summary']['reports']}
Detected technologies: {recon_res.get('technologies', [])}
Exposed endpoints/files: {recon_res.get('exposed_files', [])}
HTTP status: {recon_res.get('status_code')} / Server: {recon_res.get('server')}
Correlated CVEs: {[{'id': c.cve_id, 'cvss': c.cvss_score, 'severity': c.severity} for c in cve_res]}
"""
                system_prompt = (
                    "You are an AI Security Engineer performing autonomous contextual "
                    "reasoning over recon/triage/CVE telemetry. Respond ONLY with valid JSON "
                    "(no markdown fences, no prose outside the JSON) matching this schema: "
                    '{"executive_summary": "2-3 sentences", '
                    '"reasoning_trace": [{"evidence": "...", "interpretation": "...", '
                    '"confidence": "low|medium|high", "alternative_considered": "..."}], '
                    '"proposed_actions": [{"description": "...", "risk": "safe|review|dangerous", '
                    '"command_or_change": "...", "rationale": "..."}]}. '
                    "Proposed actions are recommendations only — never assume they will be "
                    "auto-executed. Flag anything touching firewall rules, blocking IPs, or "
                    "disabling services as risk: dangerous or review, and always give a rationale "
                    "grounded in the specific telemetry provided, not generic advice."
                )
                try:
                    headers = {'Authorization': f'Bearer {groq_key}', 'Content-Type': 'application/json'}
                    payload = {
                        'model': 'openai/gpt-oss-120b',
                        'messages': [
                            {'role': 'system', 'content': system_prompt},
                            {'role': 'user', 'content': f"Analyze this telemetry:\n{context}"},
                        ],
                        'temperature': 0.3,
                        'max_tokens': 2000,
                    }
                    resp = requests.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        json=payload, headers=headers, timeout=30,
                    )
                    if resp.status_code == 200:
                        raw = resp.json()['choices'][0]['message']['content']
                        raw_clean = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                        parsed = json.loads(raw_clean)
                        executive_summary = parsed.get("executive_summary", executive_summary)
                        reasoning_trace = parsed.get("reasoning_trace", [])
                        proposed_actions = parsed.get("proposed_actions", [])
                    else:
                        executive_summary = f"Groq API error {resp.status_code}: {resp.text[:200]}"
                except (json.JSONDecodeError, KeyError, requests.RequestException) as e:
                    executive_summary = f"AI synthesis failed ({e}) — showing raw telemetry only below."

        st.markdown("---")
        st.markdown("### 🧠 Executive Summary")
        st.info(executive_summary)

        if reasoning_trace:
            st.markdown("### Reasoning Trace")
            for step in reasoning_trace:
                st.markdown(
                    f"- **Evidence:** {step.get('evidence', '')}\n"
                    f"  **Interpretation:** {step.get('interpretation', '')} "
                    f"(_confidence: {step.get('confidence', 'unknown')}_)"
                )
                if step.get('alternative_considered'):
                    st.caption(f"Alternative considered: {step['alternative_considered']}")

        if proposed_actions:
            st.markdown("### ⚠️ Proposed Remediation Actions (require your approval)")
            for i, action in enumerate(proposed_actions):
                with st.container(border=True):
                    st.markdown(f"**{action.get('description', '')}**  \nRisk: `{action.get('risk', 'unknown')}`")
                    if action.get('command_or_change'):
                        st.code(action['command_or_change'])
                    st.caption(action.get('rationale', ''))
                    ac1, ac2 = st.columns(2)
                    if ac1.button("Approve (log only — does not execute)", key=f"ase_approve_{i}"):
                        db.log_activity("AI Security Engineer - Approved Action", action.get('description', ''), "Approved (manual)")
                        st.success("Logged as approved. Execute manually per your ops process.")
                    if ac2.button("Reject", key=f"ase_reject_{i}"):
                        st.info("Rejected — no action taken.")

        # ── Report assembly ────────────────────────────────────────────
        cve_list_md = "\n".join(
            [f"- **{c.cve_id}** (CVSS {c.cvss_score} - {c.severity}): {c.description}" for c in cve_res]
        ) if cve_res else "No correlated CVEs found."
        actions_md = "\n".join(
            [f"- **{a.get('description')}** (`{a.get('risk')}`): {a.get('rationale')}" for a in proposed_actions]
        ) if proposed_actions else "No remediation actions proposed."

        report_md = f"""# AI SECURITY ENGINEER — ASSESSMENT REPORT
**Target:** `{target}`
**Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`

## Executive Summary
{executive_summary}

## Threat Intelligence
- VirusTotal malicious detections: {ti_res['vt_summary']['malicious']}
- AbuseIPDB confidence score: {ti_res['abuse_summary']['score']}%

## Correlated Vulnerabilities
{cve_list_md}

## Proposed Remediation (pending human approval)
{actions_md}

---
*Generated by MHZALY AI Security Engineer*
"""
        st.markdown("---")
        st.download_button(
            "Download Full Report (.md)",
            data=report_md,
            file_name=f"ai_security_engineer_report_{target.replace('/', '_')}.md",
            mime="text/markdown",
            use_container_width=True,
        )
        db.log_activity("AI Security Engineer", target, "Completed")


# ═══════════════════════════════════════════════════════════════════
# WIRING — 2 edits to your existing file
# ═══════════════════════════════════════════════════════════════════
#
# 1. In the sidebar `module = st.radio(...)` list, add this entry
#    anywhere in the list:
#
#        "AI Security Engineer",
#
# 2. In the big `if module == "..." / elif module == "..."` chain,
#    add this block (anywhere among the other elif blocks):
#
#        elif module == "AI Security Engineer":
#            render_ai_security_engineer(vt_key, abuse_key, nvd_key, groq_key, db)
#
# That's it. No new files, no new imports, no new dependencies —
# it reuses BugBountyReconEngine, ThreatIntelService, and
# NVDIntelligenceClient that are already defined earlier in this file.
