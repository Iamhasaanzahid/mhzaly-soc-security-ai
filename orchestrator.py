"""
orchestrator.py — Coordinates the AI Security Engineer agent pipeline.

Pipeline (sequential, each stage feeds context to the next):
    ReconAgent -> TriageAgent -> CorrelationAgent -> ResearchAgent
        -> RemediationAgent (proposes only) -> ReportAgent

Dangerous/Review-risk actions are collected into a single approval queue
instead of being executed inline — the Streamlit dashboard renders that
queue for a human to approve/reject before anything touches real infra.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from agents.base_agent import AgentResult, ActionRisk

# Import agents as you build them out; triage_agent is implemented as an example.
from agents.triage_agent import TriageAgent
# from agents.recon_agent import ReconAgent
# from agents.correlation_agent import CorrelationAgent
# from agents.research_agent import ResearchAgent
# from agents.remediation_agent import RemediationAgent
# from agents.report_agent import ReportAgent


@dataclass
class PipelineRun:
    target: str
    results: list[AgentResult] = field(default_factory=list)
    pending_approvals: list[dict] = field(default_factory=list)

    def add(self, result: AgentResult) -> None:
        self.results.append(result)
        for action in result.proposed_actions:
            if action.risk in (ActionRisk.REVIEW, ActionRisk.DANGEROUS) and action.requires_approval:
                self.pending_approvals.append({
                    "agent": result.agent_name,
                    "target": result.target,
                    "description": action.description,
                    "risk": action.risk.value,
                    "command": action.command,
                    "rationale": action.rationale,
                })


class Orchestrator:
    def __init__(self):
        # context is shared mutable state passed to every agent; each agent
        # reads what prior agents wrote and adds its own `<name>_findings` key
        self.context: dict[str, Any] = {}

    def run_pipeline(self, target: str) -> PipelineRun:
        run = PipelineRun(target=target)

        # Stage 1: Recon (stub until recon_agent.py is wired in)
        # recon_result = ReconAgent(self.context).run(target)
        # run.add(recon_result)
        # self.context["recon_agent_findings"] = recon_result.findings

        # Stage 2: Triage
        triage_result = TriageAgent(self.context).run(target)
        run.add(triage_result)
        self.context["triage_agent_findings"] = triage_result.findings

        # Stage 3+: Correlation, Research, Remediation, Report
        # (add as each agent module is built — same run/add pattern)

        return run

    def execute_approved_action(self, action: dict) -> str:
        """
        Called only after a human clicks 'Approve' in the Streamlit UI.
        Executes exactly the reviewed command — no re-interpretation, no
        silent escalation beyond what was shown for approval.
        """
        # Real execution (e.g. subprocess to ufw/iptables) goes here,
        # gated behind explicit config (dry_run flag) and full audit logging.
        return f"Executed: {action['command']}"
