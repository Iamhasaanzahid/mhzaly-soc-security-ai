"""
orchestrator.py — Coordinates the AI Security Engineer agent pipeline.

Pipeline: ReconAgent -> TriageAgent -> CorrelationAgent
(RemediationAgent and ReportAgent slot in the same way once built.)
"""

from __future__ import annotations
from dataclasses import dataclass, field

from sec_agents.base_agent import AgentResult, ActionRisk
from sec_agents.recon_agent import ReconAgent
from sec_agents.triage_agent import TriageAgent
from sec_agents.correlation_agent import CorrelationAgent


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
        self.context: dict = {}

    def run_pipeline(self, target: str) -> PipelineRun:
        run = PipelineRun(target=target)
        self.context = {}

        recon_result = ReconAgent(self.context).run(target)
        run.add(recon_result)
        self.context["recon_agent_findings"] = recon_result.findings

        triage_result = TriageAgent(self.context).run(target)
        run.add(triage_result)
        self.context["triage_agent_findings"] = triage_result.findings

        correlation_result = CorrelationAgent(self.context).run(target)
        run.add(correlation_result)
        self.context["correlation_agent_findings"] = correlation_result.findings

        return run

    def execute_approved_action(self, action: dict) -> str:
        """Called only after a human clicks 'Approve' in the Streamlit UI."""
        return f"Executed: {action['command']}"
