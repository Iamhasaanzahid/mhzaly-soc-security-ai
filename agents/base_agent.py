"""
base_agent.py — Shared interface for all AI Security Engineer agents.

Every agent produces a structured AgentResult with:
  - the raw findings/data it gathered
  - a reasoning trace (evidence -> interpretation -> confidence)
  - proposed actions (never auto-executed by the agent itself)

This is what turns "the AI did something" into an auditable decision trail —
required for a professional security assessment report and for any
human-in-the-loop approval step later in the pipeline.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ActionRisk(str, Enum):
    """How risky is it to auto-execute this proposed action?"""
    SAFE = "safe"              # e.g. write a report, tag a finding
    REVIEW = "review"          # e.g. suggest a firewall rule
    DANGEROUS = "dangerous"    # e.g. block an IP range, disable a service


@dataclass
class ReasoningStep:
    """One link in an agent's chain of reasoning, kept for auditability."""
    evidence: str
    interpretation: str
    confidence: Confidence
    alternatives_considered: list[str] = field(default_factory=list)


@dataclass
class ProposedAction:
    description: str
    risk: ActionRisk
    command: str | None = None          # the literal command/config diff, if any
    requires_approval: bool = True       # DANGEROUS/REVIEW default True; SAFE can be False
    rationale: str = ""


@dataclass
class AgentResult:
    agent_name: str
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: dict[str, Any] = field(default_factory=dict)
    reasoning: list[ReasoningStep] = field(default_factory=list)
    proposed_actions: list[ProposedAction] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary_line(self) -> str:
        n_findings = len(self.findings)
        n_actions = len(self.proposed_actions)
        return f"[{self.agent_name}] {n_findings} finding group(s), {n_actions} proposed action(s)"


class BaseAgent:
    """
    Subclass this for each specialized agent (recon, triage, correlation,
    research, remediation, report). Keeps a consistent run() contract so the
    orchestrator can pipeline agents without knowing their internals.
    """

    name: str = "base_agent"

    def __init__(self, context: dict[str, Any]):
        # context is the shared pipeline state (target, prior agents' results, config)
        self.context = context

    def run(self, target: str) -> AgentResult:
        raise NotImplementedError

    def _result(self, target: str) -> AgentResult:
        return AgentResult(agent_name=self.name, target=target)
