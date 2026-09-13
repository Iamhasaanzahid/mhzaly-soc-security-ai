"""
base_agent.py — Shared interface for all AI Security Engineer agents.

Every agent produces a structured AgentResult with:
  - the raw findings/data it gathered
  - a reasoning trace (evidence -> interpretation -> confidence)
  - proposed actions (never auto-executed by the agent itself)
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
    SAFE = "safe"
    REVIEW = "review"
    DANGEROUS = "dangerous"


@dataclass
class ReasoningStep:
    evidence: str
    interpretation: str
    confidence: Confidence
    alternatives_considered: list[str] = field(default_factory=list)


@dataclass
class ProposedAction:
    description: str
    risk: ActionRisk
    command: str | None = None
    requires_approval: bool = True
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
        return f"[{self.agent_name}] {len(self.findings)} finding group(s), {len(self.proposed_actions)} proposed action(s)"


class BaseAgent:
    name: str = "base_agent"

    def __init__(self, context: dict[str, Any]):
        self.context = context

    def run(self, target: str) -> AgentResult:
        raise NotImplementedError

    def _result(self, target: str) -> AgentResult:
        return AgentResult(agent_name=self.name, target=target)
