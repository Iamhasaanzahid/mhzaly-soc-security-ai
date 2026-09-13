"""
correlation_agent.py — Correlates discovered surface (domains/services) with
NVD CVE data. Simple keyword-based matching here; swap in your v18.0
CPE-aware strict matching logic once you port it over — the interface stays
the same either way.
"""

from __future__ import annotations
from .base_agent import BaseAgent, AgentResult, ReasoningStep, ProposedAction, Confidence, ActionRisk
from . import connectors


class CorrelationAgent(BaseAgent):
    name = "correlation_agent"

    def run(self, target: str) -> AgentResult:
        result = self._result(target)

        # Keywords to search NVD for — normally derived from a tech-fingerprinting
        # step (Wappalyzer/banner grab). Falls back to the bare domain if nothing
        # more specific is known yet.
        keywords: list[str] = self.context.get("tech_stack_keywords") or [target]

        for keyword in keywords:
            nvd_data = connectors.query_nvd(keyword)
            result.findings[keyword] = nvd_data

            if "error" in nvd_data:
                result.errors.append(f"{keyword}: NVD lookup failed — {nvd_data['error']}")
                continue

            high_severity = [c for c in nvd_data.get("cves", []) if (c.get("cvss_score") or 0) >= 7.0]

            if high_severity:
                result.reasoning.append(ReasoningStep(
                    evidence=f"{keyword}: {len(high_severity)} of {nvd_data['count']} matched CVEs "
                             f"score >= 7.0 (High/Critical)",
                    interpretation="Keyword-based match — verify these apply to the actual "
                                   "installed version before acting",
                    confidence=Confidence.MEDIUM,
                    alternatives_considered=[
                        "Keyword search can return CVEs for unrelated products sharing a name",
                        "Without confirmed version numbers, exact applicability is unproven",
                    ],
                ))
                for cve in high_severity[:5]:
                    result.proposed_actions.append(ProposedAction(
                        description=f"Investigate {cve['id']} (CVSS {cve['cvss_score']}) against {keyword}",
                        risk=ActionRisk.REVIEW,
                        rationale=cve["description"],
                    ))

        return result
