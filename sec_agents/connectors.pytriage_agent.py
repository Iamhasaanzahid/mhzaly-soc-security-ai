"""
triage_agent.py — Real-time threat triage using VirusTotal + AbuseIPDB.

Consumes recon_agent's findings (context["recon_agent_findings"]) if present;
otherwise triages the raw target string itself, so this agent also works
standalone.
"""

from __future__ import annotations
from .base_agent import BaseAgent, AgentResult, ReasoningStep, ProposedAction, Confidence, ActionRisk
from . import connectors

HIGH_RISK_ABUSE_SCORE = 50
HIGH_DETECTION_RATIO = 0.1


class TriageAgent(BaseAgent):
    name = "triage_agent"

    def run(self, target: str) -> AgentResult:
        result = self._result(target)

        recon_findings = self.context.get("recon_agent_findings", {})
        iocs: list[str] = list(dict.fromkeys(
            recon_findings.get("ips", []) + recon_findings.get("domains", []) + [target]
        ))

        for ioc in iocs:
            vt_data = connectors.query_virustotal(ioc)
            abuse_data = connectors.query_abuseipdb(ioc) if self._is_ip(ioc) else None
            result.findings[ioc] = {"virustotal": vt_data, "abuseipdb": abuse_data}

            if "error" in vt_data and (abuse_data is None or "error" in abuse_data):
                result.errors.append(f"{ioc}: both VT and AbuseIPDB lookups failed/unconfigured")
                continue

            self._reason_about(result, ioc, vt_data, abuse_data)

        return result

    def _reason_about(self, result: AgentResult, ioc: str, vt_data: dict, abuse_data: dict | None) -> None:
        malicious = vt_data.get("malicious", 0)
        total = max(vt_data.get("total_engines", 1), 1)
        ratio = malicious / total if "error" not in vt_data else 0
        abuse_score = abuse_data.get("abuseConfidenceScore", 0) if abuse_data and "error" not in abuse_data else 0

        if ratio >= HIGH_DETECTION_RATIO or abuse_score >= HIGH_RISK_ABUSE_SCORE:
            confidence = Confidence.HIGH if ratio > 0.3 or abuse_score > 80 else Confidence.MEDIUM
            result.reasoning.append(ReasoningStep(
                evidence=f"{ioc}: {malicious}/{total} VT engines flagged malicious; AbuseIPDB score {abuse_score}",
                interpretation="Indicator shows active malicious reputation signals",
                confidence=confidence,
                alternatives_considered=[
                    "Could be a shared/CDN IP producing a false positive",
                    "Reputation data may be stale rather than reflecting current activity",
                ],
            ))
            result.proposed_actions.append(ProposedAction(
                description=f"Flag {ioc} as high-risk; consider perimeter block pending correlation",
                risk=ActionRisk.REVIEW,
                command=f"# proposed: deny {ioc} at firewall (pending approval)",
                rationale=f"VT ratio {ratio:.2f}, AbuseIPDB score {abuse_score}",
            ))
        else:
            result.reasoning.append(ReasoningStep(
                evidence=f"{ioc}: {malicious}/{total} VT engines flagged, AbuseIPDB score {abuse_score}",
                interpretation="No strong malicious signal at this time",
                confidence=Confidence.MEDIUM,
            ))

    @staticmethod
    def _is_ip(value: str) -> bool:
        parts = value.split(".")
        return len(parts) == 4 and all(p.isdigit() for p in parts)
