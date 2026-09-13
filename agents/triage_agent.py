"""
triage_agent.py — Real-time threat triage using VirusTotal + AbuseIPDB.

Expects a `connectors` module (your existing connectors.py from the
MHZALY suite) exposing:
    connectors.query_virustotal(ioc: str) -> dict
    connectors.query_abuseipdb(ip: str) -> dict

If you want to wire this directly to your existing file, just adjust the
import at the top — the agent logic doesn't otherwise change.
"""

from __future__ import annotations
from .base_agent import (
    BaseAgent, AgentResult, ReasoningStep, ProposedAction,
    Confidence, ActionRisk,
)

try:
    import connectors  # your existing MHZALY connectors.py
except ImportError:
    connectors = None  # allows this file to be imported/tested standalone


HIGH_RISK_SCORE = 50      # AbuseIPDB confidence score threshold
HIGH_DETECTION_RATIO = 0.1  # VT: >10% of engines flagging = high risk


class TriageAgent(BaseAgent):
    name = "triage_agent"

    def run(self, target: str) -> AgentResult:
        result = self._result(target)

        recon_findings = self.context.get("recon_agent_findings", {})
        iocs: list[str] = recon_findings.get("ips", []) + recon_findings.get("domains", [])

        if not iocs:
            result.errors.append("No IOCs available from recon stage — nothing to triage.")
            return result

        if connectors is None:
            result.errors.append("connectors module not found — running in stub mode.")
            return result

        for ioc in iocs:
            vt_data = self._safe_call(connectors.query_virustotal, ioc)
            abuse_data = self._safe_call(connectors.query_abuseipdb, ioc) if self._is_ip(ioc) else None

            result.findings[ioc] = {"virustotal": vt_data, "abuseipdb": abuse_data}
            self._reason_about(result, ioc, vt_data, abuse_data)

        return result

    def _reason_about(self, result: AgentResult, ioc: str, vt_data: dict | None, abuse_data: dict | None) -> None:
        malicious_hits = 0
        total_engines = 1
        if vt_data:
            malicious_hits = vt_data.get("malicious", 0)
            total_engines = max(vt_data.get("total_engines", 1), 1)

        abuse_score = abuse_data.get("abuseConfidenceScore", 0) if abuse_data else 0
        detection_ratio = malicious_hits / total_engines

        if detection_ratio >= HIGH_DETECTION_RATIO or abuse_score >= HIGH_RISK_SCORE:
            confidence = Confidence.HIGH if detection_ratio > 0.3 or abuse_score > 80 else Confidence.MEDIUM
            result.reasoning.append(ReasoningStep(
                evidence=f"{ioc}: {malicious_hits}/{total_engines} VT engines flagged malicious; "
                         f"AbuseIPDB confidence score {abuse_score}",
                interpretation="Indicator shows active malicious reputation signals",
                confidence=confidence,
                alternatives_considered=[
                    "Could be a false positive from a shared/CDN IP — check ASN and hosting context",
                    "Could be historical/stale reputation data rather than current activity",
                ],
            ))
            result.proposed_actions.append(ProposedAction(
                description=f"Flag {ioc} as high-risk and consider blocking at perimeter",
                risk=ActionRisk.REVIEW,
                command=f"# proposed: deny {ioc} at firewall (pending correlation + human approval)",
                requires_approval=True,
                rationale="Elevated malicious detection ratio / abuse confidence score",
            ))
        else:
            result.reasoning.append(ReasoningStep(
                evidence=f"{ioc}: {malicious_hits}/{total_engines} VT engines flagged, AbuseIPDB score {abuse_score}",
                interpretation="No strong malicious signal at this time",
                confidence=Confidence.MEDIUM,
            ))

    @staticmethod
    def _safe_call(fn, *args):
        try:
            return fn(*args)
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _is_ip(value: str) -> bool:
        parts = value.split(".")
        return len(parts) == 4 and all(p.isdigit() for p in parts)
