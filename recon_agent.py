"""
recon_agent.py — Subdomain + IP discovery using crt.sh and DNS resolution.

Deliberately avoids shelling out to subfinder/nmap: those aren't installed
on Streamlit Community Cloud (no system package installs there), so a
recon agent that depends on them will work locally and silently fail
in production. crt.sh (cert-transparency logs) + Python's socket module
gets you real subdomain + IP data with zero external binaries.
"""

from __future__ import annotations
import socket

from .base_agent import BaseAgent, AgentResult, ReasoningStep, Confidence
from . import connectors

MAX_SUBDOMAINS_TO_RESOLVE = 25


class ReconAgent(BaseAgent):
    name = "recon_agent"

    def run(self, target: str) -> AgentResult:
        result = self._result(target)

        crtsh_data = connectors.query_crtsh(target)
        if "error" in crtsh_data:
            result.errors.append(f"crt.sh lookup failed: {crtsh_data['error']}")
            subdomains = [target]
        else:
            subdomains = crtsh_data["subdomains"] or [target]

        resolved_ips: set[str] = set()
        resolved_map: dict[str, str] = {}
        for sub in subdomains[:MAX_SUBDOMAINS_TO_RESOLVE]:
            ip = self._resolve(sub)
            if ip:
                resolved_ips.add(ip)
                resolved_map[sub] = ip

        result.findings = {
            "domains": subdomains,
            "ips": sorted(resolved_ips),
            "resolved_map": resolved_map,
        }

        result.reasoning.append(ReasoningStep(
            evidence=f"crt.sh returned {len(subdomains)} certificate-associated hostnames; "
                     f"{len(resolved_ips)} resolved to live IPs",
            interpretation="These form the initial attack surface for triage and correlation stages",
            confidence=Confidence.HIGH if resolved_ips else Confidence.LOW,
            alternatives_considered=[
                "Some subdomains may be stale/decommissioned (cert issued but host retired)",
                "Wildcard certs can inflate the subdomain count without real distinct hosts",
            ],
        ))

        return result

    @staticmethod
    def _resolve(hostname: str) -> str | None:
        try:
            return socket.gethostbyname(hostname)
        except (socket.gaierror, UnicodeError):
            return None
