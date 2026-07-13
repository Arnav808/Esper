"""Blue Agent — recommends defensive actions that neutralise attack paths."""

from __future__ import annotations

from agents.base import BaseAgent
from analysis.findings import build_findings
from graph.state import EsperState


def _log(agent: str, status: str, message: str) -> dict:
    return {"agent": agent, "status": status, "message": message}


# Mitigation playbook: maps attack patterns → recommended actions
MITIGATION_PLAYBOOK: dict[str, dict] = {
    "Security Headers Bypass": {
        "action": "Implement all missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy).",
        "effort": "Low",
        "risk_reduction": 25,
    },
    "Remote access via SSH (port 22)": {
        "action": "Restrict SSH access via firewall rules; use key-based auth; disable password login.",
        "effort": "Medium",
        "risk_reduction": 30,
    },
    "Remote access via RDP (port 3389)": {
        "action": "Disable public RDP; use VPN or bastion host; enable NLA.",
        "effort": "Medium",
        "risk_reduction": 35,
    },
    "default": {
        "action": "Review and remediate the identified vulnerability following vendor advisories.",
        "effort": "Medium",
        "risk_reduction": 20,
    },
}


class BlueAgent(BaseAgent):
    """Analyses attack paths and recommends mitigations."""

    name = "blue_agent"

    def run(self, state: EsperState) -> dict:
        attack_graph = state.get("attack_graph")
        discovery = state.get("discovery_results", {})
        findings = self._build_findings(discovery)

        mitigations = self._generate_mitigations(attack_graph, findings)
        security_score = self._calculate_score(findings, attack_graph)

        # Build mitigation graph
        mitigation_graph = self._build_mitigation_graph(mitigations)

        return {
            "mitigation_graph": mitigation_graph,
            "security_score": security_score,
            "history": state.get("history", [])
            + [
                {
                    "agent": self.name,
                    "status": "complete",
                    "message": f"Generated {len(mitigations)} mitigations, score: {security_score}",
                }
            ],
            "logs": state.get("logs", [])
            + [_log(self.name, "complete", f"Score {security_score}, {len(mitigations)} mitigations")],
        }

    # ------------------------------------------------------------------ #
    # Findings builder (from discovery data)
    # ------------------------------------------------------------------ #

    def _build_findings(self, discovery: dict) -> list[dict]:
        """Build a findings list from raw discovery data."""
        return build_findings(discovery)

    # ------------------------------------------------------------------ #
    # Mitigation generator
    # ------------------------------------------------------------------ #

    def _generate_mitigations(self, attack_graph, findings: list[dict]) -> list[dict]:
        mitigations: list[dict] = []

        if attack_graph is not None:
            import networkx as nx

            for node, attrs in attack_graph.nodes(data=True):
                if attrs.get("type") != "chain":
                    continue
                chain_name = attrs.get("name", "")
                playbook = self._match_playbook(chain_name)
                mitigations.append(
                    {
                        "target_attack_chain": chain_name,
                        "action": playbook["action"],
                        "priority": self._impact_to_priority(attrs.get("impact", "Medium")),
                        "effort": playbook["effort"],
                        "risk_reduction": playbook["risk_reduction"],
                    }
                )

        # Always recommend header fixes if headers are missing
        has_header_finding = any("Missing" in f["title"] and f["category"] == "Security Headers" for f in findings)
        if has_header_finding:
            mitigations.append(
                {
                    "target_attack_chain": "Security Headers Bypass",
                    "action": "Implement Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options, and Referrer-Policy headers.",
                    "priority": "Medium",
                    "effort": "Low",
                    "risk_reduction": 25,
                }
            )

        # De-duplicate by action
        seen_actions: set[str] = set()
        unique: list[dict] = []
        for m in mitigations:
            if m["action"] not in seen_actions:
                seen_actions.add(m["action"])
                unique.append(m)

        return unique

    def _match_playbook(self, chain_name: str) -> dict:
        for key, playbook in MITIGATION_PLAYBOOK.items():
            if key.lower() in chain_name.lower():
                return playbook
        return MITIGATION_PLAYBOOK["default"]

    def _impact_to_priority(self, impact: str) -> str:
        return {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}.get(impact, "Medium")

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #

    def _calculate_score(self, findings: list[dict], attack_graph=None) -> int:
        score = 100

        severity_penalties = {
            "Critical": 25,
            "High": 20,
            "Medium": 10,
            "Low": 5,
        }

        for f in findings:
            score -= severity_penalties.get(f.get("severity", ""), 0)

        # Penalty for attack chains
        if attack_graph is not None:
            chain_count = sum(
                1 for _, a in attack_graph.nodes(data=True) if a.get("type") == "chain"
            )
            score -= chain_count * 5

        return max(0, min(100, score))

    # ------------------------------------------------------------------ #
    # Mitigation graph
    # ------------------------------------------------------------------ #

    def _build_mitigation_graph(self, mitigations: list[dict]):
        try:
            import networkx as nx
        except ImportError:
            return None

        G = nx.DiGraph()
        for i, m in enumerate(mitigations):
            node_id = f"mitigation:{i}"
            G.add_node(
                node_id,
                type="mitigation",
                action=m["action"],
                priority=m["priority"],
                effort=m["effort"],
                risk_reduction=m["risk_reduction"],
            )
            # Link to target chain
            chain_id = f"chain:{m['target_attack_chain']}"
            G.add_edge(chain_id, node_id, relation="mitigated_by")

        return G
