"""Red Agent — consumes Attack Planner candidates and constructs attack chains.

This agent does **not** directly traverse the Knowledge Graph for planning.
Instead it receives pre-analysed ``attack_opportunities`` from the Attack Planner
and builds full attack chains (paths) from them.
"""

from __future__ import annotations

from typing import Any

from agents.base import BaseAgent
from graph.state import EsperState

try:
    import networkx as nx
except ImportError:
    nx = None  # type: ignore[assignment]


def _log(agent: str, status: str, message: str) -> dict:
    return {"agent": agent, "status": status, "message": message}


class RedAgent(BaseAgent):
    """Builds attack chains from Attack Planner candidates.

    This agent does **not** execute attacks — it constructs plausible
    attack-path hypotheses from the candidates supplied by the Attack Planner.
    """

    name = "red_agent"

    # ------------------------------------------------------------------ #
    # Attack chain builder from candidates
    # ------------------------------------------------------------------ #

    def _build_chains_from_candidates(self, candidates: list[dict[str, Any]]) -> list[dict]:
        """Build attack chains by grouping and correlating candidates."""
        chains: list[dict] = []

        # --- Group candidates by type for chain construction ---

        # 1. Missing header candidates → Security Headers Bypass chain
        header_candidates = [c for c in candidates if c.get("type") == "missing_security_header"]
        if header_candidates:
            steps = []
            evidence = []
            for c in header_candidates:
                steps.append({
                    "step": len(steps) + 1,
                    "technique": f"Exploit missing {c.get('header', 'unknown')}",
                    "mitre_id": c.get("attack_techniques", ["T1189"])[0].split(" -")[0] if c.get("attack_techniques") else "T1189",
                    "confidence": c.get("confidence", 0.7),
                })
                evidence.append(c.get("source_node", ""))
            chains.append({
                "name": "Security Headers Bypass",
                "steps": steps,
                "impact": "Medium",
                "confidence": max(c.get("confidence", 0) for c in header_candidates),
                "evidence": [e for e in evidence if e],
            })

        # 2. Vulnerable software candidates → CVE exploitation chains
        vuln_candidates = [c for c in candidates if c.get("type") == "vulnerable_software"]
        for c in vuln_candidates:
            chains.append({
                "name": f"Exploit {c.get('cve_id', 'unknown')} on {c.get('technology', 'unknown')}",
                "steps": [
                    {
                        "step": 1,
                        "technique": f"Target {c.get('technology', 'unknown')}",
                        "mitre_id": "T1190",
                        "confidence": 0.6,
                    },
                    {
                        "step": 2,
                        "technique": f"Exploit {c.get('cve_id', 'unknown')}",
                        "mitre_id": "T1190",
                        "confidence": c.get("confidence", 0.5),
                    },
                ],
                "impact": c.get("severity", "Medium"),
                "confidence": c.get("confidence", 0.55),
                "evidence": [c.get("source_node", ""), c.get("cve_id", "")],
            })

        # 3. Exposed service candidates → network-based attack chains
        svc_candidates = [c for c in candidates if c.get("type") == "exposed_service"]
        for c in svc_candidates:
            port = c.get("port", 0)
            if port in (22, 3389):
                chains.append({
                    "name": f"Remote access via {c.get('service', 'unknown')} (port {port})",
                    "steps": [
                        {
                            "step": 1,
                            "technique": f"Connect to exposed {c.get('service', 'unknown')}",
                            "mitre_id": "T1021",
                            "confidence": c.get("confidence", 0.8),
                        }
                    ],
                    "impact": "High",
                    "confidence": c.get("confidence", 0.80),
                    "evidence": [c.get("source_node", "")],
                })

        # 4. Weak encryption candidates → network-based attack chains
        enc_candidates = [c for c in candidates if c.get("type") == "weak_encryption"]
        if enc_candidates:
            for c in enc_candidates:
                issue = c.get("issue", "weak_encryption")
                chains.append({
                    "name": f"Network interception via {issue}",
                    "steps": [
                        {
                            "step": 1,
                            "technique": f"Exploit {issue}",
                            "mitre_id": "T1557",
                            "confidence": c.get("confidence", 0.85),
                        }
                    ],
                    "impact": "High",
                    "confidence": c.get("confidence", 0.85),
                    "evidence": [c.get("source_node", "")],
                })

        # Sort by confidence descending
        chains.sort(key=lambda ch: ch.get("confidence", 0), reverse=True)
        return chains

    # ------------------------------------------------------------------ #
    # Attack graph builder
    # ------------------------------------------------------------------ #

    def _build_attack_graph(self, chains: list[dict]):
        """Build a NetworkX DiGraph from attack chains."""
        if nx is None:
            return None

        G = nx.DiGraph()

        for chain in chains:
            chain_id = f"chain:{chain['name']}"
            G.add_node(
                chain_id,
                type="chain",
                name=chain["name"],
                impact=chain.get("impact", "Medium"),
                confidence=chain.get("confidence", 0.5),
            )

            for step in chain.get("steps", []):
                step_id = f"step:{chain['name']}:{step['step']}"
                G.add_node(
                    step_id,
                    type="technique",
                    name=step["technique"],
                    mitre_id=step.get("mitre_id", ""),
                    confidence=step.get("confidence", 0.5),
                )
                G.add_edge(chain_id, step_id, relation="contains_step")

            # Link evidence
            for ev in chain.get("evidence", []):
                if G.has_node(ev) or not isinstance(ev, str):
                    continue
                G.add_node(ev, type="evidence")
                G.add_edge(chain_id, ev, relation="supported_by")

        return G

    # ------------------------------------------------------------------ #
    # Main entry
    # ------------------------------------------------------------------ #

    def run(self, state: EsperState) -> dict:
        candidates = state.get("attack_opportunities", [])

        if not candidates:
            return {
                "attack_graph": None,
                "history": state.get("history", [])
                + [{"agent": self.name, "status": "skipped", "message": "No attack candidates from Planner"}],
                "logs": state.get("logs", [])
                + [_log(self.name, "skipped", "No candidates to chain")],
            }

        # Build attack chains from Attack Planner candidates
        chains = self._build_chains_from_candidates(candidates)

        # Build attack graph
        attack_graph = self._build_attack_graph(chains)

        return {
            "attack_graph": attack_graph,
            "history": state.get("history", [])
            + [
                {
                    "agent": self.name,
                    "status": "complete",
                    "message": f"Constructed {len(chains)} attack chains from {len(candidates)} candidates",
                }
            ],
            "logs": state.get("logs", [])
            + [_log(self.name, "complete", f"{len(chains)} chains from {len(candidates)} candidates")],
        }
