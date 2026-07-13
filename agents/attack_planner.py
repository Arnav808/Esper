"""Attack Planner — analyses the Knowledge Graph to identify possible attack opportunities.

The Planner does *not* build attack chains. Instead it:
- Identifies entry points (exposed services, missing headers, open ports)
- Extracts preconditions for each entry point
- Collects relevant vulnerabilities from the KG (CVEs on detected technologies)
- Produces structured attack-candidate records

The Red Agent consumes these candidates to construct full attack chains.
"""

from __future__ import annotations

from typing import Any

from agents.base import BaseAgent
from graph.state import EsperState


def _log(agent: str, status: str, message: str) -> dict:
    return {"agent": agent, "status": status, "message": message}


class AttackPlanner(BaseAgent):
    """Examines the Security Knowledge Graph and enumerates possible attack opportunities."""

    name = "attack_planner"

    def run(self, state: EsperState) -> dict:
        kg = state.get("knowledge_graph")
        if kg is None:
            return {
                "attack_opportunities": [],
                "history": state.get("history", [])
                + [{"agent": self.name, "status": "skipped", "message": "No knowledge graph to analyse"}],
                "logs": state.get("logs", [])
                + [_log(self.name, "skipped", "No KG — no candidates generated")],
            }

        candidates = self._enumerate_candidates(kg)

        return {
            "attack_opportunities": candidates,
            "history": state.get("history", [])
            + [
                {
                    "agent": self.name,
                    "status": "complete",
                    "message": f"Identified {len(candidates)} attack candidates",
                }
            ],
            "logs": state.get("logs", [])
            + [_log(self.name, "complete", f"{len(candidates)} candidates identified")],
        }

    # ------------------------------------------------------------------ #
    # Candidate enumeration
    # ------------------------------------------------------------------ #

    def _enumerate_candidates(self, kg) -> list[dict[str, Any]]:
        """Walk the Knowledge Graph and return all possible attack candidates."""
        candidates: list[dict[str, Any]] = []
        G = kg.graph

        # Find the target domain
        domain = None
        for n, attrs in G.nodes(data=True):
            if attrs.get("type") == "target":
                domain = n
                break
        if not domain:
            return candidates

        # --- 1. Missing-header candidates ---
        for n, attrs in G.nodes(data=True):
            if attrs.get("type") == "header" and attrs.get("status") == "missing":
                candidates.append({
                    "type": "missing_security_header",
                    "entry_point": "web_application",
                    "header": attrs.get("name", ""),
                    "preconditions": ["attacker can craft HTTP request"],
                    "attack_techniques": self._header_to_techniques(attrs.get("name", "")),
                    "confidence": 0.7,
                    "impact_estimate": "Medium",
                    "source_node": n,
                })

        # --- 2. Technology / CVE candidates ---
        for tech_node, tech_attrs in G.nodes(data=True):
            if tech_attrs.get("type") != "technology":
                continue
            name = tech_attrs.get("name", "")
            version = tech_attrs.get("version")

            # Check for known CVEs on this technology
            for _, cve_node, edge_data in G.out_edges(tech_node, data=True):
                if edge_data.get("relation") != "affected_by":
                    continue
                cve_attrs = G.nodes[cve_node]
                candidates.append({
                    "type": "vulnerable_software",
                    "entry_point": "web_application",
                    "technology": name,
                    "version": version,
                    "cve_id": cve_attrs.get("cve_id", cve_node),
                    "cvss": cve_attrs.get("cvss", 0.0),
                    "severity": cve_attrs.get("severity", "Unknown"),
                    "description": cve_attrs.get("description", ""),
                    "preconditions": [f"{name} is accessible and exploitable"],
                    "confidence": 0.55,
                    "impact_estimate": cve_attrs.get("severity", "Medium"),
                    "source_node": tech_node,
                })

            # Even without CVEs, technology presence is a candidate surface
            if not any(
                edge_data.get("relation") == "affected_by"
                for _, _, edge_data in G.out_edges(tech_node, data=True)
            ):
                candidates.append({
                    "type": "technology_surface",
                    "entry_point": "web_application",
                    "technology": name,
                    "version": version,
                    "preconditions": [f"{name} is public-facing"],
                    "confidence": 0.3,
                    "impact_estimate": "Low",
                    "source_node": tech_node,
                })

        # --- 3. Exposed-service candidates ---
        for svc_node, svc_attrs in G.nodes(data=True):
            if svc_attrs.get("type") != "service":
                continue
            port = svc_attrs.get("port", 0)
            service_name = svc_attrs.get("name", "unknown")

            risk = "High" if port in (22, 3389, 21, 1433, 3306, 5432, 6379, 27017) else "Medium"

            candidates.append({
                "type": "exposed_service",
                "entry_point": "network",
                "service": service_name,
                "port": port,
                "protocol": "TCP",
                "preconditions": ["service is reachable from the internet"],
                "attack_techniques": self._service_to_techniques(service_name, port),
                "confidence": 0.8 if port in (22, 3389) else 0.6,
                "impact_estimate": risk,
                "source_node": svc_node,
            })

        # --- 4. Weak SSL/TLS candidates ---
        for n, attrs in G.nodes(data=True):
            if attrs.get("type") != "configuration":
                continue
            setting = attrs.get("setting", "")
            risk = attrs.get("risk_level", "info")
            if risk == "high" and setting in ("HTTPS Disabled", "Invalid Certificate"):
                candidates.append({
                    "type": "weak_encryption",
                    "entry_point": "network",
                    "issue": setting,
                    "preconditions": ["attacker can intercept network traffic"],
                    "confidence": 0.85,
                    "impact_estimate": "High",
                    "source_node": n,
                })

        # De-duplicate by key fields and sort by confidence descending
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for c in candidates:
            key = f"{c['type']}:{c.get('source_node', '')}:{c.get('header', '')}:{c.get('cve_id', '')}:{c.get('port', '')}:{c.get('issue', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(c)

        unique.sort(key=lambda c: c.get("confidence", 0), reverse=True)
        return unique

    # ------------------------------------------------------------------ #
    # Mapping helpers
    # ------------------------------------------------------------------ #

    def _header_to_techniques(self, header_name: str) -> list[str]:
        mapping = {
            "Content-Security-Policy": ["T1189 - Cross-Site Scripting via missing CSP"],
            "X-Frame-Options": ["T1189 - Clickjacking via missing XFO"],
            "Strict-Transport-Security": ["T1557 - Man-in-the-Middle via missing HSTS"],
            "X-Content-Type-Options": ["T1189 - MIME-sniffing attacks via missing XCTO"],
            "Referrer-Policy": ["T1557 - Information disclosure via missing Referrer-Policy"],
        }
        return mapping.get(header_name, ["T1190 - General web exploitation"])

    def _service_to_techniques(self, service: str, port: int) -> list[str]:
        mapping = {
            22: ["T1021 - Remote SSH exploitation"],
            21: ["T1048 - FTP credential brute-force"],
            3389: ["T1021 - Remote RDP exploitation"],
            3306: ["T1210 - MySQL database exposure"],
            5432: ["T1210 - PostgreSQL database exposure"],
            6379: ["T1210 - Redis unauthorised access"],
            27017: ["T1210 - MongoDB unauthorised access"],
            1433: ["T1210 - MSSQL database exposure"],
        }
        return mapping.get(port, ["T1190 - General network service exploitation"])
