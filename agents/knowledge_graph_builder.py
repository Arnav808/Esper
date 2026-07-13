"""Knowledge Graph Builder — normalises scanner output into a Security Knowledge Graph."""

from __future__ import annotations

from urllib.parse import urlparse

from agents.base import BaseAgent
from graph.knowledge_graph import SecurityKnowledgeGraph
from graph.state import EsperState
from knowledge.cve_db import CVE_KNOWLEDGE_BASE


def _log(agent: str, status: str, message: str) -> dict:
    return {"agent": agent, "status": status, "message": message}


class KnowledgeGraphBuilder(BaseAgent):
    """Normalises, correlates, and enriches discovery data into a Knowledge Graph."""

    name = "knowledge_graph_builder"

    def run(self, state: EsperState) -> dict:
        discovery = state.get("discovery_results", {})
        url = state["target_url"]
        domain = urlparse(url).netloc or urlparse(url).path

        kg = SecurityKnowledgeGraph()
        kg.add_target(url, domain)

        self._process_headers(kg, domain, discovery.get("headers", []))
        self._process_ssl(kg, domain, discovery.get("ssl", {}))
        self._process_tech(kg, domain, discovery.get("tech", {}))
        self._process_dns(kg, domain, discovery.get("dns", {}))
        self._process_ports(kg, domain, discovery.get("ports", {}))
        self._process_waf(kg, domain, discovery.get("waf", {}))

        confidence = self._score_confidence(discovery)

        return {
            "knowledge_graph": kg,
            "confidence": confidence,
            "history": state.get("history", []) + [
                {
                    "agent": self.name,
                    "status": "complete",
                    "message": (
                        f"Built KG: {kg.graph.number_of_nodes()} nodes, "
                        f"{kg.graph.number_of_edges()} edges"
                    ),
                }
            ],
            "logs": state.get("logs", [])
            + [_log(self.name, "complete", "Knowledge graph built")],
        }

    # ------------------------------------------------------------------ #
    # Per-scanner processors
    # ------------------------------------------------------------------ #

    def _process_headers(self, kg: SecurityKnowledgeGraph, domain: str, headers) -> None:
        # Handle both new dict format and legacy list format
        if isinstance(headers, dict):
            headers_list = headers.get("headers", [])
        elif isinstance(headers, list):
            headers_list = headers
        else:
            headers_list = []

        for h in headers_list:
            if isinstance(h, dict) and h.get("status") == "missing":
                kg.add_missing_header(domain, h["header"])
            elif isinstance(h, dict) and h.get("status") == "present":
                header_id = f"header:{h['header']}"
                kg.graph.add_node(header_id, type="header", name=h["header"], status="present")
                kg.graph.add_edge(domain, header_id, relation="has_header")

    def _process_ssl(self, kg: SecurityKnowledgeGraph, domain: str, ssl_data: dict) -> None:
        if not ssl_data.get("https_enabled"):
            kg.add_configuration(domain, "HTTPS Disabled", risk_level="high")
        if ssl_data.get("https_enabled") and not ssl_data.get("certificate_valid"):
            kg.add_configuration(domain, "Invalid Certificate", risk_level="high")
        if ssl_data.get("https_enabled") and ssl_data.get("certificate_valid"):
            kg.add_configuration(domain, "HTTPS Enabled", risk_level="info")

    def _process_tech(self, kg: SecurityKnowledgeGraph, domain: str, tech_data: dict) -> None:
        for tech_name in tech_data.get("technologies", []):
            tech_id = kg.add_technology(domain, tech_name)

            # Correlate with CVE knowledge base
            known_cves = CVE_KNOWLEDGE_BASE.get(tech_name, [])
            for cve in known_cves:
                kg.add_vulnerability(
                    tech_id,
                    cve["id"],
                    cvss=cve["cvss"],
                    severity=cve["severity"],
                    description=cve.get("description", ""),
                )

    def _process_dns(self, kg: SecurityKnowledgeGraph, domain: str, dns_data: dict) -> None:
        records = dns_data.get("records", {})
        for rtype in ("A", "AAAA"):
            for record in records.get(rtype, []):
                node_id = f"dns:{rtype}:{record}"
                kg.graph.add_node(node_id, type="dns", record_type=rtype, value=record)
                kg.graph.add_edge(domain, node_id, relation="resolves_to")

    def _process_ports(self, kg: SecurityKnowledgeGraph, domain: str, ports_data: dict) -> None:
        for port_info in ports_data.get("open_ports", []):
            kg.add_service(domain, port_info["service"], port_info["port"])

    def _process_waf(self, kg: SecurityKnowledgeGraph, domain: str, waf_data: dict) -> None:
        for waf in waf_data.get("detected", []):
            waf_id = f"waf:{waf['name']}"
            kg.graph.add_node(
                waf_id, type="waf", name=waf["name"], waf_type=waf["type"]
            )
            kg.graph.add_edge(domain, waf_id, relation="protected_by")

    # ------------------------------------------------------------------ #
    # Confidence scoring
    # ------------------------------------------------------------------ #

    def _score_confidence(self, discovery: dict) -> float:
        """Heuristic confidence based on how many scanners returned data."""
        signals = 0
        total = 9

        if discovery.get("headers"):
            signals += 1
        if discovery.get("ssl"):
            signals += 1
        if discovery.get("tech", {}).get("technologies"):
            signals += 1
        if discovery.get("dns", {}).get("records"):
            signals += 1
        if discovery.get("ports", {}).get("open_ports"):
            signals += 1
        if discovery.get("robots", {}).get("available"):
            signals += 1
        if discovery.get("sitemap", {}).get("available"):
            signals += 1
        if discovery.get("security_txt", {}).get("available"):
            signals += 1
        if discovery.get("waf", {}).get("detected"):
            signals += 1

        return round(signals / total, 2)
