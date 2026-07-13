"""Security Knowledge Graph — models relationships between discovered assets."""

from __future__ import annotations

import networkx as nx


class SecurityKnowledgeGraph:
    """Builds and queries a directed graph of security-relevant entities.

    Node types: target, technology, vulnerability, service, header,
                configuration, subdomain
    Edge types (``relation`` attribute): runs, exposes, affected_by,
                missing, configured, subdomain_of, requires, enables_exploit
    """

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    # ------------------------------------------------------------------ #
    # Builders
    # ------------------------------------------------------------------ #

    def add_target(self, url: str, domain: str) -> None:
        self.graph.add_node(domain, type="target", url=url)

    def add_technology(
        self, target: str, name: str, version: str | None = None
    ) -> str:
        tech_id = f"{name}:{version}" if version else name
        self.graph.add_node(tech_id, type="technology", name=name, version=version)
        self.graph.add_edge(target, tech_id, relation="runs")
        return tech_id

    def add_vulnerability(
        self,
        source_node: str,
        cve_id: str,
        cvss: float = 0.0,
        severity: str = "Unknown",
        description: str = "",
    ) -> None:
        self.graph.add_node(
            cve_id,
            type="vulnerability",
            cvss=cvss,
            severity=severity,
            description=description,
        )
        self.graph.add_edge(source_node, cve_id, relation="affected_by")

    def add_missing_header(self, target: str, header: str) -> None:
        header_id = f"header:{header}"
        self.graph.add_node(header_id, type="header", name=header, status="missing")
        self.graph.add_edge(target, header_id, relation="missing")

    def add_service(self, target: str, name: str, port: int) -> str:
        svc_id = f"service:{name}:{port}"
        self.graph.add_node(svc_id, type="service", name=name, port=port)
        self.graph.add_edge(target, svc_id, relation="exposes")
        return svc_id

    def add_configuration(
        self, target: str, setting: str, risk_level: str = "info"
    ) -> None:
        config_id = f"config:{setting}"
        self.graph.add_node(
            config_id, type="configuration", setting=setting, risk_level=risk_level
        )
        self.graph.add_edge(target, config_id, relation="configured")

    def add_subdomain(self, target: str, subdomain: str) -> None:
        self.graph.add_node(subdomain, type="subdomain", name=subdomain)
        self.graph.add_edge(subdomain, target, relation="subdomain_of")

    def add_custom_edge(
        self, source: str, target: str, relation: str, **attrs: object
    ) -> None:
        self.graph.add_edge(source, target, relation=relation, **attrs)

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    def get_nodes_by_type(self, node_type: str) -> list[dict]:
        return [
            {"id": n, **attrs}
            for n, attrs in self.graph.nodes(data=True)
            if attrs.get("type") == node_type
        ]

    def get_vulnerabilities(self) -> list[dict]:
        return self.get_nodes_by_type("vulnerability")

    def get_technologies(self) -> list[dict]:
        return self.get_nodes_by_type("technology")

    def get_missing_headers(self) -> list[dict]:
        return self.get_nodes_by_type("header")

    # ------------------------------------------------------------------ #
    # Serialisation
    # ------------------------------------------------------------------ #

    def serialize_for_llm(self) -> str:
        """Convert graph to a human-readable text block for LLM prompts."""
        lines: list[str] = ["== Security Knowledge Graph =="]

        for node_id, attrs in self.graph.nodes(data=True):
            ntype = attrs.get("type", "unknown")
            label = attrs.get("name", attrs.get("cve_id", node_id))
            extras = {
                k: v
                for k, v in attrs.items()
                if k not in ("type", "name", "cve_id")
            }
            extra_str = f" ({extras})" if extras else ""
            lines.append(f"  [{ntype}] {label}{extra_str}  (id={node_id})")

        lines.append("")
        lines.append("Relationships:")
        for src, dst, data in self.graph.edges(data=True):
            rel = data.get("relation", "unknown")
            lines.append(f"  {src} --{rel}--> {dst}")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict."""
        return {
            "nodes": [
                {"id": n, **attrs} for n, attrs in self.graph.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **data}
                for u, v, data in self.graph.edges(data=True)
            ],
        }
