"""Shared state model for the Esper LangGraph workflow."""

from typing import TypedDict, Any, Optional
from networkx import DiGraph


class AgentLog(TypedDict):
    agent: str
    status: str
    message: str


class EsperState(TypedDict):
    """State dictionary shared across all Esper agents via LangGraph."""

    # Input
    target_url: str

    # Discovery Agent output
    discovery_results: dict[str, Any]

    # Reasoning Engine output
    knowledge_graph: Optional[DiGraph]
    confidence: float

    # Attack Planner output
    attack_opportunities: list[dict[str, Any]]

    # Red Agent output
    attack_graph: Optional[DiGraph]

    # Blue Agent output
    mitigation_graph: Optional[DiGraph]

    # Scoring
    security_score: int

    # Reporting
    report: Optional[str]
    report_path: Optional[str]
    pdf_report_path: Optional[str]

    # Phase 2 — Persistence & comparison
    scan_id: Optional[int]
    previous_scan: Optional[dict[str, Any]]
    current_findings: Optional[list[dict[str, Any]]]
    comparison: Optional[dict[str, Any]]

    # Agent memory
    history: list[dict[str, Any]]
    logs: list[AgentLog]
    errors: list[str]
