"""Orchestrator — wires all agents into a sequential pipeline.

Tries to use LangGraph if available; falls back to a lightweight
sequential executor that follows the same state-merge contract.
"""

from __future__ import annotations

from graph.state import EsperState
from agents.discovery_agent import DiscoveryAgent
from agents.knowledge_graph_builder import KnowledgeGraphBuilder
from agents.attack_planner import AttackPlanner
from agents.red_agent import RedAgent
from agents.blue_agent import BlueAgent
from agents.reporting_agent import ReportingAgent
from agents.comparison_agent import ComparisonAgent
from analysis.findings import build_findings


# ------------------------------------------------------------------ #
# Agent pipeline definition
# ------------------------------------------------------------------ #

# ComparisonAgent runs manually after DB lookup — not in the pipeline.
# Attack Planner identifies attack opportunities; Red Agent builds chains from them.
_AGENTS = [
    DiscoveryAgent(),
    KnowledgeGraphBuilder(),
    AttackPlanner(),
    RedAgent(),
    BlueAgent(),
    ReportingAgent(),
]


def _make_initial_state(target_url: str) -> EsperState:
    return {
        "target_url": target_url,
        "discovery_results": {},
        "knowledge_graph": None,
        "confidence": 0.0,
        "attack_opportunities": [],
        "attack_graph": None,
        "mitigation_graph": None,
        "security_score": 100,
        "report": None,
        "report_path": None,
        "pdf_report_path": None,
        "scan_id": None,
        "previous_scan": None,
        "current_findings": [],
        "comparison": None,
        "history": [],
        "logs": [],
        "errors": [],
    }


def _run_sequential(target_url: str) -> dict:
    """Run agents sequentially, merging state after each step."""
    state: EsperState = _make_initial_state(target_url)

    for agent in _AGENTS:
        try:
            updates = agent.run(state)
            state.update(updates)  # type: ignore[arg-type]
        except Exception as exc:
            state["errors"].append(f"{agent.name}: {exc}")
            state["logs"].append(
                {"agent": agent.name, "status": "failed", "message": str(exc)}
            )

    return state


def run_assessment(target_url: str) -> dict:
    """Execute a full Esper assessment against *target_url*.

    Returns the final merged state dict.
    """
    # Try LangGraph first (optional dependency)
    try:
        from langgraph.graph import StateGraph, START, END  # type: ignore[import-untyped]

        builder = StateGraph(EsperState)
        for agent in _AGENTS:
            builder.add_node(agent.name, agent.run)

        nodes = [a.name for a in _AGENTS]
        builder.add_edge(START, nodes[0])
        for i in range(len(nodes) - 1):
            builder.add_edge(nodes[i], nodes[i + 1])
        builder.add_edge(nodes[-1], END)

        graph = builder.compile()
        result = graph.invoke(_make_initial_state(target_url))

    except ImportError:
        result = _run_sequential(target_url)

    # ------------------------------------------------------------------
    # Phase 2 — Persist scan + fetch previous for comparison
    # ------------------------------------------------------------------
    try:
        from database.database import init_db, save_scan, get_previous_scan

        init_db()

        # Compute current findings for storage & comparison
        findings = build_findings(result.get("discovery_results", {}))
        result["current_findings"] = findings  # type: ignore[typeddict-item]

        # Find the most recent prior scan BEFORE we insert
        prev = get_previous_scan(target_url)
        result["previous_scan"] = prev  # type: ignore[typeddict-item]

        # Re-run comparison agent now that previous_scan is in state
        comp_agent = ComparisonAgent()
        try:
            comp_updates = comp_agent.run(result)
            result.update(comp_updates)
        except Exception as exc:
            result["errors"].append(f"comparison_agent: {exc}")

        # Persist this scan
        scan_id = save_scan(
            target_url=target_url,
            security_score=result.get("security_score", 0),
            confidence=result.get("confidence", 0.0),
            report_path=result.get("report_path"),
            findings=findings,
            discovery=result.get("discovery_results", {}),
            attack_graph=result.get("attack_graph"),
            mitigation_graph=result.get("mitigation_graph"),
        )
        result["scan_id"] = scan_id  # type: ignore[typeddict-item]

    except Exception as exc:
        result["errors"].append(f"persistence: {exc}")

    return result
