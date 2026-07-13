"""Markdown report builder — generates structured security assessment reports.

Provides pure functions for building each section of the Esper Markdown report.
The Reporting Agent delegates to these functions rather than building reports inline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from analysis.findings import build_findings


def build_report(state: dict[str, Any]) -> str:
    """Assemble the full Markdown report from all state fields."""
    sections = [
        _header(state),
        _executive_summary(state),
        _asset_inventory(state),
        _security_findings(state),
        _attack_paths(state),
        _risk_assessment(state),
        _mitigations(state),
        _appendix(state),
    ]
    return "\n\n".join(s for s in sections if s)


def _header(state: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
    return (
        f"# 🛡️ Esper Security Assessment\n\n"
        f"**Target:** `{state['target_url']}`\n\n"
        f"**Date:** {now}\n\n"
        f"**Confidence:** {state.get('confidence', 0):.0%}"
    )


def _executive_summary(state: dict[str, Any]) -> str:
    score = state.get("security_score", 0)
    if score >= 80:
        health = "strong"
    elif score >= 60:
        health = "moderate"
    elif score >= 40:
        health = "concerning"
    else:
        health = "critical"

    findings = _get_findings(state)
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    counts_str = ", ".join(f"{v} {k}" for k, v in sorted(severity_counts.items()))

    return (
        f"## 1. Executive Summary\n\n"
        f"The target has a security score of **{score}/100**, "
        f"indicating **{health}** security posture.\n\n"
        f"**Findings:** {counts_str}\n\n"
        f"**Confidence:** {state.get('confidence', 0):.0%} — "
        f"based on the number of scanners that returned valid data."
    )


def _asset_inventory(state: dict[str, Any]) -> str:
    kg = state.get("knowledge_graph")
    if kg is None:
        return "## 2. Asset Inventory\n\n*No knowledge graph available.*"

    lines = ["## 2. Asset Inventory\n"]

    # Technologies
    techs = kg.get_technologies()
    if techs:
        lines.append("### Technologies\n")
        for t in techs:
            ver = f" {t['version']}" if t.get("version") else ""
            lines.append(f"- **{t['name']}**{ver}")

    # Services
    svcs = kg.get_nodes_by_type("service")
    if svcs:
        lines.append("\n### Open Services\n")
        for s in svcs:
            lines.append(f"- **{s['name']}** (port {s['port']})")

    # Headers
    missing = kg.get_missing_headers()
    if missing:
        lines.append("\n### Missing Security Headers\n")
        for h in missing:
            lines.append(f"- ❌ {h['name']}")

    return "\n".join(lines)


def _security_findings(state: dict[str, Any]) -> str:
    findings = _get_findings(state)
    if not findings:
        return "## 3. Security Findings\n\n✅ No findings detected."

    lines = ["## 3. Security Findings\n"]

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    sorted_findings = sorted(
        findings, key=lambda f: severity_order.get(f.get("severity", "Unknown"), 4)
    )

    for f in sorted_findings:
        sev = f.get("severity", "Unknown")
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sev, "⚪")
        lines.append(f"- {icon} **[{sev}]** {f['title']}  ")
        lines.append(f"  Category: {f.get('category', 'N/A')}")

    return "\n".join(lines)


def _attack_paths(state: dict[str, Any]) -> str:
    attack_graph = state.get("attack_graph")
    if attack_graph is None:
        return "## 4. Attack Paths\n\n*No attack graph generated.*"

    lines = ["## 4. Attack Paths\n"]

    chains = []
    for node, attrs in attack_graph.nodes(data=True):
        if attrs.get("type") == "chain":
            chains.append(attrs)

    if not chains:
        lines.append("No attack chains identified.")
        return "\n".join(lines)

    for i, chain in enumerate(chains, 1):
        impact = chain.get("impact", "Medium")
        conf = chain.get("confidence", 0)
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(impact, "⚪")

        lines.append(f"### {i}. {chain.get('name', 'Unknown')}\n")
        lines.append(f"- **Impact:** {icon} {impact}")
        lines.append(f"- **Confidence:** {conf:.0%}")

        for _, step_attrs in attack_graph.nodes(data=True):
            if step_attrs.get("type") == "technique":
                mitre = step_attrs.get("mitre_id", "")
                lines.append(f"  - {step_attrs.get('name', '')} ({mitre})")

        lines.append("")

    return "\n".join(lines)


def _risk_assessment(state: dict[str, Any]) -> str:
    score = state.get("security_score", 0)
    return (
        f"## 5. Risk Assessment\n\n"
        f"| Metric | Value |\n"
        f"|---|---|\n"
        f"| Security Score | {score}/100 |\n"
        f"| Confidence | {state.get('confidence', 0):.0%} |\n"
        f"| Target | {state['target_url']} |"
    )


def _mitigations(state: dict[str, Any]) -> str:
    mg = state.get("mitigation_graph")
    if mg is None:
        return "## 6. Recommended Mitigations\n\n*No mitigations generated.*"

    lines = ["## 6. Recommended Mitigations\n"]
    lines.append("| Priority | Action | Effort | Risk Reduction |")
    lines.append("|---|---|---|---|")

    for _, attrs in mg.nodes(data=True):
        if attrs.get("type") == "mitigation":
            lines.append(
                f"| {attrs.get('priority', 'Medium')} "
                f"| {attrs.get('action', '')} "
                f"| {attrs.get('effort', 'Medium')} "
                f"| {attrs.get('risk_reduction', 0)}% |"
            )

    return "\n".join(lines)


def _appendix(state: dict[str, Any]) -> str:
    lines = ["## 7. Appendix\n"]

    lines.append("### Agent Execution Log\n")
    for log in state.get("logs", []):
        icon = (
            "✅"
            if log["status"] == "complete"
            else "⏭️" if log["status"] == "skipped"
            else "❌"
        )
        lines.append(f"- {icon} **{log['agent']}** — {log['message']}")

    if state.get("errors"):
        lines.append("\n### Errors\n")
        for err in state["errors"]:
            lines.append(f"- ❌ {err}")

    return "\n".join(lines)


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _get_findings(state: dict[str, Any]) -> list[dict]:
    """Extract findings — reuse if already computed by the orchestrator."""
    precomputed = state.get("current_findings")
    if precomputed:
        return precomputed
    return build_findings(state.get("discovery_results", {}))


def save_report(target_url: str, report: str) -> str:
    """Write the Markdown report to disk and return the file path."""
    import os
    from urllib.parse import urlparse

    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    domain = urlparse(target_url).netloc or "unknown"
    clean = domain.replace(":", "_").replace("/", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(reports_dir, f"esper_{clean}_{ts}.md")

    with open(path, "w", encoding="utf-8") as f:
        f.write(report)

    return path
