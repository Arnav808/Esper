"""Reporting Agent — delegates to reporting/markdown.py for text and reporting/pdf.py for PDF."""

from __future__ import annotations

from agents.base import BaseAgent
from graph.state import EsperState
from reporting.markdown import build_report, save_report, _get_findings
from reporting.pdf import generate_pdf_report


def _log(agent: str, status: str, message: str) -> dict:
    return {"agent": agent, "status": status, "message": message}


class ReportingAgent(BaseAgent):
    """Orchestrates Markdown and PDF report generation from shared state."""

    name = "reporting_agent"

    def run(self, state: EsperState) -> dict:
        report = build_report(state)
        md_path = save_report(state["target_url"], report)

        # Generate PDF alongside Markdown
        pdf_path = None
        try:
            pdf_path = generate_pdf_report(
                target_url=state["target_url"],
                markdown_content=report,
                security_score=state.get("security_score", 0),
                confidence=state.get("confidence", 0),
                findings=_get_findings(state),
            )
        except Exception as exc:
            state.setdefault("errors", []).append(f"pdf_generation: {exc}")

        pdf_msg = f", PDF: {pdf_path}" if pdf_path else ""

        return {
            "report": report,
            "report_path": md_path,
            "pdf_report_path": pdf_path,
            "history": state.get("history", [])
            + [
                {
                    "agent": self.name,
                    "status": "complete",
                    "message": f"Report saved to {md_path}{pdf_msg}",
                }
            ],
            "logs": state.get("logs", [])
            + [_log(self.name, "complete", f"Markdown: {md_path}{pdf_msg}")],
        }

