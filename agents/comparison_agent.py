"""Comparison Agent — compares the current scan against the previous scan for the same target.

Generates a delta report showing new/resolved/unchanged findings and score changes.
"""

from __future__ import annotations

from typing import Any

from agents.base import BaseAgent
from graph.state import EsperState


def _log(agent: str, status: str, message: str) -> dict:
    return {"agent": agent, "status": status, "message": message}


class ComparisonAgent(BaseAgent):
    """Compares the current assessment result with the most recent prior scan."""

    name = "comparison_agent"

    def run(self, state: EsperState) -> dict:
        previous = state.get("previous_scan")

        if previous is None:
            return {
                "comparison": None,
                "history": state.get("history", [])
                + [{"agent": self.name, "status": "skipped", "message": "No previous scan found"}],
                "logs": state.get("logs", [])
                + [_log(self.name, "skipped", "No previous scan to compare against")],
            }

        current_findings = state.get("current_findings", [])
        previous_findings = previous.get("findings", [])

        comparison = self._compare(previous, state, previous_findings, current_findings)

        return {
            "comparison": comparison,
            "history": state.get("history", [])
            + [
                {
                    "agent": self.name,
                    "status": "complete",
                    "message": (
                        f"Score {previous.get('security_score', '?')} → "
                        f"{state.get('security_score', '?')} "
                        f"({comparison['score_delta']:+d})"
                    ),
                }
            ],
            "logs": state.get("logs", [])
            + [
                _log(
                    self.name,
                    "complete",
                    f"Compared with scan #{previous.get('id', '?')}: "
                    f"{len(comparison['new_findings'])} new, "
                    f"{len(comparison['resolved_findings'])} resolved",
                )
            ],
        }

    # ------------------------------------------------------------------ #
    # Comparison logic
    # ------------------------------------------------------------------ #

    def _compare(
        self,
        previous: dict[str, Any],
        current_state: dict[str, Any],
        prev_findings: list[dict[str, Any]],
        curr_findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        prev_titles = {f.get("title", "") for f in prev_findings}
        curr_titles = {f.get("title", "") for f in curr_findings}

        new_findings = [f for f in curr_findings if f.get("title", "") not in prev_titles]
        resolved_findings = [f for f in prev_findings if f.get("title", "") not in curr_titles]
        unchanged = [f for f in curr_findings if f.get("title", "") in prev_titles]

        prev_score = previous.get("security_score", 0)
        curr_score = current_state.get("security_score", 0)

        return {
            "previous_scan_id": previous.get("id"),
            "previous_score": prev_score,
            "current_score": curr_score,
            "score_delta": curr_score - prev_score,
            "previous_date": previous.get("created_at", ""),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "unchanged_findings": unchanged,
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "unchanged_count": len(unchanged),
        }
