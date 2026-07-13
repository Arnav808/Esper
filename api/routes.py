"""Flask Blueprint for Esper API routes."""

from __future__ import annotations

import traceback

from flask import Blueprint, request, jsonify

from agents.orchestrator import run_assessment
from database.database import get_history, get_scan, get_scan_findings

routes = Blueprint("routes", __name__)


# ------------------------------------------------------------------ #
# Core scan endpoint
# ------------------------------------------------------------------ #


@routes.route("/scan", methods=["POST"])
def scan_endpoint():
    """Run a full Esper assessment against a target URL."""
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"status": "error", "message": "Missing required 'url' parameter"}), 400

    target_url = data["url"]

    try:
        result = run_assessment(target_url)

        # Serialise graphs for JSON response
        kg_dict = None
        if result.get("knowledge_graph") is not None:
            kg_dict = result["knowledge_graph"].to_dict()

        ag_dict = None
        if result.get("attack_graph") is not None:
            ag_dict = {
                "nodes": [
                    {"id": n, **a} for n, a in result["attack_graph"].nodes(data=True)
                ],
                "edges": [
                    {"source": u, "target": v, **d}
                    for u, v, d in result["attack_graph"].edges(data=True)
                ],
            }

        mg_dict = None
        if result.get("mitigation_graph") is not None:
            mg_dict = {
                "nodes": [
                    {"id": n, **a} for n, a in result["mitigation_graph"].nodes(data=True)
                ],
                "edges": [
                    {"source": u, "target": v, **d}
                    for u, v, d in result["mitigation_graph"].edges(data=True)
                ],
            }

        response = {
            "status": "completed",
            "target": target_url,
            "scan_id": result.get("scan_id"),
            "security_score": result.get("security_score", 0),
            "confidence": result.get("confidence", 0),
            "knowledge_graph": kg_dict,
            "attack_graph": ag_dict,
            "mitigation_graph": mg_dict,
            "report_path": result.get("report_path"),
            "pdf_report_path": result.get("pdf_report_path"),
            "comparison": result.get("comparison"),
            "history": result.get("history", []),
            "logs": result.get("logs", []),
            "errors": result.get("errors", []),
        }

        return jsonify(response), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Pipeline failure: {e}"}), 500


# ------------------------------------------------------------------ #
# History endpoints (Phase 2)
# ------------------------------------------------------------------ #


@routes.route("/history", methods=["GET"])
def history_endpoint():
    """List scan history, optionally filtered by target."""
    target = request.args.get("target")
    limit = request.args.get("limit", 20, type=int)
    offset = request.args.get("offset", 0, type=int)

    scans = get_history(target_url=target, limit=limit, offset=offset)
    return jsonify({"status": "ok", "scans": scans, "count": len(scans)}), 200


@routes.route("/scan/<int:scan_id>", methods=["GET"])
def scan_detail_endpoint(scan_id: int):
    """Retrieve a single scan by ID with its findings."""
    scan = get_scan(scan_id)
    if scan is None:
        return jsonify({"status": "error", "message": f"Scan {scan_id} not found"}), 404

    findings = get_scan_findings(scan_id)
    scan["findings"] = findings
    return jsonify({"status": "ok", "scan": scan}), 200
