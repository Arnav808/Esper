"""Shared findings builder — extracts security findings from discovery data.

Used by both the Blue Agent and the Reporting Agent to avoid duplicating
the same header/SSL analysis logic in two places.
"""

from __future__ import annotations

from typing import Any

# Note: This module intentionally only produces header and SSL findings,
# matching the original scope. Open-service and technology findings are
# handled by the Knowledge Graph Builder via the Knowledge Graph.


def build_findings(discovery: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a findings list from raw discovery data.

    Handles both the new dict format (``{"error": ..., "headers": [...]}``)
    and the legacy list format for backward compatibility.
    """
    findings: list[dict[str, Any]] = []

    # --- Header findings ---
    headers_data = discovery.get("headers", {})
    if isinstance(headers_data, dict):
        headers_list = headers_data.get("headers", [])
    elif isinstance(headers_data, list):
        headers_list = headers_data
    else:
        headers_list = []

    for h in headers_list:
        if isinstance(h, dict) and h.get("status") == "missing":
            findings.append(
                {
                    "title": f"Missing {h.get('header')}",
                    "severity": "Medium",
                    "category": "Security Headers",
                    "cvss_score": None,
                    "cve_id": None,
                }
            )

    # --- SSL / TLS findings ---
    ssl_data = discovery.get("ssl", {})
    if not ssl_data.get("https_enabled"):
        findings.append(
            {
                "title": "Unencrypted HTTP Connection Enabled",
                "severity": "High",
                "category": "SSL/TLS Configuration",
                "cvss_score": None,
                "cve_id": None,
            }
        )
    if not ssl_data.get("certificate_valid") and ssl_data.get("https_enabled"):
        findings.append(
            {
                "title": "Invalid or Expired SSL Certificate",
                "severity": "High",
                "category": "SSL/TLS Configuration",
                "cvss_score": None,
                "cve_id": None,
            }
        )

    return findings
