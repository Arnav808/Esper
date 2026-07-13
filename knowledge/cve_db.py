"""Local CVE knowledge base mapping technology names to known vulnerabilities.

This provides a fast, offline lookup so the Reasoning Engine can correlate
discovered technologies with CVEs without needing a live NVD API call on
every scan.  The data should be kept reasonably up-to-date.
"""

from __future__ import annotations

CVE_KNOWLEDGE_BASE: dict[str, list[dict]] = {
    "Apache": [
        {
            "id": "CVE-2021-41773",
            "cvss": 9.8,
            "severity": "Critical",
            "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49.",
            "requires_missing_header": None,
        },
        {
            "id": "CVE-2021-42013",
            "cvss": 9.8,
            "severity": "Critical",
            "description": "Path traversal in Apache HTTP Server 2.4.50 (incomplete fix for CVE-2021-41773).",
            "requires_missing_header": None,
        },
    ],
    "Nginx": [
        {
            "id": "CVE-2021-23017",
            "cvss": 7.7,
            "severity": "High",
            "description": "DNS resolver off-by-one heap write.",
            "requires_missing_header": None,
        },
    ],
    "WordPress": [
        {
            "id": "CVE-2024-31210",
            "cvss": 7.5,
            "severity": "High",
            "description": "Stored XSS vulnerability via role editing.",
            "requires_missing_header": None,
        },
    ],
    "Django": [
        {
            "id": "CVE-2024-24680",
            "cvss": 7.5,
            "severity": "High",
            "description": "Denial of service via intcomma template filter.",
            "requires_missing_header": None,
        },
    ],
    "Flask": [],
    "Express": [],
    "Next.js": [],
    "React": [],
    "Angular": [],
    "Vue": [],
}
