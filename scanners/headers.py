import requests
from typing import Any


def check_security_headers(url: str) -> dict[str, Any]:
    """Check for the presence of common security headers.

    Returns:
        ``{"error": None, "headers": [...]}`` on success,
        ``{"error": "...", "headers": []}`` on failure.
    """
    target_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
    ]
    results: list[dict[str, str]] = []

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        site_headers = response.headers

        for header in target_headers:
            if header.lower() in (h.lower() for h in site_headers):
                results.append({"header": header, "status": "present"})
            else:
                results.append({"header": header, "status": "missing"})

        return {"error": None, "headers": results}

    except requests.exceptions.Timeout:
        return {"error": "Scan timed out. Target server took too long to respond.", "headers": []}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error occurred: {e}", "headers": []}


if __name__ == "__main__":
    import json

    test_url = "https://example.com"
    print(f"Executing isolated sensor test for: {test_url}...\n")
    findings = check_security_headers(test_url)
    print(json.dumps(findings, indent=4))