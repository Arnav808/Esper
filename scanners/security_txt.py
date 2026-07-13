"""security.txt scanner — fetches and parses RFC 9116 security.txt."""

from __future__ import annotations

import requests


def scan_security_txt(url: str) -> dict:
    """Fetch /.well-known/security.txt and parse its fields.

    Returns the parsed security contact information or an error.
    """
    base = url.rstrip("/")

    # Try .well-known first (RFC 9116), then root
    paths = [
        f"{base}/.well-known/security.txt",
        f"{base}/security.txt",
    ]

    for security_url in paths:
        try:
            resp = requests.get(security_url, timeout=10, allow_redirects=True)
            if resp.status_code != 200:
                continue

            content = resp.text
            parsed = _parse_security_txt(content)
            parsed["available"] = True
            parsed["url"] = security_url
            return parsed

        except requests.exceptions.RequestException:
            continue

    return {
        "error": None,
        "available": False,
        "contact": [],
        "encryption": [],
        "policy": None,
        "acknowledgments": None,
        "preferred_languages": [],
    }


def _parse_security_txt(content: str) -> dict:
    """Parse security.txt fields (simplified RFC 9116 parser)."""
    fields: dict[str, list[str] | str | None] = {
        "contact": [],
        "encryption": [],
        "policy": None,
        "acknowledgments": None,
        "preferred_languages": [],
        "expires": None,
        "csaf": None,
    }

    current_key: str | None = None

    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            if current_key and not line:
                current_key = None  # End of multi-value
            continue

        # Parse field: value
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if key in fields:
                current_key = key
                if isinstance(fields[key], list):
                    fields[key].append(value)
                else:
                    fields[key] = value

        elif current_key and isinstance(fields.get(current_key), list):
            # Continuation of a multi-value field
            fields[current_key].append(line)

    return fields


if __name__ == "__main__":
    import json

    print(json.dumps(scan_security_txt("https://example.com"), indent=2))
