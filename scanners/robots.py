"""robots.txt scanner — fetches and parses robots.txt for disallowed paths."""

from __future__ import annotations

import requests


def scan_robots(url: str) -> dict:
    """Fetch and parse /robots.txt from the target.

    Returns disallowed paths, allowed paths, and any sitemap references.
    """
    base = url.rstrip("/")
    robots_url = f"{base}/robots.txt"

    try:
        resp = requests.get(robots_url, timeout=10, allow_redirects=True)
        if resp.status_code == 404:
            return {"available": False, "disallowed": [], "sitemaps": []}

        content = resp.text
        disallowed: list[str] = []
        allowed: list[str] = []
        sitemaps: list[str] = []
        user_agents: list[str] = []

        current_agent = "*"
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            lower = line.lower()
            if lower.startswith("user-agent:"):
                current_agent = line.split(":", 1)[1].strip()
                user_agents.append(current_agent)
            elif lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.append(path)
            elif lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    allowed.append(path)
            elif lower.startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                if sm:
                    sitemaps.append(sm)

        return {
            "error": None,
            "available": True,
            "url": robots_url,
            "disallowed": disallowed,
            "allowed": allowed,
            "sitemaps": sitemaps,
            "user_agents": user_agents,
            "raw_length": len(content),
        }

    except requests.exceptions.RequestException as e:
        return {"available": False, "error": str(e), "disallowed": [], "sitemaps": []}


if __name__ == "__main__":
    import json

    print(json.dumps(scan_robots("https://example.com"), indent=2))
