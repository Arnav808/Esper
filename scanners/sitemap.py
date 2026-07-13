"""sitemap.xml scanner — fetches and parses sitemap for discovered URLs."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import requests


def scan_sitemap(url: str) -> dict:
    """Fetch and parse /sitemap.xml from the target.

    Returns discovered URLs and metadata.
    """
    base = url.rstrip("/")

    # Try common sitemap locations
    sitemap_urls = [
        f"{base}/sitemap.xml",
        f"{base}/sitemap_index.xml",
    ]

    all_urls: list[str] = []

    for sitemap_url in sitemap_urls:
        try:
            resp = requests.get(sitemap_url, timeout=10, allow_redirects=True)
            if resp.status_code != 200:
                continue

            content = resp.text
            urls = _parse_sitemap(content)
            if urls:
                all_urls.extend(urls)
                break  # Found a valid sitemap, stop trying

        except requests.exceptions.RequestException:
            continue

    return {
        "error": None,
        "available": len(all_urls) > 0,
        "url_count": len(all_urls),
        "urls": all_urls[:100],  # Cap at 100 for output size
    }


def _parse_sitemap(xml_content: str) -> list[str]:
    """Parse sitemap XML and extract <loc> URLs."""
    urls: list[str] = []

    try:
        root = ET.fromstring(xml_content)

        # Handle namespace
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

        # Try with namespace first, then without
        for elem in root.findall(".//sm:loc", ns):
            if elem.text:
                urls.append(elem.text.strip())

        if not urls:
            for elem in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                if elem.text:
                    urls.append(elem.text.strip())

        if not urls:
            # No namespace — plain XML
            for elem in root.iter():
                if elem.tag.endswith("loc") and elem.text:
                    urls.append(elem.text.strip())

    except ET.ParseError:
        pass

    return urls


if __name__ == "__main__":
    import json

    print(json.dumps(scan_sitemap("https://example.com"), indent=2))
