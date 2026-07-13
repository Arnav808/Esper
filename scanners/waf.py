"""WAF/CDN detection scanner — identifies Web Application Firewalls."""

from __future__ import annotations

import requests

# WAF/CDN signature patterns (header name → patterns)
WAF_SIGNATURES: dict[str, list[dict]] = [
    # Cloudflare
    {"header_contains": {"server": ["cloudflare"]}, "name": "Cloudflare", "type": "CDN"},
    {"header_contains": {"cf-ray": [""]}, "name": "Cloudflare", "type": "CDN"},
    # AWS WAF / CloudFront
    {"header_contains": {"server": ["cloudfront"]}, "name": "Amazon CloudFront", "type": "CDN"},
    {"header_contains": {"x-amz-cf-id": [""]}, "name": "Amazon CloudFront", "type": "CDN"},
    # Akamai
    {"header_contains": {"server": ["akamaighost"]}, "name": "Akamai", "type": "CDN"},
    {"header_contains": {"x-akamai-transformed": [""]}, "name": "Akamai", "type": "CDN"},
    # Imperva / Incapsula
    {"header_contains": {"server": ["incapsula"]}, "name": "Imperva Incapsula", "type": "WAF"},
    {"header_contains": {"x-iinfo": [""]}, "name": "Imperva Incapsula", "type": "WAF"},
    # Sucuri
    {"header_contains": {"server": ["sucuri"]}, "name": "Sucuri WAF", "type": "WAF"},
    {"header_contains": {"x-sucuri-id": [""]}, "name": "Sucuri WAF", "type": "WAF"},
    # Fortinet
    {"header_contains": {"server": ["fortiweb"]}, "name": "Fortinet FortiWeb", "type": "WAF"},
    # ModSecurity
    {"header_contains": {"server": ["mod_security"]}, "name": "ModSecurity", "type": "WAF"},
    {"header_contains": {"server": ["modsecurity"]}, "name": "ModSecurity", "type": "WAF"},
    # F5 BIG-IP
    {"header_contains": {"server": ["bigip"]}, "name": "F5 BIG-IP", "type": "WAF"},
    {"header_contains": {"set-cookie": ["BIGipServer"]}, "name": "F5 BIG-IP", "type": "WAF"},
    # Barracuda
    {"header_contains": {"server": ["barracuda"]}, "name": "Barracuda WAF", "type": "WAF"},
    # Azure Front Door
    {"header_contains": {"server": ["azure"]}, "name": "Azure Front Door", "type": "CDN"},
    {"header_contains": {"x-azure-ref": [""]}, "name": "Azure Front Door", "type": "CDN"},
]


def detect_waf(url: str) -> dict:
    """Detect WAF/CDN by inspecting HTTP response headers.

    Returns a list of detected WAF/CDN signatures.
    """
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

        detected: list[dict] = []
        seen_names: set[str] = set()

        for sig in WAF_SIGNATURES:
            for header_pattern, patterns in sig["header_contains"].items():
                header_value = headers_lower.get(header_pattern, "")
                for pattern in patterns:
                    if pattern == "" or pattern in header_value:
                        name = sig["name"]
                        if name not in seen_names:
                            detected.append({
                                "name": name,
                                "type": sig["type"],
                                "evidence": f"{header_pattern}: {headers_lower.get(header_pattern, 'N/A')}",
                            })
                            seen_names.add(name)
                        break

        return {
            "error": None,
            "detected": detected,
            "waf_found": any(d["type"] == "WAF" for d in detected),
            "cdn_found": any(d["type"] == "CDN" for d in detected),
            "server_header": headers_lower.get("server", ""),
        }

    except requests.exceptions.RequestException as e:
        return {"detected": [], "waf_found": False, "cdn_found": False, "error": str(e)}


if __name__ == "__main__":
    import json

    print(json.dumps(detect_waf("https://example.com"), indent=2))
