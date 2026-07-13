"""DNS enumeration scanner — queries common record types for a target domain."""

from __future__ import annotations

from urllib.parse import urlparse

import dns.resolver


_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


def scan_dns(url: str) -> dict:
    """Perform passive DNS lookups on the target domain.

    Returns a dict keyed by record type, each mapping to a list of records.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        return {"error": "Could not extract hostname from URL", "records": {}}

    records: dict[str, list[str]] = {}

    for rtype in _RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(hostname, rtype, lifetime=5)
            records[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            records[rtype] = []
        except dns.exception.Timeout:
            records[rtype] = []
        except Exception:
            records[rtype] = []

    return {
        "error": None,
        "hostname": hostname,
        "records": records,
        "record_types_found": [k for k, v in records.items() if v],
    }


if __name__ == "__main__":
    import json

    print(json.dumps(scan_dns("https://example.com"), indent=2))
