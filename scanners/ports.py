"""Port scanner — discovers open TCP ports on the target host."""

from __future__ import annotations

import socket
from urllib.parse import urlparse

# Common ports to probe
COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9200, 27017,
]

# Well-known service names
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Proxy", 9200: "Elasticsearch", 27017: "MongoDB",
}


def scan_ports(url: str, timeout: float = 2.0) -> dict:
    """Connect-scan common TCP ports on the target host.

    Returns a list of open ports with their service names.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        return {"error": "Could not extract hostname", "open_ports": []}

    # Resolve to IP first
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"error": f"DNS resolution failed for {hostname}", "open_ports": []}

    open_ports: list[dict] = []

    for port in COMMON_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append({
                    "port": port,
                    "service": SERVICE_MAP.get(port, "unknown"),
                    "state": "open",
                })
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue

    return {
        "error": None,
        "hostname": hostname,
        "ip": ip,
        "open_ports": open_ports,
        "ports_scanned": len(COMMON_PORTS),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(scan_ports("https://example.com"), indent=2))
