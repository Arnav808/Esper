"""Discovery Agent — runs all scanners and collects raw evidence."""

from __future__ import annotations

from datetime import datetime, timezone

from agents.base import BaseAgent
from graph.state import EsperState

# Scanner imports
from scanners.headers import check_security_headers
from scanners.ssl import check_ssl
from scanners.tech import detect_technology
from scanners.dns import scan_dns
from scanners.ports import scan_ports
from scanners.robots import scan_robots
from scanners.sitemap import scan_sitemap
from scanners.security_txt import scan_security_txt
from scanners.waf import detect_waf


def _log(agent: str, status: str, message: str) -> dict:
    return {"agent": agent, "status": status, "message": message}


class DiscoveryAgent(BaseAgent):
    """Collects evidence from the target using all available scanners."""

    name = "discovery_agent"

    def run(self, state: EsperState) -> dict:
        url = state["target_url"]

        # Run all scanners — each is independent, but run sequentially to
        # avoid overloading the target with parallel connections.
        raw_headers = check_security_headers(url)
        raw_ssl = check_ssl(url)
        raw_tech = detect_technology(url)
        raw_dns = scan_dns(url)
        raw_ports = scan_ports(url)
        raw_robots = scan_robots(url)
        raw_sitemap = scan_sitemap(url)
        raw_security_txt = scan_security_txt(url)
        raw_waf = detect_waf(url)

        discovery = {
            "headers": raw_headers,
            "ssl": raw_ssl,
            "tech": raw_tech,
            "dns": raw_dns,
            "ports": raw_ports,
            "robots": raw_robots,
            "sitemap": raw_sitemap,
            "security_txt": raw_security_txt,
            "waf": raw_waf,
        }

        scanner_count = 9

        return {
            "discovery_results": discovery,
            "history": state.get("history", []) + [
                {
                    "agent": self.name,
                    "status": "complete",
                    "message": f"Collected data from {scanner_count} scanners",
                }
            ],
            "logs": state.get("logs", [])
            + [_log(self.name, "complete", "Discovery scan complete")],
        }
