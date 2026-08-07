"""
SentinelX AI – Shodan Threat Intelligence Provider
Async client for Shodan REST API.
"""

import httpx
from typing import Any, Dict
from app.core.config import settings
from app.services.threat_intelligence.providers.base import BaseThreatProvider


class ShodanProvider(BaseThreatProvider):
    """Shodan API integration for host lookup, open ports, vulnerabilities, services, org, and ASN."""

    provider_name = "Shodan"
    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or settings.SHODAN_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    async def lookup_host(self, host: str) -> Dict[str, Any]:
        if not self.is_configured:
            return self.build_unavailable_response("API key missing (SHODAN_API_KEY not configured)")

        target_ip = host.strip()
        url = f"{self.BASE_URL}/shodan/host/{target_ip}"
        params = {"key": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, params=params)

                if response.status_code == 200:
                    data = response.json()
                    ports = data.get("ports", [])
                    vulns_raw = data.get("vulns", [])
                    vulns = list(vulns_raw.keys()) if isinstance(vulns_raw, dict) else list(vulns_raw)
                    raw_services = data.get("data", [])

                    services = []
                    for svc in raw_services:
                        services.append({
                            "port": svc.get("port"),
                            "transport": svc.get("transport", "tcp"),
                            "product": svc.get("product"),
                            "version": svc.get("version"),
                            "banner_snippet": svc.get("banner", "")[:100] if svc.get("banner") else None,
                        })

                    threat_score = 0
                    verdict = "Harmless"
                    if len(vulns) > 0 or 3389 in ports or 23 in ports:
                        verdict = "Suspicious"
                        threat_score = min(100, 30 + len(vulns) * 15)
                    if len(vulns) >= 3:
                        verdict = "Malicious"

                    return {
                        "provider": self.provider_name,
                        "status": "available",
                        "reason": None,
                        "data": {
                            "verdict": verdict,
                            "threat_score": threat_score,
                            "ip": data.get("ip_str", target_ip),
                            "hostnames": data.get("hostnames", []),
                            "open_ports": ports,
                            "vulnerabilities": vulns,
                            "services": services,
                            "organization": data.get("org"),
                            "isp": data.get("isp"),
                            "asn": data.get("asn"),
                            "os": data.get("os"),
                            "country_name": data.get("country_name"),
                            "city": data.get("city"),
                            "last_update": data.get("last_update"),
                        },
                    }

                elif response.status_code == 404:
                    return {
                        "provider": self.provider_name,
                        "status": "not_found",
                        "reason": "Host IP not found in Shodan telemetry index",
                        "data": None,
                    }
                elif response.status_code == 401:
                    return self.build_unavailable_response("Invalid or unauthorized API key (HTTP 401)")
                elif response.status_code == 429:
                    return self.build_unavailable_response("Rate limit exceeded (HTTP 429)")
                else:
                    return self.build_unavailable_response(f"HTTP error {response.status_code}: {response.text[:100]}")

        except httpx.TimeoutException:
            return self.build_unavailable_response("Request timed out (Shodan unreachable)")
        except Exception as err:
            return self.build_unavailable_response(f"Connection error: {str(err)}")

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return await self.lookup_host(ip)

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return self.build_unavailable_response("Shodan direct host lookup requires an IP address")

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        return self.build_unavailable_response("Shodan direct host lookup requires an IP address")

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return self.build_unavailable_response("Shodan direct host lookup requires an IP address")
