"""
SentinelX AI – VirusTotal Threat Intelligence Provider
Async client for VirusTotal v3 REST API.
"""

import base64
import httpx
from typing import Any, Dict
from app.core.config import settings
from app.services.threat_intelligence.providers.base import BaseThreatProvider


class VirusTotalProvider(BaseThreatProvider):
    """VirusTotal API v3 integration for IP, Domain, URL, and Hash reputation lookups."""

    provider_name = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _headers(self) -> Dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "Accept": "application/json",
        }

    async def _make_request(self, endpoint: str) -> Dict[str, Any]:
        if not self.is_configured:
            return self.build_unavailable_response("API key missing (VIRUSTOTAL_API_KEY not configured)")

        url = f"{self.BASE_URL}{endpoint}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=self._headers())

                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    total_engines = sum(stats.values()) if stats else 0

                    verdict = "Harmless"
                    if malicious > 3:
                        verdict = "Malicious"
                    elif malicious > 0 or suspicious > 0:
                        verdict = "Suspicious"

                    threat_score = 0
                    if total_engines > 0:
                        threat_score = min(100, int(((malicious * 2 + suspicious) / total_engines) * 100))

                    return {
                        "provider": self.provider_name,
                        "status": "available",
                        "reason": None,
                        "data": {
                            "verdict": verdict,
                            "threat_score": threat_score,
                            "malicious_count": malicious,
                            "suspicious_count": suspicious,
                            "harmless_count": harmless,
                            "total_engines": total_engines,
                            "reputation": data.get("reputation", 0),
                            "tags": data.get("tags", []),
                            "last_analysis_stats": stats,
                            "raw_attributes": {
                                "country": data.get("country"),
                                "asn": data.get("asn"),
                                "as_owner": data.get("as_owner"),
                                "meaningful_name": data.get("meaningful_name"),
                                "type_description": data.get("type_description"),
                                "registrar": data.get("registrar"),
                            },
                        },
                    }

                elif response.status_code == 404:
                    return {
                        "provider": self.provider_name,
                        "status": "not_found",
                        "reason": "Indicator not found in VirusTotal dataset",
                        "data": None,
                    }
                elif response.status_code == 401:
                    return self.build_unavailable_response("Invalid or unauthorized API key (HTTP 401)")
                elif response.status_code == 429:
                    return self.build_unavailable_response("Rate limit exceeded (HTTP 429)")
                else:
                    return self.build_unavailable_response(f"HTTP error {response.status_code}: {response.text[:100]}")

        except httpx.TimeoutException:
            return self.build_unavailable_response("Request timed out (VirusTotal unreachable)")
        except Exception as err:
            return self.build_unavailable_response(f"Connection error: {str(err)}")

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return await self._make_request(f"/ip_addresses/{ip.strip()}")

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return await self._make_request(f"/domains/{domain.strip()}")

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        # VirusTotal URL ID is base64url string without trailing '='
        url_id = base64.urlsafe_b64encode(url.strip().encode()).decode().rstrip("=")
        return await self._make_request(f"/urls/{url_id}")

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return await self._make_request(f"/files/{file_hash.strip()}")

    async def lookup_host(self, host: str) -> Dict[str, Any]:
        # Host lookup maps to IP or domain in VT
        if host.replace(".", "").isdigit():
            return await self.lookup_ip(host)
        return await self.lookup_domain(host)
