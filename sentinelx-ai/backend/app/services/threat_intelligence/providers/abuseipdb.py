"""
SentinelX AI – AbuseIPDB Threat Intelligence Provider
Async client for AbuseIPDB v2 REST API.
"""

import httpx
from typing import Any, Dict
from app.core.config import settings
from app.services.threat_intelligence.providers.base import BaseThreatProvider


class AbuseIPDBProvider(BaseThreatProvider):
    """AbuseIPDB API v2 integration for IP reputation, confidence score, ISP, and country metadata."""

    provider_name = "AbuseIPDB"
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _headers(self) -> Dict[str, str]:
        return {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not self.is_configured:
            return self.build_unavailable_response("API key missing (ABUSEIPDB_API_KEY not configured)")

        params = {
            "ipAddress": ip.strip(),
            "maxAgeInDays": "90",
            "verbose": "true",
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.BASE_URL, headers=self._headers(), params=params)

                if response.status_code == 200:
                    data = response.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)

                    verdict = "Harmless"
                    if score > 75:
                        verdict = "Malicious"
                    elif score > 25:
                        verdict = "Suspicious"

                    return {
                        "provider": self.provider_name,
                        "status": "available",
                        "reason": None,
                        "data": {
                            "verdict": verdict,
                            "threat_score": score,
                            "abuse_confidence_score": score,
                            "country_code": data.get("countryCode"),
                            "country_name": data.get("countryName"),
                            "isp": data.get("isp"),
                            "usage_type": data.get("usageType"),
                            "domain": data.get("domain"),
                            "total_reports": data.get("totalReports", 0),
                            "num_distinct_users": data.get("numDistinctUsers", 0),
                            "is_whitelisted": data.get("isWhitelisted", False),
                            "is_public": data.get("isPublic", True),
                            "last_reported_at": data.get("lastReportedAt"),
                        },
                    }
                elif response.status_code == 401:
                    return self.build_unavailable_response("Invalid or unauthorized API key (HTTP 401)")
                elif response.status_code == 429:
                    return self.build_unavailable_response("Rate limit exceeded (HTTP 429)")
                elif response.status_code == 422:
                    return {
                        "provider": self.provider_name,
                        "status": "not_found",
                        "reason": "Invalid or private IP address format",
                        "data": None,
                    }
                else:
                    return self.build_unavailable_response(f"HTTP error {response.status_code}: {response.text[:100]}")

        except httpx.TimeoutException:
            return self.build_unavailable_response("Request timed out (AbuseIPDB unreachable)")
        except Exception as err:
            return self.build_unavailable_response(f"Connection error: {str(err)}")

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return self.build_unavailable_response("AbuseIPDB provider only supports IP reputation lookups")

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        return self.build_unavailable_response("AbuseIPDB provider only supports IP reputation lookups")

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return self.build_unavailable_response("AbuseIPDB provider only supports IP reputation lookups")

    async def lookup_host(self, host: str) -> Dict[str, Any]:
        if host.replace(".", "").isdigit():
            return await self.lookup_ip(host)
        return self.build_unavailable_response("AbuseIPDB host lookup requires a valid IP address")
