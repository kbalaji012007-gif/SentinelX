"""
SentinelX AI – Google Gemini AI Threat Intelligence Provider
Async client for Google Gemini AI REST API to enrich IOCs with AI explanations, MITRE ATT&CK mappings, and remediation guidance.
"""

import json
import httpx
from typing import Any, Dict
from app.core.config import settings
from app.services.threat_intelligence.providers.base import BaseThreatProvider


class GeminiThreatProvider(BaseThreatProvider):
    """Google Gemini AI integration for IOC explanation, threat summary, MITRE ATT&CK mapping, and remediations."""

    provider_name = "Google Gemini AI"

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or settings.GEMINI_API_KEY
        self.model = model or getattr(settings, "GEMINI_MODEL", "gemini-2.0-flash")

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    async def generate_ai_analysis(self, ioc_type: str, value: str, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if not self.is_configured:
            return self.build_unavailable_response("API key missing (GEMINI_API_KEY not configured)")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

        prompt = f"""
You are SentinelX AI, an elite SOC Threat Analyst.
Analyze the following Indicator of Compromise (IOC):
- IOC Type: {ioc_type}
- IOC Value: {value}
- Provider Context: {json.dumps(context or {}, default=str)}

Return ONLY a raw JSON object (no markdown wrapping, no code blocks) with the following key fields:
{{
    "threat_summary": "Concise 1-2 sentence executive threat summary",
    "ioc_explanation": "Detailed explanation of what this indicator represents and its potential impact",
    "mitre_attack": [
        {{
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
            "explanation": "Why this technique is relevant"
        }}
    ],
    "remediation_recommendations": [
        "Actionable remediation step 1",
        "Actionable remediation step 2"
    ],
    "ai_confidence_score": 85,
    "severity_assessment": "High"
}}
"""

        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 1024,
            }
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(url, json=payload, headers={"Content-Type": "application/json"})

                if response.status_code == 200:
                    res_json = response.json()
                    candidates = res_json.get("candidates", [])
                    if not candidates:
                        return self.build_unavailable_response("Gemini AI returned empty candidate response")

                    raw_text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
                    if raw_text.startswith("```"):
                        raw_text = raw_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

                    try:
                        ai_data = json.loads(raw_text)
                    except Exception:
                        ai_data = {
                            "threat_summary": raw_text[:200],
                            "ioc_explanation": raw_text,
                            "mitre_attack": [],
                            "remediation_recommendations": ["Isolate host and investigate traffic."],
                            "ai_confidence_score": 75,
                            "severity_assessment": "Medium"
                        }

                    return {
                        "provider": self.provider_name,
                        "status": "available",
                        "reason": None,
                        "data": ai_data,
                    }

                elif response.status_code in (401, 403):
                    return self.build_unavailable_response(f"Invalid or unauthorized Gemini API key (HTTP {response.status_code})")
                elif response.status_code == 429:
                    return self.build_unavailable_response("Gemini AI rate limit exceeded (HTTP 429)")
                else:
                    return self.build_unavailable_response(f"HTTP error {response.status_code}: {response.text[:100]}")

        except httpx.TimeoutException:
            return self.build_unavailable_response("Request timed out (Gemini API unreachable)")
        except Exception as err:
            return self.build_unavailable_response(f"Connection error: {str(err)}")

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return await self.generate_ai_analysis("IP", ip)

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return await self.generate_ai_analysis("Domain", domain)

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        return await self.generate_ai_analysis("URL", url)

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return await self.generate_ai_analysis("FileHash-SHA256", file_hash)

    async def lookup_host(self, host: str) -> Dict[str, Any]:
        return await self.generate_ai_analysis("Host", host)
