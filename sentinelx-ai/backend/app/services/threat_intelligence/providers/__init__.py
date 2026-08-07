"""
SentinelX AI – Threat Intelligence Providers Package
Exports all Threat Intelligence providers and provides provider registration & listing utilities.
"""

from typing import Dict, List
from app.services.threat_intelligence.providers.base import BaseThreatProvider
from app.services.threat_intelligence.providers.virustotal import VirusTotalProvider
from app.services.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.services.threat_intelligence.providers.shodan import ShodanProvider
from app.services.threat_intelligence.providers.gemini import GeminiThreatProvider


def get_all_providers() -> Dict[str, BaseThreatProvider]:
    """Instantiate and return dictionary of all registered Threat Intelligence providers."""
    return {
        "VirusTotal": VirusTotalProvider(),
        "AbuseIPDB": AbuseIPDBProvider(),
        "Shodan": ShodanProvider(),
        "Google Gemini AI": GeminiThreatProvider(),
    }


def list_provider_statuses() -> List[Dict]:
    """Retrieve runtime configuration and readiness status of all providers."""
    providers = get_all_providers()
    statuses = []

    supported_types = {
        "VirusTotal": ["IP", "Domain", "URL", "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256", "Host"],
        "AbuseIPDB": ["IP", "Host"],
        "Shodan": ["IP", "Host"],
        "Google Gemini AI": ["IP", "Domain", "URL", "FileHash-SHA256", "Host"],
    }

    for name, provider in providers.items():
        configured = provider.is_configured
        statuses.append({
            "name": name,
            "configured": configured,
            "status": "ready" if configured else "unavailable",
            "reason": None if configured else "API key not configured",
            "supported_types": supported_types.get(name, []),
        })

    return statuses


__all__ = [
    "BaseThreatProvider",
    "VirusTotalProvider",
    "AbuseIPDBProvider",
    "ShodanProvider",
    "GeminiThreatProvider",
    "get_all_providers",
    "list_provider_statuses",
]
