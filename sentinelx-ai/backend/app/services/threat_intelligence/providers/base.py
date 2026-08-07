"""
SentinelX AI – Base Threat Intelligence Provider Interface
Abstract base class defining contract for external Threat Intelligence providers.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseThreatProvider(ABC):
    """Abstract interface for external Threat Intelligence providers."""

    provider_name: str

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if provider API key / environment is configured."""
        pass

    @abstractmethod
    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Query IP address reputation and metadata."""
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Query Domain reputation and metadata."""
        pass

    @abstractmethod
    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """Query URL reputation and metadata."""
        pass

    @abstractmethod
    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query File Hash (MD5, SHA-1, SHA-256) reputation."""
        pass

    @abstractmethod
    async def lookup_host(self, host: str) -> Dict[str, Any]:
        """Query Host / IP ports, services, vulnerabilities."""
        pass

    def build_unavailable_response(self, reason: str) -> Dict[str, Any]:
        """Build standard unavailable response structure."""
        return {
            "provider": self.provider_name,
            "status": "unavailable",
            "reason": reason,
            "data": None,
        }
