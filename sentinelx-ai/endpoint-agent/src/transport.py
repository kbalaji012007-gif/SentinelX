"""
SentinelX Endpoint Agent – HTTPS Transport Layer
Handles HTTP communication with the SentinelX backend APIs over HTTPS with token authentication.
"""

import logging
from typing import Any, Dict, Optional
import requests

from src.config import AgentConfig
from src.models.telemetry import TelemetryBatch, HostIdentity

logger = logging.getLogger("sentinelx-agent")


class Transport:
    """HTTP client wrapper handling authentication, retries, and API calls to SentinelX backend."""

    def __init__(self, base_url: Optional[str] = None) -> None:
        self.base_url = (base_url or AgentConfig.SENTINELX_API_URL).rstrip("/")
        self.session = requests.Session()

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers with Bearer authentication token."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SentinelX-Endpoint-Agent/1.0.0",
        }
        if AgentConfig.AGENT_TOKEN:
            headers["Authorization"] = f"Bearer {AgentConfig.AGENT_TOKEN}"
        return headers

    def enroll(self, host_identity: HostIdentity) -> Optional[Dict[str, Any]]:
        """
        Send POST /api/v1/agents/enroll payload to backend.
        Returns response JSON containing agent_token upon success.
        """
        url = f"{self.base_url}/agents/enroll"
        payload = host_identity.model_dump()

        try:
            logger.info(f"Connecting to enrollment endpoint: {url}")
            resp = self.session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
            if resp.status_code in (200, 201):
                data = resp.json()
                logger.info("Enrollment succeeded.")
                return data
            else:
                logger.error(f"Enrollment failed ({resp.status_code}): {resp.text}")
                return None
        except Exception as exc:
            logger.error(f"Network error during agent enrollment: {exc}")
            return None

    def send_heartbeat(self, agent_id: str, hostname: str, uptime: int = 0) -> Optional[Dict[str, Any]]:
        """Send periodic status heartbeat to POST /api/v1/agents/heartbeat."""
        url = f"{self.base_url}/agents/heartbeat"
        payload = {
            "agent_id": agent_id,
            "hostname": hostname,
            "agent_version": "1.0.0",
            "uptime": uptime,
            "health_status": "Healthy",
        }

        try:
            resp = self.session.post(url, json=payload, headers=self._get_headers(), timeout=10)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning(f"Heartbeat rejected ({resp.status_code}): {resp.text}")
                return None
        except Exception as exc:
            logger.warning(f"Heartbeat network error: {exc}")
            return None

    def send_telemetry_batch(self, batch: TelemetryBatch) -> Optional[Dict[str, Any]]:
        """Send batch of telemetry items to POST /api/v1/agents/telemetry."""
        url = f"{self.base_url}/agents/telemetry"
        payload = batch.model_dump(mode="json")

        try:
            resp = self.session.post(url, json=payload, headers=self._get_headers(), timeout=15)
            if resp.status_code in (200, 201):
                return resp.json()
            else:
                logger.error(f"Telemetry ingestion rejected ({resp.status_code}): {resp.text}")
                return None
        except Exception as exc:
            logger.error(f"Telemetry network error: {exc}")
            return None
