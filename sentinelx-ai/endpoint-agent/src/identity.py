"""
SentinelX Endpoint Agent – Identity Manager
Generates installation UUID, gathers non-invasive host metadata, and manages agent enrollment state.
"""

import uuid
import socket
import platform
import getpass
import logging
from typing import Dict, Any, Optional

from src.config import AgentConfig
from src.security.certificate import SecureStorage
from src.models.telemetry import HostIdentity

logger = logging.getLogger("sentinelx-agent")


class IdentityManager:
    """Manages unique installation identity and host metadata collection."""

    def __init__(self) -> None:
        self.storage = SecureStorage()

    def get_or_create_agent_id(self) -> str:
        """Retrieve existing agent UUID or generate a new one on first startup."""
        if AgentConfig.AGENT_ID:
            return AgentConfig.AGENT_ID

        saved = self.storage.load_identity(AgentConfig.IDENTITY_FILE)
        if saved and "agent_id" in saved:
            agent_id = saved["agent_id"]
            token = saved.get("agent_token", "")
            AgentConfig.update_credentials(agent_id, token)
            return agent_id

        # Generate new installation UUID
        new_agent_id = str(uuid.uuid4())
        AgentConfig.update_credentials(new_agent_id, "")
        self.save_credentials(new_agent_id, "")
        logger.info(f"Generated new agent_id: {new_agent_id}")
        return new_agent_id

    def save_credentials(self, agent_id: str, agent_token: str) -> None:
        """Persist updated credentials to local identity file."""
        data = {
            "agent_id": agent_id,
            "agent_token": agent_token,
            "hostname": self.get_hostname(),
            "updated_at": str(platform.node()),
        }
        self.storage.save_identity(AgentConfig.IDENTITY_FILE, data)
        AgentConfig.update_credentials(agent_id, agent_token)

    @staticmethod
    def get_hostname() -> str:
        """Get host name."""
        return socket.gethostname() or platform.node() or "Unknown-Host"

    @staticmethod
    def get_local_ip() -> str:
        """Get primary local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def collect_host_identity(self) -> HostIdentity:
        """Collect basic non-sensitive host specifications."""
        agent_id = self.get_or_create_agent_id()
        hostname = self.get_hostname()
        local_ip = self.get_local_ip()

        os_sys = platform.system()
        os_rel = platform.release()
        os_ver = platform.version()
        os_version_str = f"{os_sys} {os_rel} (Build {os_ver})"

        try:
            user = getpass.getuser()
        except Exception:
            user = "SystemUser"

        return HostIdentity(
            agent_id=agent_id,
            hostname=hostname,
            platform=os_sys,
            os_version=os_version_str,
            agent_version="1.0.0",
            local_ip=local_ip,
            architecture=platform.machine(),
            username=user,
            metadata={
                "processor": platform.processor(),
                "python_version": platform.python_version(),
            },
        )
