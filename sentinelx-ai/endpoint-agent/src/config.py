"""
SentinelX Endpoint Agent – Configuration Module
Loads environment variables and configuration defaults for the endpoint telemetry agent.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load local .env file if available
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)


class AgentConfig:
    """Agent runtime configuration settings."""

    SENTINELX_API_URL: str = os.getenv("SENTINELX_API_URL", "http://localhost:8000/api/v1").rstrip("/")
    AGENT_ID: str = os.getenv("AGENT_ID", "")
    AGENT_TOKEN: str = os.getenv("AGENT_TOKEN", "")
    HEARTBEAT_INTERVAL: int = int(os.getenv("HEARTBEAT_INTERVAL", "60"))
    TELEMETRY_INTERVAL: int = int(os.getenv("TELEMETRY_INTERVAL", "30"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    TEST_MODE: bool = os.getenv("TEST_MODE", "false").lower() in ("true", "1", "yes")

    # Local identity storage path
    IDENTITY_FILE: Path = Path(__file__).resolve().parent.parent / ".agent_identity.json"

    @classmethod
    def update_credentials(cls, agent_id: str, agent_token: str) -> None:
        """Update runtime credentials in memory."""
        cls.AGENT_ID = agent_id
        cls.AGENT_TOKEN = agent_token
