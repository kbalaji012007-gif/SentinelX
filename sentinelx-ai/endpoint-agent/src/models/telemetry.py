"""
SentinelX Endpoint Agent – Telemetry Models
Data representations for collected endpoint metrics, security events, and transport batches.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HostIdentity(BaseModel):
    """Host specifications and agent identification metadata."""

    agent_id: str
    hostname: str
    platform: str = "Windows"
    os_version: Optional[str] = None
    agent_version: str = "1.0.0"
    local_ip: Optional[str] = None
    architecture: Optional[str] = None
    username: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TelemetryItem(BaseModel):
    """Individual telemetry event item."""

    agent_id: Optional[str] = None
    event_type: str
    event_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = "INFO"
    payload: Dict[str, Any] = Field(default_factory=dict)
    source: str = "Endpoint Agent"
    is_simulated: bool = False


class TelemetryBatch(BaseModel):
    """Batch payload sent over HTTPS transport to backend."""

    agent_id: str
    telemetry: List[TelemetryItem]
