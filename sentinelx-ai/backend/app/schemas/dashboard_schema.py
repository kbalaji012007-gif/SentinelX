"""
SentinelX AI – Dashboard Pydantic Schemas
Response models for dashboard telemetry, metrics, and health indicators.
"""

from typing import Any
from pydantic import BaseModel, Field


class DashboardSummaryResponse(BaseModel):
    """Overall SOC metric summary."""

    active_threats_count: int = Field(..., description="Total active threats detected")
    critical_alerts_count: int = Field(..., description="Critical severity alert count (24h)")
    open_incidents_count: int = Field(..., description="Open incident tickets")
    asset_count: int = Field(..., description="Monitored enterprise asset count")
    vulnerability_count: int = Field(..., description="Unpatched vulnerability count")
    current_risk_score: int = Field(..., description="Composite risk score (0-100)")
    system_status: str = Field(default="Operational", description="SOC platform operational status")


class ServiceHealth(BaseModel):
    """Health indicator for an individual SOC subsystem."""

    service_name: str
    status: str  # Operational, Degraded, Down
    latency_ms: float
    message: str


class SystemHealthResponse(BaseModel):
    """Overall system health report."""

    status: str
    services: list[ServiceHealth]


class ActivityItem(BaseModel):
    """Recent threat or alert activity item."""

    id: str
    name: str
    severity: str
    source_ip: str
    target_asset: str
    mitre_id: str
    status: str
    detected_at: str


class RiskScoreResponse(BaseModel):
    """Detailed risk score metrics."""

    score: int
    risk_level: str  # Critical, High, Medium, Low
    primary_factors: list[str]


class TimelinePoint(BaseModel):
    """24-hour velocity point."""

    time: str
    threats: int
    alerts: int
    incidents: int


class SeverityCount(BaseModel):
    """Severity classification count."""

    name: str
    value: int
    color: str


class DashboardStatisticsResponse(BaseModel):
    """Chart and visual trend data."""

    timeline: list[TimelinePoint]
    severity_distribution: list[SeverityCount]
    top_attacker_ips: list[dict[str, Any]]
