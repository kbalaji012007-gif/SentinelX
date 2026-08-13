"""
SentinelX AI – Security Alert Pydantic Schemas
Request/response models for the real-time SOC alert system (Phase 6.4).
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ── Internal Creation Schema ─────────────────────────────────────────────────

class SecurityAlertCreate(BaseModel):
    """Internal schema used by services to create a new security alert."""

    alert_id: str = Field(..., description="Unique deduplication key for this alert")
    title: str = Field(..., max_length=500)
    description: Optional[str] = None
    alert_type: str = Field(..., max_length=100)
    severity: str = Field(default="MEDIUM")
    source: Optional[str] = None
    agent_id: Optional[UUID] = None
    log_id: Optional[UUID] = None
    threat_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    correlation_id: Optional[UUID] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    alert_metadata: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)


# ── Response Schemas ─────────────────────────────────────────────────────────

class SecurityAlertResponse(BaseModel):
    """Full alert detail response returned to SOC clients."""

    id: UUID
    alert_id: str
    title: str
    description: Optional[str] = None
    alert_type: str
    severity: str
    status: str
    source: Optional[str] = None
    agent_id: Optional[UUID] = None
    log_id: Optional[UUID] = None
    threat_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    correlation_id: Optional[UUID] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    alert_metadata: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[UUID] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityAlertSummary(BaseModel):
    """Compact alert summary for list views and real-time feeds."""

    id: UUID
    alert_id: str
    title: str
    alert_type: str
    severity: str
    status: str
    source: Optional[str] = None
    agent_id: Optional[UUID] = None
    # hostname from alert_metadata for display convenience
    hostname: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    detected_at: datetime
    updated_at: datetime
    # occurrence count from evidence
    occurrence_count: int = 1

    model_config = ConfigDict(from_attributes=True)


class SecurityAlertListResponse(BaseModel):
    """Paginated list of security alert summaries."""

    total: int
    page: int
    page_size: int
    items: List[SecurityAlertSummary]


# ── Statistics Schema ────────────────────────────────────────────────────────

class SecurityAlertStatistics(BaseModel):
    """Aggregate alert statistics for the SOC dashboard."""

    total_alerts: int = 0
    new_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    alerts_today: int = 0
    active_investigations: int = 0
    resolved_today: int = 0
    acknowledged_alerts: int = 0
    dismissed_alerts: int = 0


# ── Action Request Schemas ───────────────────────────────────────────────────

class AlertAcknowledgeRequest(BaseModel):
    """Optional notes when acknowledging an alert."""
    notes: Optional[str] = Field(default=None, max_length=2000)


class AlertInvestigateRequest(BaseModel):
    """Optional notes when starting investigation."""
    notes: Optional[str] = Field(default=None, max_length=2000)


class AlertResolveRequest(BaseModel):
    """Resolution details."""
    resolution_notes: Optional[str] = Field(default=None, max_length=2000)


class AlertDismissRequest(BaseModel):
    """Dismissal reason."""
    reason: Optional[str] = Field(default=None, max_length=2000)


# ── Test Mode Schema ─────────────────────────────────────────────────────────

class AlertTestCreate(BaseModel):
    """Used ONLY for controlled testing. Creates a SIMULATED_TEST_EVENT alert."""
    alert_type: str = Field(default="test_event")
    severity: str = Field(default="LOW")
    title: str = Field(default="Simulated Test Alert")
    description: Optional[str] = Field(default="This is a controlled test event. Not a real security incident.")
    hostname: Optional[str] = Field(default="TEST-HOST")
