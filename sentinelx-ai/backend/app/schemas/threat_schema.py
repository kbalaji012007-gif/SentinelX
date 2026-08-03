"""
SentinelX AI – Threat Detection Pydantic v2 Schemas
Validation and serialization for sentinelx.threats, sentinelx.alerts, sentinelx.ioc.
"""

from uuid import UUID
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

# ── Enums ─────────────────────────────────────────────────────────────
ThreatSeverityEnum = Literal["Critical", "High", "Medium", "Low"]
ThreatStatusEnum = Literal["New", "Investigating", "Mitigated", "Closed"]
IOCTypeEnum = Literal["IP", "Domain", "URL", "Hash", "Email"]


# ────────────────────────────────────────────────────────────────────────
# Alert Schemas
# ────────────────────────────────────────────────────────────────────────

class AlertBase(BaseModel):
    """Shared Alert attributes."""

    alert_name: str = Field(..., min_length=1, max_length=500)
    alert_type: str | None = Field(None, max_length=100)
    alert_source: str | None = Field(None, max_length=255)
    severity: ThreatSeverityEnum = Field(default="Medium")
    message: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)
    acknowledged: bool = Field(default=False)


class AlertCreate(AlertBase):
    """Schema for creating a new alert."""
    threat_id: UUID


class AlertUpdate(BaseModel):
    """Schema for updating an alert."""
    alert_name: str | None = Field(None, min_length=1, max_length=500)
    alert_type: str | None = Field(None, max_length=100)
    alert_source: str | None = Field(None, max_length=255)
    severity: ThreatSeverityEnum | None = None
    message: str | None = None
    raw_event: dict[str, Any] | None = None
    acknowledged: bool | None = None


class AlertResponse(AlertBase):
    """Schema for returning alert details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    threat_id: UUID
    created_at: datetime
    updated_at: datetime


# ────────────────────────────────────────────────────────────────────────
# IOC Schemas
# ────────────────────────────────────────────────────────────────────────

class IOCBase(BaseModel):
    """Shared IOC attributes."""

    type: IOCTypeEnum
    value: str = Field(..., min_length=1, description="IOC value (IP, domain, hash, etc.)")
    reputation: str | None = Field(None, max_length=50)
    confidence: Decimal | None = Field(None, ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class IOCCreate(IOCBase):
    """Schema for creating a new IOC."""
    threat_id: UUID


class IOCUpdate(BaseModel):
    """Schema for updating an IOC."""
    type: IOCTypeEnum | None = None
    value: str | None = Field(None, min_length=1)
    reputation: str | None = Field(None, max_length=50)
    confidence: Decimal | None = Field(None, ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class IOCResponse(IOCBase):
    """Schema for returning IOC details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    threat_id: UUID
    created_at: datetime
    updated_at: datetime


# ────────────────────────────────────────────────────────────────────────
# Threat Schemas
# ────────────────────────────────────────────────────────────────────────

class ThreatBase(BaseModel):
    """Shared Threat attributes."""

    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = None
    severity: ThreatSeverityEnum = Field(default="Medium")
    confidence_score: Decimal | None = Field(None, ge=0, le=100)
    status: ThreatStatusEnum = Field(default="New")
    source: str | None = Field(None, max_length=255)
    mitre_technique_id: str | None = Field(None, max_length=50)
    detected_at: datetime


class ThreatCreate(ThreatBase):
    """Schema for creating a new threat."""
    asset_id: UUID | None = None


class ThreatUpdate(BaseModel):
    """Schema for partially updating a threat."""
    asset_id: UUID | None = None
    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = None
    severity: ThreatSeverityEnum | None = None
    confidence_score: Decimal | None = Field(None, ge=0, le=100)
    status: ThreatStatusEnum | None = None
    source: str | None = Field(None, max_length=255)
    mitre_technique_id: str | None = Field(None, max_length=50)
    detected_at: datetime | None = None


class ThreatResponse(ThreatBase):
    """Schema for returning full threat details (with nested alerts and IOCs)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID | None = None
    alerts: list[AlertResponse] = Field(default_factory=list)
    iocs: list[IOCResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ThreatSummary(BaseModel):
    """Lightweight threat summary used in list views."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID | None = None
    title: str
    severity: str
    confidence_score: Decimal | None = None
    status: str
    source: str | None = None
    mitre_technique_id: str | None = None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime


class ThreatListResponse(BaseModel):
    """Paginated threat list response."""

    total: int
    page: int
    page_size: int
    items: list[ThreatSummary]


class ThreatStatsResponse(BaseModel):
    """Threat severity distribution stats for dashboard."""

    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
