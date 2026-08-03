"""
SentinelX AI – Incident Response Pydantic v2 Schemas
Validation and serialization models for incidents, timeline, notes, and evidence.
"""

from uuid import UUID
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

# ── Enums ─────────────────────────────────────────────────────────────
IncidentSeverityEnum = Literal["Critical", "High", "Medium", "Low"]
IncidentPriorityEnum = Literal["P0", "P1", "P2", "P3", "P4"]
IncidentStatusEnum = Literal["Open", "In Progress", "Contained", "Resolved", "Closed"]


# ────────────────────────────────────────────────────────────────────────
# Sub-component Schemas
# ────────────────────────────────────────────────────────────────────────

class IncidentTimelineCreate(BaseModel):
    """Schema for adding a timeline event."""

    event_type: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1)
    created_by: str | None = None


class IncidentTimelineResponse(BaseModel):
    """Schema for returning timeline event details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    event_type: str
    description: str
    created_by: str | None = None
    created_at: datetime


class IncidentNoteCreate(BaseModel):
    """Schema for adding an analyst note."""

    note: str = Field(..., min_length=1, description="Analyst investigation note")


class IncidentNoteResponse(BaseModel):
    """Schema for returning note details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    author_id: UUID | None = None
    note: str
    created_at: datetime


class IncidentEvidenceCreate(BaseModel):
    """Schema for attaching evidence."""

    evidence_name: str = Field(..., min_length=1, max_length=255)
    evidence_type: str | None = Field(None, max_length=100)
    file_path: str = Field(..., min_length=1)


class IncidentEvidenceResponse(BaseModel):
    """Schema for returning evidence details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    evidence_name: str
    evidence_type: str | None = None
    file_path: str
    uploaded_by: UUID | None = None
    uploaded_at: datetime


# ────────────────────────────────────────────────────────────────────────
# Main Incident Schemas
# ────────────────────────────────────────────────────────────────────────

class IncidentBase(BaseModel):
    """Shared Incident attributes."""

    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = None
    severity: IncidentSeverityEnum = Field(default="Medium")
    priority: IncidentPriorityEnum = Field(default="P2")
    status: IncidentStatusEnum = Field(default="Open")
    reported_by: str | None = Field(None, max_length=255)
    detected_at: datetime


class IncidentCreate(IncidentBase):
    """Schema for creating a new security incident."""

    threat_id: UUID | None = None
    assigned_user_id: UUID | None = None


class IncidentUpdate(BaseModel):
    """Schema for updating incident fields."""

    threat_id: UUID | None = None
    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = None
    severity: IncidentSeverityEnum | None = None
    priority: IncidentPriorityEnum | None = None
    status: IncidentStatusEnum | None = None
    assigned_user_id: UUID | None = None
    reported_by: str | None = Field(None, max_length=255)
    detected_at: datetime | None = None
    resolved_at: datetime | None = None


class IncidentAssignRequest(BaseModel):
    """Schema for assigning an analyst to an incident."""

    assigned_user_id: UUID | None = Field(..., description="UUID of analyst user, or null to unassign")


class IncidentStatusUpdateRequest(BaseModel):
    """Schema for updating incident status."""

    status: IncidentStatusEnum = Field(..., description="New incident status")


class IncidentResponse(IncidentBase):
    """Full Incident response schema including nested timeline, notes, evidence."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    threat_id: UUID | None = None
    assigned_user_id: UUID | None = None
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    timeline_events: list[IncidentTimelineResponse] = Field(default_factory=list)
    notes: list[IncidentNoteResponse] = Field(default_factory=list)
    evidence: list[IncidentEvidenceResponse] = Field(default_factory=list)


class IncidentSummary(BaseModel):
    """Lightweight incident item for table/kanban view."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    threat_id: UUID | None = None
    title: str
    severity: IncidentSeverityEnum
    priority: IncidentPriorityEnum
    status: IncidentStatusEnum
    assigned_user_id: UUID | None = None
    reported_by: str | None = None
    detected_at: datetime
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(BaseModel):
    """Paginated incident list response."""

    total: int
    page: int
    page_size: int
    items: list[IncidentSummary]


class IncidentStatsResponse(BaseModel):
    """Dashboard/aggregations response for incident response module."""

    open_incidents_count: int
    critical_incidents_count: int
    assigned_to_me_count: int
    recently_resolved_count: int
    by_status: dict[str, int]
    by_priority: dict[str, int]
