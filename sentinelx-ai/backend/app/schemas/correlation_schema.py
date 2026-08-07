"""
SentinelX AI – Correlation Pydantic v2 Schemas
Validation and serialization schemas for Threat Correlations, Attack Chains, MITRE Mappings, and Correlation Rules.
"""

from uuid import UUID
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

SeverityEnum = Literal["Critical", "High", "Medium", "Low", "Info"]
CorrelationTypeEnum = Literal[
    "IOC_Correlation",
    "Log_Anomaly",
    "Asset_Multi_Threat",
    "Incident_Cascade",
    "Mitre_Tactic_Chain",
    "User_Credential_Abuse",
]


# ────────────────────────────────────────────────────────────────────────
# Correlation Rule Schemas
# ────────────────────────────────────────────────────────────────────────

class CorrelationRuleBase(BaseModel):
    """Shared Correlation Rule attributes."""

    rule_name: str = Field(..., min_length=1, max_length=255)
    rule_type: str = Field(..., min_length=1, max_length=100)
    is_active: bool = True
    severity: SeverityEnum = "Medium"
    condition_logic: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None


class CorrelationRuleCreate(CorrelationRuleBase):
    """Schema for creating a new correlation rule."""

    pass


class CorrelationRuleUpdate(BaseModel):
    """Schema for updating a correlation rule."""

    rule_name: str | None = Field(None, min_length=1, max_length=255)
    rule_type: str | None = Field(None, min_length=1, max_length=100)
    is_active: bool | None = None
    severity: SeverityEnum | None = None
    condition_logic: dict[str, Any] | None = None
    description: str | None = None


class CorrelationRuleResponse(CorrelationRuleBase):
    """Schema for returning correlation rule details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    execution_count: int = 0
    created_at: datetime
    updated_at: datetime


class CorrelationRuleListResponse(BaseModel):
    """Paginated list of correlation rules."""

    total: int
    page: int
    page_size: int
    items: list[CorrelationRuleResponse]


# ────────────────────────────────────────────────────────────────────────
# Threat Correlation Schemas
# ────────────────────────────────────────────────────────────────────────

class ThreatCorrelationBase(BaseModel):
    """Shared Threat Correlation attributes."""

    title: str = Field(..., min_length=1, max_length=255)
    correlation_type: str = Field(..., min_length=1, max_length=100)
    severity: SeverityEnum = "Medium"
    risk_score: int = Field(50, ge=0, le=100, description="Business/security impact score (0-100)")
    confidence_score: int = Field(80, ge=0, le=100, description="Certainty of the correlation (0-100)")
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured evidence object detailing matched IOCs, IPs, assets, techniques, timeline, etc.",
    )
    asset_id: UUID | None = None
    incident_id: UUID | None = None
    threat_id: UUID | None = None
    ioc_value: str | None = Field(None, max_length=500)
    rule_id: UUID | None = None
    correlation_metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatCorrelationCreate(ThreatCorrelationBase):
    """Schema for creating a new threat correlation event."""

    pass


class ThreatCorrelationUpdate(BaseModel):
    """Schema for updating a threat correlation event."""

    title: str | None = Field(None, min_length=1, max_length=255)
    correlation_type: str | None = None
    severity: SeverityEnum | None = None
    risk_score: int | None = Field(None, ge=0, le=100)
    confidence_score: int | None = Field(None, ge=0, le=100)
    evidence: dict[str, Any] | None = None
    asset_id: UUID | None = None
    incident_id: UUID | None = None
    threat_id: UUID | None = None
    ioc_value: str | None = None
    rule_id: UUID | None = None
    metadata: dict[str, Any] | None = None


class ThreatCorrelationResponse(ThreatCorrelationBase):
    """Schema for returning detailed threat correlation event."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class ThreatCorrelationListResponse(BaseModel):
    """Paginated list of threat correlation events."""

    total: int
    page: int
    page_size: int
    items: list[ThreatCorrelationResponse]


# ────────────────────────────────────────────────────────────────────────
# Attack Chain Schemas
# ────────────────────────────────────────────────────────────────────────

class AttackChainStage(BaseModel):
    """Individual stage within an Attack Chain."""

    stage_order: int
    stage_name: str
    mitre_technique_id: str | None = None
    tactic: str | None = None
    description: str | None = None
    timestamp: str | None = None
    evidence_snippet: dict[str, Any] = Field(default_factory=dict)


class AttackChainBase(BaseModel):
    """Shared Attack Chain attributes."""

    chain_name: str = Field(..., min_length=1, max_length=255)
    severity: SeverityEnum = "High"
    overall_risk_score: int = Field(75, ge=0, le=100)
    overall_confidence_score: int = Field(85, ge=0, le=100)
    entry_point: str | None = None
    target_asset_id: UUID | None = None
    stages_json: list[AttackChainStage] = Field(default_factory=list)
    status: str = "Active"


class AttackChainCreate(AttackChainBase):
    """Schema for registering an attack chain."""

    pass


class AttackChainResponse(AttackChainBase):
    """Schema for returning attack chain details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class AttackChainListResponse(BaseModel):
    """Paginated list of attack chains."""

    total: int
    page: int
    page_size: int
    items: list[AttackChainResponse]


# ────────────────────────────────────────────────────────────────────────
# MITRE Mapping Schemas
# ────────────────────────────────────────────────────────────────────────

class MitreMappingBase(BaseModel):
    """Shared MITRE Mapping attributes."""

    entity_type: str = Field(..., min_length=1, max_length=100)
    entity_id: UUID
    technique_id: str = Field(..., min_length=1, max_length=50)
    tactic: str = Field(..., min_length=1, max_length=100)
    confidence_score: int = Field(80, ge=0, le=100)
    evidence: dict[str, Any] = Field(default_factory=dict)


class MitreMappingCreate(MitreMappingBase):
    """Schema for registering a MITRE Mapping."""

    pass


class MitreMappingResponse(MitreMappingBase):
    """Schema for returning MITRE Mapping details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class MitreMappingListResponse(BaseModel):
    """Paginated list of MITRE mappings."""

    total: int
    page: int
    page_size: int
    items: list[MitreMappingResponse]


# ────────────────────────────────────────────────────────────────────────
# Engine Action & Telemetry Schemas
# ────────────────────────────────────────────────────────────────────────

class CorrelationRunRequest(BaseModel):
    """Request payload to trigger full correlation engine pass."""

    time_window_hours: int = Field(24, ge=1, le=168)
    min_confidence: int = Field(50, ge=0, le=100)


class CorrelationRunResponse(BaseModel):
    """Response summary after executing correlation engine."""

    correlations_generated: int
    attack_chains_created: int
    mitre_mappings_added: int
    execution_time_seconds: float
    message: str


class GraphNode(BaseModel):
    """Node in correlation visualization graph."""

    id: str
    label: str
    type: Literal["Asset", "Threat", "Incident", "IOC", "Log", "MITRE"]
    severity: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Edge connecting nodes in correlation graph."""

    source: str
    target: str
    relation: str
    confidence_score: int = 80


class CorrelationGraphResponse(BaseModel):
    """Graph structure representation for UI visual graph rendering."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]


class TimelineEvent(BaseModel):
    """Chronological correlation event for timeline UI."""

    id: UUID
    title: str
    correlation_type: str
    severity: str
    risk_score: int
    confidence_score: int
    timestamp: datetime
    evidence_summary: str


class CorrelationTimelineResponse(BaseModel):
    """Chronological list of correlation events."""

    total: int
    events: list[TimelineEvent]


class CorrelationStatsResponse(BaseModel):
    """Summary metrics for Correlation Engine module."""

    total_correlations: int
    critical_correlations: int
    high_correlations: int
    active_attack_chains: int
    total_mitre_mappings: int
    avg_risk_score: float
    avg_confidence_score: float
    by_type: dict[str, int]
