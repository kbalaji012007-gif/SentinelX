"""
SentinelX AI – AI SOC Analyst Pydantic v2 Schemas
Validation and serialization schemas for AI Investigations, Threat Hunting, Risk Assessment, and Recommendations.
"""

from uuid import UUID
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class InvestigationRequest(BaseModel):
    """Payload for triggering an AI SOC investigation."""

    investigation_type: str = Field(..., description="Type: Incident, Threat, Asset, Logs, IOC, Attack_Chain, Playbook")
    target_id: str = Field(..., description="Target ID, IP, hash, or resource identifier")
    context_parameters: dict[str, Any] = Field(default_factory=dict)


class EvidenceSources(BaseModel):
    """Categorized evidence breakdown (Rule 8: Safety & AI Distinction)."""

    observed_sentinelx_data: list[str] = Field(default_factory=list)
    external_intelligence: list[str] = Field(default_factory=list)
    ai_inference: list[str] = Field(default_factory=list)
    insufficient_evidence_warning: str | None = None


class InvestigationResponse(BaseModel):
    """Detailed AI investigation report."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = None
    investigation_type: str
    target_id: str
    executive_summary: str
    technical_summary: str
    root_cause: str | None = None
    mitre_mapping: list[dict[str, Any]] = Field(default_factory=list)
    severity: str
    confidence_score: int
    recommended_actions: list[str] = Field(default_factory=list)
    evidence_sources: EvidenceSources
    created_at: datetime | None = None


class ThreatHuntRequest(BaseModel):
    """Payload for running proactive AI threat hunting."""

    hunt_type: str = Field(..., description="Type: IP, Domain, Hash, Username, Asset, Process, MITRE")
    query_value: str = Field(..., description="Value to hunt for across platform telemetry")


class ThreatHuntResponse(BaseModel):
    """Proactive threat hunting report."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = None
    hunt_type: str
    query_value: str
    findings_summary: str
    threat_level: str
    matched_artifacts: list[dict[str, Any]] = Field(default_factory=list)
    recommended_playbook_id: UUID | None = None
    created_at: datetime | None = None


class RiskAssessmentResponse(BaseModel):
    """AI predicted risk assessment report."""

    business_risk_score: int
    severity_prediction: str
    attack_spread_prediction: str
    high_risk_assets: list[dict[str, Any]] = Field(default_factory=list)
    prioritized_alerts: list[dict[str, Any]] = Field(default_factory=list)


class RecommendationResponse(BaseModel):
    """Actionable AI recommendations."""

    playbook_recommendations: list[dict[str, Any]] = Field(default_factory=list)
    remediation_recommendations: list[str] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    containment_recommendations: list[str] = Field(default_factory=list)
    recovery_recommendations: list[str] = Field(default_factory=list)


class InvestigationListResponse(BaseModel):
    """Paginated list of investigation history logs."""

    total: int
    items: list[InvestigationResponse]
