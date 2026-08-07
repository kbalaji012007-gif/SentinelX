"""
SentinelX AI – AI Copilot Pydantic v2 Schemas
Validation and serialization schemas for Copilot Chat, Explainability, and Multi-Format Report Generation.
"""

from uuid import UUID
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class AIChatRequest(BaseModel):
    """Payload for natural language Copilot chat message."""

    conversation_id: UUID | None = Field(default=None, description="Existing conversation ID or null for new")
    message: str = Field(..., description="Natural language question or prompt")
    context: dict[str, Any] = Field(default_factory=dict, description="Active editor or entity context")


class AIChatMessageResponse(BaseModel):
    """Schema for chat message response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    conversation_id: UUID
    sender: str
    content: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence_score: int = 90
    created_at: datetime


class AIChatConversationResponse(BaseModel):
    """Schema for chat conversation session."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    created_at: datetime
    messages: list[AIChatMessageResponse] = Field(default_factory=list)


class ConversationListResponse(BaseModel):
    """Paginated list of chat conversation sessions."""

    total: int
    items: list[AIChatConversationResponse]


class AIExplainRequest(BaseModel):
    """Payload for requesting AI Explainability breakdown."""

    entity_type: str = Field(..., description="Entity: Incident, Correlation, Attack_Chain, MITRE, Playbook")
    entity_id: str = Field(..., description="Entity ID or identifier")


class AIExplainResponse(BaseModel):
    """Deep explainability report (Rule 9: Fact Distinction & Safety)."""

    observed_data: list[str] = Field(default_factory=list)
    external_intelligence: list[str] = Field(default_factory=list)
    ai_reasoning: str
    confidence: int = 90
    limitations: str | None = None


class AIReportRequest(BaseModel):
    """Payload for generating security reports."""

    report_type: str = Field(..., description="Type: Executive, Incident, Threat, IOC, Correlation, Attack_Chain, SOAR")
    title: str | None = Field(default=None, description="Optional custom report title")
    output_format: str = Field(default="markdown", description="Format: pdf, markdown, json")


class AIReportResponse(BaseModel):
    """Generated report schema."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = None
    report_type: str
    title: str
    markdown_content: str
    json_content: dict[str, Any] = Field(default_factory=dict)
    created_by: str
    created_at: datetime | None = None
