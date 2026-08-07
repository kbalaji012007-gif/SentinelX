"""
SentinelX AI – AI SOC Analyst ORM Models
Schemas:
  - sentinelx.ai_investigation_history
  - sentinelx.ai_threat_hunts
"""

import uuid
from datetime import datetime
from typing import Any
from sqlalchemy import String, Text, ForeignKey, DateTime, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class AIInvestigationHistory(Base, TimestampMixin):
    """Audit log of AI SOC Analyst security investigations."""

    __tablename__ = "ai_investigation_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    investigation_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    target_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    executive_summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    technical_summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    root_cause: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    mitre_mapping: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default="[]",
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        default="High",
        nullable=False,
    )
    confidence_score: Mapped[int] = mapped_column(
        Integer,
        default=85,
        nullable=False,
    )
    recommended_actions: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default="[]",
    )
    evidence_sources: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    requested_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )


class AIThreatHunt(Base, TimestampMixin):
    """Audit log of proactive AI threat hunting operations."""

    __tablename__ = "ai_threat_hunts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    hunt_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    query_value: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    findings_summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    threat_level: Mapped[str] = mapped_column(
        String(50),
        default="Medium",
        nullable=False,
    )
    matched_artifacts: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default="[]",
    )
    recommended_playbook_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.soar_playbooks.id", ondelete="SET NULL"),
        nullable=True,
    )
    requested_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
