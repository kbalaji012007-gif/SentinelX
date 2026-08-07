"""
SentinelX AI – Correlation Module ORM Models
Schemas:
  - sentinelx.correlation_rules
  - sentinelx.threat_correlations
  - sentinelx.attack_chains
  - sentinelx.mitre_mappings
"""

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import String, Text, ForeignKey, DateTime, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class CorrelationRule(Base, TimestampMixin):
    """Correlation engine rules catalog."""

    __tablename__ = "correlation_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    rule_name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    rule_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        default="Medium",
        nullable=False,
    )
    condition_logic: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    execution_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    # Relationships
    correlations: Mapped[list["ThreatCorrelation"]] = relationship(
        "ThreatCorrelation",
        back_populates="rule",
    )


class ThreatCorrelation(Base, TimestampMixin):
    """Correlated security events connecting threats, incidents, assets, logs, and IOCs."""

    __tablename__ = "threat_correlations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    correlation_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        default="Medium",
        nullable=False,
        index=True,
    )
    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=50,
        nullable=False,
    )
    confidence_score: Mapped[int] = mapped_column(
        Integer,
        default=80,
        nullable=False,
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.assets.id", ondelete="SET NULL"),
        nullable=True,
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.incidents.id", ondelete="SET NULL"),
        nullable=True,
    )
    threat_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.threats.id", ondelete="SET NULL"),
        nullable=True,
    )
    ioc_value: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.correlation_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    correlation_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )

    # Relationships
    rule: Mapped[CorrelationRule | None] = relationship(
        "CorrelationRule",
        back_populates="correlations",
    )


class AttackChain(Base, TimestampMixin):
    """Multi-stage kill chain / attack scenario constructed by correlation engine."""

    __tablename__ = "attack_chains"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    chain_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        default="High",
        nullable=False,
    )
    overall_risk_score: Mapped[int] = mapped_column(
        Integer,
        default=75,
        nullable=False,
    )
    overall_confidence_score: Mapped[int] = mapped_column(
        Integer,
        default=85,
        nullable=False,
    )
    entry_point: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    target_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.assets.id", ondelete="SET NULL"),
        nullable=True,
    )
    stages_json: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default="[]",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="Active",
        nullable=False,
        index=True,
    )


class MitreMapping(Base, TimestampMixin):
    """Mapping between MITRE ATT&CK techniques and platform entities (threat, incident, correlation, log)."""

    __tablename__ = "mitre_mappings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    entity_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    technique_id: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    tactic: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    confidence_score: Mapped[int] = mapped_column(
        Integer,
        default=80,
        nullable=False,
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
