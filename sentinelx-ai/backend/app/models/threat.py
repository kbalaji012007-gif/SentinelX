"""
SentinelX AI – Threat Detection ORM Models
Schema: sentinelx.threats, sentinelx.alerts, sentinelx.ioc
"""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from sqlalchemy import (
    String,
    Text,
    Boolean,
    Numeric,
    ForeignKey,
    DateTime,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.asset import Asset


class Threat(Base, TimestampMixin):
    """
    Threat model representing detected security threats in the enterprise.
    Linked to an asset and may carry multiple alerts and IOCs.
    """

    __tablename__ = "threats"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_threats_severity",
        ),
        CheckConstraint(
            "status IN ('New', 'Investigating', 'Mitigated', 'Closed')",
            name="ck_threats_status",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_threats_confidence_score",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="Medium",
        index=True,
    )
    confidence_score: Mapped[Decimal | None] = mapped_column(
        Numeric(5, 2),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="New",
        index=True,
    )
    source: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    mitre_technique_id: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        index=True,
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Relationships
    asset: Mapped["Asset | None"] = relationship(
        "Asset",
        foreign_keys=[asset_id],
        lazy="select",
    )
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="threat",
        cascade="all, delete-orphan",
        lazy="select",
    )
    iocs: Mapped[list["IOC"]] = relationship(
        "IOC",
        back_populates="threat",
        cascade="all, delete-orphan",
        lazy="select",
    )


class Alert(Base, TimestampMixin):
    """
    Alert model representing individual security alerts linked to a threat.
    Carries raw event payload for forensic analysis.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_alerts_severity",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    threat_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.threats.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_name: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    alert_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    alert_source: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="Medium",
        index=True,
    )
    message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    raw_event: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    acknowledged: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    # Relationships
    threat: Mapped["Threat"] = relationship(
        "Threat",
        back_populates="alerts",
    )


class IOC(Base, TimestampMixin):
    """
    Indicator of Compromise (IOC) model for threat intelligence enrichment.
    Supports IP, Domain, URL, Hash, and Email indicator types.
    """

    __tablename__ = "ioc"
    __table_args__ = (
        CheckConstraint(
            "type IN ('IP', 'Domain', 'URL', 'Hash', 'Email')",
            name="ck_ioc_type",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name="ck_ioc_confidence",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    threat_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.threats.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
    )
    reputation: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    confidence: Mapped[Decimal | None] = mapped_column(
        Numeric(5, 2),
        nullable=True,
    )
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # Relationships
    threat: Mapped["Threat"] = relationship(
        "Threat",
        back_populates="iocs",
    )
