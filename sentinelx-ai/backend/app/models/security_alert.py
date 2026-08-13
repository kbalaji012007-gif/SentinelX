"""
SentinelX AI – Security Alert ORM Model
Schema: sentinelx.security_alerts
Real-time SOC security alert management (Phase 6.4).
"""

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import (
    String,
    Text,
    ForeignKey,
    DateTime,
    CheckConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class SecurityAlert(Base, TimestampMixin):
    """
    Real-time security alert generated from endpoint telemetry, threat detection,
    and correlation engine. Represents actionable SOC events requiring analyst attention.

    Lifecycle: NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED / DISMISSED
    """

    __tablename__ = "security_alerts"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="ck_security_alerts_severity",
        ),
        CheckConstraint(
            "status IN ('NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'DISMISSED')",
            name="ck_security_alerts_status",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Unique business key for deduplication
    alert_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Classification
    alert_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="MEDIUM", index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="NEW", index=True
    )
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Foreign key references (nullable – not all alerts have all links)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    log_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    threat_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # MITRE ATT&CK mapping
    mitre_tactic: Mapped[str | None] = mapped_column(String(200), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Evidence JSONB – stores raw event data, occurrence count, related events
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    # Additional metadata (hostname, platform, os_version, agent_version, etc.)
    alert_metadata: Mapped[dict[str, Any]] = mapped_column(
        "alert_metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    # Detection timestamp
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        default=lambda: datetime.now(timezone.utc),
    )

    # Analyst workflow timestamps
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
