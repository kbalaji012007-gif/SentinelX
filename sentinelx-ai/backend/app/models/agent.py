"""
SentinelX AI – Endpoint Agent ORM Models
Schema: sentinelx.endpoint_agents, sentinelx.agent_telemetry
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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class EndpointAgent(Base, TimestampMixin):
    """
    Endpoint agent model representing enrolled Windows telemetry agents.
    Tracks agent identity, host specs, online status, and enrollment lifecycle.
    """

    __tablename__ = "endpoint_agents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('Online', 'Offline', 'Stale', 'Disabled', 'Revoked', 'Never Seen')",
            name="ck_endpoint_agents_status",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    agent_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    platform: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="Windows",
    )
    os_version: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    agent_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="1.0.0",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="Online",
        index=True,
    )
    enrolled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    agent_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    # Relationships
    telemetry_entries: Mapped[list["AgentTelemetry"]] = relationship(
        "AgentTelemetry",
        back_populates="agent",
        cascade="all, delete-orphan",
        order_by="desc(AgentTelemetry.event_timestamp)",
    )


class AgentTelemetry(Base):
    """
    Structured telemetry event record submitted by endpoint agents.
    Stores Windows events, process executions, network socket states, and system health metrics.
    """

    __tablename__ = "agent_telemetry"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')",
            name="ck_agent_telemetry_severity",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.endpoint_agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="INFO",
        index=True,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    source: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    agent: Mapped[EndpointAgent] = relationship(
        "EndpointAgent",
        back_populates="telemetry_entries",
    )
