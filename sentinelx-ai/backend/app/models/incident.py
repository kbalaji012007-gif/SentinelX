"""
SentinelX AI – Incident Response ORM Models
Schema: sentinelx.incidents, sentinelx.incident_timeline, sentinelx.incident_notes, sentinelx.incident_evidence
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any
from sqlalchemy import (
    String,
    Text,
    ForeignKey,
    DateTime,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.threat import Threat
    from app.models.user import User


class Incident(Base, TimestampMixin):
    """
    Incident model representing security incident response tickets.
    Linked to threats and assigned analysts.
    """

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_incidents_severity",
        ),
        CheckConstraint(
            "priority IN ('P0', 'P1', 'P2', 'P3', 'P4')",
            name="ck_incidents_priority",
        ),
        CheckConstraint(
            "status IN ('Open', 'In Progress', 'Contained', 'Resolved', 'Closed')",
            name="ck_incidents_status",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    threat_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.threats.id", ondelete="SET NULL"),
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
    priority: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="P2",
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Open",
        index=True,
    )
    assigned_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reported_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    threat: Mapped["Threat | None"] = relationship("Threat", lazy="select")
    assigned_user: Mapped["User | None"] = relationship("User", lazy="selectin")
    timeline_events: Mapped[list["IncidentTimeline"]] = relationship(
        "IncidentTimeline",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimeline.created_at.desc()",
        lazy="select",
    )
    notes: Mapped[list["IncidentNote"]] = relationship(
        "IncidentNote",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentNote.created_at.desc()",
        lazy="select",
    )
    evidence: Mapped[list["IncidentEvidence"]] = relationship(
        "IncidentEvidence",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEvidence.uploaded_at.desc()",
        lazy="select",
    )


class IncidentTimeline(Base):
    """Timeline event log entry for an incident."""

    __tablename__ = "incident_timeline"
    __table_args__ = ({"schema": "sentinelx"},)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline_events")


class IncidentNote(Base):
    """Analyst note attached to an incident."""

    __tablename__ = "incident_notes"
    __table_args__ = ({"schema": "sentinelx"},)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    note: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="notes")
    author: Mapped["User | None"] = relationship("User", lazy="selectin")


class IncidentEvidence(Base):
    """Evidence file reference for forensic analysis."""

    __tablename__ = "incident_evidence"
    __table_args__ = ({"schema": "sentinelx"},)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    evidence_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    file_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="evidence")
    uploader: Mapped["User | None"] = relationship("User", lazy="selectin")
