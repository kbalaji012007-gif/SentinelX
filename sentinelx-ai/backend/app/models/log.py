"""
SentinelX AI – Log Collection ORM Models
Schema: sentinelx.log_sources, sentinelx.log_entries
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any
from sqlalchemy import (
    String,
    Text,
    Integer,
    ForeignKey,
    DateTime,
    CheckConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.asset import Asset


class LogSource(Base, TimestampMixin):
    """
    Log source model representing systems or services that emit security logs.
    Supports Syslog, Windows Event, Cloud Trail, Firewall, IDS/IPS, and more.
    """

    __tablename__ = "log_sources"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('Syslog', 'Windows Event', 'Cloud Trail', "
            "'Firewall', 'IDS/IPS', 'Endpoint', 'Application', 'Network', 'Other')",
            name="ck_log_sources_source_type",
        ),
        CheckConstraint(
            "status IN ('Active', 'Inactive', 'Error', 'Maintenance')",
            name="ck_log_sources_status",
        ),
        CheckConstraint(
            "protocol IS NULL OR protocol IN ('UDP', 'TCP', 'TLS', 'HTTPS', 'HTTP')",
            name="ck_log_sources_protocol",
        ),
        CheckConstraint(
            "port IS NULL OR (port >= 0 AND port <= 65535)",
            name="ck_log_sources_port",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    source_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    vendor: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )
    protocol: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )
    port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="Active",
        index=True,
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    entries: Mapped[list["LogEntry"]] = relationship(
        "LogEntry",
        back_populates="source",
        cascade="all, delete-orphan",
        lazy="select",
    )


class LogEntry(Base):
    """
    Log entry model representing individual security log events.
    Immutable records – no updated_at column; only created_at is tracked.
    """

    __tablename__ = "log_entries"
    __table_args__ = (
        CheckConstraint(
            "log_level IN ('TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')",
            name="ck_log_entries_log_level",
        ),
        {"schema": "sentinelx"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.log_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    log_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="INFO",
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    category: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )
    message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    raw_log: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )
    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )
    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    process_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    event_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    source: Mapped["LogSource"] = relationship(
        "LogSource",
        back_populates="entries",
    )
    asset: Mapped["Asset | None"] = relationship(
        "Asset",
        foreign_keys=[asset_id],
        lazy="select",
    )
