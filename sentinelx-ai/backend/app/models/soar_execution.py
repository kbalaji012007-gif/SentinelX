"""
SentinelX AI – SOAR Automated Response Engine ORM Models
Schemas:
  - sentinelx.soar_response_actions
  - sentinelx.soar_execution_steps
  - sentinelx.soar_execution_results
  - sentinelx.soar_connector_status
  - sentinelx.soar_webhooks
  - sentinelx.soar_notifications
"""

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import String, Text, ForeignKey, DateTime, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class SOARResponseAction(Base, TimestampMixin):
    """Catalog of registered response actions supported by SOAR engine."""

    __tablename__ = "soar_response_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    action_name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    action_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    target_type: Mapped[str] = mapped_column(
        String(100),
        default="Asset",
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    supports_rollback: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    supports_dry_run: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )


class SOARExecutionStep(Base, TimestampMixin):
    """Execution step instance within a live playbook run."""

    __tablename__ = "soar_execution_steps"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.soar_execution_history.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.soar_playbook_steps.id", ondelete="SET NULL"),
        nullable=True,
    )
    step_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    action_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="Pending",
        nullable=False,
    )
    is_dry_run: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )

    # Relationships
    results: Mapped[list["SOARExecutionResult"]] = relationship(
        "SOARExecutionResult",
        back_populates="step",
        cascade="all, delete-orphan",
    )


class SOARExecutionResult(Base, TimestampMixin):
    """Result telemetry for an executed response action step."""

    __tablename__ = "soar_execution_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    execution_step_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.soar_execution_steps.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="Success",
        nullable=False,
    )
    output_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    execution_time_ms: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    rollback_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )

    # Relationships
    step: Mapped[SOARExecutionStep] = relationship(
        "SOARExecutionStep",
        back_populates="results",
    )


class SOARConnectorStatus(Base, TimestampMixin):
    """Integration connector status and health telemetry."""

    __tablename__ = "soar_connector_status"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    connector_name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    connector_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="Online",
        nullable=False,
        index=True,
    )
    last_heartbeat: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )


class SOARWebhook(Base, TimestampMixin):
    """Outgoing integration webhook configuration."""

    __tablename__ = "soar_webhooks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    target_url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    http_method: Mapped[str] = mapped_column(
        String(10),
        default="POST",
        nullable=False,
    )
    headers: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )


class SOARNotification(Base, TimestampMixin):
    """Notification history for automated SOAR alerts."""

    __tablename__ = "soar_notifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    channel: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    recipient: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    subject: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    message_body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="Sent",
        nullable=False,
        index=True,
    )
