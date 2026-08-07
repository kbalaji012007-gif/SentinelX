"""
SentinelX AI – SOAR Engine Module ORM Models
Schemas:
  - sentinelx.soar_playbooks
  - sentinelx.soar_playbook_steps
  - sentinelx.soar_rules
  - sentinelx.soar_execution_history
  - sentinelx.soar_execution_logs
  - sentinelx.soar_approval_requests
"""

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import String, Text, ForeignKey, DateTime, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class SOARPlaybook(Base, TimestampMixin):
    """SOAR Automated Playbook catalog."""

    __tablename__ = "soar_playbooks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    trigger_type: Mapped[str] = mapped_column(
        String(100),
        default="Incident_Created",
        nullable=False,
    )
    category: Mapped[str] = mapped_column(
        String(100),
        default="Threat Response",
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
    )
    author: Mapped[str] = mapped_column(
        String(255),
        default="System Admin",
        nullable=False,
    )

    # Relationships
    steps: Mapped[list["SOARPlaybookStep"]] = relationship(
        "SOARPlaybookStep",
        back_populates="playbook",
        cascade="all, delete-orphan",
        order_by="SOARPlaybookStep.step_order",
    )
    rules: Mapped[list["SOARRule"]] = relationship(
        "SOARRule",
        back_populates="playbook",
    )
    executions: Mapped[list["SOARExecution"]] = relationship(
        "SOARExecution",
        back_populates="playbook",
    )


class SOARPlaybookStep(Base, TimestampMixin):
    """Sequential execution step within a SOAR Playbook."""

    __tablename__ = "soar_playbook_steps"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.soar_playbooks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_order: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    step_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    action_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(
        String(100),
        default="Asset",
        nullable=False,
    )
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    requires_approval: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Relationships
    playbook: Mapped[SOARPlaybook] = relationship(
        "SOARPlaybook",
        back_populates="steps",
    )


class SOARRule(Base, TimestampMixin):
    """Event-driven automation rule triggering SOAR playbooks."""

    __tablename__ = "soar_rules"

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
    trigger_event: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    condition_logic: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    playbook_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.soar_playbooks.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
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
    playbook: Mapped[SOARPlaybook | None] = relationship(
        "SOARPlaybook",
        back_populates="rules",
    )


class SOARExecution(Base, TimestampMixin):
    """SOAR playbook execution audit record."""

    __tablename__ = "soar_execution_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    playbook_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.soar_playbooks.id", ondelete="SET NULL"),
        nullable=True,
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.soar_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    trigger_source: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="Completed",
        nullable=False,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    execution_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )

    # Relationships
    playbook: Mapped[SOARPlaybook | None] = relationship(
        "SOARPlaybook",
        back_populates="executions",
    )
    logs: Mapped[list["SOARExecutionLog"]] = relationship(
        "SOARExecutionLog",
        back_populates="execution",
        cascade="all, delete-orphan",
    )
    approvals: Mapped[list["SOARApprovalRequest"]] = relationship(
        "SOARApprovalRequest",
        back_populates="execution",
        cascade="all, delete-orphan",
    )


class SOARExecutionLog(Base, TimestampMixin):
    """Granular execution log for SOAR playbook steps."""

    __tablename__ = "soar_execution_logs"

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
    log_level: Mapped[str] = mapped_column(
        String(20),
        default="INFO",
        nullable=False,
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    output_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )

    # Relationships
    execution: Mapped[SOARExecution] = relationship(
        "SOARExecution",
        back_populates="logs",
    )


class SOARApprovalRequest(Base, TimestampMixin):
    """Manual analyst approval request for high-impact SOAR response actions."""

    __tablename__ = "soar_approval_requests"

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
    status: Mapped[str] = mapped_column(
        String(50),
        default="Pending",
        nullable=False,
        index=True,
    )
    requested_by: Mapped[str] = mapped_column(
        String(255),
        default="SOAR Engine",
        nullable=False,
    )
    approved_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    execution: Mapped[SOARExecution] = relationship(
        "SOARExecution",
        back_populates="approvals",
    )
