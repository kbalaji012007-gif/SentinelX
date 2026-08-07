"""
SentinelX AI – SOAR Execution Pydantic v2 Schemas
Validation and serialization schemas for Response Actions, Execution Steps, Results, Connectors, Webhooks, and Metrics.
"""

from uuid import UUID
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class ResponseActionResponse(BaseModel):
    """Schema for returning registered response action details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action_name: str
    action_type: str
    target_type: str
    description: str | None = None
    supports_rollback: bool = True
    supports_dry_run: bool = True
    created_at: datetime


class ResponseActionListResponse(BaseModel):
    """Paginated list of response actions."""

    total: int
    items: list[ResponseActionResponse]


class ExecutionStepResponse(BaseModel):
    """Schema for returning execution step status."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    execution_id: UUID
    step_id: UUID | None = None
    step_name: str
    action_type: str
    status: str
    is_dry_run: bool
    parameters: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ExecutionStepListResponse(BaseModel):
    """List of execution steps."""

    total: int
    items: list[ExecutionStepResponse]


class ExecutionResultResponse(BaseModel):
    """Schema for returning action execution result telemetry."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    execution_step_id: UUID
    status: str
    output_payload: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    execution_time_ms: int = 0
    rollback_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ExecutionResultListResponse(BaseModel):
    """List of execution results."""

    total: int
    items: list[ExecutionResultResponse]


class ConnectorStatusResponse(BaseModel):
    """Schema for returning connector health and heartbeat."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    connector_name: str
    connector_type: str
    status: str
    last_heartbeat: datetime
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ConnectorStatusListResponse(BaseModel):
    """List of connectors status."""

    total: int
    items: list[ConnectorStatusResponse]


class NotificationResponse(BaseModel):
    """Schema for returning notification log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    channel: str
    recipient: str
    subject: str | None = None
    message_body: str
    status: str
    created_at: datetime


class NotificationListResponse(BaseModel):
    """Paginated list of notifications."""

    total: int
    page: int
    page_size: int
    items: list[NotificationResponse]


class ExecutionRunOptionsPayload(BaseModel):
    """Options payload when executing a playbook or step."""

    is_dry_run: bool = False
    parameters: dict[str, Any] = Field(default_factory=dict)


class SOARMetricsResponse(BaseModel):
    """Advanced execution metrics for SOAR engine."""

    running_playbooks: int
    successful_executions: int
    failed_executions: int
    average_execution_time_ms: float
    connector_health: dict[str, int] = Field(default_factory=dict)
    notifications_sent: int
    rollbacks_performed: int
    pending_approvals: int
