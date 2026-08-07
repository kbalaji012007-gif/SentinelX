"""
SentinelX AI – SOAR Engine Pydantic v2 Schemas
Validation and serialization schemas for Playbooks, Steps, Automation Rules, Executions, Logs, and Approval Requests.
"""

from uuid import UUID
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

ExecutionStatusEnum = Literal["Pending_Approval", "In_Progress", "Completed", "Failed", "Rejected"]
ApprovalStatusEnum = Literal["Pending", "Approved", "Rejected"]


# ────────────────────────────────────────────────────────────────────────
# SOAR Playbook Step Schemas
# ────────────────────────────────────────────────────────────────────────

class PlaybookStepBase(BaseModel):
    """Shared Playbook Step attributes."""

    step_order: int = Field(..., ge=1)
    step_name: str = Field(..., min_length=1, max_length=255)
    action_type: str = Field(..., min_length=1, max_length=100)
    target_type: str = Field("Asset", min_length=1, max_length=100)
    parameters: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False


class PlaybookStepCreate(PlaybookStepBase):
    """Schema for creating a playbook step."""

    pass


class PlaybookStepResponse(PlaybookStepBase):
    """Schema for returning a playbook step."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    playbook_id: UUID
    created_at: datetime
    updated_at: datetime


# ────────────────────────────────────────────────────────────────────────
# SOAR Playbook Schemas
# ────────────────────────────────────────────────────────────────────────

class PlaybookBase(BaseModel):
    """Shared SOAR Playbook attributes."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    trigger_type: str = Field("Incident_Created", min_length=1, max_length=100)
    category: str = Field("Threat Response", min_length=1, max_length=100)
    is_active: bool = True
    author: str = Field("System Admin", max_length=255)


class PlaybookCreate(PlaybookBase):
    """Schema for creating a new SOAR playbook with steps."""

    steps: list[PlaybookStepCreate] = Field(default_factory=list)


class PlaybookUpdate(BaseModel):
    """Schema for updating a SOAR playbook."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    trigger_type: str | None = None
    category: str | None = None
    is_active: bool | None = None
    author: str | None = None
    steps: list[PlaybookStepCreate] | None = None


class PlaybookResponse(PlaybookBase):
    """Schema for returning full playbook details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    steps: list[PlaybookStepResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class PlaybookListResponse(BaseModel):
    """Paginated list of playbooks."""

    total: int
    page: int
    page_size: int
    items: list[PlaybookResponse]


# ────────────────────────────────────────────────────────────────────────
# SOAR Rule Schemas
# ────────────────────────────────────────────────────────────────────────

class RuleBase(BaseModel):
    """Shared SOAR Automation Rule attributes."""

    rule_name: str = Field(..., min_length=1, max_length=255)
    trigger_event: str = Field(..., min_length=1, max_length=100)
    condition_logic: dict[str, Any] = Field(default_factory=dict)
    playbook_id: UUID | None = None
    is_active: bool = True
    description: str | None = None


class RuleCreate(RuleBase):
    """Schema for creating a new SOAR rule."""

    pass


class RuleUpdate(BaseModel):
    """Schema for updating a SOAR rule."""

    rule_name: str | None = Field(None, min_length=1, max_length=255)
    trigger_event: str | None = None
    condition_logic: dict[str, Any] | None = None
    playbook_id: UUID | None = None
    is_active: bool | None = None
    description: str | None = None


class RuleResponse(RuleBase):
    """Schema for returning SOAR rule details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    execution_count: int = 0
    created_at: datetime
    updated_at: datetime


class RuleListResponse(BaseModel):
    """Paginated list of SOAR rules."""

    total: int
    page: int
    page_size: int
    items: list[RuleResponse]


# ────────────────────────────────────────────────────────────────────────
# Execution & Log Schemas
# ────────────────────────────────────────────────────────────────────────

class ExecutionLogResponse(BaseModel):
    """Schema for returning execution logs."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    execution_id: UUID
    step_id: UUID | None = None
    log_level: str
    message: str
    output_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ExecutionCreate(BaseModel):
    """Payload to trigger playbook execution."""

    playbook_id: UUID
    rule_id: UUID | None = None
    trigger_source: str = Field("Manual Execution", max_length=255)
    execution_metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionResponse(BaseModel):
    """Schema for returning execution history details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    playbook_id: UUID | None = None
    rule_id: UUID | None = None
    trigger_source: str
    status: ExecutionStatusEnum
    started_at: datetime
    completed_at: datetime | None = None
    execution_metadata: dict[str, Any] = Field(default_factory=dict)
    logs: list[ExecutionLogResponse] = Field(default_factory=list)
    created_at: datetime


class ExecutionListResponse(BaseModel):
    """Paginated list of execution history records."""

    total: int
    page: int
    page_size: int
    items: list[ExecutionResponse]


# ────────────────────────────────────────────────────────────────────────
# Approval Request Schemas
# ────────────────────────────────────────────────────────────────────────

class ApprovalActionRequest(BaseModel):
    """Payload for approving or rejecting an execution step."""

    reason: str | None = None


class ApprovalResponse(BaseModel):
    """Schema for returning approval request details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    execution_id: UUID
    step_id: UUID | None = None
    status: ApprovalStatusEnum
    requested_by: str
    approved_by: str | None = None
    reason: str | None = None
    requested_at: datetime
    decided_at: datetime | None = None
    created_at: datetime


class ApprovalListResponse(BaseModel):
    """Paginated list of approval requests."""

    total: int
    page: int
    page_size: int
    items: list[ApprovalResponse]


# ────────────────────────────────────────────────────────────────────────
# SOAR Telemetry Statistics Schema
# ────────────────────────────────────────────────────────────────────────

class SOARStatsResponse(BaseModel):
    """SOAR Engine overview telemetry statistics."""

    total_playbooks: int
    active_rules: int
    pending_approvals: int
    executions_today: int
    successful_executions: int
    failed_executions: int
    by_category: dict[str, int] = Field(default_factory=dict)
