"""
SentinelX AI – SOAR Engine & Automated Response Actions API Router
JWT-protected, RBAC-enforced endpoints for Playbooks, Action Execution, Dry-Run, Rollback, Connectors, Notifications, and SOAR Telemetry Metrics.
"""

from uuid import UUID
from typing import Annotated
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole
from app.models.user import User
from app.schemas.soar_schema import (
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookResponse,
    PlaybookListResponse,
    RuleCreate,
    RuleResponse,
    RuleListResponse,
    ExecutionCreate,
    ExecutionResponse,
    ExecutionListResponse,
    ApprovalActionRequest,
    ApprovalListResponse,
    SOARStatsResponse,
)
from app.schemas.soar_execution_schema import (
    ExecutionStepResponse,
    ExecutionStepListResponse,
    ExecutionResultResponse,
    ExecutionResultListResponse,
    ConnectorStatusListResponse,
    NotificationListResponse,
    ExecutionRunOptionsPayload,
    SOARMetricsResponse,
)
from app.services.soar_service import SOARService

router = APIRouter(prefix="/soar", tags=["SOAR Automation"])

# RBAC roles
_READERS = ["Admin", "Manager", "Analyst", "ReadOnly"]
_WRITERS = ["Admin", "Manager", "Analyst"]
_ADMINS = ["Admin", "Manager"]


# ────────────────────────────────────────────────────────────────────────
# Playbook Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/playbooks",
    response_model=PlaybookListResponse,
    status_code=status.HTTP_200_OK,
    summary="List SOAR Playbooks (paginated, filterable)",
)
async def list_playbooks(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    category: Annotated[str | None, Query(description="Filter by category")] = None,
    is_active: Annotated[bool | None, Query(description="Filter active playbooks")] = None,
    search: Annotated[str | None, Query(description="Search playbook name or description")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> PlaybookListResponse:
    """Retrieve paginated list of automated SOAR response playbooks."""
    service = SOARService(db)
    return await service.list_playbooks(
        page=page, page_size=page_size, category=category, is_active=is_active, search=search
    )


@router.post(
    "/playbooks",
    response_model=PlaybookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new SOAR Playbook",
)
async def create_playbook(
    payload: PlaybookCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> PlaybookResponse:
    """Register a new automated playbook with sequential response steps."""
    service = SOARService(db)
    try:
        return await service.create_playbook(payload)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/playbooks/{id}/execute",
    response_model=ExecutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Playbook (Support Dry-Run & Parameters)",
)
async def execute_playbook(
    id: UUID,
    payload: ExecutionRunOptionsPayload = ExecutionRunOptionsPayload(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ExecutionResponse:
    """Execute a playbook using action handlers (supports dry-run simulation mode)."""
    service = SOARService(db)
    try:
        operator = f"{current_user.first_name} {current_user.last_name}"
        return await service.execute_playbook(
            playbook_id=id,
            is_dry_run=payload.is_dry_run,
            trigger_source=f"Analyst {operator}",
            parameters=payload.parameters,
        )
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/playbooks/{id}",
    response_model=PlaybookResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Playbook details by UUID",
)
async def get_playbook_by_id(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> PlaybookResponse:
    """Retrieve playbook details and steps by UUID."""
    service = SOARService(db)
    try:
        return await service.get_playbook(id)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put(
    "/playbooks/{id}",
    response_model=PlaybookResponse,
    status_code=status.HTTP_200_OK,
    summary="Update SOAR Playbook by UUID",
)
async def update_playbook(
    id: UUID,
    payload: PlaybookUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> PlaybookResponse:
    """Update existing playbook metadata or steps."""
    service = SOARService(db)
    try:
        return await service.update_playbook(id, payload)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete(
    "/playbooks/{id}",
    status_code=status.HTTP_200_OK,
    summary="Delete SOAR Playbook by UUID",
)
async def delete_playbook(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMINS)),
) -> dict[str, str]:
    """Delete playbook by UUID."""
    service = SOARService(db)
    try:
        await service.delete_playbook(id)
        return {"message": f"Playbook '{id}' deleted successfully."}
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ────────────────────────────────────────────────────────────────────────
# Rule Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/rules",
    response_model=RuleListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Automation Rules",
)
async def list_rules(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    is_active: Annotated[bool | None, Query(description="Filter active rules")] = None,
    search: Annotated[str | None, Query(description="Search rule name")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> RuleListResponse:
    """Retrieve paginated automation rules linking security events to playbooks."""
    service = SOARService(db)
    return await service.list_rules(page=page, page_size=page_size, is_active=is_active, search=search)


@router.post(
    "/rules",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Automation Rule",
)
async def create_rule(
    payload: RuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> RuleResponse:
    """Register a new event-driven automation rule."""
    service = SOARService(db)
    try:
        return await service.create_rule(payload)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ────────────────────────────────────────────────────────────────────────
# Execution & Control Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/executions",
    response_model=ExecutionListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Playbook Executions History",
)
async def list_executions(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    status_filter: Annotated[str | None, Query(alias="status", description="Filter execution status")] = None,
    playbook_id: Annotated[UUID | None, Query(description="Filter by playbook UUID")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ExecutionListResponse:
    """Retrieve paginated execution audit history."""
    service = SOARService(db)
    return await service.execution_history(page=page, page_size=page_size, status=status_filter, playbook_id=playbook_id)


@router.post(
    "/executions",
    response_model=ExecutionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Playbook Execution",
)
async def trigger_execution(
    payload: ExecutionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ExecutionResponse:
    """Record and trigger execution of a SOAR playbook."""
    service = SOARService(db)
    try:
        return await service.create_execution(payload)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/executions/{id}/cancel",
    response_model=ExecutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Cancel in-progress execution",
)
async def cancel_execution(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ExecutionResponse:
    """Cancel an in-progress or pending SOAR playbook execution."""
    service = SOARService(db)
    try:
        return await service.cancel_execution(id)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/executions/{id}/resume",
    response_model=ExecutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Resume execution",
)
async def resume_execution(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ExecutionResponse:
    """Resume a paused or pending approval execution."""
    service = SOARService(db)
    try:
        return await service.resume_execution(id)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/executions/{id}/rollback",
    response_model=ExecutionStepResponse,
    status_code=status.HTTP_200_OK,
    summary="Rollback step action",
)
async def rollback_execution_step(
    id: UUID,
    step_id: Annotated[UUID, Query(description="Step ID to revert")],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ExecutionStepResponse:
    """Revert/rollback a previously executed response action step."""
    service = SOARService(db)
    try:
        return await service.rollback_step(execution_id=id, step_id=step_id)
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/executions/{id}/steps",
    response_model=ExecutionStepListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get execution steps",
)
async def get_execution_steps(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ExecutionStepListResponse:
    """Fetch execution step timeline for a playbook run."""
    service = SOARService(db)
    return await service.get_execution_steps(id)


@router.get(
    "/executions/{id}/results",
    response_model=ExecutionResultListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get step execution results",
)
async def get_execution_results(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ExecutionResultListResponse:
    """Fetch step execution telemetry results."""
    service = SOARService(db)
    return await service.get_execution_results(id)


@router.post(
    "/executions/{id}/approve",
    response_model=ExecutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve pending SOAR Execution",
)
async def approve_execution(
    id: UUID,
    payload: ApprovalActionRequest = ApprovalActionRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ExecutionResponse:
    """Approve a pending SOAR response action request."""
    service = SOARService(db)
    try:
        approver = f"{current_user.first_name} {current_user.last_name}"
        return await service.approve_execution(id, approver_name=approver, reason=payload.reason)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/executions/{id}/reject",
    response_model=ExecutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Reject pending SOAR Execution",
)
async def reject_execution(
    id: UUID,
    payload: ApprovalActionRequest = ApprovalActionRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ExecutionResponse:
    """Reject a pending SOAR response action request."""
    service = SOARService(db)
    try:
        rejector = f"{current_user.first_name} {current_user.last_name}"
        return await service.reject_execution(id, rejector_name=rejector, reason=payload.reason)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/approvals",
    response_model=ApprovalListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Approval Requests",
)
async def list_approvals(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    status_filter: Annotated[str | None, Query(alias="status", description="Filter approval status")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ApprovalListResponse:
    """List manual approval requests."""
    service = SOARService(db)
    return await service.list_approvals(page=page, page_size=page_size, status=status_filter)


# ────────────────────────────────────────────────────────────────────────
# Connectors, Notifications & Metrics Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/connectors",
    response_model=ConnectorStatusListResponse,
    status_code=status.HTTP_200_OK,
    summary="Connector Health Telemetry",
)
async def get_connectors_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ConnectorStatusListResponse:
    """Retrieve integration connector health statuses."""
    service = SOARService(db)
    return await service.list_connectors()


@router.get(
    "/notifications",
    response_model=NotificationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Notification History",
)
async def list_notifications(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> NotificationListResponse:
    """Retrieve SOAR notification audit logs."""
    service = SOARService(db)
    return await service.list_notifications(page=page, page_size=page_size)


@router.get(
    "/metrics",
    response_model=SOARMetricsResponse,
    status_code=status.HTTP_200_OK,
    summary="Advanced SOAR Execution Metrics",
)
async def get_soar_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> SOARMetricsResponse:
    """Retrieve advanced execution metrics for SOAR dashboard widgets."""
    service = SOARService(db)
    return await service.execution_metrics()


@router.get(
    "/statistics",
    response_model=SOARStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="SOAR Engine Telemetry Statistics",
)
async def get_soar_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> SOARStatsResponse:
    """Retrieve SOAR automation engine overview statistics."""
    service = SOARService(db)
    return await service.execution_statistics()
