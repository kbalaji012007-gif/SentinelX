"""
SentinelX AI – Security Alerts REST API Router (Phase 6.4)
CRUD endpoints for SOC security alert management with full RBAC enforcement.
"""

from uuid import UUID
from typing import Annotated, List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole, get_current_user
from app.models.user import User
from app.schemas.security_alert_schema import (
    SecurityAlertListResponse,
    SecurityAlertResponse,
    SecurityAlertStatistics,
    SecurityAlertSummary,
    AlertAcknowledgeRequest,
    AlertInvestigateRequest,
    AlertResolveRequest,
    AlertDismissRequest,
    AlertTestCreate,
    SecurityAlertCreate,
)
from app.services.security_alert_service import SecurityAlertService

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])

# ── RBAC Role Groups ──────────────────────────────────────────────────────────
_READERS = [
    "Super Administrator", "Administrator", "SOC Manager", "SOC Analyst",
    "Threat Hunter", "Incident Responder", "Auditor", "Read Only",
    "Admin", "Manager", "Analyst",
]
_ANALYSTS = [
    "Super Administrator", "Administrator", "SOC Manager", "SOC Analyst",
    "Threat Hunter", "Incident Responder", "Admin", "Manager", "Analyst",
]
_MANAGERS = [
    "Super Administrator", "Administrator", "SOC Manager", "Admin", "Manager",
]


# ── Read Endpoints ────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=SecurityAlertListResponse,
    status_code=status.HTTP_200_OK,
    summary="List security alerts (paginated, filterable)",
)
async def list_alerts(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    severity: Annotated[Optional[str], Query(description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW")] = None,
    alert_status: Annotated[Optional[str], Query(alias="status", description="Filter by status: NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, DISMISSED")] = None,
    alert_type: Annotated[Optional[str], Query(description="Filter by alert type")] = None,
    agent_id: Annotated[Optional[UUID], Query(description="Filter by endpoint agent UUID")] = None,
    search: Annotated[Optional[str], Query(description="Search title, description, source, alert_type")] = None,
    since: Annotated[Optional[datetime], Query(description="Filter alerts detected after this timestamp (ISO 8601)")] = None,
    until: Annotated[Optional[datetime], Query(description="Filter alerts detected before this timestamp (ISO 8601)")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> SecurityAlertListResponse:
    """Return paginated list of security alerts with optional filters."""
    svc = SecurityAlertService(db)
    return await svc.list_alerts(
        page=page,
        page_size=page_size,
        severity=severity,
        status=alert_status,
        alert_type=alert_type,
        agent_id=agent_id,
        search=search,
        since=since,
        until=until,
    )


@router.get(
    "/statistics",
    response_model=SecurityAlertStatistics,
    status_code=status.HTTP_200_OK,
    summary="Security alert aggregate statistics",
)
async def get_alert_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> SecurityAlertStatistics:
    """Return aggregate alert counts by severity and status for the SOC dashboard."""
    svc = SecurityAlertService(db)
    return await svc.get_statistics()


@router.get(
    "/recent",
    response_model=List[SecurityAlertSummary],
    status_code=status.HTTP_200_OK,
    summary="Most recent security alerts",
)
async def get_recent_alerts(
    limit: Annotated[int, Query(ge=1, le=50, description="Number of recent alerts to return")] = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> List[SecurityAlertSummary]:
    """Return the most recent N security alerts ordered by detection time."""
    svc = SecurityAlertService(db)
    return await svc.get_recent(limit=limit)


@router.get(
    "/{alert_uuid}",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Get security alert details",
)
async def get_alert(
    alert_uuid: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> SecurityAlertResponse:
    """Retrieve full details for a single security alert by UUID."""
    svc = SecurityAlertService(db)
    alert = await svc.get_alert(alert_uuid)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert {alert_uuid} not found",
        )
    return alert


# ── Status Transition Endpoints ───────────────────────────────────────────────

@router.post(
    "/{alert_uuid}/acknowledge",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge a security alert",
)
async def acknowledge_alert(
    alert_uuid: UUID,
    body: AlertAcknowledgeRequest = AlertAcknowledgeRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ANALYSTS)),
) -> SecurityAlertResponse:
    """Acknowledge a security alert, marking it as seen by an analyst."""
    svc = SecurityAlertService(db)
    try:
        return await svc.acknowledge_alert(alert_uuid, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{alert_uuid}/investigate",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Start investigation of a security alert",
)
async def investigate_alert(
    alert_uuid: UUID,
    body: AlertInvestigateRequest = AlertInvestigateRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ANALYSTS)),
) -> SecurityAlertResponse:
    """Mark a security alert as under active investigation."""
    svc = SecurityAlertService(db)
    try:
        return await svc.investigate_alert(alert_uuid, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{alert_uuid}/resolve",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve a security alert",
)
async def resolve_alert(
    alert_uuid: UUID,
    body: AlertResolveRequest = AlertResolveRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_MANAGERS)),
) -> SecurityAlertResponse:
    """Resolve a security alert after investigation and remediation."""
    svc = SecurityAlertService(db)
    try:
        return await svc.resolve_alert(
            alert_uuid, current_user.id, resolution_notes=body.resolution_notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{alert_uuid}/dismiss",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Dismiss a security alert (Managers only)",
)
async def dismiss_alert(
    alert_uuid: UUID,
    body: AlertDismissRequest = AlertDismissRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_MANAGERS)),
) -> SecurityAlertResponse:
    """Dismiss a security alert as false positive or known benign. Manager/Admin only."""
    svc = SecurityAlertService(db)
    try:
        return await svc.dismiss_alert(alert_uuid, current_user.id, reason=body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# ── Test Mode Endpoint ────────────────────────────────────────────────────────

@router.post(
    "/test/simulate",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="[TEST ONLY] Create a simulated test alert",
)
async def create_test_alert(
    body: AlertTestCreate = AlertTestCreate(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_MANAGERS)),
) -> SecurityAlertResponse:
    """
    TEST MODE ONLY – Creates a clearly marked SIMULATED_TEST_EVENT alert.
    Used for end-to-end WebSocket and pipeline verification.
    Never mixes with production security events.
    """
    import uuid as _uuid
    svc = SecurityAlertService(db)
    test_alert_id = f"TEST-{_uuid.uuid4().hex[:8].upper()}"
    data = SecurityAlertCreate(
        alert_id=test_alert_id,
        title=f"[SIMULATED TEST EVENT] {body.title}",
        description=body.description or "Controlled test event for E2E pipeline verification.",
        alert_type=f"test_{body.alert_type}",
        severity=body.severity,
        source="TEST_MODE",
        evidence={
            "is_simulated": True,
            "test_tag": "SIMULATED_TEST_EVENT",
            "created_by": str(current_user.id),
        },
        alert_metadata={
            "hostname": body.hostname or "TEST-HOST",
            "is_test": True,
        },
    )
    alert, _ = await svc.create_alert(data)
    return SecurityAlertResponse.model_validate(alert)
