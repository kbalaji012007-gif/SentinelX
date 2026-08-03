"""
SentinelX AI – Threats API Router
JWT-protected, RBAC-enforced endpoints for threat, alert, and IOC management.
"""

from uuid import UUID
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user, RequireRole
from app.models.user import User
from app.schemas.threat_schema import (
    ThreatCreate,
    ThreatUpdate,
    ThreatResponse,
    ThreatListResponse,
    ThreatStatsResponse,
    AlertCreate,
    AlertResponse,
    IOCCreate,
    IOCResponse,
)
from app.services.threat_service import ThreatService, AlertService, IOCService

router = APIRouter(prefix="/threats", tags=["Threats"])

# RBAC role groups
_READERS = ["Admin", "Manager", "Analyst", "ReadOnly"]
_WRITERS = ["Admin", "Manager", "Analyst"]
_ADMINS = ["Admin", "Manager"]


# ────────────────────────────────────────────────────────────────────────
# Threat Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=ThreatListResponse,
    status_code=status.HTTP_200_OK,
    summary="List threats (paginated, filtered)",
)
async def list_threats(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    threat_status: Annotated[str | None, Query(alias="status", description="Filter by status")] = None,
    search: Annotated[str | None, Query(description="Search title, source, or MITRE ID")] = None,
    asset_id: Annotated[UUID | None, Query(description="Filter by asset UUID")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ThreatListResponse:
    """
    Return a paginated, filterable list of threats.
    Supports filtering by severity, status, asset, and free-text search.
    """
    service = ThreatService(db)
    return await service.list_threats(
        page=page,
        page_size=page_size,
        severity=severity,
        status=threat_status,
        search=search,
        asset_id=asset_id,
    )


@router.get(
    "/stats",
    response_model=ThreatStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Threat severity and status distribution",
)
async def get_threat_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ThreatStatsResponse:
    """Return threat count aggregations grouped by severity and status."""
    service = ThreatService(db)
    return await service.get_stats()


@router.get(
    "/{threat_id}",
    response_model=ThreatResponse,
    status_code=status.HTTP_200_OK,
    summary="Get threat detail with alerts and IOCs",
)
async def get_threat(
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ThreatResponse:
    """Retrieve a single threat with its full detail including nested alerts and IOCs."""
    service = ThreatService(db)
    threat = await service.get_threat(threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found",
        )
    return threat


@router.post(
    "",
    response_model=ThreatResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new threat",
)
async def create_threat(
    payload: ThreatCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ThreatResponse:
    """Create a new threat record. Requires Analyst, Manager, or Admin role."""
    service = ThreatService(db)
    return await service.create_threat(payload, created_by=str(current_user.id))


@router.put(
    "/{threat_id}",
    response_model=ThreatResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a threat",
)
async def update_threat(
    threat_id: UUID,
    payload: ThreatUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ThreatResponse:
    """Update threat fields. Supports partial updates via PATCH semantics (exclude_unset)."""
    service = ThreatService(db)
    threat = await service.update_threat(threat_id, payload, updated_by=str(current_user.id))
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found",
        )
    return threat


@router.delete(
    "/{threat_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a threat (Admin only)",
)
async def delete_threat(
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMINS)),
) -> None:
    """
    Permanently delete a threat and all its cascade children (alerts, IOCs).
    Restricted to Admin and Manager roles.
    """
    service = ThreatService(db)
    deleted = await service.delete_threat(threat_id, deleted_by=str(current_user.id))
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found",
        )


# ────────────────────────────────────────────────────────────────────────
# Alert Endpoints (nested under /threats router for clean prefix)
# ────────────────────────────────────────────────────────────────────────

alerts_router = APIRouter(prefix="/alerts", tags=["Alerts"])


@alerts_router.get(
    "",
    response_model=list[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="List alerts (filterable by threat, severity, acknowledged)",
)
async def list_alerts(
    threat_id: Annotated[UUID | None, Query(description="Filter by threat UUID")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    acknowledged: Annotated[bool | None, Query(description="Filter by ack status")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> list[AlertResponse]:
    """Return a filtered list of security alerts."""
    service = AlertService(db)
    return await service.list_alerts(
        threat_id=threat_id,
        severity=severity,
        acknowledged=acknowledged,
        page=page,
        page_size=page_size,
    )


@alerts_router.post(
    "",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new alert",
)
async def create_alert(
    payload: AlertCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> AlertResponse:
    """Create a new alert linked to a threat."""
    service = AlertService(db)
    return await service.create_alert(payload)


@alerts_router.patch(
    "/{alert_id}/acknowledge",
    response_model=AlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge an alert",
)
async def acknowledge_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> AlertResponse:
    """Mark an alert as acknowledged by an analyst."""
    service = AlertService(db)
    alert = await service.acknowledge_alert(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    return alert


# ────────────────────────────────────────────────────────────────────────
# IOC Endpoints
# ────────────────────────────────────────────────────────────────────────

ioc_router = APIRouter(prefix="/ioc", tags=["IOC"])


@ioc_router.get(
    "",
    response_model=list[IOCResponse],
    status_code=status.HTTP_200_OK,
    summary="List IOCs (filterable by threat, type)",
)
async def list_iocs(
    threat_id: Annotated[UUID | None, Query(description="Filter by threat UUID")] = None,
    ioc_type: Annotated[str | None, Query(alias="type", description="IP, Domain, URL, Hash, Email")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> list[IOCResponse]:
    """Return a filtered list of Indicators of Compromise."""
    service = IOCService(db)
    return await service.list_iocs(
        threat_id=threat_id,
        ioc_type=ioc_type,
        page=page,
        page_size=page_size,
    )


@ioc_router.post(
    "",
    response_model=IOCResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new IOC",
)
async def create_ioc(
    payload: IOCCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> IOCResponse:
    """Create a new IOC linked to a threat."""
    service = IOCService(db)
    return await service.create_ioc(payload)
