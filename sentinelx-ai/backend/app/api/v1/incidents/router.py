"""
SentinelX AI – Incident Response API Router
JWT-protected, RBAC-enforced endpoints for incidents, analyst assignments, timeline, notes, and evidence.
"""

from uuid import UUID
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole
from app.models.user import User
from app.schemas.incident_schema import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    IncidentListResponse,
    IncidentStatsResponse,
    IncidentAssignRequest,
    IncidentStatusUpdateRequest,
    IncidentTimelineResponse,
    IncidentNoteCreate,
    IncidentNoteResponse,
    IncidentEvidenceCreate,
    IncidentEvidenceResponse,
)
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incidents"])

# RBAC permissions
_READERS = ["Admin", "Manager", "Analyst", "ReadOnly"]
_WRITERS = ["Admin", "Manager", "Analyst"]
_ADMINS = ["Admin", "Manager"]


@router.get(
    "",
    response_model=IncidentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List incidents (paginated, filterable)",
)
async def list_incidents(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    priority: Annotated[str | None, Query(description="Filter by priority")] = None,
    incident_status: Annotated[str | None, Query(alias="status", description="Filter by status")] = None,
    assigned_user_id: Annotated[UUID | None, Query(description="Filter by assigned analyst UUID")] = None,
    search: Annotated[str | None, Query(description="Search title, description, or reported_by")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IncidentListResponse:
    """Return a paginated list of security incidents with optional filter parameters."""
    service = IncidentService(db)
    return await service.list_incidents(
        page=page,
        page_size=page_size,
        severity=severity,
        priority=priority,
        status=incident_status,
        assigned_user_id=assigned_user_id,
        search=search,
    )


@router.get(
    "/stats",
    response_model=IncidentStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Incident response dashboard statistics",
)
async def get_incident_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IncidentStatsResponse:
    """Return metrics: Open, Critical, Assigned To Me, Recently Resolved counts."""
    service = IncidentService(db)
    return await service.get_stats(current_user_id=current_user.id)


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get full incident detail",
)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IncidentResponse:
    """Retrieve full incident details including nested timeline, notes, and evidence."""
    service = IncidentService(db)
    incident = await service.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return incident


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a security incident",
)
async def create_incident(
    payload: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> IncidentResponse:
    """Create a new incident ticket."""
    service = IncidentService(db)
    creator_name = f"{current_user.first_name} {current_user.last_name}"
    return await service.create_incident(payload, created_by_name=creator_name)


@router.put(
    "/{incident_id}",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Update incident details",
)
async def update_incident(
    incident_id: UUID,
    payload: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> IncidentResponse:
    """Update fields of an existing incident."""
    service = IncidentService(db)
    updater_name = f"{current_user.first_name} {current_user.last_name}"
    incident = await service.update_incident(incident_id, payload, updated_by_name=updater_name)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return incident


@router.delete(
    "/{incident_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an incident (Admin/Manager only)",
)
async def delete_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMINS)),
) -> None:
    """Permanently delete an incident and associated items."""
    service = IncidentService(db)
    deleted = await service.delete_incident(incident_id, deleted_by=str(current_user.id))
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )


@router.post(
    "/{incident_id}/assign",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Assign analyst to incident",
)
async def assign_analyst(
    incident_id: UUID,
    payload: IncidentAssignRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> IncidentResponse:
    """Assign or unassign an analyst to handle this incident."""
    service = IncidentService(db)
    assigner_name = f"{current_user.first_name} {current_user.last_name}"
    incident = await service.assign_analyst(
        incident_id=incident_id,
        user_id=payload.assigned_user_id,
        assigned_by_name=assigner_name,
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return incident


@router.post(
    "/{incident_id}/status",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Update incident status",
)
async def update_status(
    incident_id: UUID,
    payload: IncidentStatusUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> IncidentResponse:
    """Transition incident status (Open, In Progress, Contained, Resolved, Closed)."""
    service = IncidentService(db)
    updater_name = f"{current_user.first_name} {current_user.last_name}"
    incident = await service.update_status(
        incident_id=incident_id,
        status_val=payload.status,
        updated_by_name=updater_name,
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return incident


@router.post(
    "/{incident_id}/notes",
    response_model=IncidentNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add investigation note to incident",
)
async def add_note(
    incident_id: UUID,
    payload: IncidentNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> IncidentNoteResponse:
    """Add an analyst note to the incident audit trail."""
    service = IncidentService(db)
    author_name = f"{current_user.first_name} {current_user.last_name}"
    return await service.add_note(
        incident_id=incident_id,
        payload=payload,
        author_id=current_user.id,
        author_name=author_name,
    )


@router.get(
    "/{incident_id}/timeline",
    response_model=list[IncidentTimelineResponse],
    status_code=status.HTTP_200_OK,
    summary="Get incident timeline log",
)
async def get_timeline(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> list[IncidentTimelineResponse]:
    """Retrieve full audit timeline for an incident."""
    service = IncidentService(db)
    return await service.get_timeline(incident_id)


@router.get(
    "/{incident_id}/evidence",
    response_model=list[IncidentEvidenceResponse],
    status_code=status.HTTP_200_OK,
    summary="Get attached evidence files",
)
async def get_evidence(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> list[IncidentEvidenceResponse]:
    """Retrieve attached evidence file records."""
    service = IncidentService(db)
    return await service.get_evidence(incident_id)


@router.post(
    "/{incident_id}/evidence",
    response_model=IncidentEvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Attach evidence file record",
)
async def attach_evidence(
    incident_id: UUID,
    payload: IncidentEvidenceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> IncidentEvidenceResponse:
    """Attach evidence file record to incident."""
    service = IncidentService(db)
    uploader_name = f"{current_user.first_name} {current_user.last_name}"
    return await service.add_evidence(
        incident_id=incident_id,
        payload=payload,
        uploader_id=current_user.id,
        uploader_name=uploader_name,
    )
