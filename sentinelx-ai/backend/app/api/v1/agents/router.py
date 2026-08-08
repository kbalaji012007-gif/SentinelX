"""
SentinelX AI – Endpoint Agent API Router
Provides enrollment, heartbeat, telemetry ingestion, agent management, and statistics endpoints.
Enforces Agent authentication for telemetry/heartbeat and RBAC for administrative actions.
"""

from uuid import UUID
from typing import Annotated, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole
from app.models.user import User
from app.schemas.agent_schema import (
    AgentEnrollRequest,
    AgentEnrollResponse,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentTelemetryCreate,
    AgentTelemetryBatchCreate,
    EndpointAgentResponse,
    EndpointAgentListResponse,
    EndpointAgentStatsResponse,
    EndpointDetailsResponse,
    AgentTelemetryListResponse,
    AgentTelemetryResponse,
)
from app.services.agent_service import AgentService
from app.core.exceptions import EntityNotFoundError, ValidationError

router = APIRouter(prefix="/agents", tags=["Endpoint Agents"])

# RBAC permissions
_READERS = ["Super Administrator", "Administrator", "SOC Manager", "SOC Analyst", "Threat Hunter", "Incident Responder", "Auditor", "Read Only", "Admin", "Manager", "Analyst"]
_ADMINS = ["Super Administrator", "Administrator", "SOC Manager", "Admin", "Manager"]


# ── Agent Authentication & Ingestion Endpoints ───────────────────────────────

@router.post(
    "/enroll",
    response_model=AgentEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll endpoint agent",
)
async def enroll_agent(
    payload: AgentEnrollRequest,
    db: AsyncSession = Depends(get_db),
) -> AgentEnrollResponse:
    """
    Enroll a new Windows endpoint telemetry agent or re-enroll an existing one.
    Establishes agent identity and returns a secure authentication token.
    """
    service = AgentService(db)
    return await service.enroll_agent(payload)


@router.post(
    "/heartbeat",
    response_model=AgentHeartbeatResponse,
    status_code=status.HTTP_200_OK,
    summary="Agent status heartbeat",
)
@router.post(
    "/{agent_id_path}/heartbeat",
    response_model=AgentHeartbeatResponse,
    status_code=status.HTTP_200_OK,
    summary="Agent status heartbeat",
)
async def agent_heartbeat(
    payload: AgentHeartbeatRequest,
    agent_id_path: Optional[str] = None,
    authorization: Annotated[Optional[str], Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> AgentHeartbeatResponse:
    """
    Process periodic agent heartbeat to keep endpoint status Online.
    """
    service = AgentService(db)
    if agent_id_path:
        payload.agent_id = agent_id_path

    # Authenticate via header if token provided
    if authorization:
        await service.authenticate_agent(authorization)

    return await service.process_heartbeat(payload)


@router.post(
    "/telemetry",
    response_model=dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest endpoint telemetry batch",
)
async def ingest_telemetry(
    payload: AgentTelemetryBatchCreate,
    authorization: Annotated[Optional[str], Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Ingest endpoint telemetry batch (Windows Events, processes, network sockets, system health).
    Normalizes security events into sentinelx.log_entries and triggers threat detection.
    """
    service = AgentService(db)
    if authorization:
        await service.authenticate_agent(authorization)

    return await service.ingest_telemetry(payload)


# ── Administrative & Frontend Operations ───────────────────────────────────

@router.get(
    "/statistics",
    response_model=EndpointAgentStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Endpoint dashboard statistics",
)
async def get_agent_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> EndpointAgentStatsResponse:
    """Return dashboard metrics for total, online, offline, stale agents, and telemetry count."""
    service = AgentService(db)
    return await service.get_statistics()


@router.get(
    "",
    response_model=EndpointAgentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List enrolled endpoint agents (paginated, filterable)",
)
async def list_agents(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    agent_status: Annotated[Optional[str], Query(alias="status", description="Filter by status (Online, Offline, Stale, Disabled, Revoked)")] = None,
    search: Annotated[Optional[str], Query(description="Search agent_id, hostname, platform, or OS version")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> EndpointAgentListResponse:
    """Return a paginated list of enrolled agents with summary metrics."""
    service = AgentService(db)
    return await service.list_agents(
        page=page,
        page_size=page_size,
        status=agent_status,
        search=search,
    )


@router.get(
    "/{id_or_agent_id}",
    response_model=EndpointDetailsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get endpoint detailed view",
)
async def get_agent_details(
    id_or_agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> EndpointDetailsResponse:
    """
    Retrieve full endpoint details view (System Info, Health, Recent Telemetry,
    Security Events, Threats, Network Connections, Running Processes, Timeline).
    """
    service = AgentService(db)
    try:
        return await service.get_agent_details(id_or_agent_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail)


@router.get(
    "/{id_or_agent_id}/status",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get endpoint agent status",
)
async def get_agent_status(
    id_or_agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> dict[str, Any]:
    """Retrieve calculated health status for an agent."""
    service = AgentService(db)
    try:
        details = await service.get_agent_details(id_or_agent_id)
        return {
            "agent_id": details.agent.agent_id,
            "hostname": details.agent.hostname,
            "status": details.agent.status,
            "last_seen": details.agent.last_seen,
            "risk_score": details.risk_score,
        }
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail)


@router.get(
    "/{id_or_agent_id}/telemetry",
    response_model=AgentTelemetryListResponse,
    status_code=status.HTTP_200_OK,
    summary="List telemetry records for a specific agent",
)
async def get_agent_telemetry(
    id_or_agent_id: str,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    event_type: Annotated[Optional[str], Query()] = None,
    severity: Annotated[Optional[str], Query()] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> AgentTelemetryListResponse:
    """Fetch paginated raw telemetry records submitted by an agent."""
    service = AgentService(db)
    agent = await service._resolve_agent(id_or_agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{id_or_agent_id}' not found")

    skip = (page - 1) * page_size
    records = await service.telemetry_repo.get_by_agent_id(
        agent.id, skip=skip, limit=page_size, event_type=event_type, severity=severity
    )
    total = await service.telemetry_repo.count_by_agent_id(agent.id, event_type=event_type, severity=severity)

    items = [AgentTelemetryResponse.model_validate(r) for r in records]
    return AgentTelemetryListResponse(total=total, page=page, page_size=page_size, items=items)


@router.post(
    "/{id_or_agent_id}/disable",
    response_model=EndpointAgentResponse,
    status_code=status.HTTP_200_OK,
    summary="Disable an endpoint agent (Admin/Manager only)",
)
async def disable_agent(
    id_or_agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMINS)),
) -> EndpointAgentResponse:
    """Disable agent authorization — telemetry and heartbeats from this agent will be rejected."""
    service = AgentService(db)
    try:
        return await service.disable_agent(id_or_agent_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail)


@router.post(
    "/{id_or_agent_id}/revoke",
    response_model=EndpointAgentResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke an endpoint agent (Admin/Manager only)",
)
async def revoke_agent(
    id_or_agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMINS)),
) -> EndpointAgentResponse:
    """Revoke agent enrollment authorization permanently."""
    service = AgentService(db)
    try:
        return await service.revoke_agent(id_or_agent_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.detail)
