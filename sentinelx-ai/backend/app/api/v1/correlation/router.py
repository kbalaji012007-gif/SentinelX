"""
SentinelX AI – Threat Correlation API Router
JWT-protected, RBAC-enforced endpoints for Threat Correlation Engine events, attack chains, MITRE mappings, timeline, and telemetry statistics.
"""

from uuid import UUID
from typing import Annotated
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole
from app.models.user import User
from app.schemas.correlation_schema import (
    ThreatCorrelationListResponse,
    ThreatCorrelationResponse,
    CorrelationRunRequest,
    CorrelationRunResponse,
    AttackChainResponse,
    AttackChainListResponse,
    MitreMappingListResponse,
    CorrelationTimelineResponse,
    CorrelationStatsResponse,
    CorrelationGraphResponse,
)
from app.services.correlation_engine import CorrelationEngineService

router = APIRouter(prefix="/correlation", tags=["Threat Correlation"])

# RBAC roles
_READERS = ["Admin", "Manager", "Analyst", "ReadOnly"]
_WRITERS = ["Admin", "Manager", "Analyst"]


# ────────────────────────────────────────────────────────────────────────
# Correlation Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=ThreatCorrelationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List correlated security events (paginated, filterable)",
)
async def list_correlations(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    correlation_type: Annotated[str | None, Query(description="Filter by correlation type")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    asset_id: Annotated[UUID | None, Query(description="Filter by target asset UUID")] = None,
    incident_id: Annotated[UUID | None, Query(description="Filter by incident UUID")] = None,
    threat_id: Annotated[UUID | None, Query(description="Filter by threat UUID")] = None,
    search: Annotated[str | None, Query(description="Search correlation title or IOC value")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ThreatCorrelationListResponse:
    """Retrieve paginated list of correlated security events across threats, incidents, assets, logs, and IOCs."""
    engine = CorrelationEngineService(db)
    return await engine.list_correlations(
        page=page,
        page_size=page_size,
        correlation_type=correlation_type,
        severity=severity,
        asset_id=asset_id,
        incident_id=incident_id,
        threat_id=threat_id,
        search=search,
    )


@router.post(
    "/run",
    response_model=CorrelationRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger Correlation Engine execution pass",
)
async def run_correlation_engine(
    payload: CorrelationRunRequest = CorrelationRunRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> CorrelationRunResponse:
    """Trigger real-time correlation pass evaluating IOCs, logs, assets, incidents, and MITRE techniques."""
    engine = CorrelationEngineService(db)
    return await engine.run_full_correlation(
        time_window_hours=payload.time_window_hours,
        min_confidence=payload.min_confidence,
    )


@router.get(
    "/statistics",
    response_model=CorrelationStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Correlation Engine telemetry & risk/confidence statistics",
)
async def get_correlation_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> CorrelationStatsResponse:
    """Return overview metrics, average risk scores, average confidence scores, and type distribution."""
    engine = CorrelationEngineService(db)
    return await engine.get_statistics()


@router.get(
    "/timeline",
    response_model=CorrelationTimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Correlation events chronological timeline",
)
async def get_correlation_timeline(
    limit: Annotated[int, Query(ge=1, le=100, description="Max timeline events to return")] = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> CorrelationTimelineResponse:
    """Retrieve recent correlation events ordered chronologically for UI timeline view."""
    engine = CorrelationEngineService(db)
    return await engine.get_timeline(limit=limit)


@router.get(
    "/graph",
    response_model=CorrelationGraphResponse,
    status_code=status.HTTP_200_OK,
    summary="Correlation visualization graph (nodes & edges)",
)
async def get_correlation_graph(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> CorrelationGraphResponse:
    """Retrieve nodes and edges dataset representing entity correlations for interactive graph UI."""
    engine = CorrelationEngineService(db)
    return await engine.generate_correlation_graph()


@router.get(
    "/mitre",
    response_model=MitreMappingListResponse,
    status_code=status.HTTP_200_OK,
    summary="List MITRE ATT&CK technique mappings",
)
async def list_mitre_mappings(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> MitreMappingListResponse:
    """Retrieve paginated MITRE ATT&CK technique mappings across correlated entities."""
    engine = CorrelationEngineService(db)
    return await engine.list_mitre_mappings(page=page, page_size=page_size)


@router.get(
    "/attack-chain/list",
    response_model=AttackChainListResponse,
    status_code=status.HTTP_200_OK,
    summary="List active attack chains",
)
async def list_attack_chains(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> AttackChainListResponse:
    """Retrieve paginated list of active multi-stage attack chains."""
    engine = CorrelationEngineService(db)
    return await engine.list_attack_chains(page=page, page_size=page_size)


@router.get(
    "/attack-chain/{id}",
    response_model=AttackChainResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Attack Chain details by UUID",
)
async def get_attack_chain_by_id(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> AttackChainResponse:
    """Retrieve detailed multi-stage attack chain by UUID."""
    engine = CorrelationEngineService(db)
    try:
        return await engine.get_attack_chain(id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.get(
    "/{id}",
    response_model=ThreatCorrelationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get correlation event details by UUID",
)
async def get_correlation_by_id(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ThreatCorrelationResponse:
    """Retrieve detailed correlation event by UUID including evidence, risk score, and confidence score."""
    engine = CorrelationEngineService(db)
    try:
        return await engine.get_correlation_by_id(id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
