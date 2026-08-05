"""
SentinelX AI – Threat Intelligence API Router
JWT-protected, RBAC-enforced endpoints for threat feeds, IOCs, MITRE ATT&CK techniques, and intelligence statistics.
"""

from uuid import UUID
from typing import Annotated
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole
from app.models.user import User
from app.schemas.threat_intelligence_schema import (
    ThreatFeedCreate,
    ThreatFeedResponse,
    ThreatFeedListResponse,
    IOCFeedCreate,
    IOCFeedResponse,
    IOCFeedListResponse,
    MitreTechniqueListResponse,
    ThreatIntelStatsResponse,
)
from app.services.threat_intelligence_service import ThreatIntelService

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])

# RBAC roles
_READERS = ["Admin", "Manager", "Analyst", "ReadOnly"]
_WRITERS = ["Admin", "Manager", "Analyst"]


# ────────────────────────────────────────────────────────────────────────
# Threat Feed Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/feeds",
    response_model=ThreatFeedListResponse,
    status_code=status.HTTP_200_OK,
    summary="List threat feeds (paginated, filterable)",
)
async def list_threat_feeds(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    status: Annotated[str | None, Query(description="Filter by feed status")] = None,
    feed_type: Annotated[str | None, Query(description="Filter by feed type")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ThreatFeedListResponse:
    """Retrieve paginated list of external and internal threat feeds."""
    service = ThreatIntelService(db)
    return await service.list_feeds(
        page=page, page_size=page_size, status_filter=status, feed_type=feed_type
    )


@router.post(
    "/feeds",
    response_model=ThreatFeedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new threat feed",
)
async def create_threat_feed(
    payload: ThreatFeedCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ThreatFeedResponse:
    """Register a new threat intelligence feed provider."""
    service = ThreatIntelService(db)
    return await service.create_feed(payload)


# ────────────────────────────────────────────────────────────────────────
# IOC Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/ioc",
    response_model=IOCFeedListResponse,
    status_code=status.HTTP_200_OK,
    summary="List IOC indicators (paginated, filterable)",
)
async def list_iocs(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    ioc_type: Annotated[str | None, Query(description="Filter by IOC type (IP, Domain, URL, FileHash-SHA256)")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    feed_id: Annotated[UUID | None, Query(description="Filter by feed UUID")] = None,
    search: Annotated[str | None, Query(description="Search IOC value or threat type")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IOCFeedListResponse:
    """Retrieve paginated list of Indicators of Compromise."""
    service = ThreatIntelService(db)
    return await service.list_iocs(
        page=page,
        page_size=page_size,
        ioc_type=ioc_type,
        severity=severity,
        feed_id=feed_id,
        search=search,
    )


@router.post(
    "/ioc",
    response_model=IOCFeedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a new IOC indicator",
)
async def create_ioc(
    payload: IOCFeedCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> IOCFeedResponse:
    """Add a new Indicator of Compromise to the threat intelligence engine."""
    service = ThreatIntelService(db)
    return await service.create_ioc(payload)


# ────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/mitre",
    response_model=MitreTechniqueListResponse,
    status_code=status.HTTP_200_OK,
    summary="List MITRE ATT&CK techniques",
)
async def list_mitre_techniques(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    tactic: Annotated[str | None, Query(description="Filter by tactic (e.g. Execution, Persistence)")] = None,
    search: Annotated[str | None, Query(description="Search technique ID or name")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> MitreTechniqueListResponse:
    """Retrieve paginated catalog of MITRE ATT&CK techniques and tactics."""
    service = ThreatIntelService(db)
    return await service.list_mitre_techniques(
        page=page, page_size=page_size, tactic=tactic, search=search
    )


# ────────────────────────────────────────────────────────────────────────
# Statistics Endpoint
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/stats",
    response_model=ThreatIntelStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Threat Intelligence overview statistics",
)
async def get_threat_intel_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ThreatIntelStatsResponse:
    """Return overview metrics and distributions for threat feeds and IOCs."""
    service = ThreatIntelService(db)
    return await service.get_statistics()
