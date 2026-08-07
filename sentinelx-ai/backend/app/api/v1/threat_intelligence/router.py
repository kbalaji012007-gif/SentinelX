"""
SentinelX AI – Threat Intelligence API Router
JWT-protected, RBAC-enforced endpoints for threat feeds, IOCs, MITRE ATT&CK techniques, statistics, external provider lookups, AI summaries, and cache status.
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
    IOCLookupRequest,
    IOCEnrichRequest,
    AISummaryRequest,
    IOCLookupResponse,
    ProviderStatusListResponse,
    CacheStatsResponse,
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
# External Threat Intelligence Provider Lookups
# ────────────────────────────────────────────────────────────────────────

@router.post(
    "/lookup/ip",
    response_model=IOCLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Query external providers for IP reputation",
)
async def lookup_ip_address(
    payload: IOCLookupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IOCLookupResponse:
    """Lookup IP address across VirusTotal, AbuseIPDB, Shodan, and Gemini AI."""
    service = ThreatIntelService(db)
    return await service.lookup_ip(ip=payload.value, force_refresh=payload.force_refresh)


@router.post(
    "/lookup/domain",
    response_model=IOCLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Query external providers for Domain reputation",
)
async def lookup_domain_name(
    payload: IOCLookupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IOCLookupResponse:
    """Lookup Domain across VirusTotal and Gemini AI."""
    service = ThreatIntelService(db)
    return await service.lookup_domain(domain=payload.value, force_refresh=payload.force_refresh)


@router.post(
    "/lookup/url",
    response_model=IOCLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Query external providers for URL reputation",
)
async def lookup_url_link(
    payload: IOCLookupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IOCLookupResponse:
    """Lookup URL link across VirusTotal and Gemini AI."""
    service = ThreatIntelService(db)
    return await service.lookup_url(url=payload.value, force_refresh=payload.force_refresh)


@router.post(
    "/lookup/hash",
    response_model=IOCLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Query external providers for File Hash reputation",
)
async def lookup_file_hash(
    payload: IOCLookupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IOCLookupResponse:
    """Lookup File Hash (MD5, SHA-1, SHA-256) across VirusTotal and Gemini AI."""
    service = ThreatIntelService(db)
    return await service.lookup_hash(file_hash=payload.value, force_refresh=payload.force_refresh)


@router.post(
    "/lookup/host",
    response_model=IOCLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Query external providers for Host details",
)
async def lookup_host_details(
    payload: IOCLookupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IOCLookupResponse:
    """Lookup Host details across Shodan, VirusTotal, and Gemini AI."""
    service = ThreatIntelService(db)
    return await service.lookup_host(host=payload.value, force_refresh=payload.force_refresh)


@router.post(
    "/enrich",
    response_model=IOCLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Enrich IOC with live external provider analysis & AI synthesis",
)
async def enrich_ioc_indicator(
    payload: IOCEnrichRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> IOCLookupResponse:
    """Generic IOC enrichment endpoint for any indicator type."""
    service = ThreatIntelService(db)
    return await service.enrich_ioc(
        ioc_type=payload.ioc_type,
        value=payload.value,
        force_refresh=payload.force_refresh,
    )


@router.post(
    "/ai-summary",
    status_code=status.HTTP_200_OK,
    summary="Generate AI threat summary and MITRE explanation",
)
async def generate_ai_summary(
    payload: AISummaryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
):
    """Generate Gemini AI threat summary, explanation, and MITRE mapping."""
    service = ThreatIntelService(db)
    return await service.generate_ai_summary(
        ioc_type=payload.ioc_type,
        value=payload.value,
        context=payload.context,
    )


@router.get(
    "/providers",
    response_model=ProviderStatusListResponse,
    status_code=status.HTTP_200_OK,
    summary="List external provider readiness & configuration status",
)
async def list_providers_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ProviderStatusListResponse:
    """Retrieve configuration readiness and supported types for all external providers."""
    service = ThreatIntelService(db)
    return await service.get_provider_statuses()


@router.get(
    "/cache",
    response_model=CacheStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Threat Intelligence cache telemetry & hit ratio",
)
async def get_cache_telemetry(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> CacheStatsResponse:
    """Retrieve cache hit statistics, entry counts, and recent query keys."""
    service = ThreatIntelService(db)
    return await service.get_cache_stats()


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
