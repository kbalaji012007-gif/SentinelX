"""
SentinelX AI – Threat Intelligence Service Layer
Business logic for threat feeds, IOC feeds, reputation, MITRE ATT&CK, and statistics.
"""

from uuid import UUID
from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.repositories.threat_intelligence_repo import (
    ThreatFeedRepository,
    IOCRepository,
    MitreRepository,
    ThreatCacheRepository,
)
from app.schemas.threat_intelligence_schema import (
    ThreatFeedCreate,
    ThreatFeedUpdate,
    ThreatFeedListResponse,
    ThreatFeedResponse,
    IOCFeedCreate,
    IOCFeedUpdate,
    IOCFeedListResponse,
    IOCFeedResponse,
    IOCReputationResponse,
    MitreTechniqueCreate,
    MitreTechniqueListResponse,
    MitreTechniqueResponse,
    ThreatIntelStatsResponse,
)
from app.models.threat_intelligence import ThreatFeed, IOCFeed, MitreTechnique


class ThreatIntelService:
    """Service orchestrating Threat Intelligence database operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.feed_repo = ThreatFeedRepository(session)
        self.ioc_repo = IOCRepository(session)
        self.mitre_repo = MitreRepository(session)
        self.cache_repo = ThreatCacheRepository(session)

    # ── Threat Feeds ──────────────────────────────────────────────────

    async def list_feeds(
        self,
        page: int = 1,
        page_size: int = 25,
        status_filter: str | None = None,
        feed_type: str | None = None,
    ) -> ThreatFeedListResponse:
        """Fetch paginated list of threat feeds."""
        skip = (page - 1) * page_size
        items = await self.feed_repo.list_feeds(
            skip=skip, limit=page_size, status=status_filter, feed_type=feed_type
        )
        total = await self.feed_repo.count_feeds(status=status_filter, feed_type=feed_type)

        return ThreatFeedListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[ThreatFeedResponse.model_validate(item) for item in items],
        )

    async def create_feed(self, payload: ThreatFeedCreate) -> ThreatFeedResponse:
        """Register a new threat feed."""
        existing = await self.feed_repo.get_by_name(payload.feed_name)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Threat feed with name '{payload.feed_name}' already exists",
            )
        feed = await self.feed_repo.create(payload.model_dump())
        return ThreatFeedResponse.model_validate(feed)

    # ── IOC Items ─────────────────────────────────────────────────────

    async def list_iocs(
        self,
        page: int = 1,
        page_size: int = 25,
        ioc_type: str | None = None,
        severity: str | None = None,
        feed_id: UUID | None = None,
        search: str | None = None,
    ) -> IOCFeedListResponse:
        """Fetch paginated list of IOC items."""
        skip = (page - 1) * page_size
        items = await self.ioc_repo.list_iocs(
            skip=skip,
            limit=page_size,
            ioc_type=ioc_type,
            severity=severity,
            feed_id=feed_id,
            search=search,
        )
        total = await self.ioc_repo.count_iocs(
            ioc_type=ioc_type, severity=severity, feed_id=feed_id, search=search
        )

        return IOCFeedListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[IOCFeedResponse.model_validate(item) for item in items],
        )

    async def create_ioc(self, payload: IOCFeedCreate) -> IOCFeedResponse:
        """Add a new IOC item."""
        if payload.feed_id:
            feed = await self.feed_repo.get_by_id(payload.feed_id)
            if not feed:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Feed ID {payload.feed_id} not found",
                )

        ioc = await self.ioc_repo.create(payload.model_dump())

        # Update total indicators count on feed if attached
        if payload.feed_id:
            feed = await self.feed_repo.get_by_id(payload.feed_id)
            if feed:
                feed.total_indicators += 1

        return IOCFeedResponse.model_validate(ioc)

    # ── MITRE ATT&CK ──────────────────────────────────────────────────

    async def list_mitre_techniques(
        self,
        page: int = 1,
        page_size: int = 25,
        tactic: str | None = None,
        search: str | None = None,
    ) -> MitreTechniqueListResponse:
        """Fetch paginated list of MITRE ATT&CK techniques."""
        skip = (page - 1) * page_size
        items = await self.mitre_repo.list_techniques(
            skip=skip, limit=page_size, tactic=tactic, search=search
        )
        total = await self.mitre_repo.count_techniques(tactic=tactic, search=search)

        return MitreTechniqueListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[MitreTechniqueResponse.model_validate(item) for item in items],
        )

    # ── Statistics ────────────────────────────────────────────────────

    async def get_statistics(self) -> ThreatIntelStatsResponse:
        """Compute Threat Intelligence overview statistics."""
        total_feeds = await self.feed_repo.count_feeds()
        active_feeds = await self.feed_repo.count_feeds(status="Active")
        total_iocs = await self.ioc_repo.count_iocs()

        # Count IOCs by severity
        iocs_by_severity = {}
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            cnt = await self.ioc_repo.count_iocs(severity=sev)
            if cnt > 0:
                iocs_by_severity[sev] = cnt

        # Count IOCs by type
        iocs_by_type = {}
        for t in ["IP", "Domain", "URL", "FileHash-MD5", "FileHash-SHA256", "Email"]:
            cnt = await self.ioc_repo.count_iocs(ioc_type=t)
            if cnt > 0:
                iocs_by_type[t] = cnt

        mitre_count = await self.mitre_repo.count_techniques()

        return ThreatIntelStatsResponse(
            total_feeds=total_feeds,
            active_feeds=active_feeds,
            total_iocs=total_iocs,
            iocs_by_type=iocs_by_type,
            iocs_by_severity=iocs_by_severity,
            mitre_technique_count=mitre_count,
            cached_query_count=0,
        )
