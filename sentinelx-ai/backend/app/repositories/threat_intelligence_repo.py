"""
SentinelX AI – Threat Intelligence Repositories
Data access layer for threat feeds, IOC feeds, reputation, MITRE ATT&CK, and threat cache.
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import Sequence
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intelligence import (
    ThreatFeed,
    IOCFeed,
    IOCReputation,
    MitreTechnique,
    ThreatCache,
)
from app.repositories.base_repo import BaseRepository


class ThreatFeedRepository(BaseRepository[ThreatFeed]):
    """Repository managing ThreatFeed entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ThreatFeed, session)

    async def get_by_name(self, feed_name: str) -> ThreatFeed | None:
        """Fetch threat feed by unique feed_name."""
        result = await self.session.execute(
            select(ThreatFeed).where(ThreatFeed.feed_name == feed_name)
        )
        return result.scalar_one_or_none()

    async def list_feeds(
        self,
        skip: int = 0,
        limit: int = 100,
        status: str | None = None,
        feed_type: str | None = None,
    ) -> Sequence[ThreatFeed]:
        """Fetch paginated list of threat feeds with optional status and type filters."""
        stmt = select(ThreatFeed)
        if status:
            stmt = stmt.where(ThreatFeed.status == status)
        if feed_type:
            stmt = stmt.where(ThreatFeed.feed_type == feed_type)
        
        stmt = stmt.order_by(ThreatFeed.feed_name).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_feeds(
        self,
        status: str | None = None,
        feed_type: str | None = None,
    ) -> int:
        """Count threat feeds with optional filters."""
        stmt = select(func.count(ThreatFeed.id))
        if status:
            stmt = stmt.where(ThreatFeed.status == status)
        if feed_type:
            stmt = stmt.where(ThreatFeed.feed_type == feed_type)
        result = await self.session.execute(stmt)
        return result.scalar() or 0


class IOCRepository(BaseRepository[IOCFeed]):
    """Repository managing IOCFeed and IOCReputation entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(IOCFeed, session)

    async def list_iocs(
        self,
        skip: int = 0,
        limit: int = 100,
        ioc_type: str | None = None,
        severity: str | None = None,
        feed_id: UUID | None = None,
        search: str | None = None,
    ) -> Sequence[IOCFeed]:
        """Fetch paginated list of IOC items with optional filters."""
        stmt = select(IOCFeed).options(selectinload(IOCFeed.feed))

        if ioc_type:
            stmt = stmt.where(IOCFeed.ioc_type == ioc_type)
        if severity:
            stmt = stmt.where(IOCFeed.severity == severity)
        if feed_id:
            stmt = stmt.where(IOCFeed.feed_id == feed_id)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    IOCFeed.value.ilike(pattern),
                    IOCFeed.threat_type.ilike(pattern),
                )
            )

        stmt = stmt.order_by(IOCFeed.last_seen.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_iocs(
        self,
        ioc_type: str | None = None,
        severity: str | None = None,
        feed_id: UUID | None = None,
        search: str | None = None,
    ) -> int:
        """Count total IOC items matching filters."""
        stmt = select(func.count(IOCFeed.id))

        if ioc_type:
            stmt = stmt.where(IOCFeed.ioc_type == ioc_type)
        if severity:
            stmt = stmt.where(IOCFeed.severity == severity)
        if feed_id:
            stmt = stmt.where(IOCFeed.feed_id == feed_id)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    IOCFeed.value.ilike(pattern),
                    IOCFeed.threat_type.ilike(pattern),
                )
            )

        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def get_by_value(self, value: str) -> IOCFeed | None:
        """Fetch single IOC feed item by exact value."""
        result = await self.session.execute(
            select(IOCFeed).options(selectinload(IOCFeed.feed)).where(IOCFeed.value == value)
        )
        return result.scalar_one_or_none()

    async def get_reputation(self, ioc_value: str) -> IOCReputation | None:
        """Fetch IOC reputation details by value."""
        result = await self.session.execute(
            select(IOCReputation).where(IOCReputation.ioc_value == ioc_value)
        )
        return result.scalar_one_or_none()

    async def upsert_reputation(
        self,
        ioc_value: str,
        ioc_type: str,
        reputation_score: int,
        verdict: str,
        threat_category: str | None = None,
        details: dict | None = None,
    ) -> IOCReputation:
        """Create or update reputation entry for an IOC."""
        existing = await self.get_reputation(ioc_value)
        if existing:
            existing.reputation_score = reputation_score
            existing.verdict = verdict
            if threat_category:
                existing.threat_category = threat_category
            if details:
                existing.details = details
            existing.source_count += 1
            existing.last_analyzed_at = datetime.now(timezone.utc)
            return existing

        rep = IOCReputation(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            reputation_score=reputation_score,
            verdict=verdict,
            threat_category=threat_category,
            details=details or {},
            source_count=1,
            last_analyzed_at=datetime.now(timezone.utc),
        )
        self.session.add(rep)
        return rep


class MitreRepository(BaseRepository[MitreTechnique]):
    """Repository managing MitreTechnique entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(MitreTechnique, session)

    async def get_by_technique_id(self, technique_id: str) -> MitreTechnique | None:
        """Fetch MITRE Technique by unique ID (e.g. T1059.001)."""
        result = await self.session.execute(
            select(MitreTechnique).where(MitreTechnique.technique_id == technique_id)
        )
        return result.scalar_one_or_none()

    async def list_techniques(
        self,
        skip: int = 0,
        limit: int = 100,
        tactic: str | None = None,
        search: str | None = None,
    ) -> Sequence[MitreTechnique]:
        """Fetch paginated list of MITRE techniques with optional tactic or search filter."""
        stmt = select(MitreTechnique)

        if tactic:
            stmt = stmt.where(MitreTechnique.tactic.ilike(f"%{tactic}%"))
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    MitreTechnique.technique_id.ilike(pattern),
                    MitreTechnique.name.ilike(pattern),
                    MitreTechnique.description.ilike(pattern),
                )
            )

        stmt = stmt.order_by(MitreTechnique.technique_id).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_techniques(
        self,
        tactic: str | None = None,
        search: str | None = None,
    ) -> int:
        """Count total MITRE techniques matching filters."""
        stmt = select(func.count(MitreTechnique.id))

        if tactic:
            stmt = stmt.where(MitreTechnique.tactic.ilike(f"%{tactic}%"))
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    MitreTechnique.technique_id.ilike(pattern),
                    MitreTechnique.name.ilike(pattern),
                    MitreTechnique.description.ilike(pattern),
                )
            )

        result = await self.session.execute(stmt)
        return result.scalar() or 0


class ThreatCacheRepository(BaseRepository[ThreatCache]):
    """Repository managing ThreatCache entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ThreatCache, session)

    async def get_valid_cache(self, query_key: str) -> ThreatCache | None:
        """Retrieve valid (unexpired) cached threat response."""
        now = datetime.now(timezone.utc)
        result = await self.session.execute(
            select(ThreatCache).where(
                and_(
                    ThreatCache.query_key == query_key,
                    ThreatCache.expires_at > now,
                )
            )
        )
        return result.scalar_one_or_none()

    async def set_cache(
        self,
        query_key: str,
        query_type: str,
        response_data: dict,
        ttl_seconds: int = 3600,
    ) -> ThreatCache:
        """Store or update response in threat intelligence cache."""
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=timezone.utc)

        existing = await self.get_by_key(query_key)
        if existing:
            existing.query_type = query_type
            existing.response_data = response_data
            existing.ttl_seconds = ttl_seconds
            existing.expires_at = expires_at
            return existing

        cache = ThreatCache(
            query_key=query_key,
            query_type=query_type,
            response_data=response_data,
            ttl_seconds=ttl_seconds,
            expires_at=expires_at,
        )
        self.session.add(cache)
        return cache

    async def get_by_key(self, query_key: str) -> ThreatCache | None:
        """Fetch cache entry by key regardless of expiration."""
        result = await self.session.execute(
            select(ThreatCache).where(ThreatCache.query_key == query_key)
        )
        return result.scalar_one_or_none()

    async def count_total_cache(self) -> int:
        """Count total cache entries."""
        result = await self.session.execute(select(func.count(ThreatCache.id)))
        return result.scalar() or 0

    async def count_valid_cache(self) -> int:
        """Count valid unexpired cache entries."""
        now = datetime.now(timezone.utc)
        result = await self.session.execute(
            select(func.count(ThreatCache.id)).where(ThreatCache.expires_at > now)
        )
        return result.scalar() or 0

    async def list_recent_cache_entries(self, limit: int = 20) -> Sequence[ThreatCache]:
        """List recently stored cache entries."""
        result = await self.session.execute(
            select(ThreatCache).order_by(ThreatCache.created_at.desc()).limit(limit)
        )
        return result.scalars().all()

