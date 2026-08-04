"""
SentinelX AI – Log Collection Repository
Data access layer for sentinelx.log_sources and sentinelx.log_entries.
"""

from uuid import UUID
from typing import Sequence
from datetime import datetime

from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.log import LogSource, LogEntry
from app.repositories.base_repo import BaseRepository


class LogSourceRepository(BaseRepository[LogSource]):
    """Repository managing LogSource entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(LogSource, session)

    async def get_by_name(self, name: str) -> LogSource | None:
        """Fetch a log source by exact name match."""
        result = await self.session.execute(
            select(LogSource).where(LogSource.name == name)
        )
        return result.scalar_one_or_none()

    async def get_by_status(
        self,
        status: str,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[LogSource]:
        """Fetch log sources filtered by status."""
        result = await self.session.execute(
            select(LogSource)
            .where(LogSource.status == status)
            .order_by(LogSource.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_active_sources(self) -> Sequence[LogSource]:
        """Fetch all active log sources ordered by last_seen descending."""
        result = await self.session.execute(
            select(LogSource)
            .where(LogSource.status == "Active")
            .order_by(LogSource.last_seen.desc().nullslast())
        )
        return result.scalars().all()

    async def update_last_seen(
        self,
        source_id: UUID,
        seen_at: datetime,
    ) -> LogSource | None:
        """Update the last_seen timestamp for a log source."""
        return await self.update(source_id, {"last_seen": seen_at})

    async def get_list(
        self,
        skip: int = 0,
        limit: int = 25,
        source_type: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> Sequence[LogSource]:
        """Paginated, filterable log source list query."""
        stmt = select(LogSource)

        filters = []
        if source_type:
            filters.append(LogSource.source_type == source_type)
        if status:
            filters.append(LogSource.status == status)
        if search:
            pattern = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(LogSource.name).like(pattern),
                    func.lower(LogSource.vendor).like(pattern),
                    func.lower(LogSource.hostname).like(pattern),
                    func.lower(LogSource.description).like(pattern),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        stmt = stmt.order_by(LogSource.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_filtered(
        self,
        source_type: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> int:
        """Count log sources matching given filters."""
        stmt = select(func.count()).select_from(LogSource)

        filters = []
        if source_type:
            filters.append(LogSource.source_type == source_type)
        if status:
            filters.append(LogSource.status == status)
        if search:
            pattern = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(LogSource.name).like(pattern),
                    func.lower(LogSource.vendor).like(pattern),
                    func.lower(LogSource.hostname).like(pattern),
                    func.lower(LogSource.description).like(pattern),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        result = await self.session.execute(stmt)
        return result.scalar_one() or 0


class LogEntryRepository(BaseRepository[LogEntry]):
    """Repository managing LogEntry entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(LogEntry, session)

    async def get_by_source_id(
        self,
        source_id: UUID,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[LogEntry]:
        """Fetch paginated log entries for a specific source."""
        result = await self.session.execute(
            select(LogEntry)
            .where(LogEntry.source_id == source_id)
            .order_by(LogEntry.event_timestamp.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_asset_id(
        self,
        asset_id: UUID,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[LogEntry]:
        """Fetch paginated log entries for a specific asset."""
        result = await self.session.execute(
            select(LogEntry)
            .where(LogEntry.asset_id == asset_id)
            .order_by(LogEntry.event_timestamp.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_time_range(
        self,
        start: datetime,
        end: datetime,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[LogEntry]:
        """Fetch log entries within a given time range."""
        result = await self.session.execute(
            select(LogEntry)
            .where(
                and_(
                    LogEntry.event_timestamp >= start,
                    LogEntry.event_timestamp <= end,
                )
            )
            .order_by(LogEntry.event_timestamp.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_level(
        self,
        log_level: str,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[LogEntry]:
        """Fetch log entries filtered by log level."""
        result = await self.session.execute(
            select(LogEntry)
            .where(LogEntry.log_level == log_level)
            .order_by(LogEntry.event_timestamp.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_correlation_id(
        self,
        correlation_id: UUID,
    ) -> Sequence[LogEntry]:
        """Fetch all log entries sharing a correlation ID."""
        result = await self.session.execute(
            select(LogEntry)
            .where(LogEntry.correlation_id == correlation_id)
            .order_by(LogEntry.event_timestamp.asc())
        )
        return result.scalars().all()

    async def count_by_level(self) -> dict[str, int]:
        """Aggregate log entry counts grouped by log level."""
        result = await self.session.execute(
            select(LogEntry.log_level, func.count())
            .group_by(LogEntry.log_level)
        )
        return {row[0]: row[1] for row in result.all()}

    async def search_entries(
        self,
        search: str,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[LogEntry]:
        """Search log entries by message, username, or event_type."""
        pattern = f"%{search.lower()}%"
        result = await self.session.execute(
            select(LogEntry)
            .where(
                or_(
                    func.lower(LogEntry.message).like(pattern),
                    func.lower(LogEntry.username).like(pattern),
                    func.lower(LogEntry.event_type).like(pattern),
                )
            )
            .order_by(LogEntry.event_timestamp.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_list(
        self,
        skip: int = 0,
        limit: int = 25,
        source_id: UUID | None = None,
        asset_id: UUID | None = None,
        log_level: str | None = None,
        event_type: str | None = None,
        category: str | None = None,
        search: str | None = None,
    ) -> Sequence[LogEntry]:
        """Paginated, filterable log entry list query."""
        stmt = select(LogEntry).options(selectinload(LogEntry.source))

        filters = []
        if source_id:
            filters.append(LogEntry.source_id == source_id)
        if asset_id:
            filters.append(LogEntry.asset_id == asset_id)
        if log_level:
            filters.append(LogEntry.log_level == log_level)
        if event_type:
            filters.append(LogEntry.event_type == event_type)
        if category:
            filters.append(LogEntry.category == category)
        if search:
            pattern = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(LogEntry.message).like(pattern),
                    func.lower(LogEntry.username).like(pattern),
                    func.lower(LogEntry.event_type).like(pattern),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        stmt = stmt.order_by(LogEntry.event_timestamp.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_filtered(
        self,
        source_id: UUID | None = None,
        asset_id: UUID | None = None,
        log_level: str | None = None,
        event_type: str | None = None,
        category: str | None = None,
        search: str | None = None,
    ) -> int:
        """Count log entries matching given filters."""
        stmt = select(func.count()).select_from(LogEntry)

        filters = []
        if source_id:
            filters.append(LogEntry.source_id == source_id)
        if asset_id:
            filters.append(LogEntry.asset_id == asset_id)
        if log_level:
            filters.append(LogEntry.log_level == log_level)
        if event_type:
            filters.append(LogEntry.event_type == event_type)
        if category:
            filters.append(LogEntry.category == category)
        if search:
            pattern = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(LogEntry.message).like(pattern),
                    func.lower(LogEntry.username).like(pattern),
                    func.lower(LogEntry.event_type).like(pattern),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        result = await self.session.execute(stmt)
        return result.scalar_one() or 0
