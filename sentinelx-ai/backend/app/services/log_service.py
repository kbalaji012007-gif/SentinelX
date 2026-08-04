"""
SentinelX AI – Log Collection Service Layer
Business logic for log source management, log ingestion, search, filtering, and statistics.
Follows SOLID principles with dependency injection via constructor.
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import Any, Sequence

import structlog
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.log import LogSource, LogEntry
from app.models.asset import Asset
from app.repositories.log_repo import LogSourceRepository, LogEntryRepository
from app.schemas.log_schema import (
    LogSourceCreate,
    LogSourceUpdate,
    LogSourceResponse,
    LogSourceSummary,
    LogSourceListResponse,
    LogEntryCreate,
    LogEntryResponse,
    LogEntrySummary,
    LogEntryListResponse,
    LogEntryStatsResponse,
)
from app.core.exceptions import (
    EntityNotFoundError,
    ValidationError,
    DuplicateEntityError,
    LogIngestionError,
)

logger = structlog.get_logger()

# ── Allowed enum values for validation ────────────────────────────────
VALID_LOG_LEVELS = frozenset({"TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
VALID_SOURCE_TYPES = frozenset({
    "Syslog", "Windows Event", "Cloud Trail", "Firewall",
    "IDS/IPS", "Endpoint", "Application", "Network", "Other",
})
VALID_SOURCE_STATUSES = frozenset({"Active", "Inactive", "Error", "Maintenance"})


# ────────────────────────────────────────────────────────────────────────
# Log Source Service
# ────────────────────────────────────────────────────────────────────────

class LogSourceService:
    """
    Service encapsulating all log source lifecycle operations.
    Uses LogSourceRepository for data access and enforces business rules.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = LogSourceRepository(session)

    async def create_source(self, payload: LogSourceCreate) -> LogSourceResponse:
        """Create a new log source after validating business rules."""
        # Validate source_type
        if payload.source_type not in VALID_SOURCE_TYPES:
            raise ValidationError(
                field="source_type",
                reason=f"Invalid source type '{payload.source_type}'. "
                       f"Must be one of: {', '.join(sorted(VALID_SOURCE_TYPES))}",
            )

        # Check for duplicate name
        existing = await self.repo.get_by_name(payload.name)
        if existing:
            raise DuplicateEntityError(entity="LogSource", identifier=payload.name)

        data = payload.model_dump()
        source = await self.repo.create(data)

        logger.info(
            "log_source_created",
            source_id=str(source.id),
            name=source.name,
            source_type=source.source_type,
        )

        return LogSourceResponse.model_validate(source)

    async def update_source(
        self, source_id: UUID, payload: LogSourceUpdate
    ) -> LogSourceResponse:
        """Update an existing log source. Raises EntityNotFoundError if not found."""
        existing = await self.repo.get_by_id(source_id)
        if not existing:
            raise EntityNotFoundError(entity="LogSource", entity_id=str(source_id))

        update_data = payload.model_dump(exclude_unset=True)
        if not update_data:
            return LogSourceResponse.model_validate(existing)

        # Validate source_type if being changed
        if "source_type" in update_data and update_data["source_type"] not in VALID_SOURCE_TYPES:
            raise ValidationError(
                field="source_type",
                reason=f"Invalid source type '{update_data['source_type']}'.",
            )

        # Validate status if being changed
        if "status" in update_data and update_data["status"] not in VALID_SOURCE_STATUSES:
            raise ValidationError(
                field="status",
                reason=f"Invalid status '{update_data['status']}'.",
            )

        # Check name uniqueness if being changed
        if "name" in update_data and update_data["name"] != existing.name:
            dup = await self.repo.get_by_name(update_data["name"])
            if dup:
                raise DuplicateEntityError(entity="LogSource", identifier=update_data["name"])

        updated = await self.repo.update(source_id, update_data)

        logger.info(
            "log_source_updated",
            source_id=str(source_id),
            fields=list(update_data.keys()),
        )

        return LogSourceResponse.model_validate(updated)

    async def deactivate_source(self, source_id: UUID) -> LogSourceResponse:
        """Set a log source status to Inactive."""
        existing = await self.repo.get_by_id(source_id)
        if not existing:
            raise EntityNotFoundError(entity="LogSource", entity_id=str(source_id))

        if existing.status == "Inactive":
            logger.info("log_source_already_inactive", source_id=str(source_id))
            return LogSourceResponse.model_validate(existing)

        updated = await self.repo.update(source_id, {"status": "Inactive"})

        logger.warning(
            "log_source_deactivated",
            source_id=str(source_id),
            name=existing.name,
        )

        return LogSourceResponse.model_validate(updated)

    async def get_source(self, source_id: UUID) -> LogSourceResponse:
        """Retrieve a single log source by ID."""
        source = await self.repo.get_by_id(source_id)
        if not source:
            raise EntityNotFoundError(entity="LogSource", entity_id=str(source_id))

        logger.info("log_source_fetched", source_id=str(source_id))
        return LogSourceResponse.model_validate(source)

    async def list_sources(
        self,
        page: int = 1,
        page_size: int = 25,
        source_type: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> LogSourceListResponse:
        """Return paginated, filtered log source list."""
        skip = (page - 1) * page_size

        sources = await self.repo.get_list(
            skip=skip,
            limit=page_size,
            source_type=source_type,
            status=status,
            search=search,
        )
        total = await self.repo.count_filtered(
            source_type=source_type,
            status=status,
            search=search,
        )

        items = [LogSourceSummary.model_validate(s) for s in sources]

        logger.info(
            "log_sources_listed",
            page=page,
            page_size=page_size,
            total=total,
        )

        return LogSourceListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=items,
        )

    async def update_last_seen(
        self, source_id: UUID, seen_at: datetime | None = None
    ) -> LogSourceResponse:
        """Update the last_seen timestamp for a log source."""
        existing = await self.repo.get_by_id(source_id)
        if not existing:
            raise EntityNotFoundError(entity="LogSource", entity_id=str(source_id))

        ts = seen_at or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        updated = await self.repo.update_last_seen(source_id, ts)

        logger.info(
            "log_source_last_seen_updated",
            source_id=str(source_id),
            last_seen=ts.isoformat(),
        )

        return LogSourceResponse.model_validate(updated)


# ────────────────────────────────────────────────────────────────────────
# Log Entry Service
# ────────────────────────────────────────────────────────────────────────

class LogEntryService:
    """
    Service encapsulating log entry ingestion, search, filtering, and statistics.
    Uses LogEntryRepository and LogSourceRepository for data access.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.entry_repo = LogEntryRepository(session)
        self.source_repo = LogSourceRepository(session)

    # ── Validation helpers ────────────────────────────────────────────

    async def _validate_source_exists(self, source_id: UUID) -> LogSource:
        """Verify that the referenced log source exists and return it."""
        source = await self.source_repo.get_by_id(source_id)
        if not source:
            raise EntityNotFoundError(entity="LogSource", entity_id=str(source_id))
        return source

    async def _validate_asset_exists(self, asset_id: UUID) -> None:
        """Verify that the referenced asset exists."""
        result = await self.session.execute(
            select(Asset).where(Asset.id == asset_id)
        )
        if not result.scalar_one_or_none():
            raise EntityNotFoundError(entity="Asset", entity_id=str(asset_id))

    @staticmethod
    def _validate_log_level(log_level: str) -> None:
        """Validate that log level is an accepted value."""
        if log_level not in VALID_LOG_LEVELS:
            raise ValidationError(
                field="log_level",
                reason=f"Invalid log level '{log_level}'. "
                       f"Must be one of: {', '.join(sorted(VALID_LOG_LEVELS))}",
            )

    @staticmethod
    def _validate_event_timestamp(event_timestamp: datetime) -> datetime:
        """Ensure event_timestamp is timezone-aware. Returns normalized timestamp."""
        if event_timestamp.tzinfo is None:
            return event_timestamp.replace(tzinfo=timezone.utc)
        return event_timestamp

    @staticmethod
    def _validate_correlation_id(correlation_id: UUID | None) -> None:
        """Validate that correlation_id, if provided, is a valid UUID (type-enforced by Pydantic)."""
        # Pydantic enforces UUID format; this hook is for future custom rules
        pass

    async def _validate_entry(self, payload: LogEntryCreate) -> dict[str, Any]:
        """Run all validations on a single log entry and return sanitized data dict."""
        # Validate log level
        self._validate_log_level(payload.log_level)

        # Validate event timestamp
        normalized_ts = self._validate_event_timestamp(payload.event_timestamp)

        # Validate source exists
        source = await self._validate_source_exists(payload.source_id)

        # Validate asset exists if provided
        if payload.asset_id:
            await self._validate_asset_exists(payload.asset_id)

        # Validate correlation_id
        self._validate_correlation_id(payload.correlation_id)

        data = payload.model_dump()
        data["event_timestamp"] = normalized_ts
        return data

    # ── Ingestion ─────────────────────────────────────────────────────

    async def ingest_log(self, payload: LogEntryCreate) -> LogEntryResponse:
        """Ingest a single log entry with full validation."""
        try:
            data = await self._validate_entry(payload)
            entry = await self.entry_repo.create(data)

            # Update source last_seen
            await self.source_repo.update_last_seen(
                payload.source_id,
                data["event_timestamp"],
            )

            logger.info(
                "log_entry_ingested",
                entry_id=str(entry.id),
                source_id=str(payload.source_id),
                log_level=payload.log_level,
                event_type=payload.event_type,
            )

            return LogEntryResponse.model_validate(entry)

        except Exception as exc:
            logger.error(
                "log_entry_ingestion_failed",
                source_id=str(payload.source_id),
                error=str(exc),
            )
            raise

    async def bulk_ingest_logs(
        self, entries: list[LogEntryCreate]
    ) -> dict[str, Any]:
        """
        Ingest multiple log entries in a single transaction.
        Returns a summary with success/failure counts and per-entry errors.
        """
        if not entries:
            return {"total": 0, "ingested": 0, "failed": 0, "errors": []}

        ingested_count = 0
        failed_count = 0
        errors: list[str] = []
        source_timestamps: dict[UUID, datetime] = {}

        for idx, payload in enumerate(entries):
            try:
                data = await self._validate_entry(payload)
                await self.entry_repo.create(data)
                ingested_count += 1

                # Track latest timestamp per source for batch last_seen update
                ts = data["event_timestamp"]
                if payload.source_id not in source_timestamps or ts > source_timestamps[payload.source_id]:
                    source_timestamps[payload.source_id] = ts

            except Exception as exc:
                failed_count += 1
                errors.append(f"Entry [{idx}]: {str(exc)}")
                logger.warning(
                    "bulk_ingest_entry_failed",
                    index=idx,
                    error=str(exc),
                )

        # Batch update last_seen for all affected sources
        for sid, ts in source_timestamps.items():
            try:
                await self.source_repo.update_last_seen(sid, ts)
            except Exception as exc:
                logger.warning(
                    "bulk_ingest_last_seen_update_failed",
                    source_id=str(sid),
                    error=str(exc),
                )

        logger.info(
            "bulk_log_ingestion_complete",
            total=len(entries),
            ingested=ingested_count,
            failed=failed_count,
        )

        if failed_count > 0 and ingested_count == 0:
            raise LogIngestionError(
                message=f"All {failed_count} log entries failed ingestion.",
                failed_count=failed_count,
                errors=errors,
            )

        return {
            "total": len(entries),
            "ingested": ingested_count,
            "failed": failed_count,
            "errors": errors,
        }

    # ── Search & Filtering ────────────────────────────────────────────

    async def search_logs(
        self,
        search: str,
        page: int = 1,
        page_size: int = 25,
    ) -> LogEntryListResponse:
        """Full-text search across log message, username, and event_type."""
        skip = (page - 1) * page_size

        entries = await self.entry_repo.search_entries(
            search=search, skip=skip, limit=page_size
        )
        total = await self.entry_repo.count_filtered(search=search)

        items = [LogEntrySummary.model_validate(e) for e in entries]

        logger.info(
            "log_entries_searched",
            search=search,
            page=page,
            total=total,
        )

        return LogEntryListResponse(
            total=total, page=page, page_size=page_size, items=items
        )

    async def filter_logs(
        self,
        page: int = 1,
        page_size: int = 25,
        source_id: UUID | None = None,
        asset_id: UUID | None = None,
        log_level: str | None = None,
        event_type: str | None = None,
        category: str | None = None,
        search: str | None = None,
    ) -> LogEntryListResponse:
        """Return paginated, multi-filter log entry list."""
        # Validate log_level if provided
        if log_level:
            self._validate_log_level(log_level)

        skip = (page - 1) * page_size

        entries = await self.entry_repo.get_list(
            skip=skip,
            limit=page_size,
            source_id=source_id,
            asset_id=asset_id,
            log_level=log_level,
            event_type=event_type,
            category=category,
            search=search,
        )
        total = await self.entry_repo.count_filtered(
            source_id=source_id,
            asset_id=asset_id,
            log_level=log_level,
            event_type=event_type,
            category=category,
            search=search,
        )

        items = [LogEntrySummary.model_validate(e) for e in entries]

        logger.info(
            "log_entries_filtered",
            page=page,
            page_size=page_size,
            total=total,
        )

        return LogEntryListResponse(
            total=total, page=page, page_size=page_size, items=items
        )

    async def get_logs_by_time_range(
        self,
        start: datetime,
        end: datetime,
        page: int = 1,
        page_size: int = 25,
    ) -> LogEntryListResponse:
        """Fetch log entries within a specific time range."""
        start = self._validate_event_timestamp(start)
        end = self._validate_event_timestamp(end)

        if start > end:
            raise ValidationError(
                field="time_range",
                reason="Start time must be before or equal to end time.",
            )

        skip = (page - 1) * page_size
        entries = await self.entry_repo.get_by_time_range(
            start=start, end=end, skip=skip, limit=page_size
        )

        # Count for pagination (use filtered count with time range)
        total_result = await self.session.execute(
            select(func.count()).select_from(LogEntry).where(
                and_(
                    LogEntry.event_timestamp >= start,
                    LogEntry.event_timestamp <= end,
                )
            )
        )
        total = total_result.scalar_one() or 0

        items = [LogEntrySummary.model_validate(e) for e in entries]

        logger.info(
            "log_entries_by_time_range",
            start=start.isoformat(),
            end=end.isoformat(),
            total=total,
        )

        return LogEntryListResponse(
            total=total, page=page, page_size=page_size, items=items
        )

    async def get_logs_by_level(
        self,
        log_level: str,
        page: int = 1,
        page_size: int = 25,
    ) -> LogEntryListResponse:
        """Fetch log entries filtered by log level."""
        self._validate_log_level(log_level)
        return await self.filter_logs(page=page, page_size=page_size, log_level=log_level)

    async def get_logs_by_event_type(
        self,
        event_type: str,
        page: int = 1,
        page_size: int = 25,
    ) -> LogEntryListResponse:
        """Fetch log entries filtered by event type."""
        return await self.filter_logs(page=page, page_size=page_size, event_type=event_type)

    async def get_logs_by_asset(
        self,
        asset_id: UUID,
        page: int = 1,
        page_size: int = 25,
    ) -> LogEntryListResponse:
        """Fetch log entries for a specific asset."""
        await self._validate_asset_exists(asset_id)
        return await self.filter_logs(page=page, page_size=page_size, asset_id=asset_id)

    async def get_logs_by_source(
        self,
        source_id: UUID,
        page: int = 1,
        page_size: int = 25,
    ) -> LogEntryListResponse:
        """Fetch log entries for a specific log source."""
        await self._validate_source_exists(source_id)
        return await self.filter_logs(page=page, page_size=page_size, source_id=source_id)

    async def get_logs_by_username(
        self,
        username: str,
        page: int = 1,
        page_size: int = 25,
    ) -> LogEntryListResponse:
        """Fetch log entries for a specific username via search."""
        return await self.search_logs(search=username, page=page, page_size=page_size)

    async def get_logs_by_correlation_id(
        self,
        correlation_id: UUID,
    ) -> list[LogEntryResponse]:
        """Fetch all log entries sharing a correlation ID."""
        self._validate_correlation_id(correlation_id)
        entries = await self.entry_repo.get_by_correlation_id(correlation_id)

        logger.info(
            "log_entries_by_correlation_id",
            correlation_id=str(correlation_id),
            count=len(entries),
        )

        return [LogEntryResponse.model_validate(e) for e in entries]

    # ── Statistics ────────────────────────────────────────────────────

    async def count_by_level(self) -> dict[str, int]:
        """Return log entry count grouped by log level."""
        distribution = await self.entry_repo.count_by_level()

        logger.info("log_stats_count_by_level", distribution=distribution)
        return distribution

    async def count_by_source(self) -> dict[str, int]:
        """Return log entry count grouped by source name."""
        result = await self.session.execute(
            select(LogSource.name, func.count(LogEntry.id))
            .join(LogEntry, LogEntry.source_id == LogSource.id)
            .group_by(LogSource.name)
        )
        distribution = {row[0]: row[1] for row in result.all()}

        logger.info("log_stats_count_by_source", source_count=len(distribution))
        return distribution

    async def count_by_event_type(self) -> dict[str, int]:
        """Return log entry count grouped by event_type."""
        result = await self.session.execute(
            select(LogEntry.event_type, func.count(LogEntry.id))
            .group_by(LogEntry.event_type)
        )
        distribution = {row[0]: row[1] for row in result.all()}

        logger.info("log_stats_count_by_event_type", type_count=len(distribution))
        return distribution

    async def top_log_sources(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the top N log sources by entry count."""
        result = await self.session.execute(
            select(
                LogSource.id,
                LogSource.name,
                LogSource.source_type,
                func.count(LogEntry.id).label("entry_count"),
            )
            .join(LogEntry, LogEntry.source_id == LogSource.id)
            .group_by(LogSource.id, LogSource.name, LogSource.source_type)
            .order_by(func.count(LogEntry.id).desc())
            .limit(limit)
        )

        top_sources = [
            {
                "source_id": str(row[0]),
                "name": row[1],
                "source_type": row[2],
                "entry_count": row[3],
            }
            for row in result.all()
        ]

        logger.info("log_stats_top_sources", limit=limit, count=len(top_sources))
        return top_sources

    async def log_volume_over_time(
        self,
        interval: str = "hour",
        limit: int = 24,
    ) -> list[dict[str, Any]]:
        """
        Return log volume aggregated over time buckets.
        Supported intervals: 'hour', 'day', 'week'.
        """
        valid_intervals = {"hour", "day", "week"}
        if interval not in valid_intervals:
            raise ValidationError(
                field="interval",
                reason=f"Invalid interval '{interval}'. Must be one of: {', '.join(sorted(valid_intervals))}",
            )

        trunc_fn = func.date_trunc(interval, LogEntry.event_timestamp)

        result = await self.session.execute(
            select(
                trunc_fn.label("time_bucket"),
                func.count(LogEntry.id).label("count"),
            )
            .group_by(trunc_fn)
            .order_by(trunc_fn.desc())
            .limit(limit)
        )

        volume = [
            {
                "time_bucket": row[0].isoformat() if row[0] else None,
                "count": row[1],
            }
            for row in result.all()
        ]

        logger.info(
            "log_stats_volume_over_time",
            interval=interval,
            buckets=len(volume),
        )

        return volume

    async def get_stats(self) -> LogEntryStatsResponse:
        """Compute comprehensive log entry statistics for dashboard widgets."""
        total = await self.entry_repo.count()
        by_level = await self.entry_repo.count_by_level()
        by_event_type = await self.count_by_event_type()

        # Count by category
        result = await self.session.execute(
            select(LogEntry.category, func.count(LogEntry.id))
            .where(LogEntry.category.isnot(None))
            .group_by(LogEntry.category)
        )
        by_category = {row[0]: row[1] for row in result.all()}

        return LogEntryStatsResponse(
            total_entries=total,
            by_level=by_level,
            by_event_type=by_event_type,
            by_category=by_category,
        )
