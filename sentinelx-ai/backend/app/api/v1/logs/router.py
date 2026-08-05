"""
SentinelX AI – Log Collection API Router
JWT-protected, RBAC-enforced endpoints for log sources, log entries, search, and statistics.
"""

from uuid import UUID
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole
from app.models.user import User
from app.schemas.log_schema import (
    LogSourceCreate,
    LogSourceUpdate,
    LogSourceResponse,
    LogSourceListResponse,
    LogEntryCreate,
    LogEntryResponse,
    LogEntrySummary,
    LogEntryListResponse,
    LogEntryStatsResponse,
)
from app.services.log_service import LogSourceService, LogEntryService
from app.core.exceptions import (
    EntityNotFoundError,
    ValidationError,
    DuplicateEntityError,
    LogIngestionError,
)

router = APIRouter(prefix="/logs", tags=["Logs"])

# RBAC role groups
_READERS = ["Admin", "Manager", "Analyst", "ReadOnly"]
_WRITERS = ["Admin", "Manager", "Analyst"]
_ADMINS = ["Admin", "Manager"]


# ── Exception handler helper ─────────────────────────────────────────

def _handle_domain_exception(exc: Exception) -> None:
    """Map domain exceptions to HTTP responses."""
    if isinstance(exc, EntityNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        )
    if isinstance(exc, DuplicateEntityError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.detail,
        )
    if isinstance(exc, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.detail,
        )
    if isinstance(exc, LogIngestionError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": exc.message,
                "failed_count": exc.failed_count,
                "errors": exc.errors,
            },
        )


# ────────────────────────────────────────────────────────────────────────
# Log Source Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/sources",
    response_model=LogSourceListResponse,
    status_code=status.HTTP_200_OK,
    summary="List log sources (paginated, filterable)",
)
async def list_log_sources(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    source_type: Annotated[str | None, Query(description="Filter by source type")] = None,
    source_status: Annotated[str | None, Query(alias="status", description="Filter by status")] = None,
    search: Annotated[str | None, Query(description="Search name, vendor, hostname, or description")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> LogSourceListResponse:
    """Return a paginated list of log sources with optional filters."""
    service = LogSourceService(db)
    return await service.list_sources(
        page=page,
        page_size=page_size,
        source_type=source_type,
        status=source_status,
        search=search,
    )


@router.get(
    "/sources/{source_id}",
    response_model=LogSourceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get log source detail",
)
async def get_log_source(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> LogSourceResponse:
    """Retrieve full details for a single log source."""
    service = LogSourceService(db)
    try:
        return await service.get_source(source_id)
    except EntityNotFoundError as exc:
        _handle_domain_exception(exc)


@router.post(
    "/sources",
    response_model=LogSourceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new log source",
)
async def create_log_source(
    payload: LogSourceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> LogSourceResponse:
    """Register a new log source in the platform."""
    service = LogSourceService(db)
    try:
        return await service.create_source(payload)
    except (ValidationError, DuplicateEntityError) as exc:
        _handle_domain_exception(exc)


@router.put(
    "/sources/{source_id}",
    response_model=LogSourceResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a log source",
)
async def update_log_source(
    source_id: UUID,
    payload: LogSourceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> LogSourceResponse:
    """Update fields of an existing log source."""
    service = LogSourceService(db)
    try:
        return await service.update_source(source_id, payload)
    except (EntityNotFoundError, ValidationError, DuplicateEntityError) as exc:
        _handle_domain_exception(exc)


@router.delete(
    "/sources/{source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate a log source (Admin/Manager only)",
)
async def deactivate_log_source(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMINS)),
) -> None:
    """
    Deactivate a log source by setting its status to Inactive.
    Does not delete log entries — preserves audit trail.
    """
    service = LogSourceService(db)
    try:
        await service.deactivate_source(source_id)
    except EntityNotFoundError as exc:
        _handle_domain_exception(exc)


# ────────────────────────────────────────────────────────────────────────
# Log Entry Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.get(
    "/search",
    response_model=LogEntryListResponse,
    status_code=status.HTTP_200_OK,
    summary="Search log entries",
)
async def search_log_entries(
    keyword: Annotated[str | None, Query(description="Keyword search in message, username, event_type")] = None,
    level: Annotated[str | None, Query(description="Filter by log level")] = None,
    source: Annotated[UUID | None, Query(description="Filter by source UUID")] = None,
    asset: Annotated[UUID | None, Query(description="Filter by asset UUID")] = None,
    username: Annotated[str | None, Query(description="Filter by username")] = None,
    event_type: Annotated[str | None, Query(description="Filter by event type")] = None,
    category: Annotated[str | None, Query(description="Filter by category")] = None,
    start_time: Annotated[datetime | None, Query(description="Start of time range (ISO 8601)")] = None,
    end_time: Annotated[datetime | None, Query(description="End of time range (ISO 8601)")] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> LogEntryListResponse:
    """
    Search and filter log entries with multiple criteria.
    Supports keyword search, level/source/asset/username/event_type/category filters,
    time range filtering, and pagination.
    """
    service = LogEntryService(db)

    try:
        # Time range query takes precedence when both start and end are provided
        if start_time and end_time:
            return await service.get_logs_by_time_range(
                start=start_time,
                end=end_time,
                page=page,
                page_size=page_size,
            )

        # Use the multi-filter endpoint for all other combinations
        return await service.filter_logs(
            page=page,
            page_size=page_size,
            source_id=source,
            asset_id=asset,
            log_level=level,
            event_type=event_type,
            category=category,
            search=keyword or username,
        )
    except (EntityNotFoundError, ValidationError) as exc:
        _handle_domain_exception(exc)


@router.get(
    "/stats",
    response_model=LogEntryStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Log collection statistics",
)
@router.get(
    "/statistics",
    response_model=LogEntryStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Log collection statistics",
)
async def get_log_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> LogEntryStatsResponse:
    """
    Return comprehensive log collection statistics:
    total logs, by level, by source, by event type, top sources, volume timeline.
    """
    service = LogEntryService(db)
    stats = await service.get_stats()
    return stats


@router.get(
    "/statistics/top-sources",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Top log sources by volume",
)
async def get_top_log_sources(
    limit: Annotated[int, Query(ge=1, le=50, description="Number of top sources")] = 10,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> list[dict[str, Any]]:
    """Return the top N log sources ranked by log entry volume."""
    service = LogEntryService(db)
    return await service.top_log_sources(limit=limit)


@router.get(
    "/statistics/volume",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Log volume over time",
)
async def get_log_volume(
    interval: Annotated[str, Query(description="Time bucket: hour, day, or week")] = "hour",
    limit: Annotated[int, Query(ge=1, le=168, description="Number of time buckets")] = 24,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> list[dict[str, Any]]:
    """Return log volume aggregated over time buckets."""
    service = LogEntryService(db)
    try:
        return await service.log_volume_over_time(interval=interval, limit=limit)
    except ValidationError as exc:
        _handle_domain_exception(exc)


@router.get(
    "/statistics/by-level",
    response_model=dict[str, int],
    status_code=status.HTTP_200_OK,
    summary="Log count by level",
)
async def get_logs_count_by_level(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> dict[str, int]:
    """Return log entry counts grouped by log level."""
    service = LogEntryService(db)
    return await service.count_by_level()


@router.get(
    "/statistics/by-source",
    response_model=dict[str, int],
    status_code=status.HTTP_200_OK,
    summary="Log count by source",
)
async def get_logs_count_by_source(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> dict[str, int]:
    """Return log entry counts grouped by source name."""
    service = LogEntryService(db)
    return await service.count_by_source()


@router.get(
    "/statistics/by-event-type",
    response_model=dict[str, int],
    status_code=status.HTTP_200_OK,
    summary="Log count by event type",
)
async def get_logs_count_by_event_type(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> dict[str, int]:
    """Return log entry counts grouped by event type."""
    service = LogEntryService(db)
    return await service.count_by_event_type()


@router.get(
    "",
    response_model=LogEntryListResponse,
    status_code=status.HTTP_200_OK,
    summary="List log entries (paginated, filterable)",
)
async def list_log_entries(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    source_id: Annotated[UUID | None, Query(description="Filter by source UUID")] = None,
    asset_id: Annotated[UUID | None, Query(description="Filter by asset UUID")] = None,
    log_level: Annotated[str | None, Query(description="Filter by log level")] = None,
    event_type: Annotated[str | None, Query(description="Filter by event type")] = None,
    category: Annotated[str | None, Query(description="Filter by category")] = None,
    search: Annotated[str | None, Query(description="Search message, username, or event_type")] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> LogEntryListResponse:
    """Return a paginated list of log entries with optional filters."""
    service = LogEntryService(db)
    try:
        return await service.filter_logs(
            page=page,
            page_size=page_size,
            source_id=source_id,
            asset_id=asset_id,
            log_level=log_level,
            event_type=event_type,
            category=category,
            search=search,
        )
    except ValidationError as exc:
        _handle_domain_exception(exc)


@router.get(
    "/{entry_id}",
    response_model=LogEntryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get log entry detail",
)
async def get_log_entry(
    entry_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> LogEntryResponse:
    """Retrieve full details for a single log entry."""
    service = LogEntryService(db)
    entry = await service.entry_repo.get_by_id(entry_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log entry {entry_id} not found",
        )
    return LogEntryResponse.model_validate(entry)


@router.post(
    "",
    response_model=LogEntryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a single log entry",
)
async def ingest_log_entry(
    payload: LogEntryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> LogEntryResponse:
    """Ingest a single log entry with full validation."""
    service = LogEntryService(db)
    try:
        return await service.ingest_log(payload)
    except (EntityNotFoundError, ValidationError) as exc:
        _handle_domain_exception(exc)


@router.post(
    "/bulk",
    response_model=dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Bulk ingest log entries",
)
async def bulk_ingest_log_entries(
    entries: list[LogEntryCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> dict[str, Any]:
    """
    Ingest multiple log entries in a single request.
    Returns a summary with ingested/failed counts and per-entry error messages.
    """
    service = LogEntryService(db)
    try:
        return await service.bulk_ingest_logs(entries)
    except LogIngestionError as exc:
        _handle_domain_exception(exc)
