"""
SentinelX AI – Log Collection Pydantic v2 Schemas
Validation and serialization for sentinelx.log_sources and sentinelx.log_entries.
"""

from uuid import UUID
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

# ── Enums ─────────────────────────────────────────────────────────────
LogSourceTypeEnum = Literal[
    "Syslog",
    "Windows Event",
    "Cloud Trail",
    "Firewall",
    "IDS/IPS",
    "Endpoint",
    "Application",
    "Network",
    "Other",
]
LogSourceStatusEnum = Literal["Active", "Inactive", "Error", "Maintenance"]
LogProtocolEnum = Literal["UDP", "TCP", "TLS", "HTTPS", "HTTP"]
LogLevelEnum = Literal["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


# ────────────────────────────────────────────────────────────────────────
# Log Source Schemas
# ────────────────────────────────────────────────────────────────────────

class LogSourceBase(BaseModel):
    """Shared Log Source attributes."""

    name: str = Field(..., min_length=1, max_length=255)
    source_type: LogSourceTypeEnum
    vendor: str | None = Field(None, max_length=255)
    description: str | None = None
    hostname: str | None = Field(None, max_length=255)
    ip_address: str | None = Field(None, max_length=45)
    protocol: LogProtocolEnum | None = None
    port: int | None = Field(None, ge=0, le=65535)
    status: LogSourceStatusEnum = Field(default="Active")


class LogSourceCreate(LogSourceBase):
    """Schema for creating a new log source."""
    pass


class LogSourceUpdate(BaseModel):
    """Schema for partially updating a log source."""

    name: str | None = Field(None, min_length=1, max_length=255)
    source_type: LogSourceTypeEnum | None = None
    vendor: str | None = Field(None, max_length=255)
    description: str | None = None
    hostname: str | None = Field(None, max_length=255)
    ip_address: str | None = Field(None, max_length=45)
    protocol: LogProtocolEnum | None = None
    port: int | None = Field(None, ge=0, le=65535)
    status: LogSourceStatusEnum | None = None
    last_seen: datetime | None = None


class LogSourceResponse(LogSourceBase):
    """Schema for returning full log source details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    last_seen: datetime | None = None
    created_at: datetime
    updated_at: datetime


class LogSourceSummary(BaseModel):
    """Lightweight log source summary for list views."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    source_type: str
    vendor: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    status: str
    last_seen: datetime | None = None
    created_at: datetime
    updated_at: datetime


class LogSourceListResponse(BaseModel):
    """Paginated log source list response."""

    total: int
    page: int
    page_size: int
    items: list[LogSourceSummary]


# ────────────────────────────────────────────────────────────────────────
# Log Entry Schemas
# ────────────────────────────────────────────────────────────────────────

class LogEntryBase(BaseModel):
    """Shared Log Entry attributes."""

    event_timestamp: datetime
    log_level: LogLevelEnum = Field(default="INFO")
    event_type: str = Field(..., min_length=1, max_length=100)
    category: str | None = Field(None, max_length=100)
    message: str | None = None
    raw_log: dict[str, Any] = Field(default_factory=dict)
    source_ip: str | None = Field(None, max_length=45)
    destination_ip: str | None = Field(None, max_length=45)
    username: str | None = Field(None, max_length=255)
    process_name: str | None = Field(None, max_length=255)
    event_id: str | None = Field(None, max_length=100)
    correlation_id: UUID | None = None


class LogEntryCreate(LogEntryBase):
    """Schema for creating a new log entry."""

    source_id: UUID
    asset_id: UUID | None = None


class LogEntryResponse(LogEntryBase):
    """Schema for returning full log entry details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_id: UUID
    asset_id: UUID | None = None
    created_at: datetime


class LogEntrySummary(BaseModel):
    """Lightweight log entry summary for table views."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_id: UUID
    asset_id: UUID | None = None
    event_timestamp: datetime
    log_level: str
    event_type: str
    category: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    event_id: str | None = None
    created_at: datetime


class LogEntryListResponse(BaseModel):
    """Paginated log entry list response."""

    total: int
    page: int
    page_size: int
    items: list[LogEntrySummary]


class LogEntryStatsResponse(BaseModel):
    """Log entry aggregation stats for dashboard widgets."""

    total_entries: int
    by_level: dict[str, int]
    by_event_type: dict[str, int]
    by_category: dict[str, int]
