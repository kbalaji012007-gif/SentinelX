"""
SentinelX AI – Threat Intelligence Pydantic v2 Schemas
Validation and serialization schemas for threat feeds, IOC feeds, IOC reputation, MITRE ATT&CK, and cache.
"""

from uuid import UUID
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

# ── Enums ─────────────────────────────────────────────────────────────
FeedStatusEnum = Literal["Active", "Inactive", "Error", "Deprecated"]
IOCTypeEnum = Literal["IP", "Domain", "URL", "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256", "Email"]
IOCSeverityEnum = Literal["Critical", "High", "Medium", "Low", "Info"]
VerdictEnum = Literal["Malicious", "Suspicious", "Harmless", "Unknown"]


# ────────────────────────────────────────────────────────────────────────
# Threat Feed Schemas
# ────────────────────────────────────────────────────────────────────────

class ThreatFeedBase(BaseModel):
    """Shared Threat Feed attributes."""

    feed_name: str = Field(..., min_length=1, max_length=255)
    feed_type: str = Field(..., min_length=1, max_length=100)
    provider: str = Field(..., min_length=1, max_length=255)
    feed_url: str | None = None
    api_key_required: bool = False
    reliability_score: int = Field(80, ge=0, le=100)
    confidence_score: int = Field(80, ge=0, le=100)
    status: FeedStatusEnum = "Active"
    description: str | None = None


class ThreatFeedCreate(ThreatFeedBase):
    """Schema for registering a new threat feed."""

    pass


class ThreatFeedUpdate(BaseModel):
    """Schema for updating an existing threat feed."""

    feed_name: str | None = Field(None, min_length=1, max_length=255)
    feed_type: str | None = Field(None, min_length=1, max_length=100)
    provider: str | None = Field(None, min_length=1, max_length=255)
    feed_url: str | None = None
    api_key_required: bool | None = None
    reliability_score: int | None = Field(None, ge=0, le=100)
    confidence_score: int | None = Field(None, ge=0, le=100)
    status: FeedStatusEnum | None = None
    description: str | None = None


class ThreatFeedResponse(ThreatFeedBase):
    """Schema for returning threat feed details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    last_fetched_at: datetime | None = None
    total_indicators: int = 0
    created_at: datetime
    updated_at: datetime


class ThreatFeedListResponse(BaseModel):
    """Paginated list of threat feeds."""

    total: int
    page: int
    page_size: int
    items: list[ThreatFeedResponse]


# ────────────────────────────────────────────────────────────────────────
# IOC Feed Item Schemas
# ────────────────────────────────────────────────────────────────────────

class IOCFeedBase(BaseModel):
    """Shared IOC Feed Item attributes."""

    feed_id: UUID | None = None
    ioc_type: IOCTypeEnum
    value: str = Field(..., min_length=1, max_length=500)
    severity: IOCSeverityEnum = "Medium"
    threat_type: str = "Malware"
    confidence: int = Field(80, ge=0, le=100)
    tags: list[Any] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    expiration_date: datetime | None = None


class IOCFeedCreate(IOCFeedBase):
    """Schema for adding a new IOC feed item."""

    pass


class IOCFeedUpdate(BaseModel):
    """Schema for updating an IOC feed item."""

    ioc_type: IOCTypeEnum | None = None
    value: str | None = Field(None, min_length=1, max_length=500)
    severity: IOCSeverityEnum | None = None
    threat_type: str | None = None
    confidence: int | None = Field(None, ge=0, le=100)
    tags: list[Any] | None = None
    raw_metadata: dict[str, Any] | None = None
    is_active: bool | None = None
    expiration_date: datetime | None = None


class IOCFeedResponse(IOCFeedBase):
    """Schema for returning IOC feed item details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime


class IOCFeedListResponse(BaseModel):
    """Paginated list of IOC feed items."""

    total: int
    page: int
    page_size: int
    items: list[IOCFeedResponse]


# ────────────────────────────────────────────────────────────────────────
# IOC Reputation Schemas
# ────────────────────────────────────────────────────────────────────────

class IOCReputationBase(BaseModel):
    """Shared IOC Reputation attributes."""

    ioc_value: str = Field(..., min_length=1, max_length=500)
    ioc_type: str = Field(..., min_length=1, max_length=50)
    reputation_score: int = Field(50, ge=0, le=100)
    verdict: VerdictEnum = "Unknown"
    threat_category: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class IOCReputationCreate(IOCReputationBase):
    """Schema for registering IOC reputation."""

    source_count: int = 1


class IOCReputationResponse(IOCReputationBase):
    """Schema for returning IOC reputation details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_count: int
    last_analyzed_at: datetime
    created_at: datetime
    updated_at: datetime


# ────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Technique Schemas
# ────────────────────────────────────────────────────────────────────────

class MitreTechniqueBase(BaseModel):
    """Shared MITRE Technique attributes."""

    technique_id: str = Field(..., min_length=2, max_length=50)
    name: str = Field(..., min_length=1, max_length=255)
    tactic: str = Field(..., min_length=1, max_length=100)
    description: str | None = None
    platforms: list[Any] = Field(default_factory=list)
    data_sources: list[Any] = Field(default_factory=list)
    detection_methods: str | None = None
    mitigation: str | None = None
    is_subtechnique: bool = False
    parent_technique_id: str | None = None


class MitreTechniqueCreate(MitreTechniqueBase):
    """Schema for registering a MITRE Technique."""

    pass


class MitreTechniqueResponse(MitreTechniqueBase):
    """Schema for returning MITRE Technique details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class MitreTechniqueListResponse(BaseModel):
    """Paginated list of MITRE techniques."""

    total: int
    page: int
    page_size: int
    items: list[MitreTechniqueResponse]


# ────────────────────────────────────────────────────────────────────────
# Threat Cache Schemas
# ────────────────────────────────────────────────────────────────────────

class ThreatCacheBase(BaseModel):
    """Shared Threat Intelligence Cache attributes."""

    query_key: str = Field(..., min_length=1, max_length=255)
    query_type: str = Field(..., min_length=1, max_length=100)
    response_data: dict[str, Any]
    ttl_seconds: int = Field(3600, gt=0)


class ThreatCacheCreate(ThreatCacheBase):
    """Schema for storing cached threat responses."""

    expires_at: datetime


class ThreatCacheResponse(ThreatCacheBase):
    """Schema for returning cached threat responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    expires_at: datetime
    created_at: datetime


# ────────────────────────────────────────────────────────────────────────
# Threat Intelligence Statistics Schema
# ────────────────────────────────────────────────────────────────────────

class ThreatIntelStatsResponse(BaseModel):
    """Summary statistics for Threat Intelligence module."""

    total_feeds: int
    active_feeds: int
    total_iocs: int
    iocs_by_type: dict[str, int]
    iocs_by_severity: dict[str, int]
    mitre_technique_count: int
    cached_query_count: int
