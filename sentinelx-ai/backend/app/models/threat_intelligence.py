"""
SentinelX AI – Threat Intelligence ORM Models
Schemas:
  - sentinelx.threat_feeds
  - sentinelx.ioc_feeds
  - sentinelx.ioc_reputation
  - sentinelx.mitre_attack
  - sentinelx.threat_intelligence_cache
"""

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import String, Text, ForeignKey, DateTime, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class ThreatFeed(Base, TimestampMixin):
    """Threat feed provider details."""

    __tablename__ = "threat_feeds"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    feed_name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    feed_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    feed_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    api_key_required: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    reliability_score: Mapped[int] = mapped_column(
        Integer,
        default=80,
        nullable=False,
    )
    confidence_score: Mapped[int] = mapped_column(
        Integer,
        default=80,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="Active",
        nullable=False,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    last_fetched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    total_indicators: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    # Relationships
    ioc_items: Mapped[list["IOCFeed"]] = relationship(
        "IOCFeed",
        back_populates="feed",
        cascade="all, delete-orphan",
    )


class IOCFeed(Base, TimestampMixin):
    """Indicators of Compromise (IOC) ingested from threat feeds."""

    __tablename__ = "ioc_feeds"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    feed_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.threat_feeds.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    ioc_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    value: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        default="Medium",
        nullable=False,
        index=True,
    )
    threat_type: Mapped[str] = mapped_column(
        String(100),
        default="Malware",
        nullable=False,
    )
    confidence: Mapped[int] = mapped_column(
        Integer,
        default=80,
        nullable=False,
    )
    tags: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default="[]",
    )
    raw_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expiration_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    feed: Mapped[ThreatFeed | None] = relationship(
        "ThreatFeed",
        back_populates="ioc_items",
    )


class IOCReputation(Base, TimestampMixin):
    """Aggregated reputation score & analysis for individual IOC indicators."""

    __tablename__ = "ioc_reputation"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    ioc_value: Mapped[str] = mapped_column(
        String(500),
        unique=True,
        nullable=False,
        index=True,
    )
    ioc_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    reputation_score: Mapped[int] = mapped_column(
        Integer,
        default=50,
        nullable=False,
    )
    verdict: Mapped[str] = mapped_column(
        String(50),
        default="Unknown",
        nullable=False,
        index=True,
    )
    threat_category: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    source_count: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    last_analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )


class MitreTechnique(Base, TimestampMixin):
    """MITRE ATT&CK Matrix Techniques & Tactics catalog."""

    __tablename__ = "mitre_attack"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    technique_id: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    tactic: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    platforms: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default="[]",
    )
    data_sources: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default="[]",
    )
    detection_methods: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    mitigation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    is_subtechnique: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    parent_technique_id: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )


class ThreatCache(Base):
    """Caching table for threat intelligence query responses."""

    __tablename__ = "threat_intelligence_cache"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    query_key: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    query_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    response_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )
    ttl_seconds: Mapped[int] = mapped_column(
        Integer,
        default=3600,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
