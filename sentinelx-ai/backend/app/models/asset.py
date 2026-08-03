"""
SentinelX AI – Asset ORM Model
Schema: sentinelx.assets
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any
from sqlalchemy import String, Text, ForeignKey, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.asset_group import AssetGroup


class Asset(Base, TimestampMixin):
    """Asset model representing servers, workstations, cloud resources, routers, switches, and firewalls."""

    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    asset_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.asset_groups.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    hostname: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    asset_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    asset_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    operating_system: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    ip_address: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )
    mac_address: Mapped[str | None] = mapped_column(
        String(17),
        nullable=True,
    )
    owner: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    department: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    criticality: Mapped[str] = mapped_column(
        String(20),
        default="Medium",
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="Active",
        nullable=False,
        index=True,
    )
    location: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    serial_number: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    tags: Mapped[list[Any]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default="[]",
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    asset_group: Mapped["AssetGroup"] = relationship(
        "AssetGroup",
        back_populates="assets",
    )
