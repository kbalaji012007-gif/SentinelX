"""
SentinelX AI – AssetGroup ORM Model
Schema: sentinelx.asset_groups
"""

import uuid
from typing import TYPE_CHECKING
from sqlalchemy import String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.asset import Asset


class AssetGroup(Base, TimestampMixin):
    """Asset group model for organizing network assets by environment, site, or tier."""

    __tablename__ = "asset_groups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    assets: Mapped[list["Asset"]] = relationship(
        "Asset",
        back_populates="asset_group",
        passive_deletes="RESTRICT",
    )
