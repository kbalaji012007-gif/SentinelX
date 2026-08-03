"""
SentinelX AI – Asset & AssetGroup Repositories
Data access layer for sentinelx.asset_groups and sentinelx.assets.
"""

from uuid import UUID
from typing import Sequence
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset_group import AssetGroup
from app.models.asset import Asset
from app.repositories.base_repo import BaseRepository


class AssetGroupRepository(BaseRepository[AssetGroup]):
    """Repository managing AssetGroup entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AssetGroup, session)

    async def get_by_name(self, name: str) -> AssetGroup | None:
        """Fetch asset group by unique name."""
        result = await self.session.execute(
            select(AssetGroup).where(AssetGroup.name == name)
        )
        return result.scalar_one_or_none()


class AssetRepository(BaseRepository[Asset]):
    """Repository managing Asset entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Asset, session)

    async def get_by_hostname(self, hostname: str) -> Asset | None:
        """Fetch asset by unique hostname with eager-loaded asset group."""
        result = await self.session.execute(
            select(Asset)
            .options(selectinload(Asset.asset_group))
            .where(Asset.hostname == hostname)
        )
        return result.scalar_one_or_none()

    async def get_by_ip_address(self, ip_address: str) -> Sequence[Asset]:
        """Fetch assets matching IP address."""
        result = await self.session.execute(
            select(Asset)
            .options(selectinload(Asset.asset_group))
            .where(Asset.ip_address == ip_address)
        )
        return result.scalars().all()

    async def get_by_type(self, asset_type: str, skip: int = 0, limit: int = 100) -> Sequence[Asset]:
        """Fetch assets filtered by asset type (e.g. Server, Firewall)."""
        result = await self.session.execute(
            select(Asset)
            .where(Asset.asset_type == asset_type)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_criticality(self, criticality: str, skip: int = 0, limit: int = 100) -> Sequence[Asset]:
        """Fetch assets filtered by criticality (e.g. Critical, High)."""
        result = await self.session.execute(
            select(Asset)
            .where(Asset.criticality == criticality)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_status(self, status: str, skip: int = 0, limit: int = 100) -> Sequence[Asset]:
        """Fetch assets filtered by status (e.g. Active, Maintenance)."""
        result = await self.session.execute(
            select(Asset)
            .where(Asset.status == status)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_group(self, asset_group_id: UUID, skip: int = 0, limit: int = 100) -> Sequence[Asset]:
        """Fetch assets belonging to a specific asset group."""
        result = await self.session.execute(
            select(Asset)
            .where(Asset.asset_group_id == asset_group_id)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
