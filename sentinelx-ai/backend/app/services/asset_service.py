"""
SentinelX AI – Asset Service Layer
Business logic for managing asset inventory and asset groups.
"""

from uuid import UUID
from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.repositories.asset_repo import AssetRepository, AssetGroupRepository
from app.schemas.asset_schema import AssetCreate, AssetUpdate, AssetGroupCreate
from app.models.asset import Asset
from app.models.asset_group import AssetGroup


class AssetService:
    """Service managing asset inventory operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.asset_repo = AssetRepository(session)
        self.group_repo = AssetGroupRepository(session)

    async def get_all_assets(self, skip: int = 0, limit: int = 100) -> Sequence[Asset]:
        """List assets from sentinelx.assets."""
        return await self.asset_repo.get_all(skip=skip, limit=limit)

    async def get_asset_by_id(self, asset_id: UUID) -> Asset:
        """Fetch asset by ID."""
        asset = await self.asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset with id {asset_id} not found",
            )
        return asset

    async def create_asset(self, payload: AssetCreate) -> Asset:
        """Register a new asset."""
        group = await self.group_repo.get_by_id(payload.asset_group_id)
        if not group:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Asset group id {payload.asset_group_id} does not exist",
            )
        return await self.asset_repo.create(payload.model_dump())
