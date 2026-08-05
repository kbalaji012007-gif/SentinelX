"""
SentinelX AI – Asset Management API Router
Endpoints for querying and registering enterprise network assets.
"""

from uuid import UUID
from typing import Sequence
from fastapi import APIRouter, Depends, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.user import User
from app.schemas.asset_schema import AssetResponse, AssetCreate
from app.services.asset_service import AssetService

router = APIRouter(prefix="/assets", tags=["Asset Management"])


@router.get("", response_model=list[AssetResponse], status_code=status.HTTP_200_OK)
async def get_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch paginated list of enterprise network assets."""
    service = AssetService(db)
    return await service.get_all_assets(skip=skip, limit=limit)


@router.get("/{asset_id}", response_model=AssetResponse, status_code=status.HTTP_200_OK)
async def get_asset_by_id(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch asset by unique ID."""
    service = AssetService(db)
    return await service.get_asset_by_id(asset_id)


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Register a new enterprise asset."""
    service = AssetService(db)
    return await service.create_asset(payload)
