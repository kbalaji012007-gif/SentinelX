"""
SentinelX AI – Dashboard Repository
Queries database tables in sentinelx schema for dashboard aggregation statistics.
"""

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.user import User
from app.models.role import Role


class DashboardRepository:
    """Repository collecting metric aggregations from the sentinelx schema."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_asset_count(self) -> int:
        """Count total assets in sentinelx.assets."""
        result = await self.session.execute(
            select(func.count()).select_from(Asset)
        )
        return result.scalar_one() or 0

    async def get_user_count(self) -> int:
        """Count total registered users."""
        result = await self.session.execute(
            select(func.count()).select_from(User)
        )
        return result.scalar_one() or 0

    async def get_active_user_count(self) -> int:
        """Count active users."""
        result = await self.session.execute(
            select(func.count()).select_from(User).where(User.is_active.is_(True))
        )
        return result.scalar_one() or 0
