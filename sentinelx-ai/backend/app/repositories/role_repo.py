"""
SentinelX AI – Role Repository
Data access layer for sentinelx.roles.
"""

from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.role import Role
from app.repositories.base_repo import BaseRepository


class RoleRepository(BaseRepository[Role]):
    """Repository managing Role entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Role, session)

    async def get_by_name(self, name: str) -> Role | None:
        """Fetch a role by its unique name."""
        result = await self.session.execute(
            select(Role).where(Role.name == name)
        )
        return result.scalar_one_or_none()
