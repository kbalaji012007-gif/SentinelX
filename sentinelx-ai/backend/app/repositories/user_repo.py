"""
SentinelX AI – User Repository
Data access layer for sentinelx.users.
"""

from uuid import UUID
from typing import Sequence
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.base_repo import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository managing User entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(User, session)

    async def get_by_email(self, email: str) -> User | None:
        """Fetch user by unique email with eager-loaded role."""
        result = await self.session.execute(
            select(User)
            .options(selectinload(User.role))
            .where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_by_id_with_role(self, id: UUID) -> User | None:
        """Fetch user by ID with eager-loaded role details."""
        result = await self.session.execute(
            select(User)
            .options(selectinload(User.role))
            .where(User.id == id)
        )
        return result.scalar_one_or_none()

    async def get_users_by_role(self, role_id: UUID, skip: int = 0, limit: int = 100) -> Sequence[User]:
        """Fetch all users assigned to a specific role."""
        result = await self.session.execute(
            select(User)
            .where(User.role_id == role_id)
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
