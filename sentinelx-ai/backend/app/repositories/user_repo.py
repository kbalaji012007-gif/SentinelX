"""
SentinelX AI – User Repository
Data access layer for sentinelx.users.
"""

from uuid import UUID
from typing import Sequence, Tuple
from sqlalchemy import select, func, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.role import Role
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

    async def get_role_by_name(self, role_name: str) -> Role | None:
        """Fetch role entity by name."""
        result = await self.session.execute(
            select(Role).where(func.lower(Role.name) == func.lower(role_name))
        )
        return result.scalar_one_or_none()

    async def list_roles(self) -> Sequence[Role]:
        """Fetch all available roles."""
        result = await self.session.execute(select(Role).order_by(Role.name))
        return result.scalars().all()

    async def list_users_paginated(
        self,
        search: str | None = None,
        role_name: str | None = None,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> Tuple[Sequence[User], int]:
        """List users with search, role filter, status filter, and pagination."""
        query = select(User).options(selectinload(User.role)).join(Role, User.role_id == Role.id)
        count_query = select(func.count(User.id)).join(Role, User.role_id == Role.id)

        filters = []
        if search:
            s = f"%{search}%"
            filters.append(
                or_(
                    User.first_name.ilike(s),
                    User.last_name.ilike(s),
                    User.email.ilike(s),
                )
            )
        if role_name:
            filters.append(func.lower(Role.name) == func.lower(role_name))
        if is_active is not None:
            filters.append(User.is_active == is_active)

        if filters:
            query = query.where(*filters)
            count_query = count_query.where(*filters)

        total = (await self.session.execute(count_query)).scalar_one()

        skip = (page - 1) * page_size
        query = query.order_by(User.created_at.desc()).offset(skip).limit(page_size)

        items = (await self.session.execute(query)).scalars().all()
        return items, total
