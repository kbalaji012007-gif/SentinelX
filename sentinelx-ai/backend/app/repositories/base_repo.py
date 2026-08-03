"""
SentinelX AI – Generic Base Repository
Generic Async SQLAlchemy CRUD repository pattern.
"""

from typing import Generic, TypeVar, Sequence, Any
from uuid import UUID
from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """Generic repository providing asynchronous CRUD operations for SQLAlchemy models."""

    def __init__(self, model: type[ModelType], session: AsyncSession) -> None:
        self.model = model
        self.session = session

    async def get_by_id(self, id: UUID) -> ModelType | None:
        """Fetch a single record by primary key UUID."""
        result = await self.session.execute(
            select(self.model).where(self.model.id == id) # type: ignore[attr-defined]
        )
        return result.scalar_one_or_none()

    async def get_all(self, skip: int = 0, limit: int = 100) -> Sequence[ModelType]:
        """Fetch all records with pagination."""
        result = await self.session.execute(
            select(self.model).offset(skip).limit(limit)
        )
        return result.scalars().all()

    async def create(self, obj_in: dict[str, Any]) -> ModelType:
        """Create and persist a new model instance."""
        db_obj = self.model(**obj_in)
        self.session.add(db_obj)
        await self.session.commit()
        await self.session.refresh(db_obj)
        return db_obj

    async def update(self, id: UUID, obj_in: dict[str, Any]) -> ModelType | None:
        """Update an existing record by UUID."""
        await self.session.execute(
            update(self.model)
            .where(self.model.id == id) # type: ignore[attr-defined]
            .values(**obj_in)
        )
        await self.session.commit()
        return await self.get_by_id(id)

    async def delete(self, id: UUID) -> bool:
        """Delete a record by UUID."""
        result = await self.session.execute(
            delete(self.model).where(self.model.id == id) # type: ignore[attr-defined]
        )
        await self.session.commit()
        return result.rowcount > 0

    async def count(self) -> int:
        """Count total rows for the model."""
        result = await self.session.execute(
            select(func.count()).select_from(self.model)
        )
        return result.scalar_one() or 0
