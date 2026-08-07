"""
SentinelX AI – AI SOC Analyst Repositories
Data access layer for AI Investigation History and Threat Hunt logs.
"""

from uuid import UUID
from typing import Sequence
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_soc import AIInvestigationHistory, AIThreatHunt
from app.repositories.base_repo import BaseRepository


class AIInvestigationRepository(BaseRepository[AIInvestigationHistory]):
    """Repository managing AIInvestigationHistory entity operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AIInvestigationHistory, session)

    async def list_investigations(
        self, skip: int = 0, limit: int = 25, investigation_type: str | None = None
    ) -> Sequence[AIInvestigationHistory]:
        """Fetch paginated AI investigation audit trail."""
        stmt = select(AIInvestigationHistory).order_by(AIInvestigationHistory.created_at.desc())
        if investigation_type:
            stmt = stmt.where(AIInvestigationHistory.investigation_type == investigation_type)
        result = await self.session.execute(stmt.offset(skip).limit(limit))
        return result.scalars().all()

    async def count_investigations(self, investigation_type: str | None = None) -> int:
        """Count total AI investigations."""
        stmt = select(func.count(AIInvestigationHistory.id))
        if investigation_type:
            stmt = stmt.where(AIInvestigationHistory.investigation_type == investigation_type)
        result = await self.session.execute(stmt)
        return result.scalar() or 0


class AIThreatHuntRepository(BaseRepository[AIThreatHunt]):
    """Repository managing AIThreatHunt entity operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AIThreatHunt, session)

    async def list_hunts(self, skip: int = 0, limit: int = 25) -> Sequence[AIThreatHunt]:
        """Fetch paginated AI threat hunt audit logs."""
        result = await self.session.execute(
            select(AIThreatHunt).order_by(AIThreatHunt.created_at.desc()).offset(skip).limit(limit)
        )
        return result.scalars().all()

    async def count_hunts(self) -> int:
        """Count total threat hunts."""
        result = await self.session.execute(select(func.count(AIThreatHunt.id)))
        return result.scalar() or 0
