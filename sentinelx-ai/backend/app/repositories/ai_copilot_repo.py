"""
SentinelX AI – AI Copilot Repositories
Data access layer for AI Chat Conversations, Messages, and Generated Reports.
"""

from uuid import UUID
from typing import Sequence
from sqlalchemy import select, func, delete
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_copilot import AIChatConversation, AIChatMessage, AIGeneratedReport
from app.repositories.base_repo import BaseRepository


class AIChatRepository(BaseRepository[AIChatConversation]):
    """Repository managing AIChatConversation and AIChatMessage entities."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AIChatConversation, session)

    async def get_with_messages(self, conversation_id: UUID) -> AIChatConversation | None:
        """Fetch conversation with ordered chat messages."""
        result = await self.session.execute(
            select(AIChatConversation)
            .options(selectinload(AIChatConversation.messages))
            .where(AIChatConversation.id == conversation_id)
        )
        return result.scalar_one_or_none()

    async def list_user_conversations(self, skip: int = 0, limit: int = 25) -> Sequence[AIChatConversation]:
        """Fetch list of active conversation sessions."""
        result = await self.session.execute(
            select(AIChatConversation)
            .options(selectinload(AIChatConversation.messages))
            .order_by(AIChatConversation.updated_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def delete_conversation(self, conversation_id: UUID) -> bool:
        """Delete conversation by ID."""
        conv = await self.get_by_id(conversation_id)
        if not conv:
            return False
        await self.delete(conv)
        await self.session.commit()
        return True


class AIReportRepository(BaseRepository[AIGeneratedReport]):
    """Repository managing AIGeneratedReport entity operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AIGeneratedReport, session)

    async def list_reports(self, skip: int = 0, limit: int = 25) -> Sequence[AIGeneratedReport]:
        """Fetch paginated list of generated reports."""
        result = await self.session.execute(
            select(AIGeneratedReport).order_by(AIGeneratedReport.created_at.desc()).offset(skip).limit(limit)
        )
        return result.scalars().all()
