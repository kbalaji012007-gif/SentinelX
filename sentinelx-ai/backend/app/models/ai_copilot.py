"""
SentinelX AI – AI Copilot ORM Models
Schemas:
  - sentinelx.ai_chat_conversations
  - sentinelx.ai_chat_messages
  - sentinelx.ai_generated_reports
"""

import uuid
from datetime import datetime
from typing import Any
from sqlalchemy import String, Text, ForeignKey, DateTime, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class AIChatConversation(Base, TimestampMixin):
    """Conversation session for natural language AI Copilot chat."""

    __tablename__ = "ai_chat_conversations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    messages: Mapped[list["AIChatMessage"]] = relationship(
        "AIChatMessage",
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="AIChatMessage.created_at.asc()",
    )


class AIChatMessage(Base):
    """Chat message in an AI Copilot conversation."""

    __tablename__ = "ai_chat_messages"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinelx.ai_chat_conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sender: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    confidence_score: Mapped[int] = mapped_column(
        Integer,
        default=90,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    conversation: Mapped[AIChatConversation] = relationship(
        "AIChatConversation",
        back_populates="messages",
    )


class AIGeneratedReport(Base, TimestampMixin):
    """Generated security report in Markdown, JSON, and PDF formats."""

    __tablename__ = "ai_generated_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    report_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    markdown_content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    json_content: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    created_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
