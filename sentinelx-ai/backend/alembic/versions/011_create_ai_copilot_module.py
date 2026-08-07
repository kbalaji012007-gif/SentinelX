"""Create AI Copilot Module (ai_chat_conversations, ai_chat_messages, ai_generated_reports in sentinelx schema)

Revision ID: 011_ai_copilot_module
Revises: 010_ai_soc_module
Create Date: 2026-08-07 18:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "011_ai_copilot_module"
down_revision: Union[str, None] = "010_ai_soc_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.ai_chat_conversations ────────────────────────────
    op.create_table(
        "ai_chat_conversations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )

    # ── 2. sentinelx.ai_chat_messages ─────────────────────────────────
    op.create_table(
        "ai_chat_messages",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "conversation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.ai_chat_conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sender", sa.String(length=50), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("confidence_score", sa.Integer(), server_default="90", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_ai_messages_conv",
        "ai_chat_messages",
        ["conversation_id"],
        schema="sentinelx",
    )

    # ── 3. sentinelx.ai_generated_reports ─────────────────────────────
    op.create_table(
        "ai_generated_reports",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("report_type", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("markdown_content", sa.Text(), nullable=False),
        sa.Column("json_content", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_ai_reports_type",
        "ai_generated_reports",
        ["report_type"],
        schema="sentinelx",
    )


def downgrade() -> None:
    op.drop_table("ai_generated_reports", schema="sentinelx")
    op.drop_table("ai_chat_messages", schema="sentinelx")
    op.drop_table("ai_chat_conversations", schema="sentinelx")
