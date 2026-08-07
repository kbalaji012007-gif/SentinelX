"""Create AI SOC Module (ai_investigation_history, ai_threat_hunts in sentinelx schema)

Revision ID: 010_ai_soc_module
Revises: 009_soar_execution_module
Create Date: 2026-08-07 17:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "010_ai_soc_module"
down_revision: Union[str, None] = "009_soar_execution_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.ai_investigation_history ─────────────────────────
    op.create_table(
        "ai_investigation_history",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("investigation_type", sa.String(length=100), nullable=False),
        sa.Column("target_id", sa.String(length=255), nullable=False),
        sa.Column("executive_summary", sa.Text(), nullable=False),
        sa.Column("technical_summary", sa.Text(), nullable=False),
        sa.Column("root_cause", sa.Text(), nullable=True),
        sa.Column("mitre_mapping", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("severity", sa.String(length=50), server_default="High", nullable=False),
        sa.Column("confidence_score", sa.Integer(), server_default="85", nullable=False),
        sa.Column("recommended_actions", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("evidence_sources", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_ai_investigations_type",
        "ai_investigation_history",
        ["investigation_type"],
        schema="sentinelx",
    )

    # ── 2. sentinelx.ai_threat_hunts ───────────────────────────────────
    op.create_table(
        "ai_threat_hunts",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("hunt_type", sa.String(length=100), nullable=False),
        sa.Column("query_value", sa.String(length=500), nullable=False),
        sa.Column("findings_summary", sa.Text(), nullable=False),
        sa.Column("threat_level", sa.String(length=50), server_default="Medium", nullable=False),
        sa.Column("matched_artifacts", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column(
            "recommended_playbook_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_playbooks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_ai_threat_hunts_type",
        "ai_threat_hunts",
        ["hunt_type"],
        schema="sentinelx",
    )


def downgrade() -> None:
    op.drop_table("ai_threat_hunts", schema="sentinelx")
    op.drop_table("ai_investigation_history", schema="sentinelx")
