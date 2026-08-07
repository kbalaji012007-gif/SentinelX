"""Create SOAR module tables in sentinelx schema (soar_playbooks, soar_playbook_steps, soar_rules, soar_execution_history, soar_execution_logs, soar_approval_requests)

Revision ID: 008_soar_module
Revises: 007_correlation_module
Create Date: 2026-08-07 16:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "008_soar_module"
down_revision: Union[str, None] = "007_correlation_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.soar_playbooks ───────────────────────────────────
    op.create_table(
        "soar_playbooks",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("trigger_type", sa.String(length=100), server_default="Incident_Created", nullable=False),
        sa.Column("category", sa.String(length=100), server_default="Threat Response", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("author", sa.String(length=255), server_default="System Admin", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_playbooks_active",
        "soar_playbooks",
        ["is_active"],
        schema="sentinelx",
    )

    # ── 2. sentinelx.soar_playbook_steps ──────────────────────────────
    op.create_table(
        "soar_playbook_steps",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "playbook_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_playbooks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("step_order", sa.Integer(), nullable=False),
        sa.Column("step_name", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=100), nullable=False),
        sa.Column("target_type", sa.String(length=100), server_default="Asset", nullable=False),
        sa.Column("parameters", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("requires_approval", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_playbook_steps_playbook",
        "soar_playbook_steps",
        ["playbook_id"],
        schema="sentinelx",
    )

    # ── 3. sentinelx.soar_rules ────────────────────────────────────────
    op.create_table(
        "soar_rules",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("rule_name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("trigger_event", sa.String(length=100), nullable=False),
        sa.Column("condition_logic", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column(
            "playbook_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_playbooks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("execution_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_rules_active",
        "soar_rules",
        ["is_active"],
        schema="sentinelx",
    )

    # ── 4. sentinelx.soar_execution_history ───────────────────────────
    op.create_table(
        "soar_execution_history",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "playbook_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_playbooks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_rules.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("trigger_source", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), server_default="Completed", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_execution_status",
        "soar_execution_history",
        ["status"],
        schema="sentinelx",
    )

    # ── 5. sentinelx.soar_execution_logs ──────────────────────────────
    op.create_table(
        "soar_execution_logs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_execution_history.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "step_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_playbook_steps.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("log_level", sa.String(length=20), server_default="INFO", nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("output_data", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_execution_logs_exec",
        "soar_execution_logs",
        ["execution_id"],
        schema="sentinelx",
    )

    # ── 6. sentinelx.soar_approval_requests ───────────────────────────
    op.create_table(
        "soar_approval_requests",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_execution_history.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "step_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_playbook_steps.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(length=50), server_default="Pending", nullable=False),
        sa.Column("requested_by", sa.String(length=255), server_default="SOAR Engine", nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_approvals_status",
        "soar_approval_requests",
        ["status"],
        schema="sentinelx",
    )


def downgrade() -> None:
    op.drop_table("soar_approval_requests", schema="sentinelx")
    op.drop_table("soar_execution_logs", schema="sentinelx")
    op.drop_table("soar_execution_history", schema="sentinelx")
    op.drop_table("soar_rules", schema="sentinelx")
    op.drop_table("soar_playbook_steps", schema="sentinelx")
    op.drop_table("soar_playbooks", schema="sentinelx")
