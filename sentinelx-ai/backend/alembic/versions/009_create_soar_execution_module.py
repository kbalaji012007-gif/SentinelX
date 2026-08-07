"""Create SOAR Execution Module (soar_response_actions, soar_execution_steps, soar_execution_results, soar_connector_status, soar_webhooks, soar_notifications in sentinelx schema)

Revision ID: 009_soar_execution_module
Revises: 008_soar_module
Create Date: 2026-08-07 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "009_soar_execution_module"
down_revision: Union[str, None] = "008_soar_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.soar_response_actions ───────────────────────────
    op.create_table(
        "soar_response_actions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("action_name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("action_type", sa.String(length=100), nullable=False),
        sa.Column("target_type", sa.String(length=100), server_default="Asset", nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("supports_rollback", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("supports_dry_run", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_response_actions_type",
        "soar_response_actions",
        ["action_type"],
        schema="sentinelx",
    )

    # ── 2. sentinelx.soar_execution_steps ─────────────────────────────
    op.create_table(
        "soar_execution_steps",
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
        sa.Column("step_name", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), server_default="Pending", nullable=False),
        sa.Column("is_dry_run", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("parameters", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_execution_steps_exec",
        "soar_execution_steps",
        ["execution_id"],
        schema="sentinelx",
    )

    # ── 3. sentinelx.soar_execution_results ───────────────────────────
    op.create_table(
        "soar_execution_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "execution_step_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.soar_execution_steps.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=50), server_default="Success", nullable=False),
        sa.Column("output_payload", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("execution_time_ms", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rollback_data", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_execution_results_step",
        "soar_execution_results",
        ["execution_step_id"],
        schema="sentinelx",
    )

    # ── 4. sentinelx.soar_connector_status ───────────────────────────
    op.create_table(
        "soar_connector_status",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("connector_name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("connector_type", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), server_default="Online", nullable=False),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("details", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_connector_status",
        "soar_connector_status",
        ["status"],
        schema="sentinelx",
    )

    # ── 5. sentinelx.soar_webhooks ─────────────────────────────────────
    op.create_table(
        "soar_webhooks",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("target_url", sa.String(length=500), nullable=False),
        sa.Column("http_method", sa.String(length=10), server_default="POST", nullable=False),
        sa.Column("headers", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )

    # ── 6. sentinelx.soar_notifications ──────────────────────────────
    op.create_table(
        "soar_notifications",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("channel", sa.String(length=50), nullable=False),
        sa.Column("recipient", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=True),
        sa.Column("message_body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=50), server_default="Sent", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_soar_notifications_status",
        "soar_notifications",
        ["status"],
        schema="sentinelx",
    )


def downgrade() -> None:
    op.drop_table("soar_notifications", schema="sentinelx")
    op.drop_table("soar_webhooks", schema="sentinelx")
    op.drop_table("soar_connector_status", schema="sentinelx")
    op.drop_table("soar_execution_results", schema="sentinelx")
    op.drop_table("soar_execution_steps", schema="sentinelx")
    op.drop_table("soar_response_actions", schema="sentinelx")
