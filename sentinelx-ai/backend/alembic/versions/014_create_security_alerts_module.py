"""Create security_alerts module for real-time SOC monitoring (Phase 6.4)

Revision ID: 014_security_alerts_module
Revises: 013_endpoint_agent_module
Create Date: 2026-08-13 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "014_security_alerts_module"
down_revision: Union[str, None] = "013_endpoint_agent_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.security_alerts ──────────────────────────────────
    op.create_table(
        "security_alerts",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("alert_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("alert_type", sa.String(length=100), nullable=False),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'MEDIUM'"),
        ),
        sa.Column(
            "status",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'NEW'"),
        ),
        sa.Column("source", sa.String(length=255), nullable=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("log_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("threat_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("mitre_tactic", sa.String(length=200), nullable=True),
        sa.Column("mitre_technique", sa.String(length=100), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "alert_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="ck_security_alerts_severity",
        ),
        sa.CheckConstraint(
            "status IN ('NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'DISMISSED')",
            name="ck_security_alerts_status",
        ),
        schema="sentinelx",
    )

    # ── 2. Unique constraint on alert_id ──────────────────────────────
    op.create_index(
        "idx_security_alerts_alert_id",
        "security_alerts",
        ["alert_id"],
        unique=True,
        schema="sentinelx",
    )

    # ── 3. Performance indexes ────────────────────────────────────────
    op.create_index(
        "idx_security_alerts_severity",
        "security_alerts",
        ["severity"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_security_alerts_status",
        "security_alerts",
        ["status"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_security_alerts_detected_at",
        "security_alerts",
        ["detected_at"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_security_alerts_agent_id",
        "security_alerts",
        ["agent_id"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_security_alerts_alert_type",
        "security_alerts",
        ["alert_type"],
        schema="sentinelx",
    )

    # ── 4. Updated_at trigger ─────────────────────────────────────────
    op.execute("""
        CREATE TRIGGER trigger_security_alerts_updated_at
            BEFORE UPDATE ON sentinelx.security_alerts
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # ── 5. Row Level Security ─────────────────────────────────────────
    op.execute("ALTER TABLE sentinelx.security_alerts ENABLE ROW LEVEL SECURITY;")
    op.execute(
        'CREATE POLICY "Allow authenticated read security_alerts" ON sentinelx.security_alerts '
        "FOR SELECT TO authenticated USING (true);"
    )
    op.execute(
        'CREATE POLICY "Allow service role full access to security_alerts" ON sentinelx.security_alerts '
        "FOR ALL TO service_role USING (true) WITH CHECK (true);"
    )


def downgrade() -> None:
    op.execute(
        'DROP POLICY IF EXISTS "Allow authenticated read security_alerts" ON sentinelx.security_alerts;'
    )
    op.execute(
        'DROP POLICY IF EXISTS "Allow service role full access to security_alerts" ON sentinelx.security_alerts;'
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trigger_security_alerts_updated_at ON sentinelx.security_alerts;"
    )
    op.drop_table("security_alerts", schema="sentinelx")
