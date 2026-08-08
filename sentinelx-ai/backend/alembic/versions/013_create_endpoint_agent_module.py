"""Create endpoint agent module (endpoint_agents, agent_telemetry tables in sentinelx schema)

Revision ID: 013_endpoint_agent_module
Revises: 012_user_management_roles
Create Date: 2026-08-08 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "013_endpoint_agent_module"
down_revision: Union[str, None] = "012_user_management_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.endpoint_agents ──────────────────────────────────
    op.create_table(
        "endpoint_agents",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("agent_id", sa.String(length=100), nullable=False, unique=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("platform", sa.String(length=100), nullable=False),
        sa.Column("os_version", sa.String(length=255), nullable=True),
        sa.Column("agent_version", sa.String(length=50), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'Online'"),
        ),
        sa.Column(
            "enrolled_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
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
            "status IN ('Online', 'Offline', 'Stale', 'Disabled', 'Revoked', 'Never Seen')",
            name="ck_endpoint_agents_status",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_endpoint_agents_agent_id", "endpoint_agents", ["agent_id"], unique=True, schema="sentinelx")
    op.create_index("idx_endpoint_agents_hostname", "endpoint_agents", ["hostname"], schema="sentinelx")
    op.create_index("idx_endpoint_agents_status", "endpoint_agents", ["status"], schema="sentinelx")

    op.execute("""
        CREATE TRIGGER trigger_endpoint_agents_updated_at
            BEFORE UPDATE ON sentinelx.endpoint_agents
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # ── 2. sentinelx.agent_telemetry ──────────────────────────────────
    op.create_table(
        "agent_telemetry",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'INFO'"),
        ),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("source", sa.String(length=100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.CheckConstraint(
            "severity IN ('TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')",
            name="ck_agent_telemetry_severity",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["sentinelx.endpoint_agents.id"],
            name="fk_agent_telemetry_agent",
            ondelete="CASCADE",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_agent_telemetry_agent_id", "agent_telemetry", ["agent_id"], schema="sentinelx")
    op.create_index("idx_agent_telemetry_event_type", "agent_telemetry", ["event_type"], schema="sentinelx")
    op.create_index("idx_agent_telemetry_event_timestamp", "agent_telemetry", ["event_timestamp"], schema="sentinelx")
    op.create_index("idx_agent_telemetry_severity", "agent_telemetry", ["severity"], schema="sentinelx")

    # ── 3. Row Level Security ─────────────────────────────────────────
    op.execute("ALTER TABLE sentinelx.endpoint_agents ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.agent_telemetry ENABLE ROW LEVEL SECURITY;")

    for table in ["endpoint_agents", "agent_telemetry"]:
        op.execute(f'CREATE POLICY "Allow authenticated read {table}" ON sentinelx.{table} FOR SELECT TO authenticated USING (true);')
        op.execute(f'CREATE POLICY "Allow service role full access to {table}" ON sentinelx.{table} FOR ALL TO service_role USING (true) WITH CHECK (true);')


def downgrade() -> None:
    for table in ["agent_telemetry", "endpoint_agents"]:
        op.execute(f'DROP POLICY IF EXISTS "Allow authenticated read {table}" ON sentinelx.{table};')
        op.execute(f'DROP POLICY IF EXISTS "Allow service role full access to {table}" ON sentinelx.{table};')

    op.execute("DROP TRIGGER IF EXISTS trigger_endpoint_agents_updated_at ON sentinelx.endpoint_agents;")

    op.drop_table("agent_telemetry", schema="sentinelx")
    op.drop_table("endpoint_agents", schema="sentinelx")
