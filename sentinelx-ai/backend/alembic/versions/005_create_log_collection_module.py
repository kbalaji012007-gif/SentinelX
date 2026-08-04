"""Create log collection module (log_sources, log_entries tables in sentinelx schema)

Revision ID: 005_log_collection_module
Revises: 004_incident_module
Create Date: 2026-08-04 17:33:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "005_log_collection_module"
down_revision: Union[str, None] = "004_incident_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.log_sources ──────────────────────────────────────
    op.create_table(
        "log_sources",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("source_type", sa.String(length=100), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("protocol", sa.String(length=20), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'Active'"),
        ),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
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
            "source_type IN ('Syslog', 'Windows Event', 'Cloud Trail', "
            "'Firewall', 'IDS/IPS', 'Endpoint', 'Application', 'Network', 'Other')",
            name="ck_log_sources_source_type",
        ),
        sa.CheckConstraint(
            "status IN ('Active', 'Inactive', 'Error', 'Maintenance')",
            name="ck_log_sources_status",
        ),
        sa.CheckConstraint(
            "protocol IS NULL OR protocol IN ('UDP', 'TCP', 'TLS', 'HTTPS', 'HTTP')",
            name="ck_log_sources_protocol",
        ),
        sa.CheckConstraint(
            "port IS NULL OR (port >= 0 AND port <= 65535)",
            name="ck_log_sources_port",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_log_sources_source_type", "log_sources", ["source_type"], schema="sentinelx")
    op.create_index("idx_log_sources_status", "log_sources", ["status"], schema="sentinelx")

    op.execute("""
        CREATE TRIGGER trigger_log_sources_updated_at
            BEFORE UPDATE ON sentinelx.log_sources
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # ── 2. sentinelx.log_entries ──────────────────────────────────────
    op.create_table(
        "log_entries",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "event_timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "log_level",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'INFO'"),
        ),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "raw_log",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_ip", sa.String(length=45), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("event_id", sa.String(length=100), nullable=True),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.CheckConstraint(
            "log_level IN ('TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')",
            name="ck_log_entries_log_level",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sentinelx.log_sources.id"],
            name="fk_log_entries_source",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["sentinelx.assets.id"],
            name="fk_log_entries_asset",
            ondelete="SET NULL",
        ),
        schema="sentinelx",
    )

    # ── 3. Indexes (all requested + FK indexes) ──────────────────────
    op.create_index("idx_log_entries_source_id", "log_entries", ["source_id"], schema="sentinelx")
    op.create_index("idx_log_entries_asset_id", "log_entries", ["asset_id"], schema="sentinelx")
    op.create_index("idx_log_entries_event_timestamp", "log_entries", ["event_timestamp"], schema="sentinelx")
    op.create_index("idx_log_entries_log_level", "log_entries", ["log_level"], schema="sentinelx")
    op.create_index("idx_log_entries_event_type", "log_entries", ["event_type"], schema="sentinelx")
    op.create_index("idx_log_entries_category", "log_entries", ["category"], schema="sentinelx")
    op.create_index("idx_log_entries_source_ip", "log_entries", ["source_ip"], schema="sentinelx")
    op.create_index("idx_log_entries_destination_ip", "log_entries", ["destination_ip"], schema="sentinelx")
    op.create_index("idx_log_entries_username", "log_entries", ["username"], schema="sentinelx")
    op.create_index("idx_log_entries_event_id", "log_entries", ["event_id"], schema="sentinelx")
    op.create_index("idx_log_entries_correlation_id", "log_entries", ["correlation_id"], schema="sentinelx")

    # ── 4. Row Level Security ─────────────────────────────────────────
    op.execute("ALTER TABLE sentinelx.log_sources ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.log_entries ENABLE ROW LEVEL SECURITY;")

    for table in ["log_sources", "log_entries"]:
        op.execute(f'CREATE POLICY "Allow authenticated read {table}" ON sentinelx.{table} FOR SELECT TO authenticated USING (true);')
        op.execute(f'CREATE POLICY "Allow service role full access to {table}" ON sentinelx.{table} FOR ALL TO service_role USING (true) WITH CHECK (true);')


def downgrade() -> None:
    for table in ["log_entries", "log_sources"]:
        op.execute(f'DROP POLICY IF EXISTS "Allow authenticated read {table}" ON sentinelx.{table};')
        op.execute(f'DROP POLICY IF EXISTS "Allow service role full access to {table}" ON sentinelx.{table};')

    op.execute("DROP TRIGGER IF EXISTS trigger_log_sources_updated_at ON sentinelx.log_sources;")

    op.drop_table("log_entries", schema="sentinelx")
    op.drop_table("log_sources", schema="sentinelx")
