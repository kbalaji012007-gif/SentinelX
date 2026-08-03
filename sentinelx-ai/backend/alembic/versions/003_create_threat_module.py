"""Create threat detection module (threats, alerts, ioc tables in sentinelx schema)

Revision ID: 003_threat_module
Revises: 002_asset_module
Create Date: 2026-08-03 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "003_threat_module"
down_revision: Union[str, None] = "002_asset_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.threats ─────────────────────────────────────────
    op.create_table(
        "threats",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'Medium'"),
        ),
        sa.Column("confidence_score", sa.Numeric(5, 2), nullable=True),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'New'"),
        ),
        sa.Column("source", sa.String(length=255), nullable=True),
        sa.Column("mitre_technique_id", sa.String(length=50), nullable=True),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
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
            "severity IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_threats_severity",
        ),
        sa.CheckConstraint(
            "status IN ('New', 'Investigating', 'Mitigated', 'Closed')",
            name="ck_threats_status",
        ),
        sa.CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_threats_confidence_score",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["sentinelx.assets.id"],
            name="fk_threats_asset",
            ondelete="SET NULL",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_threats_asset_id", "threats", ["asset_id"], schema="sentinelx")
    op.create_index("idx_threats_severity", "threats", ["severity"], schema="sentinelx")
    op.create_index("idx_threats_status", "threats", ["status"], schema="sentinelx")
    op.create_index(
        "idx_threats_detected_at", "threats", ["detected_at"], schema="sentinelx"
    )
    op.create_index(
        "idx_threats_mitre_technique_id",
        "threats",
        ["mitre_technique_id"],
        schema="sentinelx",
    )

    op.execute("""
        CREATE TRIGGER trigger_threats_updated_at
            BEFORE UPDATE ON sentinelx.threats
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # ── 2. sentinelx.alerts ──────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("threat_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_name", sa.String(length=500), nullable=False),
        sa.Column("alert_type", sa.String(length=100), nullable=True),
        sa.Column("alert_source", sa.String(length=255), nullable=True),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'Medium'"),
        ),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "raw_event",
            postgresql.JSONB(as_text=True),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "acknowledged",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
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
            "severity IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_alerts_severity",
        ),
        sa.ForeignKeyConstraint(
            ["threat_id"],
            ["sentinelx.threats.id"],
            name="fk_alerts_threat",
            ondelete="CASCADE",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_alerts_threat_id", "alerts", ["threat_id"], schema="sentinelx")
    op.create_index("idx_alerts_severity", "alerts", ["severity"], schema="sentinelx")
    op.create_index(
        "idx_alerts_acknowledged", "alerts", ["acknowledged"], schema="sentinelx"
    )
    op.create_index(
        "idx_alerts_created_at", "alerts", ["created_at"], schema="sentinelx"
    )

    op.execute("""
        CREATE TRIGGER trigger_alerts_updated_at
            BEFORE UPDATE ON sentinelx.alerts
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # ── 3. sentinelx.ioc ─────────────────────────────────────────────
    op.create_table(
        "ioc",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("threat_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("type", sa.String(length=20), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("reputation", sa.String(length=50), nullable=True),
        sa.Column("confidence", sa.Numeric(5, 2), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
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
            "type IN ('IP', 'Domain', 'URL', 'Hash', 'Email')",
            name="ck_ioc_type",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name="ck_ioc_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["threat_id"],
            ["sentinelx.threats.id"],
            name="fk_ioc_threat",
            ondelete="CASCADE",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_ioc_threat_id", "ioc", ["threat_id"], schema="sentinelx")
    op.create_index("idx_ioc_type", "ioc", ["type"], schema="sentinelx")
    op.create_index("idx_ioc_value", "ioc", ["value"], schema="sentinelx")
    op.create_index("idx_ioc_last_seen", "ioc", ["last_seen"], schema="sentinelx")

    op.execute("""
        CREATE TRIGGER trigger_ioc_updated_at
            BEFORE UPDATE ON sentinelx.ioc
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # ── 4. Row Level Security ─────────────────────────────────────────
    op.execute("ALTER TABLE sentinelx.threats ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.alerts ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.ioc ENABLE ROW LEVEL SECURITY;")

    # Threats RLS
    op.execute("""
        CREATE POLICY "Allow authenticated read threats"
            ON sentinelx.threats FOR SELECT TO authenticated USING (true);
    """)
    op.execute("""
        CREATE POLICY "Allow service role full access to threats"
            ON sentinelx.threats FOR ALL TO service_role USING (true) WITH CHECK (true);
    """)

    # Alerts RLS
    op.execute("""
        CREATE POLICY "Allow authenticated read alerts"
            ON sentinelx.alerts FOR SELECT TO authenticated USING (true);
    """)
    op.execute("""
        CREATE POLICY "Allow service role full access to alerts"
            ON sentinelx.alerts FOR ALL TO service_role USING (true) WITH CHECK (true);
    """)

    # IOC RLS
    op.execute("""
        CREATE POLICY "Allow authenticated read ioc"
            ON sentinelx.ioc FOR SELECT TO authenticated USING (true);
    """)
    op.execute("""
        CREATE POLICY "Allow service role full access to ioc"
            ON sentinelx.ioc FOR ALL TO service_role USING (true) WITH CHECK (true);
    """)


def downgrade() -> None:
    # Drop RLS policies
    op.execute('DROP POLICY IF EXISTS "Allow authenticated read ioc" ON sentinelx.ioc;')
    op.execute('DROP POLICY IF EXISTS "Allow service role full access to ioc" ON sentinelx.ioc;')
    op.execute('DROP POLICY IF EXISTS "Allow authenticated read alerts" ON sentinelx.alerts;')
    op.execute('DROP POLICY IF EXISTS "Allow service role full access to alerts" ON sentinelx.alerts;')
    op.execute('DROP POLICY IF EXISTS "Allow authenticated read threats" ON sentinelx.threats;')
    op.execute('DROP POLICY IF EXISTS "Allow service role full access to threats" ON sentinelx.threats;')

    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS trigger_ioc_updated_at ON sentinelx.ioc;")
    op.execute("DROP TRIGGER IF EXISTS trigger_alerts_updated_at ON sentinelx.alerts;")
    op.execute("DROP TRIGGER IF EXISTS trigger_threats_updated_at ON sentinelx.threats;")

    # Drop tables (cascade order: child tables first)
    op.drop_table("ioc", schema="sentinelx")
    op.drop_table("alerts", schema="sentinelx")
    op.drop_table("threats", schema="sentinelx")
