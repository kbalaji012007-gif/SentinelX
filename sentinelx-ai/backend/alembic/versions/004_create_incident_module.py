"""Create incident response module (incidents, incident_timeline, incident_notes, incident_evidence tables in sentinelx schema)

Revision ID: 004_incident_module
Revises: 003_threat_module
Create Date: 2026-08-03 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "004_incident_module"
down_revision: Union[str, None] = "003_threat_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.incidents ─────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("threat_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'Medium'"),
        ),
        sa.Column(
            "priority",
            sa.String(length=10),
            nullable=False,
            server_default=sa.text("'P2'"),
        ),
        sa.Column(
            "status",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'Open'"),
        ),
        sa.Column("assigned_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reported_by", sa.String(length=255), nullable=True),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
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
            name="ck_incidents_severity",
        ),
        sa.CheckConstraint(
            "priority IN ('P0', 'P1', 'P2', 'P3', 'P4')",
            name="ck_incidents_priority",
        ),
        sa.CheckConstraint(
            "status IN ('Open', 'In Progress', 'Contained', 'Resolved', 'Closed')",
            name="ck_incidents_status",
        ),
        sa.ForeignKeyConstraint(
            ["threat_id"],
            ["sentinelx.threats.id"],
            name="fk_incidents_threat",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_user_id"],
            ["sentinelx.users.id"],
            name="fk_incidents_assigned_user",
            ondelete="SET NULL",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_incidents_threat_id", "incidents", ["threat_id"], schema="sentinelx")
    op.create_index("idx_incidents_severity", "incidents", ["severity"], schema="sentinelx")
    op.create_index("idx_incidents_priority", "incidents", ["priority"], schema="sentinelx")
    op.create_index("idx_incidents_status", "incidents", ["status"], schema="sentinelx")
    op.create_index("idx_incidents_assigned_user_id", "incidents", ["assigned_user_id"], schema="sentinelx")
    op.create_index("idx_incidents_detected_at", "incidents", ["detected_at"], schema="sentinelx")

    op.execute("""
        CREATE TRIGGER trigger_incidents_updated_at
            BEFORE UPDATE ON sentinelx.incidents
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # ── 2. sentinelx.incident_timeline ───────────────────────────────
    op.create_table(
        "incident_timeline",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinelx.incidents.id"],
            name="fk_incident_timeline_incident",
            ondelete="CASCADE",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_incident_timeline_incident_id", "incident_timeline", ["incident_id"], schema="sentinelx")
    op.create_index("idx_incident_timeline_created_at", "incident_timeline", ["created_at"], schema="sentinelx")

    # ── 3. sentinelx.incident_notes ──────────────────────────────────
    op.create_table(
        "incident_notes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinelx.incidents.id"],
            name="fk_incident_notes_incident",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["sentinelx.users.id"],
            name="fk_incident_notes_author",
            ondelete="SET NULL",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_incident_notes_incident_id", "incident_notes", ["incident_id"], schema="sentinelx")
    op.create_index("idx_incident_notes_author_id", "incident_notes", ["author_id"], schema="sentinelx")
    op.create_index("idx_incident_notes_created_at", "incident_notes", ["created_at"], schema="sentinelx")

    # ── 4. sentinelx.incident_evidence ───────────────────────────────
    op.create_table(
        "incident_evidence",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_name", sa.String(length=255), nullable=False),
        sa.Column("evidence_type", sa.String(length=100), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("uploaded_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "uploaded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinelx.incidents.id"],
            name="fk_incident_evidence_incident",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by"],
            ["sentinelx.users.id"],
            name="fk_incident_evidence_uploaded_by",
            ondelete="SET NULL",
        ),
        schema="sentinelx",
    )

    op.create_index("idx_incident_evidence_incident_id", "incident_evidence", ["incident_id"], schema="sentinelx")
    op.create_index("idx_incident_evidence_uploaded_by", "incident_evidence", ["uploaded_by"], schema="sentinelx")
    op.create_index("idx_incident_evidence_uploaded_at", "incident_evidence", ["uploaded_at"], schema="sentinelx")

    # ── 5. Row Level Security ─────────────────────────────────────────
    op.execute("ALTER TABLE sentinelx.incidents ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.incident_timeline ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.incident_notes ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.incident_evidence ENABLE ROW LEVEL SECURITY;")

    for table in ["incidents", "incident_timeline", "incident_notes", "incident_evidence"]:
        op.execute(f'CREATE POLICY "Allow authenticated read {table}" ON sentinelx.{table} FOR SELECT TO authenticated USING (true);')
        op.execute(f'CREATE POLICY "Allow service role full access to {table}" ON sentinelx.{table} FOR ALL TO service_role USING (true) WITH CHECK (true);')


def downgrade() -> None:
    for table in ["incident_evidence", "incident_notes", "incident_timeline", "incidents"]:
        op.execute(f'DROP POLICY IF EXISTS "Allow authenticated read {table}" ON sentinelx.{table};')
        op.execute(f'DROP POLICY IF EXISTS "Allow service role full access to {table}" ON sentinelx.{table};')

    op.execute("DROP TRIGGER IF EXISTS trigger_incidents_updated_at ON sentinelx.incidents;")

    op.drop_table("incident_evidence", schema="sentinelx")
    op.drop_table("incident_notes", schema="sentinelx")
    op.drop_table("incident_timeline", schema="sentinelx")
    op.drop_table("incidents", schema="sentinelx")
