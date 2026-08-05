"""Create threat intelligence module (threat_feeds, ioc_feeds, ioc_reputation, mitre_attack, threat_intelligence_cache in sentinelx schema)

Revision ID: 006_threat_intelligence_module
Revises: 005_log_collection_module
Create Date: 2026-08-05 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "006_threat_intelligence_module"
down_revision: Union[str, None] = "005_log_collection_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.threat_feeds ────────────────────────────────────
    op.create_table(
        "threat_feeds",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("feed_name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("feed_type", sa.String(length=100), nullable=False),
        sa.Column("provider", sa.String(length=255), nullable=False),
        sa.Column("feed_url", sa.Text(), nullable=True),
        sa.Column("api_key_required", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("reliability_score", sa.Integer(), server_default="80", nullable=False),
        sa.Column("confidence_score", sa.Integer(), server_default="80", nullable=False),
        sa.Column("status", sa.String(length=50), server_default="Active", nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("last_fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_indicators", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_threat_feeds_status",
        "threat_feeds",
        ["status"],
        schema="sentinelx",
    )

    # ── 2. sentinelx.ioc_feeds ───────────────────────────────────────
    op.create_table(
        "ioc_feeds",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "feed_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.threat_feeds.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("ioc_type", sa.String(length=50), nullable=False),
        sa.Column("value", sa.String(length=500), nullable=False),
        sa.Column("severity", sa.String(length=50), server_default="Medium", nullable=False),
        sa.Column("threat_type", sa.String(length=100), server_default="Malware", nullable=False),
        sa.Column("confidence", sa.Integer(), server_default="80", nullable=False),
        sa.Column("tags", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("raw_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expiration_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_ioc_feeds_type_val",
        "ioc_feeds",
        ["ioc_type", "value"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_ioc_feeds_feed_id",
        "ioc_feeds",
        ["feed_id"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_ioc_feeds_severity",
        "ioc_feeds",
        ["severity"],
        schema="sentinelx",
    )

    # ── 3. sentinelx.ioc_reputation ──────────────────────────────────
    op.create_table(
        "ioc_reputation",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("ioc_value", sa.String(length=500), nullable=False, unique=True),
        sa.Column("ioc_type", sa.String(length=50), nullable=False),
        sa.Column("reputation_score", sa.Integer(), server_default="50", nullable=False),
        sa.Column("verdict", sa.String(length=50), server_default="Unknown", nullable=False),
        sa.Column("threat_category", sa.String(length=100), nullable=True),
        sa.Column("source_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("last_analyzed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("details", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_ioc_reputation_verdict",
        "ioc_reputation",
        ["verdict"],
        schema="sentinelx",
    )

    # ── 4. sentinelx.mitre_attack ─────────────────────────────────────
    op.create_table(
        "mitre_attack",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("technique_id", sa.String(length=50), nullable=False, unique=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("tactic", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("platforms", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("data_sources", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("detection_methods", sa.Text(), nullable=True),
        sa.Column("mitigation", sa.Text(), nullable=True),
        sa.Column("is_subtechnique", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("parent_technique_id", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_mitre_attack_tactic",
        "mitre_attack",
        ["tactic"],
        schema="sentinelx",
    )

    # ── 5. sentinelx.threat_intelligence_cache ───────────────────────
    op.create_table(
        "threat_intelligence_cache",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("query_key", sa.String(length=255), nullable=False, unique=True),
        sa.Column("query_type", sa.String(length=100), nullable=False),
        sa.Column("response_data", postgresql.JSONB(), nullable=False),
        sa.Column("ttl_seconds", sa.Integer(), server_default="3600", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_threat_intel_cache_key",
        "threat_intelligence_cache",
        ["query_key"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_threat_intel_cache_expires",
        "threat_intelligence_cache",
        ["expires_at"],
        schema="sentinelx",
    )


def downgrade() -> None:
    op.drop_table("threat_intelligence_cache", schema="sentinelx")
    op.drop_table("mitre_attack", schema="sentinelx")
    op.drop_table("ioc_reputation", schema="sentinelx")
    op.drop_table("ioc_feeds", schema="sentinelx")
    op.drop_table("threat_feeds", schema="sentinelx")
