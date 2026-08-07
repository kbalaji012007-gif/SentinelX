"""Create correlation module (correlation_rules, threat_correlations, attack_chains, mitre_mappings in sentinelx schema)

Revision ID: 007_correlation_module
Revises: 006_threat_intelligence_module
Create Date: 2026-08-07 16:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "007_correlation_module"
down_revision: Union[str, None] = "006_threat_intelligence_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. sentinelx.correlation_rules ────────────────────────────────
    op.create_table(
        "correlation_rules",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("rule_name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("rule_type", sa.String(length=100), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("severity", sa.String(length=50), server_default="Medium", nullable=False),
        sa.Column("condition_logic", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("execution_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_correlation_rules_active",
        "correlation_rules",
        ["is_active"],
        schema="sentinelx",
    )

    # ── 2. sentinelx.threat_correlations ──────────────────────────────
    op.create_table(
        "threat_correlations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("correlation_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=50), server_default="Medium", nullable=False),
        sa.Column("risk_score", sa.Integer(), server_default="50", nullable=False),
        sa.Column("confidence_score", sa.Integer(), server_default="80", nullable=False),
        sa.Column("evidence", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "threat_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.threats.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("ioc_value", sa.String(length=500), nullable=True),
        sa.Column(
            "rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.correlation_rules.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("correlation_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_threat_correlations_type",
        "threat_correlations",
        ["correlation_type"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_threat_correlations_severity",
        "threat_correlations",
        ["severity"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_threat_correlations_created",
        "threat_correlations",
        ["created_at"],
        schema="sentinelx",
    )

    # ── 3. sentinelx.attack_chains ────────────────────────────────────
    op.create_table(
        "attack_chains",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("chain_name", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=50), server_default="High", nullable=False),
        sa.Column("overall_risk_score", sa.Integer(), server_default="75", nullable=False),
        sa.Column("overall_confidence_score", sa.Integer(), server_default="85", nullable=False),
        sa.Column("entry_point", sa.String(length=255), nullable=True),
        sa.Column(
            "target_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinelx.assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("stages_json", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("status", sa.String(length=50), server_default="Active", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_attack_chains_status",
        "attack_chains",
        ["status"],
        schema="sentinelx",
    )

    # ── 4. sentinelx.mitre_mappings ───────────────────────────────────
    op.create_table(
        "mitre_mappings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("entity_type", sa.String(length=100), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("technique_id", sa.String(length=50), nullable=False),
        sa.Column("tactic", sa.String(length=100), nullable=False),
        sa.Column("confidence_score", sa.Integer(), server_default="80", nullable=False),
        sa.Column("evidence", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="sentinelx",
    )
    op.create_index(
        "idx_mitre_mappings_entity",
        "mitre_mappings",
        ["entity_type", "entity_id"],
        schema="sentinelx",
    )
    op.create_index(
        "idx_mitre_mappings_technique",
        "mitre_mappings",
        ["technique_id"],
        schema="sentinelx",
    )


def downgrade() -> None:
    op.drop_table("mitre_mappings", schema="sentinelx")
    op.drop_table("attack_chains", schema="sentinelx")
    op.drop_table("threat_correlations", schema="sentinelx")
    op.drop_table("correlation_rules", schema="sentinelx")
