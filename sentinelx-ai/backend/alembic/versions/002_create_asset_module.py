"""Create asset management module (asset_groups and assets tables in sentinelx schema)

Revision ID: 002_asset_module
Revises: 001_identity_module
Create Date: 2026-08-03 16:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "002_asset_module"
down_revision: Union[str, None] = "001_identity_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinelx.asset_groups table
    op.create_table(
        "asset_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(length=100), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        schema="sentinelx",
    )

    # Asset groups index
    op.create_index("idx_asset_groups_name", "asset_groups", ["name"], unique=True, schema="sentinelx")

    # Asset groups updated_at trigger
    op.execute("""
        CREATE TRIGGER trigger_asset_groups_updated_at
            BEFORE UPDATE ON sentinelx.asset_groups
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # 2. Create sentinelx.assets table
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_group_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False, unique=True),
        sa.Column("asset_name", sa.String(length=255), nullable=False),
        sa.Column("asset_type", sa.String(length=50), nullable=False),
        sa.Column("operating_system", sa.String(length=100), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("mac_address", sa.String(length=17), nullable=True),
        sa.Column("owner", sa.String(length=100), nullable=True),
        sa.Column("department", sa.String(length=100), nullable=True),
        sa.Column("criticality", sa.String(length=20), nullable=False, server_default=sa.text("'Medium'")),
        sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'Active'")),
        sa.Column("location", sa.String(length=100), nullable=True),
        sa.Column("serial_number", sa.String(length=100), nullable=True),
        sa.Column("tags", postgresql.JSONB(as_text=True), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.ForeignKeyConstraint(
            ["asset_group_id"],
            ["sentinelx.asset_groups.id"],
            name="fk_assets_asset_group",
            ondelete="RESTRICT",
        ),
        schema="sentinelx",
    )

    # Assets indexes
    op.create_index("idx_assets_asset_group_id", "assets", ["asset_group_id"], schema="sentinelx")
    op.create_index("idx_assets_hostname", "assets", ["hostname"], unique=True, schema="sentinelx")
    op.create_index("idx_assets_ip_address", "assets", ["ip_address"], schema="sentinelx")
    op.create_index("idx_assets_asset_type", "assets", ["asset_type"], schema="sentinelx")
    op.create_index("idx_assets_criticality", "assets", ["criticality"], schema="sentinelx")
    op.create_index("idx_assets_status", "assets", ["status"], schema="sentinelx")

    # Assets updated_at trigger
    op.execute("""
        CREATE TRIGGER trigger_assets_updated_at
            BEFORE UPDATE ON sentinelx.assets
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # 3. Enable RLS
    op.execute("ALTER TABLE sentinelx.asset_groups ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.assets ENABLE ROW LEVEL SECURITY;")

    # 4. RLS Policies
    op.execute("""
        CREATE POLICY "Allow authenticated read asset_groups"
            ON sentinelx.asset_groups FOR SELECT TO authenticated USING (true);
    """)
    op.execute("""
        CREATE POLICY "Allow service role full access to asset_groups"
            ON sentinelx.asset_groups FOR ALL TO service_role USING (true) WITH CHECK (true);
    """)
    op.execute("""
        CREATE POLICY "Allow authenticated read assets"
            ON sentinelx.assets FOR SELECT TO authenticated USING (true);
    """)
    op.execute("""
        CREATE POLICY "Allow service role full access to assets"
            ON sentinelx.assets FOR ALL TO service_role USING (true) WITH CHECK (true);
    """)


def downgrade() -> None:
    # Drop policies
    op.execute("DROP POLICY IF EXISTS \"Allow authenticated read asset_groups\" ON sentinelx.asset_groups;")
    op.execute("DROP POLICY IF EXISTS \"Allow service role full access to asset_groups\" ON sentinelx.asset_groups;")
    op.execute("DROP POLICY IF EXISTS \"Allow authenticated read assets\" ON sentinelx.assets;")
    op.execute("DROP POLICY IF EXISTS \"Allow service role full access to assets\" ON sentinelx.assets;")

    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS trigger_assets_updated_at ON sentinelx.assets;")
    op.execute("DROP TRIGGER IF EXISTS trigger_asset_groups_updated_at ON sentinelx.asset_groups;")

    # Drop tables
    op.drop_table("assets", schema="sentinelx")
    op.drop_table("asset_groups", schema="sentinelx")
