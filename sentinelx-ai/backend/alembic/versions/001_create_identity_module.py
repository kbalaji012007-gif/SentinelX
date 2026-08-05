"""Create identity module (roles and users tables in sentinelx schema)

Revision ID: 001_identity_module
Revises:
Create Date: 2026-08-03 16:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001_identity_module"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinelx schema
    op.execute("CREATE SCHEMA IF NOT EXISTS sentinelx")

    # 2. Create sentinelx.set_updated_at function
    op.execute("""
        CREATE OR REPLACE FUNCTION sentinelx.set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # 3. Create sentinelx.roles table
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(length=50), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("permissions", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_system_role", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        schema="sentinelx",
    )

    # Roles index
    op.create_index("idx_roles_name", "roles", ["name"], unique=True, schema="sentinelx")

    # Roles updated_at trigger
    op.execute("""
        CREATE TRIGGER trigger_roles_updated_at
            BEFORE UPDATE ON sentinelx.roles
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # 4. Create sentinelx.users table
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("first_name", sa.String(length=100), nullable=False),
        sa.Column("last_name", sa.String(length=100), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("phone", sa.String(length=50), nullable=True),
        sa.Column("avatar_url", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["sentinelx.roles.id"],
            name="fk_users_role",
            ondelete="RESTRICT",
        ),
        schema="sentinelx",
    )

    # Users indexes
    op.create_index("idx_users_role_id", "users", ["role_id"], schema="sentinelx")
    op.create_index("idx_users_email", "users", ["email"], unique=True, schema="sentinelx")
    op.create_index("idx_users_is_active", "users", ["is_active"], schema="sentinelx")

    # Users updated_at trigger
    op.execute("""
        CREATE TRIGGER trigger_users_updated_at
            BEFORE UPDATE ON sentinelx.users
            FOR EACH ROW
            EXECUTE FUNCTION sentinelx.set_updated_at();
    """)

    # 5. Enable RLS
    op.execute("ALTER TABLE sentinelx.roles ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE sentinelx.users ENABLE ROW LEVEL SECURITY;")

    # 6. RLS Policies
    op.execute("""
        CREATE POLICY "Allow authenticated read roles"
            ON sentinelx.roles FOR SELECT TO authenticated USING (true);
    """)
    op.execute("""
        CREATE POLICY "Allow service role full access to roles"
            ON sentinelx.roles FOR ALL TO service_role USING (true) WITH CHECK (true);
    """)
    op.execute("""
        CREATE POLICY "Allow users to read own profile"
            ON sentinelx.users FOR SELECT TO authenticated USING (auth.uid() = id);
    """)
    op.execute("""
        CREATE POLICY "Allow service role full access to users"
            ON sentinelx.users FOR ALL TO service_role USING (true) WITH CHECK (true);
    """)


def downgrade() -> None:
    # Drop policies
    op.execute("DROP POLICY IF EXISTS \"Allow authenticated read roles\" ON sentinelx.roles;")
    op.execute("DROP POLICY IF EXISTS \"Allow service role full access to roles\" ON sentinelx.roles;")
    op.execute("DROP POLICY IF EXISTS \"Allow users to read own profile\" ON sentinelx.users;")
    op.execute("DROP POLICY IF EXISTS \"Allow service role full access to users\" ON sentinelx.users;")

    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS trigger_users_updated_at ON sentinelx.users;")
    op.execute("DROP TRIGGER IF EXISTS trigger_roles_updated_at ON sentinelx.roles;")

    # Drop tables
    op.drop_table("users", schema="sentinelx")
    op.drop_table("roles", schema="sentinelx")

    # Drop function
    op.execute("DROP FUNCTION IF EXISTS sentinelx.set_updated_at();")
