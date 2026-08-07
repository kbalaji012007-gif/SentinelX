"""Seed User Management Roles in sentinelx.roles

Revision ID: 012_user_management_roles
Revises: 011_ai_copilot_module
Create Date: 2026-08-07 18:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "012_user_management_roles"
down_revision: Union[str, None] = "011_ai_copilot_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ROLES = [
    ("Super Administrator", "Full unrestricted access across all SentinelX AI modules and settings"),
    ("Administrator", "Administrative access to SOC operations, configurations, and users"),
    ("SOC Manager", "SOC operational management, incident approvals, and playbooks"),
    ("SOC Analyst", "Threat monitoring, incident triage, and correlation analysis"),
    ("Threat Hunter", "Proactive threat hunting, IOC queries, and deep forensics"),
    ("Incident Responder", "Incident response execution, SOAR triggers, and containment"),
    ("Auditor", "Read-only access to audit logs, compliance reports, and history"),
    ("Read Only", "View-only access to general dashboards and non-sensitive telemetry"),
]


def upgrade() -> None:
    conn = op.get_bind()
    for name, desc in ROLES:
        conn.execute(
            sa.text(
                """
                INSERT INTO sentinelx.roles (id, name, description, created_at, updated_at)
                VALUES (gen_random_uuid(), :name, :desc, now(), now())
                ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
                """
            ),
            {"name": name, "desc": desc},
        )


def downgrade() -> None:
    pass
