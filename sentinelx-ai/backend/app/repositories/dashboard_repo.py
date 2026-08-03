"""
SentinelX AI – Dashboard Repository
Queries database tables in sentinelx schema for dashboard aggregation statistics.
Includes live threat, alert, and asset metric queries.
"""

from typing import Any
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.user import User
from app.models.threat import Threat, Alert


class DashboardRepository:
    """Repository collecting metric aggregations from the sentinelx schema."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ── Asset metrics ────────────────────────────────────────────────

    async def get_asset_count(self) -> int:
        """Count total assets in sentinelx.assets."""
        result = await self.session.execute(
            select(func.count()).select_from(Asset)
        )
        return result.scalar_one() or 0

    async def get_user_count(self) -> int:
        """Count total registered users."""
        result = await self.session.execute(
            select(func.count()).select_from(User)
        )
        return result.scalar_one() or 0

    async def get_active_user_count(self) -> int:
        """Count active users."""
        result = await self.session.execute(
            select(func.count()).select_from(User).where(User.is_active.is_(True))
        )
        return result.scalar_one() or 0

    # ── Threat metrics ───────────────────────────────────────────────

    async def get_active_threat_count(self) -> int:
        """Count threats with status 'New' or 'Investigating'."""
        result = await self.session.execute(
            select(func.count()).select_from(Threat).where(
                Threat.status.in_(["New", "Investigating"])
            )
        )
        return result.scalar_one() or 0

    async def get_threat_count(self) -> int:
        """Count all threats."""
        result = await self.session.execute(
            select(func.count()).select_from(Threat)
        )
        return result.scalar_one() or 0

    async def get_severity_distribution(self) -> list[dict[str, Any]]:
        """Return threat counts grouped by severity for the pie chart."""
        result = await self.session.execute(
            select(Threat.severity, func.count(Threat.id).label("value"))
            .group_by(Threat.severity)
        )
        color_map = {
            "Critical": "#ff1744",
            "High": "#ff6d00",
            "Medium": "#ffd600",
            "Low": "#448aff",
        }
        rows = result.all()
        return [
            {"name": row[0], "value": row[1], "color": color_map.get(row[0], "#888")}
            for row in rows
        ]

    async def get_recent_threats(self, limit: int = 5) -> list[dict[str, Any]]:
        """Fetch the most recent threats for the activity feed."""
        result = await self.session.execute(
            select(Threat)
            .order_by(Threat.detected_at.desc())
            .limit(limit)
        )
        threats = result.scalars().all()
        return [
            {
                "id": str(t.id),
                "name": t.title,
                "severity": t.severity,
                "source_ip": t.source or "N/A",
                "target_asset": str(t.asset_id) if t.asset_id else "N/A",
                "mitre_id": t.mitre_technique_id or "N/A",
                "status": t.status,
                "detected_at": t.detected_at.isoformat(),
            }
            for t in threats
        ]

    # ── Alert metrics ────────────────────────────────────────────────

    async def get_critical_alert_count(self) -> int:
        """Count unacknowledged critical alerts."""
        result = await self.session.execute(
            select(func.count()).select_from(Alert).where(
                Alert.severity == "Critical",
            )
        )
        return result.scalar_one() or 0

    async def get_alert_count(self) -> int:
        """Count all alerts."""
        result = await self.session.execute(
            select(func.count()).select_from(Alert)
        )
        return result.scalar_one() or 0

    # ── Incident metrics ─────────────────────────────────────────────

    async def get_open_incident_count(self) -> int:
        """Count open and in progress incidents."""
        from app.models.incident import Incident
        result = await self.session.execute(
            select(func.count()).select_from(Incident).where(
                Incident.status.in_(["Open", "In Progress"])
            )
        )
        return result.scalar_one() or 0
