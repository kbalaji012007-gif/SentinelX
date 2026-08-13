"""
SentinelX AI – Security Alert Repository Layer
Data access for real-time SOC security alerts (Phase 6.4).
"""

from uuid import UUID
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Sequence
from sqlalchemy import select, update, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_alert import SecurityAlert
from app.repositories.base_repo import BaseRepository


class SecurityAlertRepository(BaseRepository[SecurityAlert]):
    """Data access repository for SecurityAlert records."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SecurityAlert, session)

    async def get_by_alert_id(self, alert_id: str) -> Optional[SecurityAlert]:
        """Fetch alert by unique business key (used for deduplication)."""
        result = await self.session.execute(
            select(SecurityAlert).where(SecurityAlert.alert_id == alert_id)
        )
        return result.scalar_one_or_none()

    async def find_duplicate(
        self,
        alert_type: str,
        agent_id: Optional[UUID],
        window_seconds: int = 300,
    ) -> Optional[SecurityAlert]:
        """
        Find an existing non-resolved alert of the same type for the same agent
        within the deduplication window.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        conditions = [
            SecurityAlert.alert_type == alert_type,
            SecurityAlert.detected_at >= cutoff,
            SecurityAlert.status.not_in(["RESOLVED", "DISMISSED"]),
        ]
        if agent_id:
            conditions.append(SecurityAlert.agent_id == agent_id)

        result = await self.session.execute(
            select(SecurityAlert)
            .where(and_(*conditions))
            .order_by(SecurityAlert.detected_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_list(
        self,
        skip: int = 0,
        limit: int = 25,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        alert_type: Optional[str] = None,
        agent_id: Optional[UUID] = None,
        search: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Sequence[SecurityAlert]:
        """Fetch paginated, filtered security alert records."""
        stmt = select(SecurityAlert)
        conditions = self._build_conditions(
            severity, status, alert_type, agent_id, search, since, until
        )
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(SecurityAlert.detected_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_filtered(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        alert_type: Optional[str] = None,
        agent_id: Optional[UUID] = None,
        search: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> int:
        """Count alerts matching given filters."""
        stmt = select(func.count(SecurityAlert.id))
        conditions = self._build_conditions(
            severity, status, alert_type, agent_id, search, since, until
        )
        if conditions:
            stmt = stmt.where(and_(*conditions))
        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def get_recent(self, limit: int = 20) -> Sequence[SecurityAlert]:
        """Fetch the most recent N alerts ordered by detected_at DESC."""
        result = await self.session.execute(
            select(SecurityAlert)
            .order_by(SecurityAlert.detected_at.desc())
            .limit(limit)
        )
        return result.scalars().all()

    async def get_statistics(self) -> Dict[str, int]:
        """Compute aggregate statistics across all security alerts."""
        today_cutoff = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        # Total by status
        status_result = await self.session.execute(
            select(SecurityAlert.status, func.count(SecurityAlert.id))
            .group_by(SecurityAlert.status)
        )
        status_counts: Dict[str, int] = {row[0]: row[1] for row in status_result.all()}

        # Total by severity
        severity_result = await self.session.execute(
            select(SecurityAlert.severity, func.count(SecurityAlert.id))
            .group_by(SecurityAlert.severity)
        )
        severity_counts: Dict[str, int] = {row[0]: row[1] for row in severity_result.all()}

        # Alerts detected today
        today_count_result = await self.session.execute(
            select(func.count(SecurityAlert.id)).where(
                SecurityAlert.detected_at >= today_cutoff
            )
        )
        alerts_today = today_count_result.scalar_one() or 0

        # Resolved today
        resolved_today_result = await self.session.execute(
            select(func.count(SecurityAlert.id)).where(
                and_(
                    SecurityAlert.status == "RESOLVED",
                    SecurityAlert.resolved_at >= today_cutoff,
                )
            )
        )
        resolved_today = resolved_today_result.scalar_one() or 0

        total_all_result = await self.session.execute(
            select(func.count(SecurityAlert.id))
        )
        total_alerts = total_all_result.scalar_one() or 0

        return {
            "total_alerts": total_alerts,
            "new_alerts": status_counts.get("NEW", 0),
            "critical_alerts": severity_counts.get("CRITICAL", 0),
            "high_alerts": severity_counts.get("HIGH", 0),
            "medium_alerts": severity_counts.get("MEDIUM", 0),
            "low_alerts": severity_counts.get("LOW", 0),
            "alerts_today": alerts_today,
            "active_investigations": status_counts.get("INVESTIGATING", 0),
            "resolved_today": resolved_today,
            "acknowledged_alerts": status_counts.get("ACKNOWLEDGED", 0),
            "dismissed_alerts": status_counts.get("DISMISSED", 0),
        }

    async def update_status(
        self,
        alert_uuid: UUID,
        new_status: str,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> Optional[SecurityAlert]:
        """Update alert status and optional fields (acknowledged_at, resolved_at, etc.)."""
        update_data: Dict[str, Any] = {
            "status": new_status,
            "updated_at": datetime.now(timezone.utc),
        }
        if extra_fields:
            update_data.update(extra_fields)

        await self.session.execute(
            update(SecurityAlert)
            .where(SecurityAlert.id == alert_uuid)
            .values(**update_data)
        )
        await self.session.flush()

        result = await self.session.execute(
            select(SecurityAlert).where(SecurityAlert.id == alert_uuid)
        )
        return result.scalar_one_or_none()

    async def update_evidence(
        self, alert_uuid: UUID, evidence: Dict[str, Any]
    ) -> Optional[SecurityAlert]:
        """Update the evidence JSONB on an existing alert (for deduplication aggregation)."""
        await self.session.execute(
            update(SecurityAlert)
            .where(SecurityAlert.id == alert_uuid)
            .values(
                evidence=evidence,
                updated_at=datetime.now(timezone.utc),
            )
        )
        await self.session.flush()
        result = await self.session.execute(
            select(SecurityAlert).where(SecurityAlert.id == alert_uuid)
        )
        return result.scalar_one_or_none()

    # ── Internal Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_conditions(
        severity: Optional[str],
        status: Optional[str],
        alert_type: Optional[str],
        agent_id: Optional[UUID],
        search: Optional[str],
        since: Optional[datetime],
        until: Optional[datetime],
    ) -> list:
        conditions = []
        if severity:
            conditions.append(SecurityAlert.severity == severity.upper())
        if status:
            conditions.append(SecurityAlert.status == status.upper())
        if alert_type:
            conditions.append(SecurityAlert.alert_type == alert_type)
        if agent_id:
            conditions.append(SecurityAlert.agent_id == agent_id)
        if search:
            pattern = f"%{search}%"
            conditions.append(
                or_(
                    SecurityAlert.title.ilike(pattern),
                    SecurityAlert.description.ilike(pattern),
                    SecurityAlert.alert_type.ilike(pattern),
                    SecurityAlert.source.ilike(pattern),
                )
            )
        if since:
            conditions.append(SecurityAlert.detected_at >= since)
        if until:
            conditions.append(SecurityAlert.detected_at <= until)
        return conditions
