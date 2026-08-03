"""
SentinelX AI – Threat Detection Repositories
Data access layer for sentinelx.threats, sentinelx.alerts, sentinelx.ioc.
"""

from uuid import UUID
from typing import Sequence
from decimal import Decimal
from datetime import datetime

from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat import Threat, Alert, IOC
from app.repositories.base_repo import BaseRepository


# ────────────────────────────────────────────────────────────────────────
# Threat Repository
# ────────────────────────────────────────────────────────────────────────

class ThreatRepository(BaseRepository[Threat]):
    """Repository managing Threat entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Threat, session)

    async def get_by_id_with_relations(self, id: UUID) -> Threat | None:
        """Fetch a threat with its alerts and IOCs eagerly loaded."""
        result = await self.session.execute(
            select(Threat)
            .options(
                selectinload(Threat.alerts),
                selectinload(Threat.iocs),
            )
            .where(Threat.id == id)
        )
        return result.scalar_one_or_none()

    async def get_list(
        self,
        skip: int = 0,
        limit: int = 25,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
        asset_id: UUID | None = None,
    ) -> Sequence[Threat]:
        """
        Paginated threat list with optional filtering by severity, status,
        asset, and free-text search over title and source.
        """
        stmt = select(Threat)

        filters = []
        if severity:
            filters.append(Threat.severity == severity)
        if status:
            filters.append(Threat.status == status)
        if asset_id:
            filters.append(Threat.asset_id == asset_id)
        if search:
            pattern = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(Threat.title).like(pattern),
                    func.lower(Threat.source).like(pattern),
                    func.lower(Threat.mitre_technique_id).like(pattern),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        stmt = stmt.order_by(Threat.detected_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_filtered(
        self,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
        asset_id: UUID | None = None,
    ) -> int:
        """Count threats matching the given filters."""
        stmt = select(func.count()).select_from(Threat)

        filters = []
        if severity:
            filters.append(Threat.severity == severity)
        if status:
            filters.append(Threat.status == status)
        if asset_id:
            filters.append(Threat.asset_id == asset_id)
        if search:
            pattern = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(Threat.title).like(pattern),
                    func.lower(Threat.source).like(pattern),
                    func.lower(Threat.mitre_technique_id).like(pattern),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def get_by_severity(
        self, severity: str, skip: int = 0, limit: int = 100
    ) -> Sequence[Threat]:
        """Fetch threats filtered by severity level."""
        result = await self.session.execute(
            select(Threat)
            .where(Threat.severity == severity)
            .order_by(Threat.detected_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_status(
        self, status: str, skip: int = 0, limit: int = 100
    ) -> Sequence[Threat]:
        """Fetch threats filtered by status."""
        result = await self.session.execute(
            select(Threat)
            .where(Threat.status == status)
            .order_by(Threat.detected_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_active_count(self) -> int:
        """Count threats with status New or Investigating (active)."""
        result = await self.session.execute(
            select(func.count()).select_from(Threat).where(
                Threat.status.in_(["New", "Investigating"])
            )
        )
        return result.scalar_one() or 0

    async def get_severity_distribution(self) -> dict[str, int]:
        """Return count of threats grouped by severity."""
        result = await self.session.execute(
            select(Threat.severity, func.count(Threat.id))
            .group_by(Threat.severity)
        )
        return {row[0]: row[1] for row in result.all()}

    async def get_status_distribution(self) -> dict[str, int]:
        """Return count of threats grouped by status."""
        result = await self.session.execute(
            select(Threat.status, func.count(Threat.id))
            .group_by(Threat.status)
        )
        return {row[0]: row[1] for row in result.all()}

    async def get_recent(self, limit: int = 5) -> Sequence[Threat]:
        """Fetch the most recently detected threats."""
        result = await self.session.execute(
            select(Threat)
            .order_by(Threat.detected_at.desc())
            .limit(limit)
        )
        return result.scalars().all()


# ────────────────────────────────────────────────────────────────────────
# Alert Repository
# ────────────────────────────────────────────────────────────────────────

class AlertRepository(BaseRepository[Alert]):
    """Repository managing Alert entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Alert, session)

    async def get_by_threat_id(
        self, threat_id: UUID, skip: int = 0, limit: int = 100
    ) -> Sequence[Alert]:
        """Fetch all alerts for a given threat."""
        result = await self.session.execute(
            select(Alert)
            .where(Alert.threat_id == threat_id)
            .order_by(Alert.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_unacknowledged(
        self, skip: int = 0, limit: int = 100
    ) -> Sequence[Alert]:
        """Fetch all unacknowledged alerts."""
        result = await self.session.execute(
            select(Alert)
            .where(Alert.acknowledged.is_(False))
            .order_by(Alert.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def acknowledge(self, id: UUID) -> Alert | None:
        """Mark an alert as acknowledged."""
        return await self.update(id, {"acknowledged": True})

    async def get_critical_count(self) -> int:
        """Count unacknowledged critical alerts."""
        result = await self.session.execute(
            select(func.count()).select_from(Alert).where(
                and_(
                    Alert.severity == "Critical",
                    Alert.acknowledged.is_(False),
                )
            )
        )
        return result.scalar_one() or 0

    async def get_list_filtered(
        self,
        threat_id: UUID | None = None,
        severity: str | None = None,
        acknowledged: bool | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Sequence[Alert]:
        """Paginated alert list with optional filters."""
        stmt = select(Alert)
        filters = []
        if threat_id:
            filters.append(Alert.threat_id == threat_id)
        if severity:
            filters.append(Alert.severity == severity)
        if acknowledged is not None:
            filters.append(Alert.acknowledged.is_(acknowledged))
        if filters:
            stmt = stmt.where(and_(*filters))
        stmt = stmt.order_by(Alert.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()


# ────────────────────────────────────────────────────────────────────────
# IOC Repository
# ────────────────────────────────────────────────────────────────────────

class IOCRepository(BaseRepository[IOC]):
    """Repository managing IOC entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(IOC, session)

    async def get_by_threat_id(
        self, threat_id: UUID, skip: int = 0, limit: int = 100
    ) -> Sequence[IOC]:
        """Fetch all IOCs for a given threat."""
        result = await self.session.execute(
            select(IOC)
            .where(IOC.threat_id == threat_id)
            .order_by(IOC.last_seen.desc().nullslast())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_type(
        self, ioc_type: str, skip: int = 0, limit: int = 100
    ) -> Sequence[IOC]:
        """Fetch IOCs filtered by type (IP, Domain, URL, Hash, Email)."""
        result = await self.session.execute(
            select(IOC)
            .where(IOC.type == ioc_type)
            .order_by(IOC.last_seen.desc().nullslast())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    async def get_by_value(self, value: str) -> IOC | None:
        """Fetch a specific IOC by its exact value."""
        result = await self.session.execute(
            select(IOC).where(IOC.value == value)
        )
        return result.scalar_one_or_none()

    async def get_list_filtered(
        self,
        threat_id: UUID | None = None,
        ioc_type: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Sequence[IOC]:
        """Paginated IOC list with optional filters."""
        stmt = select(IOC)
        filters = []
        if threat_id:
            filters.append(IOC.threat_id == threat_id)
        if ioc_type:
            filters.append(IOC.type == ioc_type)
        if filters:
            stmt = stmt.where(and_(*filters))
        stmt = stmt.order_by(IOC.last_seen.desc().nullslast()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()
