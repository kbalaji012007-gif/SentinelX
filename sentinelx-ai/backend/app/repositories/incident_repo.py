"""
SentinelX AI – Incident Response Repository
Data access layer for sentinelx.incidents, timeline, notes, and evidence.
"""

from uuid import UUID
from typing import Sequence
from datetime import datetime, timezone

from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident, IncidentTimeline, IncidentNote, IncidentEvidence
from app.repositories.base_repo import BaseRepository


class IncidentRepository(BaseRepository[Incident]):
    """Repository managing Incident entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Incident, session)

    async def get_by_id_with_relations(self, id: UUID) -> Incident | None:
        """Fetch an incident with eager-loaded assigned user, timeline, notes, and evidence."""
        result = await self.session.execute(
            select(Incident)
            .options(
                selectinload(Incident.assigned_user),
                selectinload(Incident.timeline_events),
                selectinload(Incident.notes).selectinload(IncidentNote.author),
                selectinload(Incident.evidence).selectinload(IncidentEvidence.uploader),
            )
            .where(Incident.id == id)
        )
        return result.scalar_one_or_none()

    async def get_list(
        self,
        skip: int = 0,
        limit: int = 25,
        severity: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        assigned_user_id: UUID | None = None,
        search: str | None = None,
    ) -> Sequence[Incident]:
        """Paginated, filterable incident list query."""
        stmt = select(Incident).options(selectinload(Incident.assigned_user))

        filters = []
        if severity:
            filters.append(Incident.severity == severity)
        if priority:
            filters.append(Incident.priority == priority)
        if status:
            filters.append(Incident.status == status)
        if assigned_user_id:
            filters.append(Incident.assigned_user_id == assigned_user_id)
        if search:
            pattern = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(Incident.title).like(pattern),
                    func.lower(Incident.description).like(pattern),
                    func.lower(Incident.reported_by).like(pattern),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        stmt = stmt.order_by(Incident.detected_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_filtered(
        self,
        severity: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        assigned_user_id: UUID | None = None,
        search: str | None = None,
    ) -> int:
        """Count incidents matching given filters."""
        stmt = select(func.count()).select_from(Incident)

        filters = []
        if severity:
            filters.append(Incident.severity == severity)
        if priority:
            filters.append(Incident.priority == priority)
        if status:
            filters.append(Incident.status == status)
        if assigned_user_id:
            filters.append(Incident.assigned_user_id == assigned_user_id)
        if search:
            pattern = f"%{search.lower()}%"
            filters.append(
                or_(
                    func.lower(Incident.title).like(pattern),
                    func.lower(Incident.description).like(pattern),
                    func.lower(Incident.reported_by).like(pattern),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def get_open_count(self) -> int:
        """Count open and in-progress incidents."""
        result = await self.session.execute(
            select(func.count()).select_from(Incident).where(
                Incident.status.in_(["Open", "In Progress"])
            )
        )
        return result.scalar_one() or 0

    async def get_critical_count(self) -> int:
        """Count critical severity active incidents."""
        result = await self.session.execute(
            select(func.count()).select_from(Incident).where(
                and_(
                    Incident.severity == "Critical",
                    Incident.status.in_(["Open", "In Progress"]),
                )
            )
        )
        return result.scalar_one() or 0

    async def get_assigned_to_user_count(self, user_id: UUID) -> int:
        """Count active incidents assigned to specific user."""
        result = await self.session.execute(
            select(func.count()).select_from(Incident).where(
                and_(
                    Incident.assigned_user_id == user_id,
                    Incident.status.in_(["Open", "In Progress"]),
                )
            )
        )
        return result.scalar_one() or 0

    async def get_recently_resolved_count(self) -> int:
        """Count resolved or closed incidents."""
        result = await self.session.execute(
            select(func.count()).select_from(Incident).where(
                Incident.status.in_(["Resolved", "Closed"])
            )
        )
        return result.scalar_one() or 0

    async def get_recently_resolved(self, limit: int = 5) -> Sequence[Incident]:
        """Fetch recently resolved/closed incidents."""
        result = await self.session.execute(
            select(Incident)
            .where(Incident.status.in_(["Resolved", "Closed"]))
            .order_by(Incident.resolved_at.desc().nullslast())
            .limit(limit)
        )
        return result.scalars().all()

    async def assign_user(self, incident_id: UUID, user_id: UUID | None) -> Incident | None:
        """Assign analyst user to incident."""
        await self.update(incident_id, {"assigned_user_id": user_id})
        return await self.get_by_id_with_relations(incident_id)

    async def update_status(self, incident_id: UUID, status_val: str) -> Incident | None:
        """Update incident status and set resolved_at if Resolved/Closed."""
        update_fields: dict[str, Any] = {"status": status_val}
        if status_val in ("Resolved", "Closed"):
            update_fields["resolved_at"] = datetime.now(timezone.utc)

        await self.update(incident_id, update_fields)
        return await self.get_by_id_with_relations(incident_id)


class IncidentTimelineRepository(BaseRepository[IncidentTimeline]):
    """Repository managing timeline entries for an incident."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(IncidentTimeline, session)

    async def get_by_incident_id(self, incident_id: UUID) -> Sequence[IncidentTimeline]:
        """Fetch timeline entries for an incident sorted by created_at DESC."""
        result = await self.session.execute(
            select(IncidentTimeline)
            .where(IncidentTimeline.incident_id == incident_id)
            .order_by(IncidentTimeline.created_at.desc())
        )
        return result.scalars().all()


class IncidentNoteRepository(BaseRepository[IncidentNote]):
    """Repository managing analyst notes for an incident."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(IncidentNote, session)

    async def get_by_incident_id(self, incident_id: UUID) -> Sequence[IncidentNote]:
        """Fetch notes for an incident with eager author details."""
        result = await self.session.execute(
            select(IncidentNote)
            .options(selectinload(IncidentNote.author))
            .where(IncidentNote.incident_id == incident_id)
            .order_by(IncidentNote.created_at.desc())
        )
        return result.scalars().all()


class IncidentEvidenceRepository(BaseRepository[IncidentEvidence]):
    """Repository managing evidence uploads for an incident."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(IncidentEvidence, session)

    async def get_by_incident_id(self, incident_id: UUID) -> Sequence[IncidentEvidence]:
        """Fetch evidence items for an incident with uploader info."""
        result = await self.session.execute(
            select(IncidentEvidence)
            .options(selectinload(IncidentEvidence.uploader))
            .where(IncidentEvidence.incident_id == incident_id)
            .order_by(IncidentEvidence.uploaded_at.desc())
        )
        return result.scalars().all()
