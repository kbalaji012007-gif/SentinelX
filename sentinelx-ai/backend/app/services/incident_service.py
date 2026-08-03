"""
SentinelX AI – Incident Response Service Layer
Business logic and orchestration for security incidents, timeline, analyst notes, and evidence.
Follows SOLID principles with dependency injection via constructor.
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident, IncidentTimeline, IncidentNote, IncidentEvidence
from app.repositories.incident_repo import (
    IncidentRepository,
    IncidentTimelineRepository,
    IncidentNoteRepository,
    IncidentEvidenceRepository,
)
from app.schemas.incident_schema import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    IncidentSummary,
    IncidentListResponse,
    IncidentStatsResponse,
    IncidentTimelineCreate,
    IncidentTimelineResponse,
    IncidentNoteCreate,
    IncidentNoteResponse,
    IncidentEvidenceCreate,
    IncidentEvidenceResponse,
)

logger = structlog.get_logger()


class IncidentService:
    """Service encapsulating incident lifecycle management and workflow operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = IncidentRepository(session)
        self.timeline_repo = IncidentTimelineRepository(session)
        self.note_repo = IncidentNoteRepository(session)
        self.evidence_repo = IncidentEvidenceRepository(session)

    async def list_incidents(
        self,
        page: int = 1,
        page_size: int = 25,
        severity: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        assigned_user_id: UUID | None = None,
        search: str | None = None,
    ) -> IncidentListResponse:
        """Return paginated, filtered incident list."""
        skip = (page - 1) * page_size

        incidents = await self.repo.get_list(
            skip=skip,
            limit=page_size,
            severity=severity,
            priority=priority,
            status=status,
            assigned_user_id=assigned_user_id,
            search=search,
        )
        total = await self.repo.count_filtered(
            severity=severity,
            priority=priority,
            status=status,
            assigned_user_id=assigned_user_id,
            search=search,
        )

        items = [IncidentSummary.model_validate(inc) for inc in incidents]

        logger.info(
            "incidents_listed",
            page=page,
            page_size=page_size,
            total=total,
            severity=severity,
            status=status,
        )

        return IncidentListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=items,
        )

    async def get_incident(self, incident_id: UUID) -> IncidentResponse | None:
        """Fetch incident details with eager timeline, notes, evidence, and user relation."""
        incident = await self.repo.get_by_id_with_relations(incident_id)
        if not incident:
            return None

        logger.info("incident_fetched", incident_id=str(incident_id))
        return IncidentResponse.model_validate(incident)

    async def create_incident(self, payload: IncidentCreate, created_by_name: str) -> IncidentResponse:
        """Create a new incident ticket and log initial timeline event."""
        data = payload.model_dump()
        if data.get("detected_at") and data["detected_at"].tzinfo is None:
            data["detected_at"] = data["detected_at"].replace(tzinfo=timezone.utc)

        incident = await self.repo.create(data)

        # Log initial creation event in timeline
        await self.timeline_repo.create({
            "incident_id": incident.id,
            "event_type": "Incident Created",
            "description": f"Incident '{incident.title}' declared with severity {incident.severity} and priority {incident.priority}.",
            "created_by": created_by_name,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info(
            "incident_created",
            incident_id=str(incident.id),
            severity=incident.severity,
            priority=incident.priority,
            created_by=created_by_name,
        )

        full = await self.repo.get_by_id_with_relations(incident.id)
        return IncidentResponse.model_validate(full)

    async def update_incident(
        self, incident_id: UUID, payload: IncidentUpdate, updated_by_name: str
    ) -> IncidentResponse | None:
        """Update incident fields and log timeline entry if significant status/priority changes occur."""
        existing = await self.repo.get_by_id(incident_id)
        if not existing:
            return None

        update_data = payload.model_dump(exclude_unset=True)
        if not update_data:
            return IncidentResponse.model_validate(await self.repo.get_by_id_with_relations(incident_id))

        # Check for status/priority change to log timeline
        status_changed = "status" in update_data and update_data["status"] != existing.status
        priority_changed = "priority" in update_data and update_data["priority"] != existing.priority

        if status_changed and update_data["status"] in ("Resolved", "Closed"):
            update_data["resolved_at"] = datetime.now(timezone.utc)

        await self.repo.update(incident_id, update_data)

        if status_changed:
            await self.timeline_repo.create({
                "incident_id": incident_id,
                "event_type": "Status Changed",
                "description": f"Status updated from '{existing.status}' to '{update_data['status']}'.",
                "created_by": updated_by_name,
                "created_at": datetime.now(timezone.utc),
            })

        if priority_changed:
            await self.timeline_repo.create({
                "incident_id": incident_id,
                "event_type": "Priority Changed",
                "description": f"Priority adjusted from '{existing.priority}' to '{update_data['priority']}'.",
                "created_by": updated_by_name,
                "created_at": datetime.now(timezone.utc),
            })

        logger.info("incident_updated", incident_id=str(incident_id), updated_by=updated_by_name)
        full = await self.repo.get_by_id_with_relations(incident_id)
        return IncidentResponse.model_validate(full)

    async def delete_incident(self, incident_id: UUID, deleted_by: str) -> bool:
        """Delete an incident and all its cascade children."""
        deleted = await self.repo.delete(incident_id)
        if deleted:
            logger.warning("incident_deleted", incident_id=str(incident_id), deleted_by=deleted_by)
        return deleted

    async def assign_analyst(
        self, incident_id: UUID, user_id: UUID | None, assigned_by_name: str
    ) -> IncidentResponse | None:
        """Assign or unassign an analyst to the incident."""
        incident = await self.repo.assign_user(incident_id, user_id)
        if not incident:
            return None

        assignee_name = f"{incident.assigned_user.first_name} {incident.assigned_user.last_name}" if incident.assigned_user else "Unassigned"

        await self.timeline_repo.create({
            "incident_id": incident_id,
            "event_type": "Analyst Assignment",
            "description": f"Incident assigned to {assignee_name}.",
            "created_by": assigned_by_name,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info("incident_assigned", incident_id=str(incident_id), assignee=assignee_name)
        return IncidentResponse.model_validate(incident)

    async def update_status(
        self, incident_id: UUID, status_val: str, updated_by_name: str
    ) -> IncidentResponse | None:
        """Update incident status and add timeline entry."""
        existing = await self.repo.get_by_id(incident_id)
        if not existing:
            return None

        incident = await self.repo.update_status(incident_id, status_val)
        if not incident:
            return None

        await self.timeline_repo.create({
            "incident_id": incident_id,
            "event_type": "Status Changed",
            "description": f"Status updated to '{status_val}'.",
            "created_by": updated_by_name,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info("incident_status_updated", incident_id=str(incident_id), new_status=status_val)
        return IncidentResponse.model_validate(incident)

    async def add_note(
        self, incident_id: UUID, payload: IncidentNoteCreate, author_id: UUID, author_name: str
    ) -> IncidentNoteResponse:
        """Add an investigation note to the incident."""
        note_obj = await self.note_repo.create({
            "incident_id": incident_id,
            "author_id": author_id,
            "note": payload.note,
            "created_at": datetime.now(timezone.utc),
        })

        await self.timeline_repo.create({
            "incident_id": incident_id,
            "event_type": "Analyst Note Added",
            "description": f"Analyst {author_name} added an investigation note.",
            "created_by": author_name,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info("incident_note_added", incident_id=str(incident_id), author_id=str(author_id))
        return IncidentNoteResponse.model_validate(note_obj)

    async def get_timeline(self, incident_id: UUID) -> list[IncidentTimelineResponse]:
        """Fetch timeline events for an incident."""
        events = await self.timeline_repo.get_by_incident_id(incident_id)
        return [IncidentTimelineResponse.model_validate(e) for e in events]

    async def get_evidence(self, incident_id: UUID) -> list[IncidentEvidenceResponse]:
        """Fetch evidence file attachments for an incident."""
        items = await self.evidence_repo.get_by_incident_id(incident_id)
        return [IncidentEvidenceResponse.model_validate(item) for item in items]

    async def add_evidence(
        self, incident_id: UUID, payload: IncidentEvidenceCreate, uploader_id: UUID, uploader_name: str
    ) -> IncidentEvidenceResponse:
        """Attach evidence file metadata to an incident."""
        item = await self.evidence_repo.create({
            "incident_id": incident_id,
            "evidence_name": payload.evidence_name,
            "evidence_type": payload.evidence_type,
            "file_path": payload.file_path,
            "uploaded_by": uploader_id,
            "uploaded_at": datetime.now(timezone.utc),
        })

        await self.timeline_repo.create({
            "incident_id": incident_id,
            "event_type": "Evidence Attached",
            "description": f"Evidence file '{payload.evidence_name}' attached by {uploader_name}.",
            "created_by": uploader_name,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info("incident_evidence_added", incident_id=str(incident_id), evidence_name=payload.evidence_name)
        return IncidentEvidenceResponse.model_validate(item)

    async def get_stats(self, current_user_id: UUID) -> IncidentStatsResponse:
        """Compute live incident stats for dashboard widgets."""
        open_count = await self.repo.get_open_count()
        critical_count = await self.repo.get_critical_count()
        assigned_count = await self.repo.get_assigned_to_user_count(current_user_id)
        resolved_count = await self.repo.get_recently_resolved_count()

        return IncidentStatsResponse(
            open_incidents_count=open_count,
            critical_incidents_count=critical_count,
            assigned_to_me_count=assigned_count,
            recently_resolved_count=resolved_count,
            by_status={},
            by_priority={},
        )
