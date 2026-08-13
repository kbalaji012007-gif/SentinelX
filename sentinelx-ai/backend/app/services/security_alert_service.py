"""
SentinelX AI – Security Alert Service Layer (Phase 6.4)
Business logic for creating, deduplicating, querying, and managing real-time security alerts.
Integrates with the RealtimeConnectionManager to broadcast SOC events.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_alert import SecurityAlert
from app.repositories.security_alert_repo import SecurityAlertRepository
from app.schemas.security_alert_schema import (
    SecurityAlertCreate,
    SecurityAlertResponse,
    SecurityAlertSummary,
    SecurityAlertListResponse,
    SecurityAlertStatistics,
)
from app.realtime.manager import realtime_manager
from app.realtime.events import RealtimeEventType
from app.core.config import settings

logger = structlog.get_logger()


def _to_summary(alert: SecurityAlert) -> SecurityAlertSummary:
    """Convert a SecurityAlert ORM object to a SecurityAlertSummary."""
    evidence = alert.evidence or {}
    meta = alert.alert_metadata or {}
    return SecurityAlertSummary(
        id=alert.id,
        alert_id=alert.alert_id,
        title=alert.title,
        alert_type=alert.alert_type,
        severity=alert.severity,
        status=alert.status,
        source=alert.source,
        agent_id=alert.agent_id,
        hostname=meta.get("hostname"),
        mitre_tactic=alert.mitre_tactic,
        mitre_technique=alert.mitre_technique,
        detected_at=alert.detected_at,
        updated_at=alert.updated_at,
        occurrence_count=evidence.get("occurrence_count", 1),
    )


class SecurityAlertService:
    """
    Service encapsulating all security alert lifecycle operations.
    Handles creation with deduplication, status transitions, and real-time broadcasting.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = SecurityAlertRepository(session)

    # ── Alert Creation & Deduplication ────────────────────────────────────────

    async def create_alert(
        self,
        data: SecurityAlertCreate,
        dedup_window_seconds: Optional[int] = None,
    ) -> tuple[SecurityAlert, bool]:
        """
        Create a new security alert or aggregate into an existing duplicate.

        Returns (alert, is_new) where is_new=False means an existing alert was updated.
        Broadcasts alert.created or alert.updated accordingly.
        """
        if dedup_window_seconds is None:
            dedup_window_seconds = getattr(settings, "ALERT_DEDUP_WINDOW_SECONDS", 300)

        # ── Deduplication check ───────────────────────────────────────────────
        existing = await self.repo.find_duplicate(
            alert_type=data.alert_type,
            agent_id=data.agent_id,
            window_seconds=dedup_window_seconds,
        )

        if existing:
            # Aggregate: increment occurrence count and merge evidence
            ev = dict(existing.evidence or {})
            ev["occurrence_count"] = ev.get("occurrence_count", 1) + 1
            ev["last_occurrence"] = datetime.now(timezone.utc).isoformat()
            # Merge new evidence fields without overwriting core forensics
            for k, v in data.evidence.items():
                if k not in ("occurrence_count", "last_occurrence"):
                    ev.setdefault(k, v)

            updated = await self.repo.update_evidence(existing.id, ev)
            alert = updated or existing

            logger.info(
                "security_alert_deduplicated",
                alert_id=alert.alert_id,
                alert_type=data.alert_type,
                occurrence_count=ev["occurrence_count"],
            )

            # Broadcast alert.updated
            await realtime_manager.broadcast(
                RealtimeEventType.ALERT_UPDATED,
                self._alert_to_broadcast_payload(_to_summary(alert)),
            )
            await self.session.commit()
            return alert, False

        # ── Create new alert ──────────────────────────────────────────────────
        evidence = dict(data.evidence)
        evidence.setdefault("occurrence_count", 1)
        evidence.setdefault("first_occurrence", data.detected_at.isoformat())

        alert_dict: Dict[str, Any] = {
            "alert_id": data.alert_id,
            "title": data.title,
            "description": data.description,
            "alert_type": data.alert_type,
            "severity": data.severity.upper(),
            "status": "NEW",
            "source": data.source,
            "agent_id": data.agent_id,
            "log_id": data.log_id,
            "threat_id": data.threat_id,
            "incident_id": data.incident_id,
            "correlation_id": data.correlation_id,
            "mitre_tactic": data.mitre_tactic,
            "mitre_technique": data.mitre_technique,
            "evidence": evidence,
            "alert_metadata": data.alert_metadata,
            "detected_at": data.detected_at,
        }

        alert = await self.repo.create(alert_dict)
        await self.session.commit()

        logger.info(
            "security_alert_created",
            alert_id=alert.alert_id,
            alert_type=data.alert_type,
            severity=data.severity,
            source=data.source,
        )

        # Broadcast alert.created
        await realtime_manager.broadcast(
            RealtimeEventType.ALERT_CREATED,
            self._alert_to_broadcast_payload(_to_summary(alert)),
        )

        return alert, True

    # ── Status Transitions ────────────────────────────────────────────────────

    async def acknowledge_alert(
        self, alert_uuid: UUID, analyst_user_id: UUID
    ) -> SecurityAlertResponse:
        """Mark alert as ACKNOWLEDGED by an analyst."""
        now = datetime.now(timezone.utc)
        alert = await self.repo.update_status(
            alert_uuid,
            "ACKNOWLEDGED",
            extra_fields={
                "acknowledged_at": now,
                "acknowledged_by": analyst_user_id,
            },
        )
        if not alert:
            raise ValueError(f"Alert {alert_uuid} not found")

        await self.session.commit()
        logger.info("security_alert_acknowledged", alert_id=str(alert_uuid), analyst=str(analyst_user_id))

        await realtime_manager.broadcast(
            RealtimeEventType.ALERT_ACKNOWLEDGED,
            {"alert_id": str(alert_uuid), "acknowledged_by": str(analyst_user_id)},
        )
        return SecurityAlertResponse.model_validate(alert)

    async def investigate_alert(
        self, alert_uuid: UUID, analyst_user_id: UUID
    ) -> SecurityAlertResponse:
        """Mark alert as INVESTIGATING."""
        alert = await self.repo.update_status(alert_uuid, "INVESTIGATING")
        if not alert:
            raise ValueError(f"Alert {alert_uuid} not found")

        await self.session.commit()
        logger.info("security_alert_investigating", alert_id=str(alert_uuid), analyst=str(analyst_user_id))

        await realtime_manager.broadcast(
            RealtimeEventType.ALERT_INVESTIGATED,
            {"alert_id": str(alert_uuid), "investigated_by": str(analyst_user_id)},
        )
        return SecurityAlertResponse.model_validate(alert)

    async def resolve_alert(
        self, alert_uuid: UUID, analyst_user_id: UUID, resolution_notes: Optional[str] = None
    ) -> SecurityAlertResponse:
        """Mark alert as RESOLVED."""
        now = datetime.now(timezone.utc)
        extra: Dict[str, Any] = {
            "resolved_at": now,
            "resolved_by": analyst_user_id,
        }
        if resolution_notes:
            # Store in evidence
            alert_now = await self.repo.get_by_id(alert_uuid)
            if alert_now:
                ev = dict(alert_now.evidence or {})
                ev["resolution_notes"] = resolution_notes
                await self.repo.update_evidence(alert_uuid, ev)

        alert = await self.repo.update_status(alert_uuid, "RESOLVED", extra_fields=extra)
        if not alert:
            raise ValueError(f"Alert {alert_uuid} not found")

        await self.session.commit()
        logger.info("security_alert_resolved", alert_id=str(alert_uuid), analyst=str(analyst_user_id))

        await realtime_manager.broadcast(
            RealtimeEventType.ALERT_RESOLVED,
            {"alert_id": str(alert_uuid), "resolved_by": str(analyst_user_id)},
        )
        return SecurityAlertResponse.model_validate(alert)

    async def dismiss_alert(
        self, alert_uuid: UUID, analyst_user_id: UUID, reason: Optional[str] = None
    ) -> SecurityAlertResponse:
        """Mark alert as DISMISSED."""
        if reason:
            alert_now = await self.repo.get_by_id(alert_uuid)
            if alert_now:
                ev = dict(alert_now.evidence or {})
                ev["dismiss_reason"] = reason
                await self.repo.update_evidence(alert_uuid, ev)

        alert = await self.repo.update_status(alert_uuid, "DISMISSED")
        if not alert:
            raise ValueError(f"Alert {alert_uuid} not found")

        await self.session.commit()
        logger.info("security_alert_dismissed", alert_id=str(alert_uuid), analyst=str(analyst_user_id))

        await realtime_manager.broadcast(
            RealtimeEventType.ALERT_DISMISSED,
            {"alert_id": str(alert_uuid), "dismissed_by": str(analyst_user_id)},
        )
        return SecurityAlertResponse.model_validate(alert)

    # ── Query Methods ─────────────────────────────────────────────────────────

    async def list_alerts(
        self,
        page: int = 1,
        page_size: int = 25,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        alert_type: Optional[str] = None,
        agent_id: Optional[UUID] = None,
        search: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> SecurityAlertListResponse:
        """Return paginated, filtered alerts."""
        skip = (page - 1) * page_size
        alerts = await self.repo.get_list(
            skip=skip,
            limit=page_size,
            severity=severity,
            status=status,
            alert_type=alert_type,
            agent_id=agent_id,
            search=search,
            since=since,
            until=until,
        )
        total = await self.repo.count_filtered(
            severity=severity,
            status=status,
            alert_type=alert_type,
            agent_id=agent_id,
            search=search,
            since=since,
            until=until,
        )
        items = [_to_summary(a) for a in alerts]
        return SecurityAlertListResponse(total=total, page=page, page_size=page_size, items=items)

    async def get_alert(self, alert_uuid: UUID) -> Optional[SecurityAlertResponse]:
        """Retrieve single alert by internal UUID."""
        alert = await self.repo.get_by_id(alert_uuid)
        if not alert:
            return None
        return SecurityAlertResponse.model_validate(alert)

    async def get_statistics(self) -> SecurityAlertStatistics:
        """Return aggregate alert statistics."""
        stats = await self.repo.get_statistics()
        return SecurityAlertStatistics(**stats)

    async def get_recent(self, limit: int = 20) -> List[SecurityAlertSummary]:
        """Return the most recent N alerts."""
        alerts = await self.repo.get_recent(limit=limit)
        return [_to_summary(a) for a in alerts]

    # ── Internal Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _alert_to_broadcast_payload(summary: SecurityAlertSummary) -> Dict[str, Any]:
        """Convert alert summary to a JSON-serializable broadcast payload."""
        return {
            "id": str(summary.id),
            "alert_id": summary.alert_id,
            "title": summary.title,
            "alert_type": summary.alert_type,
            "severity": summary.severity,
            "status": summary.status,
            "source": summary.source,
            "hostname": summary.hostname,
            "agent_id": str(summary.agent_id) if summary.agent_id else None,
            "mitre_tactic": summary.mitre_tactic,
            "mitre_technique": summary.mitre_technique,
            "detected_at": summary.detected_at.isoformat(),
            "occurrence_count": summary.occurrence_count,
        }
