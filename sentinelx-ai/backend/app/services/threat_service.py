"""
SentinelX AI – Threat Detection Service Layer
Business logic for threat, alert, and IOC management.
Follows SOLID principles with dependency injection via constructor.
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat import Threat, Alert, IOC
from app.repositories.threat_repo import ThreatRepository, AlertRepository, IOCRepository
from app.schemas.threat_schema import (
    ThreatCreate,
    ThreatUpdate,
    ThreatResponse,
    ThreatSummary,
    ThreatListResponse,
    ThreatStatsResponse,
    AlertCreate,
    AlertUpdate,
    AlertResponse,
    IOCCreate,
    IOCUpdate,
    IOCResponse,
)

logger = structlog.get_logger()


# ────────────────────────────────────────────────────────────────────────
# Threat Service
# ────────────────────────────────────────────────────────────────────────

class ThreatService:
    """
    Service encapsulating all threat lifecycle operations.
    Uses ThreatRepository for data access and enforces business rules.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = ThreatRepository(session)

    async def list_threats(
        self,
        page: int = 1,
        page_size: int = 25,
        severity: str | None = None,
        status: str | None = None,
        search: str | None = None,
        asset_id: UUID | None = None,
    ) -> ThreatListResponse:
        """Return paginated, filtered threat list."""
        skip = (page - 1) * page_size

        threats, total = await _gather_list_and_count(
            self.repo, skip, page_size, severity, status, search, asset_id
        )

        items = [ThreatSummary.model_validate(t) for t in threats]

        logger.info(
            "threats_listed",
            page=page,
            page_size=page_size,
            total=total,
            severity=severity,
            status=status,
        )

        return ThreatListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=items,
        )

    async def get_threat(self, threat_id: UUID) -> ThreatResponse | None:
        """Retrieve a threat with all nested alerts and IOCs."""
        threat = await self.repo.get_by_id_with_relations(threat_id)
        if not threat:
            return None

        logger.info("threat_fetched", threat_id=str(threat_id))
        return ThreatResponse.model_validate(threat)

    async def create_threat(self, payload: ThreatCreate, created_by: str) -> ThreatResponse:
        """Create a new threat record."""
        data = payload.model_dump()
        # Ensure detected_at is timezone-aware
        if data.get("detected_at") and data["detected_at"].tzinfo is None:
            data["detected_at"] = data["detected_at"].replace(tzinfo=timezone.utc)

        threat = await self.repo.create(data)

        logger.info(
            "threat_created",
            threat_id=str(threat.id),
            severity=threat.severity,
            created_by=created_by,
        )

        # Reload with relations for response
        full = await self.repo.get_by_id_with_relations(threat.id)
        return ThreatResponse.model_validate(full)

    async def update_threat(
        self, threat_id: UUID, payload: ThreatUpdate, updated_by: str
    ) -> ThreatResponse | None:
        """Partially update threat fields."""
        existing = await self.repo.get_by_id(threat_id)
        if not existing:
            return None

        update_data = payload.model_dump(exclude_unset=True)
        if not update_data:
            # Nothing to change — return current state
            return ThreatResponse.model_validate(
                await self.repo.get_by_id_with_relations(threat_id)
            )

        await self.repo.update(threat_id, update_data)

        logger.info(
            "threat_updated",
            threat_id=str(threat_id),
            fields=list(update_data.keys()),
            updated_by=updated_by,
        )

        full = await self.repo.get_by_id_with_relations(threat_id)
        return ThreatResponse.model_validate(full)

    async def delete_threat(self, threat_id: UUID, deleted_by: str) -> bool:
        """Delete a threat and all its cascade children (alerts, IOCs)."""
        deleted = await self.repo.delete(threat_id)

        if deleted:
            logger.warning(
                "threat_deleted",
                threat_id=str(threat_id),
                deleted_by=deleted_by,
            )

        return deleted

    async def get_stats(self) -> ThreatStatsResponse:
        """Compute severity and status distribution for dashboard widgets."""
        total = await self.repo.count()
        by_severity = await self.repo.get_severity_distribution()
        by_status = await self.repo.get_status_distribution()

        return ThreatStatsResponse(
            total=total,
            by_severity=by_severity,
            by_status=by_status,
        )


async def _gather_list_and_count(
    repo: ThreatRepository,
    skip: int,
    limit: int,
    severity: str | None,
    status: str | None,
    search: str | None,
    asset_id: UUID | None,
) -> tuple[Any, int]:
    """Helper: run list + count concurrently (sequential to keep single session)."""
    threats = await repo.get_list(skip, limit, severity, status, search, asset_id)
    total = await repo.count_filtered(severity, status, search, asset_id)
    return threats, total


# ────────────────────────────────────────────────────────────────────────
# Alert Service
# ────────────────────────────────────────────────────────────────────────

class AlertService:
    """Service encapsulating alert lifecycle and acknowledgement workflow."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = AlertRepository(session)

    async def list_alerts(
        self,
        threat_id: UUID | None = None,
        severity: str | None = None,
        acknowledged: bool | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[AlertResponse]:
        """Return filtered, paginated alert list."""
        skip = (page - 1) * page_size
        alerts = await self.repo.get_list_filtered(
            threat_id=threat_id,
            severity=severity,
            acknowledged=acknowledged,
            skip=skip,
            limit=page_size,
        )
        return [AlertResponse.model_validate(a) for a in alerts]

    async def create_alert(self, payload: AlertCreate) -> AlertResponse:
        """Create a new alert linked to a threat."""
        alert = await self.repo.create(payload.model_dump())
        logger.info("alert_created", alert_id=str(alert.id), threat_id=str(payload.threat_id))
        return AlertResponse.model_validate(alert)

    async def acknowledge_alert(self, alert_id: UUID) -> AlertResponse | None:
        """Mark an alert as acknowledged."""
        alert = await self.repo.acknowledge(alert_id)
        if alert:
            logger.info("alert_acknowledged", alert_id=str(alert_id))
        return AlertResponse.model_validate(alert) if alert else None


# ────────────────────────────────────────────────────────────────────────
# IOC Service
# ────────────────────────────────────────────────────────────────────────

class IOCService:
    """Service managing IOC (Indicators of Compromise) lifecycle."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = IOCRepository(session)

    async def list_iocs(
        self,
        threat_id: UUID | None = None,
        ioc_type: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[IOCResponse]:
        """Return filtered, paginated IOC list."""
        skip = (page - 1) * page_size
        iocs = await self.repo.get_list_filtered(
            threat_id=threat_id,
            ioc_type=ioc_type,
            skip=skip,
            limit=page_size,
        )
        return [IOCResponse.model_validate(i) for i in iocs]

    async def create_ioc(self, payload: IOCCreate) -> IOCResponse:
        """Create a new IOC linked to a threat."""
        ioc = await self.repo.create(payload.model_dump())
        logger.info("ioc_created", ioc_id=str(ioc.id), type=payload.type, value=payload.value)
        return IOCResponse.model_validate(ioc)

    async def update_ioc(self, ioc_id: UUID, payload: IOCUpdate) -> IOCResponse | None:
        """Update IOC fields."""
        update_data = payload.model_dump(exclude_unset=True)
        if not update_data:
            ioc = await self.repo.get_by_id(ioc_id)
            return IOCResponse.model_validate(ioc) if ioc else None
        ioc = await self.repo.update(ioc_id, update_data)
        return IOCResponse.model_validate(ioc) if ioc else None

    async def delete_ioc(self, ioc_id: UUID) -> bool:
        """Remove an IOC record."""
        return await self.repo.delete(ioc_id)
