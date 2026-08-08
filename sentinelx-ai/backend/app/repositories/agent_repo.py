"""
SentinelX AI – Endpoint Agent Repository Layer
Data access layer for endpoint agents and agent telemetry records.
"""

from uuid import UUID
from datetime import datetime, timezone, timedelta
from typing import Sequence, Any, Optional, Dict
from sqlalchemy import select, update, func, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import EndpointAgent, AgentTelemetry
from app.repositories.base_repo import BaseRepository


class AgentRepository(BaseRepository[EndpointAgent]):
    """Data access repository for EndpointAgent models."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(EndpointAgent, session)

    async def get_by_agent_id(self, agent_id: str) -> EndpointAgent | None:
        """Fetch agent by unique installation string identifier."""
        result = await self.session.execute(
            select(EndpointAgent).where(EndpointAgent.agent_id == agent_id)
        )
        return result.scalar_one_or_none()

    async def get_list(
        self,
        skip: int = 0,
        limit: int = 25,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Sequence[EndpointAgent]:
        """Fetch paginated, filtered agent records."""
        stmt = select(EndpointAgent)

        conditions = []
        if status:
            conditions.append(EndpointAgent.status == status)
        if search:
            pattern = f"%{search}%"
            conditions.append(
                or_(
                    EndpointAgent.agent_id.ilike(pattern),
                    EndpointAgent.hostname.ilike(pattern),
                    EndpointAgent.platform.ilike(pattern),
                    EndpointAgent.os_version.ilike(pattern),
                )
            )

        if conditions:
            stmt = stmt.where(and_(*conditions))

        stmt = stmt.order_by(EndpointAgent.last_seen.desc().nulls_last()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_filtered(
        self,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> int:
        """Count agent records matching optional filters."""
        stmt = select(func.count()).select_from(EndpointAgent)

        conditions = []
        if status:
            conditions.append(EndpointAgent.status == status)
        if search:
            pattern = f"%{search}%"
            conditions.append(
                or_(
                    EndpointAgent.agent_id.ilike(pattern),
                    EndpointAgent.hostname.ilike(pattern),
                    EndpointAgent.platform.ilike(pattern),
                    EndpointAgent.os_version.ilike(pattern),
                )
            )

        if conditions:
            stmt = stmt.where(and_(*conditions))

        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def update_last_seen(
        self,
        agent_id_str: str,
        seen_at: datetime,
        metadata_update: Optional[Dict[str, Any]] = None,
        new_status: Optional[str] = None,
    ) -> EndpointAgent | None:
        """Update last_seen timestamp, optional metadata, and optional status."""
        agent = await self.get_by_agent_id(agent_id_str)
        if not agent:
            return None

        update_values: Dict[str, Any] = {"last_seen": seen_at}
        if new_status and agent.status not in ("Disabled", "Revoked"):
            update_values["status"] = new_status
        elif agent.status == "Offline" or agent.status == "Stale":
            update_values["status"] = "Online"

        if metadata_update:
            merged_meta = dict(agent.agent_metadata or {})
            merged_meta.update(metadata_update)
            update_values["agent_metadata"] = merged_meta

        await self.session.execute(
            update(EndpointAgent)
            .where(EndpointAgent.agent_id == agent_id_str)
            .values(**update_values)
        )
        await self.session.commit()
        return await self.get_by_agent_id(agent_id_str)

    async def set_agent_status(self, id_or_agent_id: str, new_status: str) -> EndpointAgent | None:
        """Set agent enrollment status (e.g. Disabled, Revoked, Online)."""
        # Try fetching by internal UUID first, then by string agent_id
        agent = None
        try:
            agent_uuid = UUID(id_or_agent_id)
            agent = await self.get_by_id(agent_uuid)
        except (ValueError, TypeError):
            pass

        if not agent:
            agent = await self.get_by_agent_id(id_or_agent_id)

        if not agent:
            return None

        await self.session.execute(
            update(EndpointAgent)
            .where(EndpointAgent.id == agent.id)
            .values(status=new_status)
        )
        await self.session.commit()
        return await self.get_by_id(agent.id)

    async def get_status_distribution(self) -> Dict[str, int]:
        """Return agent count grouped by status."""
        result = await self.session.execute(
            select(EndpointAgent.status, func.count(EndpointAgent.id)).group_by(EndpointAgent.status)
        )
        return {row[0]: row[1] for row in result.all()}


class AgentTelemetryRepository(BaseRepository[AgentTelemetry]):
    """Data access repository for AgentTelemetry models."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AgentTelemetry, session)

    async def create_batch(self, telemetry_dicts: list[dict[str, Any]]) -> list[AgentTelemetry]:
        """Insert a batch of telemetry records in a single session transaction."""
        objects = [AgentTelemetry(**item) for item in telemetry_dicts]
        self.session.add_all(objects)
        await self.session.commit()
        return objects

    async def get_by_agent_id(
        self,
        agent_id_uuid: UUID,
        skip: int = 0,
        limit: int = 25,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Sequence[AgentTelemetry]:
        """Fetch telemetry records for a specific agent UUID."""
        stmt = select(AgentTelemetry).where(AgentTelemetry.agent_id == agent_id_uuid)

        if event_type:
            stmt = stmt.where(AgentTelemetry.event_type == event_type)
        if severity:
            stmt = stmt.where(AgentTelemetry.severity == severity)

        stmt = stmt.order_by(AgentTelemetry.event_timestamp.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_by_agent_id(
        self,
        agent_id_uuid: UUID,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> int:
        """Count telemetry records for a specific agent UUID."""
        stmt = select(func.count()).select_from(AgentTelemetry).where(AgentTelemetry.agent_id == agent_id_uuid)

        if event_type:
            stmt = stmt.where(AgentTelemetry.event_type == event_type)
        if severity:
            stmt = stmt.where(AgentTelemetry.severity == severity)

        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def count_today(self) -> int:
        """Count telemetry records created since 00:00 UTC today."""
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        result = await self.session.execute(
            select(func.count()).select_from(AgentTelemetry).where(AgentTelemetry.created_at >= today_start)
        )
        return result.scalar_one() or 0
