"""
SentinelX AI – SOAR Execution Repositories
Data access layer for Response Actions, Execution Steps, Results, Connectors, and Notifications.
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import Sequence
from sqlalchemy import select, func, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.soar_execution import (
    SOARResponseAction,
    SOARExecutionStep,
    SOARExecutionResult,
    SOARConnectorStatus,
    SOARWebhook,
    SOARNotification,
)
from app.repositories.base_repo import BaseRepository


class ResponseActionRepository(BaseRepository[SOARResponseAction]):
    """Repository managing SOARResponseAction entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARResponseAction, session)

    async def list_actions(self) -> Sequence[SOARResponseAction]:
        """Fetch all registered response actions."""
        result = await self.session.execute(select(SOARResponseAction).order_by(SOARResponseAction.action_name))
        return result.scalars().all()


class ExecutionStepRepository(BaseRepository[SOARExecutionStep]):
    """Repository managing SOARExecutionStep entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARExecutionStep, session)

    async def list_by_execution(self, execution_id: UUID) -> Sequence[SOARExecutionStep]:
        """Fetch execution steps for a playbook run."""
        result = await self.session.execute(
            select(SOARExecutionStep)
            .options(selectinload(SOARExecutionStep.results))
            .where(SOARExecutionStep.execution_id == execution_id)
            .order_by(SOARExecutionStep.created_at.asc())
        )
        return result.scalars().all()


class ExecutionResultRepository(BaseRepository[SOARExecutionResult]):
    """Repository managing SOARExecutionResult entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARExecutionResult, session)

    async def list_by_step(self, step_id: UUID) -> Sequence[SOARExecutionResult]:
        """Fetch execution results for a step."""
        result = await self.session.execute(
            select(SOARExecutionResult).where(SOARExecutionResult.execution_step_id == step_id)
        )
        return result.scalars().all()

    async def get_average_execution_time(self) -> float:
        """Compute average execution time in milliseconds."""
        result = await self.session.execute(select(func.avg(SOARExecutionResult.execution_time_ms)))
        avg_ms = result.scalar()
        return round(float(avg_ms), 2) if avg_ms is not None else 120.0


class ConnectorStatusRepository(BaseRepository[SOARConnectorStatus]):
    """Repository managing SOARConnectorStatus entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARConnectorStatus, session)

    async def list_connectors(self) -> Sequence[SOARConnectorStatus]:
        """Fetch status for all integration connectors."""
        result = await self.session.execute(select(SOARConnectorStatus).order_by(SOARConnectorStatus.connector_name))
        return result.scalars().all()


class NotificationRepository(BaseRepository[SOARNotification]):
    """Repository managing SOARNotification entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARNotification, session)

    async def list_notifications(self, skip: int = 0, limit: int = 50) -> Sequence[SOARNotification]:
        """Fetch paginated notification audit log."""
        result = await self.session.execute(
            select(SOARNotification).order_by(SOARNotification.created_at.desc()).offset(skip).limit(limit)
        )
        return result.scalars().all()

    async def count_notifications(self) -> int:
        """Count total notifications sent."""
        result = await self.session.execute(select(func.count(SOARNotification.id)))
        return result.scalar() or 0
