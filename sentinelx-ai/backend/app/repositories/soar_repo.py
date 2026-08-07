"""
SentinelX AI – SOAR Engine Repositories
Data access layer for Playbooks, Steps, Rules, Execution History, Logs, and Approvals.
"""

from uuid import UUID
from datetime import datetime, timezone, timedelta
from typing import Sequence, Dict, Any
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.soar import (
    SOARPlaybook,
    SOARPlaybookStep,
    SOARRule,
    SOARExecution,
    SOARExecutionLog,
    SOARApprovalRequest,
)
from app.repositories.base_repo import BaseRepository


class PlaybookRepository(BaseRepository[SOARPlaybook]):
    """Repository managing SOARPlaybook entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARPlaybook, session)

    async def get_by_name(self, name: str) -> SOARPlaybook | None:
        """Fetch playbook by unique name."""
        result = await self.session.execute(
            select(SOARPlaybook).where(SOARPlaybook.name == name)
        )
        return result.scalar_one_or_none()

    async def get_with_steps(self, playbook_id: UUID) -> SOARPlaybook | None:
        """Fetch playbook along with eager-loaded steps."""
        result = await self.session.execute(
            select(SOARPlaybook)
            .options(selectinload(SOARPlaybook.steps))
            .where(SOARPlaybook.id == playbook_id)
        )
        return result.scalar_one_or_none()

    async def list_playbooks(
        self,
        skip: int = 0,
        limit: int = 100,
        category: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> Sequence[SOARPlaybook]:
        """Fetch paginated playbooks with steps."""
        stmt = select(SOARPlaybook).options(selectinload(SOARPlaybook.steps))

        if category:
            stmt = stmt.where(SOARPlaybook.category == category)
        if is_active is not None:
            stmt = stmt.where(SOARPlaybook.is_active == is_active)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    SOARPlaybook.name.ilike(pattern),
                    SOARPlaybook.description.ilike(pattern),
                    SOARPlaybook.category.ilike(pattern),
                )
            )

        stmt = stmt.order_by(SOARPlaybook.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_playbooks(
        self,
        category: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> int:
        """Count playbooks matching filters."""
        stmt = select(func.count(SOARPlaybook.id))
        if category:
            stmt = stmt.where(SOARPlaybook.category == category)
        if is_active is not None:
            stmt = stmt.where(SOARPlaybook.is_active == is_active)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    SOARPlaybook.name.ilike(pattern),
                    SOARPlaybook.description.ilike(pattern),
                    SOARPlaybook.category.ilike(pattern),
                )
            )

        result = await self.session.execute(stmt)
        return result.scalar() or 0


class RuleRepository(BaseRepository[SOARRule]):
    """Repository managing SOARRule entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARRule, session)

    async def get_by_name(self, rule_name: str) -> SOARRule | None:
        """Fetch rule by name."""
        result = await self.session.execute(
            select(SOARRule).where(SOARRule.rule_name == rule_name)
        )
        return result.scalar_one_or_none()

    async def list_rules(
        self,
        skip: int = 0,
        limit: int = 100,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> Sequence[SOARRule]:
        """Fetch paginated rules."""
        stmt = select(SOARRule)
        if is_active is not None:
            stmt = stmt.where(SOARRule.is_active == is_active)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    SOARRule.rule_name.ilike(pattern),
                    SOARRule.trigger_event.ilike(pattern),
                    SOARRule.description.ilike(pattern),
                )
            )

        stmt = stmt.order_by(SOARRule.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_rules(self, is_active: bool | None = None) -> int:
        """Count rules matching active filter."""
        stmt = select(func.count(SOARRule.id))
        if is_active is not None:
            stmt = stmt.where(SOARRule.is_active == is_active)
        result = await self.session.execute(stmt)
        return result.scalar() or 0


class ExecutionRepository(BaseRepository[SOARExecution]):
    """Repository managing SOARExecution entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARExecution, session)

    async def get_with_details(self, execution_id: UUID) -> SOARExecution | None:
        """Fetch execution record with logs and approval requests."""
        result = await self.session.execute(
            select(SOARExecution)
            .options(
                selectinload(SOARExecution.logs),
                selectinload(SOARExecution.approvals),
            )
            .where(SOARExecution.id == execution_id)
        )
        return result.scalar_one_or_none()

    async def list_executions(
        self,
        skip: int = 0,
        limit: int = 100,
        status: str | None = None,
        playbook_id: UUID | None = None,
    ) -> Sequence[SOARExecution]:
        """Fetch paginated executions."""
        stmt = select(SOARExecution).options(
            selectinload(SOARExecution.logs),
            selectinload(SOARExecution.approvals),
        )

        if status:
            stmt = stmt.where(SOARExecution.status == status)
        if playbook_id:
            stmt = stmt.where(SOARExecution.playbook_id == playbook_id)

        stmt = stmt.order_by(SOARExecution.started_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_executions(self, status: str | None = None) -> int:
        """Count total execution records."""
        stmt = select(func.count(SOARExecution.id))
        if status:
            stmt = stmt.where(SOARExecution.status == status)
        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def count_executions_today(self) -> int:
        """Count executions started in the last 24 hours."""
        today_start = datetime.now(timezone.utc) - timedelta(hours=24)
        result = await self.session.execute(
            select(func.count(SOARExecution.id)).where(SOARExecution.started_at >= today_start)
        )
        return result.scalar() or 0


class ApprovalRepository(BaseRepository[SOARApprovalRequest]):
    """Repository managing SOARApprovalRequest entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SOARApprovalRequest, session)

    async def list_approvals(
        self,
        skip: int = 0,
        limit: int = 100,
        status: str | None = None,
    ) -> Sequence[SOARApprovalRequest]:
        """Fetch paginated approval requests."""
        stmt = select(SOARApprovalRequest)
        if status:
            stmt = stmt.where(SOARApprovalRequest.status == status)
        stmt = stmt.order_by(SOARApprovalRequest.requested_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_pending(self) -> int:
        """Count pending approval requests."""
        result = await self.session.execute(
            select(func.count(SOARApprovalRequest.id)).where(SOARApprovalRequest.status == "Pending")
        )
        return result.scalar() or 0
