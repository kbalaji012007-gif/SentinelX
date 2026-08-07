"""
SentinelX AI – SOAR Engine Foundation Service Layer
Business logic for Security Playbooks, Automation Rules, Execution Records, and Analyst Approval Workflows.
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import Sequence, List
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.soar import (
    SOARPlaybook,
    SOARPlaybookStep,
    SOARRule,
    SOARExecution,
    SOARExecutionLog,
    SOARApprovalRequest,
)
from app.repositories.soar_repo import (
    PlaybookRepository,
    RuleRepository,
    ExecutionRepository,
    ApprovalRepository,
)
from app.schemas.soar_schema import (
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookResponse,
    PlaybookListResponse,
    RuleCreate,
    RuleResponse,
    RuleListResponse,
    ExecutionCreate,
    ExecutionResponse,
    ExecutionListResponse,
    ApprovalResponse,
    ApprovalListResponse,
    SOARStatsResponse,
    ExecutionLogResponse,
)


class SOARService:
    """SOAR Engine orchestration service managing Playbooks, Rules, Executions, and Approvals."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.playbook_repo = PlaybookRepository(session)
        self.rule_repo = RuleRepository(session)
        self.execution_repo = ExecutionRepository(session)
        self.approval_repo = ApprovalRepository(session)

    # ── Playbook Operations ──────────────────────────────────────────────────

    async def create_playbook(self, payload: PlaybookCreate) -> PlaybookResponse:
        """Create a new SOAR playbook with sequential steps."""
        existing = await self.playbook_repo.get_by_name(payload.name)
        if existing:
            raise ValueError(f"Playbook with name '{payload.name}' already exists.")

        playbook = SOARPlaybook(
            name=payload.name,
            description=payload.description,
            trigger_type=payload.trigger_type,
            category=payload.category,
            is_active=payload.is_active,
            author=payload.author,
        )

        for step_data in payload.steps:
            step = SOARPlaybookStep(
                step_order=step_data.step_order,
                step_name=step_data.step_name,
                action_type=step_data.action_type,
                target_type=step_data.target_type,
                parameters=step_data.parameters,
                requires_approval=step_data.requires_approval,
            )
            playbook.steps.append(step)

        self.session.add(playbook)
        await self.session.commit()
        await self.session.refresh(playbook)
        return PlaybookResponse.model_validate(playbook)

    async def get_playbook(self, playbook_id: UUID) -> PlaybookResponse:
        """Fetch single playbook by UUID with steps."""
        pb = await self.playbook_repo.get_with_steps(playbook_id)
        if not pb:
            raise KeyError(f"Playbook ID '{playbook_id}' not found.")
        return PlaybookResponse.model_validate(pb)

    async def update_playbook(self, playbook_id: UUID, payload: PlaybookUpdate) -> PlaybookResponse:
        """Update existing playbook attributes and steps."""
        pb = await self.playbook_repo.get_with_steps(playbook_id)
        if not pb:
            raise KeyError(f"Playbook ID '{playbook_id}' not found.")

        if payload.name is not None:
            pb.name = payload.name
        if payload.description is not None:
            pb.description = payload.description
        if payload.trigger_type is not None:
            pb.trigger_type = payload.trigger_type
        if payload.category is not None:
            pb.category = payload.category
        if payload.is_active is not None:
            pb.is_active = payload.is_active
        if payload.author is not None:
            pb.author = payload.author

        if payload.steps is not None:
            pb.steps.clear()
            for step_data in payload.steps:
                step = SOARPlaybookStep(
                    step_order=step_data.step_order,
                    step_name=step_data.step_name,
                    action_type=step_data.action_type,
                    target_type=step_data.target_type,
                    parameters=step_data.parameters,
                    requires_approval=step_data.requires_approval,
                )
                pb.steps.append(step)

        await self.session.commit()
        await self.session.refresh(pb)
        return PlaybookResponse.model_validate(pb)

    async def delete_playbook(self, playbook_id: UUID) -> bool:
        """Delete a playbook by UUID."""
        pb = await self.playbook_repo.get_by_id(playbook_id)
        if not pb:
            raise KeyError(f"Playbook ID '{playbook_id}' not found.")

        await self.playbook_repo.delete(pb)
        await self.session.commit()
        return True

    async def list_playbooks(
        self,
        page: int = 1,
        page_size: int = 25,
        category: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> PlaybookListResponse:
        """Fetch paginated list of playbooks."""
        skip = (page - 1) * page_size
        items = await self.playbook_repo.list_playbooks(
            skip=skip, limit=page_size, category=category, is_active=is_active, search=search
        )
        total = await self.playbook_repo.count_playbooks(category=category, is_active=is_active, search=search)
        return PlaybookListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[PlaybookResponse.model_validate(pb) for pb in items],
        )

    # ── Rule Operations ──────────────────────────────────────────────────────

    async def create_rule(self, payload: RuleCreate) -> RuleResponse:
        """Create a new event-driven automation rule."""
        existing = await self.rule_repo.get_by_name(payload.rule_name)
        if existing:
            raise ValueError(f"Rule with name '{payload.rule_name}' already exists.")

        rule = SOARRule(
            rule_name=payload.rule_name,
            trigger_event=payload.trigger_event,
            condition_logic=payload.condition_logic,
            playbook_id=payload.playbook_id,
            is_active=payload.is_active,
            description=payload.description,
        )

        self.session.add(rule)
        await self.session.commit()
        await self.session.refresh(rule)
        return RuleResponse.model_validate(rule)

    async def list_rules(
        self,
        page: int = 1,
        page_size: int = 25,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> RuleListResponse:
        """Fetch paginated automation rules."""
        skip = (page - 1) * page_size
        items = await self.rule_repo.list_rules(skip=skip, limit=page_size, is_active=is_active, search=search)
        total = await self.rule_repo.count_rules(is_active=is_active)
        return RuleListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[RuleResponse.model_validate(r) for r in items],
        )

    # ── Execution & Approval Operations ──────────────────────────────────────

    async def create_execution(self, payload: ExecutionCreate) -> ExecutionResponse:
        """Record a playbook execution event and initiate step logs or approval requests."""
        pb = await self.playbook_repo.get_with_steps(payload.playbook_id)
        if not pb:
            raise KeyError(f"Playbook ID '{payload.playbook_id}' not found.")

        has_approval_step = any(s.requires_approval for s in pb.steps)
        initial_status = "Pending_Approval" if has_approval_step else "Completed"

        execution = SOARExecution(
            playbook_id=payload.playbook_id,
            rule_id=payload.rule_id,
            trigger_source=payload.trigger_source,
            status=initial_status,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc) if not has_approval_step else None,
            execution_metadata=payload.execution_metadata,
        )
        self.session.add(execution)
        await self.session.flush()

        # Generate execution step logs
        for step in pb.steps:
            log_msg = f"Step '{step.step_name}' ({step.action_type}) queued."
            if step.requires_approval:
                log_msg += " Paused awaiting analyst approval."
                approval = SOARApprovalRequest(
                    execution_id=execution.id,
                    step_id=step.id,
                    status="Pending",
                    requested_by="SOAR Engine",
                    requested_at=datetime.now(timezone.utc),
                )
                self.session.add(approval)

            log_entry = SOARExecutionLog(
                execution_id=execution.id,
                step_id=step.id,
                log_level="INFO",
                message=log_msg,
                output_data={"action": step.action_type, "target": step.target_type},
            )
            self.session.add(log_entry)

        await self.session.commit()
        full_exec = await self.execution_repo.get_with_details(execution.id)
        return ExecutionResponse.model_validate(full_exec)

    async def approve_execution(self, execution_id: UUID, approver_name: str, reason: str | None = None) -> ExecutionResponse:
        """Approve a pending SOAR execution request."""
        exec_record = await self.execution_repo.get_with_details(execution_id)
        if not exec_record:
            raise KeyError(f"Execution ID '{execution_id}' not found.")

        exec_record.status = "Completed"
        exec_record.completed_at = datetime.now(timezone.utc)

        for app in exec_record.approvals:
            if app.status == "Pending":
                app.status = "Approved"
                app.approved_by = approver_name
                app.reason = reason or "Approved by SOC Analyst"
                app.decided_at = datetime.now(timezone.utc)

        log_entry = SOARExecutionLog(
            execution_id=exec_record.id,
            log_level="INFO",
            message=f"Execution approved by {approver_name}. Playbook steps resumed.",
            output_data={"approver": approver_name, "reason": reason},
        )
        self.session.add(log_entry)

        await self.session.commit()
        full_exec = await self.execution_repo.get_with_details(execution_id)
        return ExecutionResponse.model_validate(full_exec)

    async def reject_execution(self, execution_id: UUID, rejector_name: str, reason: str | None = None) -> ExecutionResponse:
        """Reject a pending SOAR execution request."""
        exec_record = await self.execution_repo.get_with_details(execution_id)
        if not exec_record:
            raise KeyError(f"Execution ID '{execution_id}' not found.")

        exec_record.status = "Rejected"
        exec_record.completed_at = datetime.now(timezone.utc)

        for app in exec_record.approvals:
            if app.status == "Pending":
                app.status = "Rejected"
                app.approved_by = rejector_name
                app.reason = reason or "Rejected by SOC Analyst"
                app.decided_at = datetime.now(timezone.utc)

        log_entry = SOARExecutionLog(
            execution_id=exec_record.id,
            log_level="WARN",
            message=f"Execution rejected by {rejector_name}. Response actions halted.",
            output_data={"rejector": rejector_name, "reason": reason},
        )
        self.session.add(log_entry)

        await self.session.commit()
        full_exec = await self.execution_repo.get_with_details(execution_id)
        return ExecutionResponse.model_validate(full_exec)

    async def execution_history(
        self,
        page: int = 1,
        page_size: int = 25,
        status: str | None = None,
        playbook_id: UUID | None = None,
    ) -> ExecutionListResponse:
        """Fetch paginated execution audit history."""
        skip = (page - 1) * page_size
        items = await self.execution_repo.list_executions(skip=skip, limit=page_size, status=status, playbook_id=playbook_id)
        total = await self.execution_repo.count_executions(status=status)
        return ExecutionListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[ExecutionResponse.model_validate(ex) for ex in items],
        )

    async def list_approvals(self, page: int = 1, page_size: int = 25, status: str | None = None) -> ApprovalListResponse:
        """Fetch approval requests."""
        skip = (page - 1) * page_size
        items = await self.approval_repo.list_approvals(skip=skip, limit=page_size, status=status)
        total = await self.approval_repo.count_pending()
        return ApprovalListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[ApprovalResponse.model_validate(app) for app in items],
        )

    async def execution_statistics(self) -> SOARStatsResponse:
        """Compute summary telemetry metrics for SOAR engine."""
        total_pb = await self.playbook_repo.count_playbooks()
        active_r = await self.rule_repo.count_rules(is_active=True)
        pending_app = await self.approval_repo.count_pending()
        exec_today = await self.execution_repo.count_executions_today()
        success_exec = await self.execution_repo.count_executions(status="Completed")
        failed_exec = await self.execution_repo.count_executions(status="Failed")

        return SOARStatsResponse(
            total_playbooks=total_pb,
            active_rules=active_r,
            pending_approvals=pending_app,
            executions_today=exec_today,
            successful_executions=success_exec,
            failed_executions=failed_exec,
            by_category={"Threat Response": total_pb, "Containment": active_r},
        )
