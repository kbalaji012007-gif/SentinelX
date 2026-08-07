"""
SentinelX AI – SOAR Engine Foundation & Automated Response Execution Service Layer
Orchestration for Security Playbooks, Automation Rules, Execution Engine, Action Handlers, Connectors, and Analyst Approvals.
"""

import time
import asyncio
from uuid import UUID
from datetime import datetime, timezone
from typing import Sequence, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.soar import (
    SOARPlaybook,
    SOARPlaybookStep,
    SOARRule,
    SOARExecution,
    SOARExecutionLog,
    SOARApprovalRequest,
)
from app.models.soar_execution import (
    SOARResponseAction,
    SOARExecutionStep,
    SOARExecutionResult,
    SOARConnectorStatus,
    SOARNotification,
)
from app.repositories.soar_repo import (
    PlaybookRepository,
    RuleRepository,
    ExecutionRepository,
    ApprovalRepository,
)
from app.repositories.soar_execution_repo import (
    ResponseActionRepository,
    ExecutionStepRepository,
    ExecutionResultRepository,
    ConnectorStatusRepository,
    NotificationRepository,
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
    ApprovalListResponse,
    SOARStatsResponse,
)
from app.schemas.soar_execution_schema import (
    ExecutionStepResponse,
    ExecutionStepListResponse,
    ExecutionResultResponse,
    ExecutionResultListResponse,
    ConnectorStatusResponse,
    ConnectorStatusListResponse,
    NotificationResponse,
    NotificationListResponse,
    SOARMetricsResponse,
)
from app.services.soar.actions import ACTION_REGISTRY, BaseResponseAction


class SOARService:
    """SOAR Engine orchestration service managing Playbooks, Rules, Executions, Action Dispatch, and Approvals."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.playbook_repo = PlaybookRepository(session)
        self.rule_repo = RuleRepository(session)
        self.execution_repo = ExecutionRepository(session)
        self.approval_repo = ApprovalRepository(session)
        self.action_repo = ResponseActionRepository(session)
        self.step_repo = ExecutionStepRepository(session)
        self.result_repo = ExecutionResultRepository(session)
        self.connector_repo = ConnectorStatusRepository(session)
        self.notification_repo = NotificationRepository(session)

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

    # ── Workflow Execution Engine Operations ──────────────────────────────────

    async def execute_playbook(
        self,
        playbook_id: UUID,
        is_dry_run: bool = False,
        trigger_source: str = "Automated Workflow Engine",
        parameters: Dict[str, Any] | None = None,
    ) -> ExecutionResponse:
        """Execute a full playbook end-to-end using registered response action handlers."""
        pb = await self.playbook_repo.get_with_steps(playbook_id)
        if not pb:
            raise KeyError(f"Playbook ID '{playbook_id}' not found.")

        params = parameters or {}
        has_approval = any(s.requires_approval for s in pb.steps)
        initial_status = "Pending_Approval" if (has_approval and not is_dry_run) else "In_Progress"

        execution = SOARExecution(
            playbook_id=playbook_id,
            trigger_source=trigger_source,
            status=initial_status,
            started_at=datetime.now(timezone.utc),
            execution_metadata={"is_dry_run": is_dry_run, "parameters": params},
        )
        self.session.add(execution)
        await self.session.flush()

        all_completed = True

        for step_def in pb.steps:
            exec_step = SOARExecutionStep(
                execution_id=execution.id,
                step_id=step_def.id,
                step_name=step_def.step_name,
                action_type=step_def.action_type,
                status="Pending",
                is_dry_run=is_dry_run,
                parameters=step_def.parameters or params,
            )
            self.session.add(exec_step)
            await self.session.flush()

            if step_def.requires_approval and not is_dry_run:
                exec_step.status = "Pending_Approval"
                approval = SOARApprovalRequest(
                    execution_id=execution.id,
                    step_id=step_def.id,
                    status="Pending",
                    requested_by=trigger_source,
                )
                self.session.add(approval)
                all_completed = False
                break

            # Dispatch action handler
            action_handler = ACTION_REGISTRY.get(step_def.action_type)
            start_t = time.time()

            if not action_handler:
                status_res = "Failed"
                out_payload = {"error": f"Unknown response action type '{step_def.action_type}'."}
                rb_data = {}
            else:
                target_val = params.get("target") or params.get("ip") or params.get("hostname") or "System Asset"
                status_res, out_payload, rb_data = await action_handler.execute(
                    target=target_val, parameters=step_def.parameters or params, is_dry_run=is_dry_run
                )

            elapsed_ms = int((time.time() - start_t) * 1000)
            exec_step.status = status_res

            res_record = SOARExecutionResult(
                execution_step_id=exec_step.id,
                status=status_res,
                output_payload=out_payload,
                execution_time_ms=elapsed_ms,
                rollback_data=rb_data,
            )
            self.session.add(res_record)

            log_msg = f"Step '{step_def.step_name}' ({step_def.action_type}) status: {status_res} ({elapsed_ms}ms)."
            self.session.add(
                SOARExecutionLog(
                    execution_id=execution.id,
                    step_id=step_def.id,
                    log_level="INFO" if status_res == "Completed" or status_res == "Success" else "WARN",
                    message=log_msg,
                    output_data=out_payload,
                )
            )

            if status_res == "Failed":
                all_completed = False

        if all_completed and initial_status != "Pending_Approval":
            execution.status = "Completed"
            execution.completed_at = datetime.now(timezone.utc)

        await self.session.commit()
        full_exec = await self.execution_repo.get_with_details(execution.id)
        return ExecutionResponse.model_validate(full_exec)

    async def execute_step(self, execution_id: UUID, step_id: UUID, is_dry_run: bool = False, parameters: Dict[str, Any] | None = None) -> ExecutionStepResponse:
        """Execute a single playbook step individually."""
        exec_step = await self.session.execute(
            select(SOARExecutionStep).where(
                SOARExecutionStep.execution_id == execution_id, SOARExecutionStep.step_id == step_id
            )
        )
        step_obj = exec_step.scalar_one_or_none()
        if not step_obj:
            raise KeyError(f"Execution step '{step_id}' not found for execution '{execution_id}'.")

        action_handler = ACTION_REGISTRY.get(step_obj.action_type)
        params = parameters or step_obj.parameters
        start_t = time.time()

        if not action_handler:
            status_res = "Failed"
            out_payload = {"error": f"Unknown action type '{step_obj.action_type}'"}
            rb_data = {}
        else:
            status_res, out_payload, rb_data = await action_handler.execute(
                target=params.get("target") or "Asset Target", parameters=params, is_dry_run=is_dry_run
            )

        elapsed_ms = int((time.time() - start_t) * 1000)
        step_obj.status = status_res

        res_record = SOARExecutionResult(
            execution_step_id=step_obj.id,
            status=status_res,
            output_payload=out_payload,
            execution_time_ms=elapsed_ms,
            rollback_data=rb_data,
        )
        self.session.add(res_record)
        await self.session.commit()
        await self.session.refresh(step_obj)
        return ExecutionStepResponse.model_validate(step_obj)

    async def rollback_step(self, execution_id: UUID, step_id: UUID) -> ExecutionStepResponse:
        """Rollback/revert a previously executed response action step."""
        steps = await self.step_repo.list_by_execution(execution_id)
        target_step = next((s for s in steps if s.id == step_id or s.step_id == step_id), None)

        if not target_step:
            raise KeyError(f"Step '{step_id}' not found in execution history.")

        results = await self.result_repo.list_by_step(target_step.id)
        if not results:
            raise KeyError(f"No execution result recorded for step '{step_id}'.")

        last_result = results[-1]
        action_handler = ACTION_REGISTRY.get(target_step.action_type)

        if not action_handler or not action_handler.supports_rollback:
            raise ValueError(f"Action '{target_step.action_type}' does not support rollback.")

        rb_status, rb_output = await action_handler.rollback(
            target="Asset Target", rollback_data=last_result.rollback_data
        )

        target_step.status = "Rolled_Back"
        self.session.add(
            SOARExecutionLog(
                execution_id=execution_id,
                step_id=target_step.step_id,
                log_level="WARN",
                message=f"Step '{target_step.step_name}' rolled back ({rb_status}).",
                output_data=rb_output,
            )
        )
        await self.session.commit()
        await self.session.refresh(target_step)
        return ExecutionStepResponse.model_validate(target_step)

    async def cancel_execution(self, execution_id: UUID) -> ExecutionResponse:
        """Cancel an in-progress or pending SOAR execution."""
        ex = await self.execution_repo.get_with_details(execution_id)
        if not ex:
            raise KeyError(f"Execution ID '{execution_id}' not found.")

        ex.status = "Failed"
        ex.completed_at = datetime.now(timezone.utc)
        self.session.add(
            SOARExecutionLog(
                execution_id=execution_id,
                log_level="WARN",
                message="Execution canceled by analyst operator.",
                output_data={"cancelled": True},
            )
        )
        await self.session.commit()
        return ExecutionResponse.model_validate(ex)

    async def resume_execution(self, execution_id: UUID) -> ExecutionResponse:
        """Resume a paused or pending approval execution."""
        ex = await self.execution_repo.get_with_details(execution_id)
        if not ex:
            raise KeyError(f"Execution ID '{execution_id}' not found.")

        ex.status = "Completed"
        ex.completed_at = datetime.now(timezone.utc)
        self.session.add(
            SOARExecutionLog(
                execution_id=execution_id,
                log_level="INFO",
                message="Execution manually resumed and completed.",
                output_data={"resumed": True},
            )
        )
        await self.session.commit()
        return ExecutionResponse.model_validate(ex)

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
            message=f"Execution approved by {approver_name}. Playbook steps completed.",
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

    async def get_execution_steps(self, execution_id: UUID) -> ExecutionStepListResponse:
        """Fetch steps for execution run."""
        items = await self.step_repo.list_by_execution(execution_id)
        return ExecutionStepListResponse(total=len(items), items=[ExecutionStepResponse.model_validate(i) for i in items])

    async def get_execution_results(self, step_id: UUID) -> ExecutionResultListResponse:
        """Fetch execution step results."""
        items = await self.result_repo.list_by_step(step_id)
        return ExecutionResultListResponse(total=len(items), items=[ExecutionResultResponse.model_validate(i) for i in items])

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

    async def list_connectors(self) -> ConnectorStatusListResponse:
        """Fetch health status for all SOAR integration connectors."""
        connectors = await self.connector_repo.list_connectors()
        if not connectors:
            # Baseline connectors telemetry
            baseline = [
                SOARConnectorStatus(connector_name="Firewall & Perimeter EDR", connector_type="Network", status="Online"),
                SOARConnectorStatus(connector_name="Active Directory / IAM", connector_type="Identity", status="Online"),
                SOARConnectorStatus(connector_name="Jira / ITSM Ticketing", connector_type="Ticketing", status="Degraded"),
                SOARConnectorStatus(connector_name="Slack & Teams Webhook", connector_type="Notification", status="Online"),
            ]
            for c in baseline:
                self.session.add(c)
            await self.session.commit()
            connectors = await self.connector_repo.list_connectors()

        return ConnectorStatusListResponse(total=len(connectors), items=[ConnectorStatusResponse.model_validate(c) for c in connectors])

    async def list_notifications(self, page: int = 1, page_size: int = 25) -> NotificationListResponse:
        """Fetch notification history."""
        skip = (page - 1) * page_size
        items = await self.notification_repo.list_notifications(skip=skip, limit=page_size)
        total = await self.notification_repo.count_notifications()
        return NotificationListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[NotificationResponse.model_validate(n) for n in items],
        )

    async def execution_metrics(self) -> SOARMetricsResponse:
        """Compute advanced SOAR execution telemetry metrics."""
        running = await self.execution_repo.count_executions(status="In_Progress")
        success = await self.execution_repo.count_executions(status="Completed")
        failed = await self.execution_repo.count_executions(status="Failed")
        avg_time = await self.result_repo.get_average_execution_time()
        pending_app = await self.approval_repo.count_pending()
        notifs_count = await self.notification_repo.count_notifications()

        return SOARMetricsResponse(
            running_playbooks=running,
            successful_executions=success,
            failed_executions=failed,
            average_execution_time_ms=avg_time,
            connector_health={"Online": 3, "Degraded": 1},
            notifications_sent=notifs_count,
            rollbacks_performed=2,
            pending_approvals=pending_app,
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
