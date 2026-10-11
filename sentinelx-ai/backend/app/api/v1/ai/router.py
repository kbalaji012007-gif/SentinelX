"""
SentinelX AI – AI SOC Analyst & Copilot API Router
JWT-protected, RBAC-enforced endpoints for AI Investigations, Threat Hunting,
Copilot Natural Language Chat, Explainability, Multi-Format Report Generation,
Conversation Management, and Safe SOAR Response Actions.
"""

from uuid import UUID
from typing import Annotated
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole
from app.models.user import User
from app.models.ai_copilot import AIChatConversation
from app.schemas.ai_soc_schema import (
    InvestigationRequest,
    InvestigationResponse,
    InvestigationListResponse,
    ThreatHuntRequest,
    ThreatHuntResponse,
    RiskAssessmentResponse,
    RecommendationResponse,
)
from app.schemas.ai_copilot_schema import (
    AIChatRequest,
    AIChatMessageResponse,
    AIChatConversationCreate,
    AIChatConversationResponse,
    ConversationListResponse,
    AIExplainRequest,
    AIExplainResponse,
    AIReportRequest,
    AIReportResponse,
    SafeActionExecuteRequest,
    SafeActionExecuteResponse,
)
from app.services.ai_soc import (
    AIInvestigationService,
    AIThreatHuntingService,
    AIRiskAssessmentService,
    AIRecommendationService,
    AICopilotService,
    AIReportGeneratorService,
)

router = APIRouter(prefix="/ai", tags=["AI SOC Analyst & Copilot"])

# RBAC roles
_READERS = [
    "Super Administrator",
    "Administrator",
    "Admin",
    "SOC Manager",
    "Manager",
    "SOC Analyst",
    "Analyst",
    "Threat Hunter",
    "Incident Responder",
    "Auditor",
    "Read Only",
    "ReadOnly",
]
_WRITERS = [
    "Super Administrator",
    "Administrator",
    "Admin",
    "SOC Manager",
    "Manager",
    "SOC Analyst",
    "Analyst",
    "Threat Hunter",
    "Incident Responder",
    "Auditor",
    "Read Only",
    "ReadOnly",
]
_ADMINS = [
    "Super Administrator",
    "Administrator",
    "Admin",
    "SOC Manager",
]


# ────────────────────────────────────────────────────────────────────────
# Copilot Natural Language Chat & Conversation Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.post(
    "/chat",
    response_model=AIChatMessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Copilot Natural Language Security Chat",
)
async def copilot_chat(
    payload: AIChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> AIChatMessageResponse:
    """Interact with Enterprise AI Copilot using natural language security queries."""
    service = AICopilotService(db)
    user_name = f"{current_user.first_name} {current_user.last_name}"
    return await service.chat_interaction(payload, user_name=user_name, current_user=current_user)


@router.get(
    "/conversations",
    response_model=ConversationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List AI Copilot Chat Conversations",
)
async def list_conversations(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=50, description="Items per page")] = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> ConversationListResponse:
    """Fetch paginated list of chat conversation sessions."""
    service = AICopilotService(db)
    skip = (page - 1) * page_size
    convs = await service.chat_repo.list_user_conversations(skip=skip, limit=page_size)
    items = [AIChatConversationResponse.model_validate(c) for c in convs]
    return ConversationListResponse(total=len(items), items=items)


@router.get(
    "/conversations/{id}",
    response_model=AIChatConversationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get AI Copilot Chat Conversation Details",
)
async def get_conversation(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> AIChatConversationResponse:
    """Fetch single conversation session with full ordered message history."""
    service = AICopilotService(db)
    conv = await service.chat_repo.get_with_messages(id)
    if not conv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation session '{id}' not found.",
        )
    return AIChatConversationResponse.model_validate(conv)


@router.post(
    "/conversations",
    response_model=AIChatConversationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New AI Copilot Chat Conversation",
)
async def create_conversation(
    payload: AIChatConversationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> AIChatConversationResponse:
    """Explicitly create a new conversation session."""
    conv = AIChatConversation(title=payload.title, user_id=current_user.id)
    db.add(conv)
    await db.commit()
    await db.refresh(conv)
    return AIChatConversationResponse.model_validate(conv)


@router.delete(
    "/conversations/{id}",
    status_code=status.HTTP_200_OK,
    summary="Delete AI Copilot Chat Conversation",
)
async def delete_conversation(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> dict[str, str]:
    """Delete conversation session and all associated chat messages."""
    service = AICopilotService(db)
    deleted = await service.chat_repo.delete_conversation(id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation session '{id}' not found.",
        )
    return {"message": f"Conversation '{id}' deleted successfully."}


# ────────────────────────────────────────────────────────────────────────
# Safe SOAR Response Action Execution
# ────────────────────────────────────────────────────────────────────────

@router.post(
    "/action/execute",
    response_model=SafeActionExecuteResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Confirmed Safe Response Action",
)
async def execute_safe_action(
    payload: SafeActionExecuteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> SafeActionExecuteResponse:
    """
    Execute or dry-run a recommended response action through SentinelX SOAR action registry.
    Requires explicit analyst confirmation if not in dry-run mode.
    """
    if not payload.is_dry_run and not payload.confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Safety constraint: Impactful response action requires explicit confirmation ('confirmed': true).",
        )

    service = AICopilotService(db)
    user_name = f"{current_user.first_name} {current_user.last_name}"
    res = await service.tools.execute_safe_action(
        action_type=payload.action_type,
        target=payload.target,
        parameters=payload.parameters or {"target": payload.target},
        is_dry_run=payload.is_dry_run,
        confirmed_by=user_name,
    )

    return SafeActionExecuteResponse(
        success=res["success"],
        status=res["status"],
        action_type=payload.action_type,
        target=payload.target,
        is_dry_run=payload.is_dry_run,
        output=res.get("output", {}),
        rollback_data=res.get("rollback_data", {}),
        executed_by=user_name,
        executed_at=res.get("executed_at", ""),
        error=res.get("error"),
    )


# ────────────────────────────────────────────────────────────────────────
# Explainability & Report Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.post(
    "/explain",
    response_model=AIExplainResponse,
    status_code=status.HTTP_200_OK,
    summary="AI Explainability Breakdown",
)
async def explain_entity(
    payload: AIExplainRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> AIExplainResponse:
    """Generate deep AI explainability for Incidents, Correlations, Attack Chains, MITRE, or Playbooks."""
    service = AICopilotService(db)
    return await service.explain_entity(entity_type=payload.entity_type, entity_id=payload.entity_id)


@router.post(
    "/report",
    response_model=AIReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate AI Security Report",
)
async def generate_report(
    payload: AIReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> AIReportResponse:
    """Generate security report in Markdown, JSON, or PDF structure."""
    service = AIReportGeneratorService(db)
    user_name = f"{current_user.first_name} {current_user.last_name}"
    return await service.generate_report(payload, user_name=user_name)


# ────────────────────────────────────────────────────────────────────────
# Investigation & Threat Hunting Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger AI SOC Investigation",
)
async def trigger_investigation(
    payload: InvestigationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> InvestigationResponse:
    """Trigger an AI investigation for an incident, threat, asset, log query, or IOC."""
    service = AIInvestigationService(db)
    operator = f"{current_user.first_name} {current_user.last_name}"

    inv_type = payload.investigation_type.upper()
    if inv_type == "INCIDENT":
        return await service.investigate_incident(payload.target_id, operator_name=operator)
    elif inv_type == "THREAT":
        return await service.investigate_threat(payload.target_id, operator_name=operator)
    elif inv_type == "ASSET":
        return await service.investigate_asset(payload.target_id, operator_name=operator)
    else:
        return await service.investigate_incident(payload.target_id, operator_name=operator)


@router.post(
    "/hunt",
    response_model=ThreatHuntResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Proactive AI Threat Hunt",
)
async def execute_threat_hunt(
    payload: ThreatHuntRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ThreatHuntResponse:
    """Run proactive threat hunt by IP, domain, hash, username, asset, or MITRE technique."""
    service = AIThreatHuntingService(db)
    operator = f"{current_user.first_name} {current_user.last_name}"
    return await service.execute_hunt(
        hunt_type=payload.hunt_type, query_value=payload.query_value, operator_name=operator
    )


@router.post(
    "/risk-assessment",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="AI Business Risk & Predictive Assessment",
)
async def get_risk_assessment(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> RiskAssessmentResponse:
    """Compute platform-wide AI risk score and attack spread predictions."""
    service = AIRiskAssessmentService(db)
    return await service.calculate_risk_assessment()


@router.post(
    "/recommend",
    response_model=RecommendationResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate AI Response Recommendations",
)
async def get_ai_recommendations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> RecommendationResponse:
    """Generate Playbook, remediation, containment, and recovery recommendations."""
    service = AIRecommendationService(db)
    return await service.generate_recommendations()


@router.post(
    "/summary",
    response_model=InvestigationResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Executive AI Summary",
)
async def get_executive_summary(
    payload: InvestigationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> InvestigationResponse:
    """Generate high-level executive security summary."""
    service = AIInvestigationService(db)
    operator = f"{current_user.first_name} {current_user.last_name}"
    return await service.investigate_incident(payload.target_id, operator_name=operator)


@router.get(
    "/history",
    response_model=InvestigationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List AI Investigation Audit History",
)
async def list_investigation_history(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> InvestigationListResponse:
    """Fetch paginated AI investigation audit history logs."""
    service = AIInvestigationService(db)
    items = await service.list_investigations(page=page, page_size=page_size)
    return InvestigationListResponse(total=len(items), items=items)


@router.delete(
    "/history/{id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Investigation / Chat History",
)
async def delete_history_item(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMINS)),
) -> dict[str, str]:
    """Delete investigation history item or chat conversation."""
    service = AICopilotService(db)
    await service.chat_repo.delete_conversation(id)
    return {"message": f"History item '{id}' deleted successfully."}
