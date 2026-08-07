"""
SentinelX AI – Models Package
Exposes Base, Role, User, AssetGroup, Asset, Threat, Alert, IOC, Log, ThreatIntelligence, Correlation, and SOAR Engine ORM models.
"""

from app.models.base import Base, TimestampMixin
from app.models.role import Role
from app.models.user import User
from app.models.asset_group import AssetGroup
from app.models.asset import Asset
from app.models.threat import Threat, Alert, IOC
from app.models.incident import Incident, IncidentTimeline, IncidentNote, IncidentEvidence
from app.models.log import LogSource, LogEntry
from app.models.threat_intelligence import (
    ThreatFeed,
    IOCFeed,
    IOCReputation,
    MitreTechnique,
    ThreatCache,
)
from app.models.correlation import (
    CorrelationRule,
    ThreatCorrelation,
    AttackChain,
    MitreMapping,
)
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
    SOARWebhook,
    SOARNotification,
)
from app.models.ai_soc import AIInvestigationHistory, AIThreatHunt
from app.models.ai_copilot import AIChatConversation, AIChatMessage, AIGeneratedReport

__all__ = [
    "Base",
    "TimestampMixin",
    "Role",
    "User",
    "AssetGroup",
    "Asset",
    "Threat",
    "Alert",
    "IOC",
    "Incident",
    "IncidentTimeline",
    "IncidentNote",
    "IncidentEvidence",
    "LogSource",
    "LogEntry",
    "ThreatFeed",
    "IOCFeed",
    "IOCReputation",
    "MitreTechnique",
    "ThreatCache",
    "CorrelationRule",
    "ThreatCorrelation",
    "AttackChain",
    "MitreMapping",
    "SOARPlaybook",
    "SOARPlaybookStep",
    "SOARRule",
    "SOARExecution",
    "SOARExecutionLog",
    "SOARApprovalRequest",
    "SOARResponseAction",
    "SOARExecutionStep",
    "SOARExecutionResult",
    "SOARConnectorStatus",
    "SOARWebhook",
    "SOARNotification",
    "AIInvestigationHistory",
    "AIThreatHunt",
    "AIChatConversation",
    "AIChatMessage",
    "AIGeneratedReport",
]
