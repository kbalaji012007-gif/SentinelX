"""
SentinelX AI – SOAR Actions Package
Exposes BaseResponseAction and action registry mapping action_type to action class instances.
"""

from typing import Dict
from app.services.soar.actions.base import BaseResponseAction
from app.services.soar.actions.handlers import (
    BlockIPAction,
    BlockDomainAction,
    BlockURLAction,
    BlockHashAction,
    IsolateHostAction,
    DisableUserAction,
    KillProcessAction,
    CloseIncidentAction,
    EscalateIncidentAction,
    CreateTicketAction,
    SendEmailAction,
    SlackNotificationAction,
    TeamsNotificationAction,
    WebhookAction,
)

# Registry mapping action_type string to action handler instance
ACTION_REGISTRY: Dict[str, BaseResponseAction] = {
    "Block_IP": BlockIPAction(),
    "Block_Domain": BlockDomainAction(),
    "Block_URL": BlockURLAction(),
    "Block_Hash": BlockHashAction(),
    "Isolate_Host": IsolateHostAction(),
    "Disable_User": DisableUserAction(),
    "Kill_Process": KillProcessAction(),
    "Close_Incident": CloseIncidentAction(),
    "Escalate_Incident": EscalateIncidentAction(),
    "Create_Ticket": CreateTicketAction(),
    "Send_Email": SendEmailAction(),
    "Slack_Notification": SlackNotificationAction(),
    "Teams_Notification": TeamsNotificationAction(),
    "Webhook": WebhookAction(),
}

__all__ = [
    "BaseResponseAction",
    "ACTION_REGISTRY",
    "BlockIPAction",
    "BlockDomainAction",
    "BlockURLAction",
    "BlockHashAction",
    "IsolateHostAction",
    "DisableUserAction",
    "KillProcessAction",
    "CloseIncidentAction",
    "EscalateIncidentAction",
    "CreateTicketAction",
    "SendEmailAction",
    "SlackNotificationAction",
    "TeamsNotificationAction",
    "WebhookAction",
]
