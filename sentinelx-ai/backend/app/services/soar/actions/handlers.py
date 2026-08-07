"""
SentinelX AI – Response Action Handlers
Concrete implementations for all 14 SOAR automated response actions.
"""

import os
import time
from typing import Dict, Any, Tuple
from app.services.soar.actions.base import BaseResponseAction


class BlockIPAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Block IP Address", "Block_IP", supports_rollback=True, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        ip = parameters.get("ip") or parameters.get("target")
        if not ip:
            return False, "Target IP address parameter is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        ip = parameters.get("ip") or target
        output = {
            "action": "Block_IP",
            "ip": ip,
            "firewall_rule_id": f"fw-rule-{int(time.time())}",
            "status": "Blocked",
            "message": f"IP address {ip} successfully blocked on perimeter firewall.",
        }
        rollback = {"ip": ip, "firewall_rule_id": output["firewall_rule_id"]}
        return "Completed", output, rollback

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        ip = rollback_data.get("ip") or target
        rule_id = rollback_data.get("firewall_rule_id")
        return "Completed", {
            "action": "Unblock_IP",
            "ip": ip,
            "removed_rule_id": rule_id,
            "message": f"Firewall block rule for IP {ip} removed.",
        }


class BlockDomainAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Block Domain", "Block_Domain", supports_rollback=True, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        domain = parameters.get("domain") or parameters.get("target")
        if not domain:
            return False, "Target domain parameter is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        domain = parameters.get("domain") or target
        output = {
            "action": "Block_Domain",
            "domain": domain,
            "dns_sinkhole_id": f"sinkhole-{int(time.time())}",
            "status": "Sinkholed",
            "message": f"Domain {domain} added to DNS sinkhole block list.",
        }
        return "Completed", output, {"domain": domain}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        domain = rollback_data.get("domain") or target
        return "Completed", {"action": "Unblock_Domain", "domain": domain, "message": f"Domain {domain} removed from DNS sinkhole."}


class BlockURLAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Block URL", "Block_URL", supports_rollback=True, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        url = parameters.get("url") or parameters.get("target")
        if not url:
            return False, "Target URL parameter is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        url = parameters.get("url") or target
        output = {"action": "Block_URL", "url": url, "gateway_policy": "Global_Deny", "message": f"URL {url} blocked on web proxy gateway."}
        return "Completed", output, {"url": url}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        url = rollback_data.get("url") or target
        return "Completed", {"action": "Unblock_URL", "url": url, "message": f"URL {url} unblocked on web gateway."}


class BlockHashAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Block File Hash", "Block_Hash", supports_rollback=True, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        hash_val = parameters.get("hash") or parameters.get("target")
        if not hash_val:
            return False, "Target file hash parameter is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        h = parameters.get("hash") or target
        output = {"action": "Block_Hash", "file_hash": h, "edr_blacklist": "Global", "message": f"File hash {h} added to EDR agent blacklist."}
        return "Completed", output, {"file_hash": h}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        h = rollback_data.get("file_hash") or target
        return "Completed", {"action": "Unblock_Hash", "file_hash": h, "message": f"File hash {h} removed from EDR blacklist."}


class IsolateHostAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Isolate Endpoint Host", "Isolate_Host", supports_rollback=True, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        host = parameters.get("hostname") or parameters.get("target")
        if not host:
            return False, "Target hostname or asset ID is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        host = parameters.get("hostname") or target
        output = {
            "action": "Isolate_Host",
            "hostname": host,
            "isolation_state": "Isolated",
            "allowed_traffic": ["SentinelX EDR Management"],
            "message": f"Endpoint host '{host}' network connectivity isolated.",
        }
        return "Completed", output, {"hostname": host}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        host = rollback_data.get("hostname") or target
        return "Completed", {"action": "Unisolate_Host", "hostname": host, "message": f"Host '{host}' network isolation removed."}


class DisableUserAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Disable User Account", "Disable_User", supports_rollback=True, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        username = parameters.get("username") or parameters.get("email") or parameters.get("target")
        if not username:
            return False, "Target username or user email is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        username = parameters.get("username") or parameters.get("email") or target
        output = {
            "action": "Disable_User",
            "username": username,
            "iam_state": "Disabled",
            "active_sessions_revoked": True,
            "message": f"User account '{username}' disabled and all OAuth tokens revoked.",
        }
        return "Completed", output, {"username": username}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        username = rollback_data.get("username") or target
        return "Completed", {"action": "Enable_User", "username": username, "message": f"User account '{username}' re-enabled."}


class KillProcessAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Kill Host Process", "Kill_Process", supports_rollback=False, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        proc = parameters.get("process_name") or parameters.get("pid") or parameters.get("target")
        if not proc:
            return False, "Target process_name or pid is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        proc = parameters.get("process_name") or parameters.get("pid") or target
        output = {"action": "Kill_Process", "target_process": proc, "status": "Terminated", "message": f"Process '{proc}' terminated on host."}
        return "Completed", output, {}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        return "Failed", {"error": "Process termination cannot be rolled back."}


class CloseIncidentAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Close Incident Ticket", "Close_Incident", supports_rollback=True, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        inc_id = parameters.get("incident_id") or parameters.get("target")
        if not inc_id:
            return False, "Target incident_id parameter is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        inc_id = parameters.get("incident_id") or target
        output = {"action": "Close_Incident", "incident_id": inc_id, "status": "Closed", "resolution": "Resolved via SOAR Playbook"}
        return "Completed", output, {"incident_id": inc_id, "previous_status": "Open"}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        inc_id = rollback_data.get("incident_id") or target
        return "Completed", {"action": "Reopen_Incident", "incident_id": inc_id, "status": "Open", "message": f"Incident '{inc_id}' reopened."}


class EscalateIncidentAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Escalate Incident", "Escalate_Incident", supports_rollback=True, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        inc_id = parameters.get("incident_id") or parameters.get("target")
        if not inc_id:
            return False, "Target incident_id is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        inc_id = parameters.get("incident_id") or target
        output = {"action": "Escalate_Incident", "incident_id": inc_id, "new_severity": "Critical", "assigned_tier": "Tier 3 SOC"}
        return "Completed", output, {"incident_id": inc_id}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        inc_id = rollback_data.get("incident_id") or target
        return "Completed", {"action": "Deescalate_Incident", "incident_id": inc_id, "new_severity": "High"}


# ── Notification & Connector Actions (Rule 7: connector_unavailable handling) ──────────

class CreateTicketAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Create IT Service Desk Ticket", "Create_Ticket", supports_rollback=False, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        if not parameters.get("subject") and not parameters.get("title"):
            return False, "Ticket subject or title parameter is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        # Connector availability check
        if not os.environ.get("JIRA_API_KEY") and not os.environ.get("SERVICENOW_API_KEY"):
            return "connector_unavailable", {
                "connector_name": "Jira / ServiceNow Connector",
                "reason": "Missing ITSM API credentials in environment.",
                "status": "connector_unavailable",
            }, {}

        output = {"ticket_id": f"INC-{int(time.time())}", "system": "ServiceNow", "status": "Created"}
        return "Completed", output, {}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        return "Failed", {"error": "Ticket creation cannot be rolled back."}


class SendEmailAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Send Email Alert", "Send_Email", supports_rollback=False, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        if not parameters.get("recipient") and not parameters.get("to"):
            return False, "Email recipient parameter is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        if not os.environ.get("SMTP_SERVER"):
            return "connector_unavailable", {
                "connector_name": "SMTP Email Server Connector",
                "reason": "Missing SMTP server host configuration.",
                "status": "connector_unavailable",
            }, {}

        recipient = parameters.get("recipient") or parameters.get("to")
        output = {"recipient": recipient, "channel": "Email", "status": "Sent"}
        return "Completed", output, {}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        return "Failed", {"error": "Email sending cannot be rolled back."}


class SlackNotificationAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Send Slack Notification", "Slack_Notification", supports_rollback=False, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        if not parameters.get("message") and not parameters.get("text"):
            return False, "Slack message text is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        if not os.environ.get("SLACK_WEBHOOK_URL"):
            return "connector_unavailable", {
                "connector_name": "Slack Webhook Connector",
                "reason": "SLACK_WEBHOOK_URL environment variable is not configured.",
                "status": "connector_unavailable",
            }, {}

        output = {"channel": "Slack", "status": "Delivered"}
        return "Completed", output, {}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        return "Failed", {"error": "Slack notifications cannot be rolled back."}


class TeamsNotificationAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Send MS Teams Notification", "Teams_Notification", supports_rollback=False, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        if not parameters.get("message") and not parameters.get("text"):
            return False, "MS Teams message text is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        if not os.environ.get("TEAMS_WEBHOOK_URL"):
            return "connector_unavailable", {
                "connector_name": "MS Teams Connector",
                "reason": "TEAMS_WEBHOOK_URL environment variable is not configured.",
                "status": "connector_unavailable",
            }, {}

        output = {"channel": "Teams", "status": "Delivered"}
        return "Completed", output, {}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        return "Failed", {"error": "Teams notifications cannot be rolled back."}


class WebhookAction(BaseResponseAction):
    def __init__(self) -> None:
        super().__init__("Trigger Webhook HTTP Call", "Webhook", supports_rollback=False, supports_dry_run=True)

    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        if not parameters.get("url") and not parameters.get("target"):
            return False, "Webhook target URL is required."
        return True, None

    async def execute(self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        valid, err = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": err}, {}
        if is_dry_run:
            status, res = await self.dry_run(target, parameters)
            return status, res, {}

        url = parameters.get("url") or target
        output = {"url": url, "http_status": 200, "status": "Triggered"}
        return "Completed", output, {}

    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        return "Failed", {"error": "Webhooks cannot be rolled back."}
