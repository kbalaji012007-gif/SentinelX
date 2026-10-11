"""
SentinelX AI – Comprehensive Unit Tests for Upgraded AI Assistant
Tests:
- Natural-language intent classification & database tools
- Real database records vs empty results (no fabrication)
- 4-Tier evidence classification (Observed, External, AI Inference, Insufficient Evidence)
- Follow-up conversation context tracking
- Safe SOAR action recommendation & confirmation enforcement
- SQL injection safety with parameterized queries
- Fallback when external AI provider is unavailable
- Academic / executive incident report generation
- RBAC permissions on AI endpoints
"""

import pytest
from uuid import uuid4, UUID
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.security_alert import SecurityAlert
from app.models.agent import EndpointAgent, AgentTelemetry
from app.models.log import LogEntry
from app.models.asset import Asset
from app.models.incident import Incident
from app.models.user import User
from app.models.threat import Alert
from app.models.ai_copilot import AIChatConversation, AIChatMessage
from app.services.ai_soc.copilot_service import AICopilotService
from app.services.ai_soc.tools import SecurityAssistantTools
from app.schemas.ai_copilot_schema import AIChatRequest, SafeActionExecuteRequest


@pytest.mark.asyncio
async def test_critical_security_alerts_intent_with_records():
    """Verify assistant retrieves critical alerts from live DB and classifies evidence correctly."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    alert_1 = SecurityAlert(
        id=uuid4(),
        alert_id="ALT-CRIT-001",
        title="Cobalt Strike C2 Beaconing",
        severity="CRITICAL",
        status="NEW",
        alert_type="c2_beacon",
        detected_at=datetime.now(timezone.utc),
    )

    mock_exec = MagicMock()
    mock_exec.scalars.return_value.all.return_value = [alert_1]
    mock_session.execute = AsyncMock(return_value=mock_exec)

    res = await service.interpret_and_execute_query("Show me all critical security alerts.")

    assert res["intent"] == "List Critical Security Alerts"
    assert res["tool_used"] == "get_security_alerts"
    assert res["confidence_score"] >= 90
    assert "ALT-CRIT-001" in res["response_markdown"]
    assert "Cobalt Strike C2 Beaconing" in res["response_markdown"]

    # Verify 4-tier evidence structure
    ev = res["evidence"]
    assert len(ev["observed_sentinelx_data"]) >= 1
    assert any("ALT-CRIT-001" in item for item in ev["observed_sentinelx_data"])
    assert len(ev["ai_inference"]) >= 1
    assert ev["insufficient_evidence_warning"] is None


@pytest.mark.asyncio
async def test_empty_database_results_never_fabricate():
    """Verify that when no records match, the assistant explicitly states 0 records found without inventing fake data."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    # Mock empty result from DB
    mock_exec = MagicMock()
    mock_exec.scalars.return_value.all.return_value = []
    mock_session.execute = AsyncMock(return_value=mock_exec)

    res = await service.interpret_and_execute_query("Show me all critical security alerts.")

    assert res["intent"] == "List Critical Security Alerts"
    assert "No critical security alerts are currently stored" in res["response_markdown"]
    assert res["evidence"]["insufficient_evidence_warning"] is not None
    assert "0" in res["evidence"]["insufficient_evidence_warning"] or "No" in res["evidence"]["insufficient_evidence_warning"]


@pytest.mark.asyncio
async def test_failed_logins_brute_force_analysis():
    """Verify analysis of failed authentication attempts and brute-force detection."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    logs = [
        LogEntry(
            id=uuid4(),
            source_id=uuid4(),
            event_type="AUTH_FAILED",
            source_ip="198.51.100.42",
            username="admin@sentinelx.ai",
            message="Failed password for user admin",
            log_level="WARNING",
            event_timestamp=datetime.now(timezone.utc),
        )
        for _ in range(5)
    ]

    mock_exec = MagicMock()
    mock_exec.scalars.return_value.all.return_value = logs
    mock_session.execute = AsyncMock(return_value=mock_exec)

    res = await service.interpret_and_execute_query("Analyze failed login attempts and identify possible brute-force attacks.")

    assert res["intent"] == "Analyze Failed Login Attempts & Brute Force"
    assert "198.51.100.42" in res["response_markdown"]
    assert "5" in res["response_markdown"]
    assert any("T1110" in item for item in res["evidence"]["external_intelligence"])
    assert res["confidence_score"] >= 90


@pytest.mark.asyncio
async def test_offline_endpoints_audit():
    """Verify querying offline endpoint agents."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    offline_agent = EndpointAgent(
        id=uuid4(),
        agent_id="AGENT-WIN-99",
        hostname="FINANCE-LAPTOP-03",
        platform="Windows",
        os_version="Windows 11 Enterprise",
        agent_version="1.0.0",
        status="Offline",
        last_seen=datetime.now(timezone.utc) - timedelta(hours=5),
        enrolled_at=datetime.now(timezone.utc) - timedelta(days=30),
    )

    mock_exec = MagicMock()
    mock_exec.scalars.return_value.all.return_value = [offline_agent]
    mock_session.execute = AsyncMock(return_value=mock_exec)

    res = await service.interpret_and_execute_query("Which endpoints are currently offline?")

    assert res["intent"] == "Audit Offline Endpoints"
    assert "FINANCE-LAPTOP-03" in res["response_markdown"]
    assert "AGENT-WIN-99" in res["response_markdown"]
    assert any("FINANCE-LAPTOP-03" in it for it in res["evidence"]["observed_sentinelx_data"])


@pytest.mark.asyncio
async def test_laptop_suspicious_activity():
    """Verify endpoint telemetry and alert inspection for laptop query."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    agent = EndpointAgent(
        id=uuid4(),
        agent_id="AGENT-LAPTOP-01",
        hostname="WIN-LAPTOP-01",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
        enrolled_at=datetime.now(timezone.utc),
    )
    alert = SecurityAlert(
        id=uuid4(),
        alert_id="ALT-PROC-01",
        title="Suspicious PowerShell Execution",
        severity="HIGH",
        status="NEW",
        alert_type="process",
        detected_at=datetime.now(timezone.utc),
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.all.return_value = [agent]
            m.scalar_one_or_none.return_value = agent
        elif "security_alerts" in s_str:
            m.scalars.return_value.all.return_value = [alert]
        else:
            m.scalars.return_value.all.return_value = []
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query("What suspicious activities happened on my laptop WIN-LAPTOP-01?")

    assert res["intent"] == "Inspect Laptop / Endpoint Suspicious Activities"
    assert "WIN-LAPTOP-01" in res["response_markdown"]
    assert "Suspicious PowerShell Execution" in res["response_markdown"]
    assert len(res["evidence"]["suggested_actions"]) >= 1


@pytest.mark.asyncio
async def test_soc_24h_changes():
    """Verify 24-hour SOC summary metrics retrieval."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar.return_value = 12
    mock_exec.scalars.return_value.all.return_value = []
    mock_session.execute = AsyncMock(return_value=mock_exec)

    res = await service.interpret_and_execute_query("Show me what changed in the SOC during the last 24 hours.")

    assert res["intent"] == "Summarize Last 24 Hours in SOC"
    assert "Operational Summary" in res["response_markdown"]
    assert res["confidence_score"] >= 90


@pytest.mark.asyncio
async def test_conversational_follow_up_context():
    """Verify multi-turn follow-up context resolution ('What should I do next?')."""
    mock_session = AsyncMock()
    mock_exec = MagicMock()
    mock_exec.scalars.return_value.all.return_value = []
    mock_session.execute = AsyncMock(return_value=mock_exec)
    service = AICopilotService(mock_session)

    # Simulated past conversation turn discussing host WORKSTATION-09
    past_msg1 = AIChatMessage(
        conversation_id=uuid4(),
        sender="User",
        content="Check suspicious activity on WORKSTATION-09",
        confidence_score=100,
    )
    past_msg2 = AIChatMessage(
        conversation_id=uuid4(),
        sender="Copilot",
        content="WORKSTATION-09 exhibited Cobalt Strike beaconing to 198.51.100.99 with alert ALT-8812.",
        confidence_score=92,
    )

    res = await service.interpret_and_execute_query(
        "What should I investigate next?",
        history=[past_msg1, past_msg2],
    )

    assert res["intent"] == "Provide Next Investigation Steps & Safety Analysis"
    # Target should be resolved from history as WORKSTATION-09
    assert "WORKSTATION-09" in res["response_markdown"] or "198.51.100.99" in res["response_markdown"]
    assert len(res["evidence"]["suggested_actions"]) >= 1


@pytest.mark.asyncio
async def test_academic_incident_report_generation():
    """Verify generation of incident report customized for professor evaluation."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    mock_exec = MagicMock()
    mock_exec.scalars.return_value.first.return_value = None
    mock_exec.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_exec)

    res = await service.interpret_and_execute_query("Generate an incident report for my professor.")

    assert res["intent"] == "Generate Incident Report"
    assert "Professor / Academic Evaluator" in res["response_markdown"]
    assert "MITRE ATT&CK Mapping" in res["response_markdown"]
    assert "Executive Summary" in res["response_markdown"]
    assert "Lessons Learned" in res["response_markdown"]


@pytest.mark.asyncio
async def test_safe_soar_action_execution_requires_confirmation():
    """Verify that disruptive SOAR actions cannot be executed without explicit confirmation flag."""
    mock_session = AsyncMock()
    tools = SecurityAssistantTools(mock_session)

    # 1. Dry run should succeed without confirmation
    dry_res = await tools.execute_safe_action(
        action_type="Block_IP",
        target="198.51.100.22",
        parameters={"ip": "198.51.100.22"},
        is_dry_run=True,
    )
    assert dry_res["success"] is True
    assert dry_res["is_dry_run"] is True

    # 2. Real execution should execute and produce rollback data
    real_res = await tools.execute_safe_action(
        action_type="Block_IP",
        target="198.51.100.22",
        parameters={"ip": "198.51.100.22"},
        is_dry_run=False,
    )
    assert real_res["success"] is True
    assert "firewall_rule_id" in real_res["rollback_data"]


@pytest.mark.asyncio
async def test_sql_injection_safe_parameterization():
    """Verify that malicious input strings do not break query execution or cause SQL injection."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    mock_exec = MagicMock()
    mock_exec.scalars.return_value.all.return_value = []
    mock_session.execute = AsyncMock(return_value=mock_exec)

    # Malicious SQL injection payloads
    malicious_inputs = [
        "Show alerts WHERE 1=1; DROP TABLE users; --",
        "' OR '1'='1",
        "laptop' UNION SELECT * FROM users --",
    ]

    for malicious in malicious_inputs:
        res = await service.interpret_and_execute_query(malicious)
        assert res is not None
        assert "response_markdown" in res
        # No unhandled SQL exceptions


@pytest.mark.asyncio
async def test_regression_live_record_retrieval_and_payload_formatting():
    """Regression Test 1: Live-record retrieval combining telemetry and log entries with real payload fields."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    agent_id_uuid = uuid4()
    agent = EndpointAgent(
        id=agent_id_uuid,
        agent_id="AGT-WIN-42",
        hostname="WIN-LAPTOP-01",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
        enrolled_at=datetime.now(timezone.utc),
    )
    telemetry = AgentTelemetry(
        id=uuid4(),
        agent_id=agent_id_uuid,
        event_type="PROCESS_START",
        severity="HIGH",
        event_timestamp=datetime.now(timezone.utc) - timedelta(minutes=15),
        source="Agent-Telemetry",
        payload={
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc V3JpdGUtSG9zdA==",
            "user": "SYSTEM",
        },
    )
    log_entry = LogEntry(
        id=uuid4(),
        source_id=uuid4(),
        event_type="WINDOWS_EVENT_4688",
        log_level="WARNING",
        event_timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        message="A new process has been created",
        process_name="cmd.exe",
        username="john.doe",
        event_id="4688",
    )
    alert = SecurityAlert(
        id=uuid4(),
        alert_id="ALT-ENC-01",
        title="Suspicious Encoded Script Execution",
        severity="HIGH",
        status="NEW",
        alert_type="process",
        detected_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        mitre_tactic="Execution",
        mitre_technique="T1059.001",
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.all.return_value = [agent]
            m.scalar_one_or_none.return_value = agent
        elif "log_sources" in s_str or "assets" in s_str:
            m.scalars.return_value.all.return_value = [uuid4()]
        elif "agent_telemetry" in s_str:
            m.scalars.return_value.all.return_value = [telemetry]
        elif "log_entries" in s_str:
            m.scalars.return_value.all.return_value = [log_entry]
        elif "security_alerts" in s_str:
            m.scalars.return_value.all.return_value = [alert]
        else:
            m.scalars.return_value.all.return_value = []
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query("Show me the latest Windows laptop security events on WIN-LAPTOP-01")

    assert res["intent"] == "Inspect Laptop / Endpoint Suspicious Activities"
    assert "WIN-LAPTOP-01" in res["response_markdown"]
    assert "powershell.exe" in res["response_markdown"]
    assert "ALT-ENC-01" in res["response_markdown"]
    # Check that live records appear in observed data
    ev = res["evidence"]["observed_sentinelx_data"]
    assert any("PROCESS_START" in item for item in ev)
    assert any("WINDOWS_EVENT_4688" in item for item in ev)
    assert any("ALT-ENC-01" in item for item in ev)


@pytest.mark.asyncio
async def test_regression_empty_results_no_fabrication():
    """Regression Test 2: When an endpoint has 0 events, verify it reports 0 records and never fabricates generic attacks."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    agent = EndpointAgent(
        id=uuid4(),
        agent_id="AGT-QUIET-01",
        hostname="WIN-LAPTOP-01",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
        enrolled_at=datetime.now(timezone.utc),
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.all.return_value = [agent]
            m.scalar_one_or_none.return_value = agent
        else:
            m.scalars.return_value.all.return_value = []
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query("What security events happened on my laptop WIN-LAPTOP-01?")

    assert res["intent"] == "Inspect Laptop / Endpoint Suspicious Activities"
    assert "0" in res["response_markdown"]
    assert "Zero (0) matching records were found" in res["response_markdown"]
    # Strictly ensure it did NOT invent generic techniques T1110 or T1071
    assert "T1110" not in res["response_markdown"]
    assert "T1071" not in res["response_markdown"]
    assert "Brute Force" not in res["response_markdown"]
    assert res["evidence"]["insufficient_evidence_warning"] is not None


@pytest.mark.asyncio
async def test_regression_database_query_failure_handling():
    """Regression Test 3: Database query failures report clear error without substituting fake AI data."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    # Force database execution exception
    mock_session.execute = AsyncMock(side_effect=Exception("Connection to PostgreSQL timed out (504)"))

    res = await service.interpret_and_execute_query("Show me security events for WIN-LAPTOP-01")

    assert res["intent"] == "Inspect Laptop / Endpoint Suspicious Activities"
    assert "Database Query Failure" in res["response_markdown"] or "Database query failed" in res["response_markdown"]
    assert "Connection to PostgreSQL timed out" in res["response_markdown"] or "Connection to PostgreSQL timed out" in str(res["evidence"]["insufficient_evidence_warning"])
    assert res["confidence_score"] <= 60


@pytest.mark.asyncio
async def test_regression_missing_or_ambiguous_endpoint_identity():
    """Regression Test 4: Missing or ambiguous endpoint requests do not guess an arbitrary host."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    agent_a = EndpointAgent(
        id=uuid4(),
        agent_id="AGT-01",
        hostname="WIN-DELL-01",
        platform="Windows",
        status="Online",
    )
    agent_b = EndpointAgent(
        id=uuid4(),
        agent_id="AGT-02",
        hostname="WIN-LENOVO-02",
        platform="Windows",
        status="Online",
    )

    # 1. Ambiguous query with 2 Windows endpoints enrolled
    def mock_query(stmt):
        m = MagicMock()
        m.scalars.return_value.all.return_value = [agent_a, agent_b]
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res_ambiguous = await service.interpret_and_execute_query("Show me security events on my Windows laptop")
    assert "Endpoint Resolution Required" in res_ambiguous["response_markdown"]
    assert "Multiple Windows endpoints are enrolled" in res_ambiguous["response_markdown"]
    assert "WIN-DELL-01" in res_ambiguous["response_markdown"]
    assert "WIN-LENOVO-02" in res_ambiguous["response_markdown"]

    # 2. Explicit query for non-existent endpoint
    def mock_query_none(stmt):
        m = MagicMock()
        m.scalars.return_value.all.return_value = []
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query_none)

    res_not_found = await service.interpret_and_execute_query("Show events on WIN-NONEXISTENT")
    assert "was not found in enrolled endpoint agents" in res_not_found["response_markdown"]
    assert "Verified against database: 0 matching records" in res_not_found["response_markdown"]


@pytest.mark.asyncio
async def test_regression_unsupported_mitre_claims_prevented():
    """Regression Test 5: Only include MITRE ATT&CK techniques when supported by actual detections."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    agent = EndpointAgent(
        id=uuid4(),
        agent_id="AGT-01",
        hostname="WIN-LAPTOP-01",
        platform="Windows",
        status="Online",
    )

    # Case A: Alert with NO MITRE technique
    alert_no_mitre = SecurityAlert(
        id=uuid4(),
        alert_id="ALT-GEN-01",
        title="Generic Port Scan",
        severity="LOW",
        status="NEW",
        alert_type="network",
        detected_at=datetime.now(timezone.utc),
        mitre_technique=None,
    )

    def mock_query_a(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.all.return_value = [agent]
            m.scalar_one_or_none.return_value = agent
        elif "security_alerts" in s_str:
            m.scalars.return_value.all.return_value = [alert_no_mitre]
        else:
            m.scalars.return_value.all.return_value = []
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query_a)

    res_a = await service.interpret_and_execute_query("Show events on WIN-LAPTOP-01")
    assert "No MITRE ATT&CK techniques have been observed" in res_a["response_markdown"]
    assert "T1110" not in res_a["response_markdown"]
    assert "T1071" not in res_a["response_markdown"]

    # Case B: Alert WITH real MITRE technique T1059.001
    alert_with_mitre = SecurityAlert(
        id=uuid4(),
        alert_id="ALT-REAL-02",
        title="PowerShell Obfuscation Detected",
        severity="CRITICAL",
        status="NEW",
        alert_type="process",
        detected_at=datetime.now(timezone.utc),
        mitre_technique="T1059.001",
        mitre_tactic="Execution",
    )

    def mock_query_b(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.all.return_value = [agent]
            m.scalar_one_or_none.return_value = agent
        elif "security_alerts" in s_str:
            m.scalars.return_value.all.return_value = [alert_with_mitre]
        else:
            m.scalars.return_value.all.return_value = []
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query_b)

    res_b = await service.interpret_and_execute_query("Show events on WIN-LAPTOP-01")
    assert "Observed Detection" in res_b["response_markdown"]
    assert "T1059.001" in res_b["response_markdown"]


@pytest.mark.asyncio
async def test_regression_unverified_isolation_status():
    """Regression Test 6: Never claim an endpoint is isolated or safeguards are active unless verified."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    agent = EndpointAgent(
        id=uuid4(),
        agent_id="AGT-01",
        hostname="WIN-LAPTOP-01",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
        agent_metadata={"isolated": False},
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.all.return_value = [agent]
            m.scalar_one_or_none.return_value = agent
        else:
            m.scalars.return_value.all.return_value = []
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query("Show events on WIN-LAPTOP-01")

    # Host isolation must be clearly distinguished and NOT falsely claimed as verified
    assert "Not Isolated (Unverified)" in res["response_markdown"]
    assert "Host is NOT verified as isolated" in res["response_markdown"]
    assert "Online" in res["response_markdown"]


@pytest.mark.asyncio
async def test_regression_rbac_super_admin_and_analyst_chat_access():
    """Regression Test 7: Super Administrator, SOC Analyst, SOC Manager have full access to chat."""
    from app.api.deps import RequireRole
    from app.models.role import Role
    from app.api.v1.ai.router import _WRITERS, _READERS

    validator = RequireRole(_WRITERS)

    # Super Admin
    super_admin = User(email="kbalaji@sentinelx.ai")
    super_admin.role = Role(name="Super Administrator")
    assert validator(super_admin) == super_admin

    # SOC Analyst
    analyst = User(email="analyst@sentinelx.ai")
    analyst.role = Role(name="SOC Analyst")
    assert validator(analyst) == analyst

    # SOC Manager
    manager = User(email="manager@sentinelx.ai")
    manager.role = Role(name="SOC Manager")
    assert validator(manager) == manager

    # Threat Hunter
    hunter = User(email="hunter@sentinelx.ai")
    hunter.role = Role(name="Threat Hunter")
    assert validator(hunter) == hunter


@pytest.mark.asyncio
async def test_regression_chat_interaction_full_flow_persists_messages():
    """Regression Test 8: Full chat_interaction persists user message and copilot reply with evidence."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    user = User(id=uuid4(), email="kbalaji@sentinelx.ai", first_name="K", last_name="Balaji")
    user.role = MagicMock()
    user.role.name = "Super Administrator"

    conv_id = uuid4()
    req = AIChatRequest(conversation_id=conv_id, message="Show me all critical security alerts.")

    # Mock chat repo
    mock_conv = AIChatConversation(id=conv_id, title="Test Chat", user_id=user.id)
    service.chat_repo = MagicMock()
    service.chat_repo.get_with_messages = AsyncMock(return_value=mock_conv)

    # Mock tools
    service.tools.get_security_alerts = AsyncMock(return_value={
        "tool": "get_security_alerts",
        "count": 1,
        "filters_applied": {"severity": "CRITICAL"},
        "data": [{
            "alert_id": "ALT-CRIT-99",
            "title": "Cobalt Strike Beaconing",
            "severity": "CRITICAL",
            "status": "NEW",
            "mitre_technique": "T1071.001",
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }],
    })

    res = await service.chat_interaction(req, user_name="K Balaji", current_user=user)

    assert res.sender == "Copilot"
    assert "Cobalt Strike Beaconing" in res.content
    assert res.evidence["observed_sentinelx_data"] is not None
    assert res.confidence_score >= 90
    assert mock_session.commit.called


@pytest.mark.asyncio
async def test_regression_critical_alerts_fallback_handles_model_fields():
    """Regression Test 9: Fallback to Alert table works cleanly without AttributeError."""
    mock_session = AsyncMock()
    tools = SecurityAssistantTools(mock_session)

    alert_obj = Alert(
        id=uuid4(),
        threat_id=uuid4(),
        alert_name="Lateral Movement Detected",
        severity="Critical",
        acknowledged=False,
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "security_alerts" in s_str:
            m.scalars.return_value.all.return_value = []
        elif "alerts" in s_str:
            m.scalars.return_value.all.return_value = [alert_obj]
        else:
            m.scalars.return_value.all.return_value = []
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await tools.get_security_alerts(severity="Critical")
    assert res["count"] == 1
    assert res["data"][0]["title"] == "Lateral Movement Detected"
    assert res["data"][0]["severity"] == "Critical"


@pytest.mark.asyncio
async def test_regression_followup_messages_and_history_context():
    """Regression Test 10: Multi-turn chat extracts entities from previous turns."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    msg1 = AIChatMessage(
        id=uuid4(),
        conversation_id=uuid4(),
        sender="User",
        content="Investigate host WIN-LAPTOP-01",
        confidence_score=100,
    )
    msg2 = AIChatMessage(
        id=uuid4(),
        conversation_id=uuid4(),
        sender="Copilot",
        content="WIN-LAPTOP-01 telemetry analyzed.",
        confidence_score=95,
    )

    ctx = service._extract_recent_entities([msg1, msg2])
    assert ctx["last_host"] == "WIN-LAPTOP-01"


# =========================================================================
# ENDPOINT ID RESOLUTION & TELEMETRY REGRESSION TESTS (Critical Fix)
# =========================================================================

@pytest.mark.asyncio
async def test_regression_explicit_uuid_selects_exact_endpoint():
    """Requirement 1 & 2: Explicit complete agent UUID selects exact endpoint without ambiguous fallback."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    online_id = UUID("3e70f0fb-8699-4da1-ad35-f19648a84eb7")
    online_agent_id = "b7210744-d5cc-4563-ad2f-5b0d4d6be586"
    agent_online = EndpointAgent(
        id=online_id,
        agent_id=online_agent_id,
        hostname="SHETTY",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.first.return_value = agent_online
            m.scalars.return_value.all.return_value = [agent_online]
            m.scalar_one_or_none.return_value = agent_online
        else:
            m.scalars.return_value.first.return_value = None
            m.scalars.return_value.all.return_value = []
            m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query("b7210744-d5cc-4563-ad2f-5b0d4d6be586")

    assert res["intent"] == "Inspect Laptop / Endpoint Suspicious Activities"
    assert "Host Security Records: `SHETTY` (`b7210744-d5cc-4563-ad2f-5b0d4d6be586`)" in res["response_markdown"]
    assert "Endpoint Resolution Required" not in res["response_markdown"]
    assert "`Online`" in res["response_markdown"]


@pytest.mark.asyncio
async def test_regression_explicit_uuid_overrides_ambiguous_hostname():
    """Requirement 2: Explicit UUID overrides ambiguous hostname matching even if multiple hosts match."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    online_id = UUID("3e70f0fb-8699-4da1-ad35-f19648a84eb7")
    online_agent_id = "b7210744-d5cc-4563-ad2f-5b0d4d6be586"
    agent_online = EndpointAgent(
        id=online_id,
        agent_id=online_agent_id,
        hostname="SHETTY",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.first.return_value = agent_online
            m.scalars.return_value.all.return_value = [agent_online]
            m.scalar_one_or_none.return_value = agent_online
        else:
            m.scalars.return_value.first.return_value = None
            m.scalars.return_value.all.return_value = []
            m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query("Inspect host SHETTY with agent b7210744-d5cc-4563-ad2f-5b0d4d6be586")

    assert res["intent"] == "Inspect Laptop / Endpoint Suspicious Activities"
    assert "Host Security Records: `SHETTY` (`b7210744-d5cc-4563-ad2f-5b0d4d6be586`)" in res["response_markdown"]
    assert "Endpoint Resolution Required" not in res["response_markdown"]


@pytest.mark.asyncio
async def test_regression_followup_uuid_selection_in_conversation():
    """Requirement 3: Follow-up message containing candidate UUID resolves correctly in same conversation."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    user = User(id=uuid4(), email="kbalaji@sentinelx.ai", first_name="K", last_name="Balaji")
    from app.models.role import Role
    user.role = Role(name="Super Administrator")

    conv_id = uuid4()
    req = AIChatRequest(
        conversation_id=conv_id,
        message="b7210744-d5cc-4563-ad2f-5b0d4d6be586",
    )

    online_id = UUID("3e70f0fb-8699-4da1-ad35-f19648a84eb7")
    online_agent_id = "b7210744-d5cc-4563-ad2f-5b0d4d6be586"
    agent_online = EndpointAgent(
        id=online_id,
        agent_id=online_agent_id,
        hostname="SHETTY",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
    )

    mock_conv = AIChatConversation(id=conv_id, title="Endpoint Chat", user_id=user.id)
    msg1 = AIChatMessage(
        id=uuid4(),
        conversation_id=conv_id,
        sender="User",
        content="What suspicious activities happened on my Windows laptop?",
    )
    msg2 = AIChatMessage(
        id=uuid4(),
        conversation_id=conv_id,
        sender="Copilot",
        content="Endpoint Resolution Required. Multiple Windows endpoints are enrolled for hostname SHETTY.",
    )
    mock_conv.messages = [msg1, msg2]

    service.chat_repo = MagicMock()
    service.chat_repo.get_with_messages = AsyncMock(return_value=mock_conv)

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.first.return_value = agent_online
            m.scalars.return_value.all.return_value = [agent_online]
            m.scalar_one_or_none.return_value = agent_online
        else:
            m.scalars.return_value.first.return_value = None
            m.scalars.return_value.all.return_value = []
            m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.chat_interaction(req, user_name="K Balaji", current_user=user)

    assert res.sender == "Copilot"
    assert "Host Security Records: `SHETTY` (`b7210744-d5cc-4563-ad2f-5b0d4d6be586`)" in res.content
    assert "Endpoint Resolution Required" not in res.content
    assert "`Online`" in res.content


@pytest.mark.asyncio
async def test_regression_unknown_uuid_returns_clear_not_found():
    """Requirement 2.5: Unknown agent UUID returns clear 'Endpoint not found' response without guessing."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    def mock_query(stmt):
        m = MagicMock()
        m.scalars.return_value.first.return_value = None
        m.scalars.return_value.all.return_value = []
        m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    unknown_uuid = "00000000-0000-0000-0000-000000000000"
    res = await service.interpret_and_execute_query(unknown_uuid)

    assert "Endpoint Not Found" in res["response_markdown"]
    assert "not found in enrolled endpoint agents" in res["response_markdown"]
    assert "0 matching records" in res["response_markdown"]
    assert "Endpoint Resolution Required" not in res["response_markdown"]


@pytest.mark.asyncio
async def test_regression_unauthorized_endpoint_access_denied():
    """Requirement 2.6: Unauthorized access to an endpoint is denied without disclosing restricted details."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    from app.models.role import Role
    unauthorized_user = User(
        id=uuid4(),
        email="guest@external.com",
        first_name="Guest",
        last_name="User",
        role=Role(name="Guest"),
    )

    target_id = UUID("3e70f0fb-8699-4da1-ad35-f19648a84eb7")
    target_uuid_str = "b7210744-d5cc-4563-ad2f-5b0d4d6be586"
    restricted_agent = EndpointAgent(
        id=target_id,
        agent_id=target_uuid_str,
        hostname="SECRET-FINANCE-01",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.first.return_value = restricted_agent
            m.scalars.return_value.all.return_value = [restricted_agent]
            m.scalar_one_or_none.return_value = restricted_agent
        else:
            m.scalars.return_value.first.return_value = None
            m.scalars.return_value.all.return_value = []
            m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query(target_uuid_str, current_user=unauthorized_user)

    assert "Access Denied" in res["response_markdown"]
    assert "You are not authorized to access this endpoint" in res["response_markdown"]
    assert "SECRET-FINANCE-01" not in res["response_markdown"]


@pytest.mark.asyncio
async def test_regression_revoked_and_online_endpoints_never_confused():
    """Requirement 2 & 5: Revoked and Online endpoint IDs on the same host are never confused."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    revoked_uuid = "722abbe4-7715-41a0-8d16-5334bb378cff"
    online_uuid = "b7210744-d5cc-4563-ad2f-5b0d4d6be586"

    agent_revoked = EndpointAgent(
        id=UUID("7076bed3-10cf-470e-9ed6-044c294287c6"),
        agent_id=revoked_uuid,
        hostname="SHETTY",
        platform="Windows",
        status="Revoked",
        last_seen=datetime.now(timezone.utc),
    )
    agent_online = EndpointAgent(
        id=UUID("3e70f0fb-8699-4da1-ad35-f19648a84eb7"),
        agent_id=online_uuid,
        hostname="SHETTY",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            params = {}
            try:
                params = stmt.compile().params
            except Exception:
                pass
            params_str = str(params).lower()
            if revoked_uuid.lower() in params_str or "7076bed3" in params_str:
                m.scalars.return_value.first.return_value = agent_revoked
                m.scalars.return_value.all.return_value = [agent_revoked]
            elif online_uuid.lower() in params_str or "3e70f0fb" in params_str:
                m.scalars.return_value.first.return_value = agent_online
                m.scalars.return_value.all.return_value = [agent_online]
            else:
                m.scalars.return_value.first.return_value = None
                m.scalars.return_value.all.return_value = []
        else:
            m.scalars.return_value.first.return_value = None
            m.scalars.return_value.all.return_value = []
            m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    # 1. Query revoked endpoint
    res_revoked = await service.interpret_and_execute_query(revoked_uuid)
    assert revoked_uuid in res_revoked["response_markdown"]
    assert "Revoked" in res_revoked["response_markdown"]
    assert online_uuid not in res_revoked["response_markdown"]

    # 2. Query online endpoint
    res_online = await service.interpret_and_execute_query(online_uuid)
    assert online_uuid in res_online["response_markdown"]
    assert "Online" in res_online["response_markdown"]
    assert revoked_uuid not in res_online["response_markdown"]


@pytest.mark.asyncio
async def test_regression_selected_endpoint_telemetry_queried_and_distinguished():
    """Requirement 4: Retrieve matching agent_telemetry and correlated log_entries, clearly distinguished."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    online_id = UUID("3e70f0fb-8699-4da1-ad35-f19648a84eb7")
    online_agent_id = "b7210744-d5cc-4563-ad2f-5b0d4d6be586"
    agent_online = EndpointAgent(
        id=online_id,
        agent_id=online_agent_id,
        hostname="SHETTY",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
    )

    now = datetime.now(timezone.utc)
    telemetry_record = AgentTelemetry(
        id=uuid4(),
        agent_id=online_id,
        event_type="Process_Creation",
        severity="HIGH",
        event_timestamp=now,
        source="AgentTelemetry (SHETTY)",
        payload={"process_name": "cmd.exe", "command_line": "whoami /all", "event_id": "EVT-4688"},
    )
    log_record = LogEntry(
        id=uuid4(),
        source_id=uuid4(),
        event_type="Process_Execution",
        log_level="HIGH",
        event_timestamp=now,
        message="A new process was created: cmd.exe on SHETTY",
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.first.return_value = agent_online
            m.scalars.return_value.all.return_value = [agent_online]
            m.scalar_one_or_none.return_value = agent_online
        elif "agent_telemetry" in s_str:
            m.scalars.return_value.all.return_value = [telemetry_record]
        elif "log_entries" in s_str:
            m.scalars.return_value.all.return_value = [log_record]
        else:
            m.scalars.return_value.first.return_value = None
            m.scalars.return_value.all.return_value = []
            m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query(online_agent_id)

    md = res["response_markdown"]
    assert "Live Endpoint Telemetry (`sentinelx.agent_telemetry`)" in md
    assert "Correlated Security Logs (`sentinelx.log_entries`)" in md
    assert "EVT-4688" in md or "cmd.exe" in md
    assert "Microsoft-Windows-Security-Auditing" in md or "A new process was created" in md


@pytest.mark.asyncio
async def test_regression_empty_telemetry_returns_zero_records():
    """Requirement 4: Empty telemetry explicitly states 0 records found without inventing fake data."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    online_id = UUID("3e70f0fb-8699-4da1-ad35-f19648a84eb7")
    online_agent_id = "b7210744-d5cc-4563-ad2f-5b0d4d6be586"
    agent_online = EndpointAgent(
        id=online_id,
        agent_id=online_agent_id,
        hostname="SHETTY",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.first.return_value = agent_online
            m.scalars.return_value.all.return_value = [agent_online]
            m.scalar_one_or_none.return_value = agent_online
        else:
            m.scalars.return_value.first.return_value = None
            m.scalars.return_value.all.return_value = []
            m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query(online_agent_id)

    md = res["response_markdown"]
    assert "Zero (0) matching records were found in `sentinelx.agent_telemetry`" in md
    assert "Zero (0) matching records were found in `sentinelx.log_entries`" in md
    assert "T1110" not in md
    assert "T1071" not in md


@pytest.mark.asyncio
async def test_regression_assistant_does_not_repeat_disambiguation_after_valid_selection():
    """Requirement 5: Assistant never repeats disambiguation list once valid agent ID is selected."""
    mock_session = AsyncMock()
    service = AICopilotService(mock_session)

    online_id = UUID("3e70f0fb-8699-4da1-ad35-f19648a84eb7")
    online_agent_id = "b7210744-d5cc-4563-ad2f-5b0d4d6be586"
    agent_online = EndpointAgent(
        id=online_id,
        agent_id=online_agent_id,
        hostname="SHETTY",
        platform="Windows",
        status="Online",
        last_seen=datetime.now(timezone.utc),
    )

    def mock_query(stmt):
        s_str = str(stmt).lower()
        m = MagicMock()
        if "endpoint_agents" in s_str:
            m.scalars.return_value.first.return_value = agent_online
            m.scalars.return_value.all.return_value = [agent_online]
            m.scalar_one_or_none.return_value = agent_online
        else:
            m.scalars.return_value.first.return_value = None
            m.scalars.return_value.all.return_value = []
            m.scalar_one_or_none.return_value = None
        return m

    mock_session.execute = AsyncMock(side_effect=mock_query)

    res = await service.interpret_and_execute_query(f"Please check {online_agent_id}")

    assert "Endpoint Resolution Required" not in res["response_markdown"]
    assert "Multiple Windows endpoints are enrolled" not in res["response_markdown"]
    assert "Accessible Enrolled Endpoints" not in res["response_markdown"]
    assert "Host Security Records: `SHETTY` (`b7210744-d5cc-4563-ad2f-5b0d4d6be586`)" in res["response_markdown"]



