"""
SentinelX AI – Endpoint Agent Service Layer
Business logic for agent enrollment, heartbeat tracking, telemetry normalization, log pipeline integration, and threat detection triggers.
Follows SOLID principles with dependency injection via constructor.
"""

from uuid import UUID
from datetime import datetime, timezone, timedelta
from typing import Any, List, Dict, Optional, Tuple

import structlog
import jwt
from fastapi import HTTPException, status
from sqlalchemy import select, func, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import EndpointAgent, AgentTelemetry
from app.models.threat import Threat, Alert
from app.repositories.agent_repo import AgentRepository, AgentTelemetryRepository
from app.repositories.threat_repo import ThreatRepository
from app.schemas.agent_schema import (
    AgentEnrollRequest,
    AgentEnrollResponse,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentTelemetryCreate,
    AgentTelemetryBatchCreate,
    AgentTelemetryResponse,
    EndpointAgentSummary,
    EndpointAgentResponse,
    EndpointAgentListResponse,
    EndpointAgentStatsResponse,
    EndpointDetailsResponse,
)
from app.schemas.log_schema import LogEntryCreate, LogSourceCreate
from app.schemas.threat_schema import ThreatCreate, AlertCreate
from app.services.log_service import LogSourceService, LogEntryService
from app.services.threat_service import ThreatService
from app.core.config import settings
from app.core.exceptions import EntityNotFoundError, ValidationError

logger = structlog.get_logger()

# Token secret fallback for agent token signing
AGENT_TOKEN_SECRET = getattr(settings, "SECRET_KEY", "sentinelx-agent-secret-key-change-in-prod")
AGENT_TOKEN_ALGORITHM = "HS256"


class AgentService:
    """
    Service encapsulating all Endpoint Agent operations.
    Integrates agent telemetry into sentinelx.log_entries and triggers threat detection workflows.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.agent_repo = AgentRepository(session)
        self.telemetry_repo = AgentTelemetryRepository(session)
        self.log_source_service = LogSourceService(session)
        self.log_entry_service = LogEntryService(session)
        self.threat_service = ThreatService(session)
        self.threat_repo = ThreatRepository(session)

    # ── Agent Authentication Helper ──────────────────────────────────────────

    def generate_agent_token(self, agent_id: str) -> str:
        """Generate a signed agent token for authentication."""
        payload = {
            "sub": agent_id,
            "type": "agent",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(days=30),
        }
        return jwt.encode(payload, AGENT_TOKEN_SECRET, algorithm=AGENT_TOKEN_ALGORITHM)

    async def authenticate_agent(self, token_or_agent_id: str) -> EndpointAgent:
        """
        Authenticate an agent by token or agent_id string.
        Validates that the agent exists and is not Disabled or Revoked.
        """
        agent_id_str = token_or_agent_id

        # If Bearer token passed, decode it
        if token_or_agent_id.startswith("Bearer "):
            token_or_agent_id = token_or_agent_id[7:].strip()

        try:
            payload = jwt.decode(
                token_or_agent_id,
                AGENT_TOKEN_SECRET,
                algorithms=[AGENT_TOKEN_ALGORITHM],
                options={"verify_exp": False},  # Allow long-running local agents
            )
            agent_id_str = payload.get("sub", agent_id_str)
        except Exception:
            # Fallback to direct agent_id lookup
            pass

        agent = await self.agent_repo.get_by_agent_id(agent_id_str)
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Agent identity '{agent_id_str}' not recognized.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if agent.status == "Disabled":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Endpoint agent is currently disabled by administrator.",
            )

        if agent.status == "Revoked":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Endpoint agent authorization has been revoked.",
            )

        return agent

    # ── Enrollment ────────────────────────────────────────────────────────────

    async def enroll_agent(self, payload: AgentEnrollRequest) -> AgentEnrollResponse:
        """
        Enroll or re-enroll an endpoint agent.
        Registers an associated LogSource and returns a secure token.
        """
        existing = await self.agent_repo.get_by_agent_id(payload.agent_id)

        meta = dict(payload.metadata)
        if payload.local_ip:
            meta["local_ip"] = payload.local_ip
        if payload.architecture:
            meta["architecture"] = payload.architecture
        if payload.username:
            meta["username"] = payload.username

        now = datetime.now(timezone.utc)

        if existing:
            if existing.status == "Revoked":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot enroll a revoked agent. Please generate a new agent identity.",
                )

            update_data = {
                "hostname": payload.hostname,
                "platform": payload.platform,
                "os_version": payload.os_version,
                "agent_version": payload.agent_version,
                "status": "Online",
                "last_seen": now,
                "agent_metadata": meta,
            }
            agent = await self.agent_repo.update(existing.id, update_data)
            logger.info("agent_re_enrolled", agent_id=payload.agent_id, hostname=payload.hostname)
        else:
            agent_dict = {
                "agent_id": payload.agent_id,
                "hostname": payload.hostname,
                "platform": payload.platform,
                "os_version": payload.os_version,
                "agent_version": payload.agent_version,
                "status": "Online",
                "enrolled_at": now,
                "last_seen": now,
                "agent_metadata": meta,
            }
            agent = await self.agent_repo.create(agent_dict)
            logger.info("agent_enrolled", agent_id=payload.agent_id, hostname=payload.hostname)

        # Ensure an associated log source exists in sentinelx.log_sources
        source_name = f"Endpoint Agent: {payload.hostname}"
        existing_source = await self.log_source_service.repo.get_by_name(source_name)
        if not existing_source:
            try:
                await self.log_source_service.create_source(
                    LogSourceCreate(
                        name=source_name,
                        source_type="Endpoint",
                        vendor="SentinelX Agent",
                        description=f"Endpoint Telemetry Agent running on {payload.hostname}",
                        hostname=payload.hostname,
                        ip_address=payload.local_ip,
                        protocol="HTTPS",
                        status="Active",
                    )
                )
            except Exception as exc:
                logger.warning("log_source_auto_register_failed", error=str(exc))

        agent_token = self.generate_agent_token(agent.agent_id)

        return AgentEnrollResponse(
            id=agent.id,
            agent_id=agent.agent_id,
            hostname=agent.hostname,
            platform=agent.platform,
            os_version=agent.os_version,
            agent_version=agent.agent_version,
            status=agent.status,
            enrolled_at=agent.enrolled_at,
            agent_token=agent_token,
        )

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    async def process_heartbeat(self, payload: AgentHeartbeatRequest) -> AgentHeartbeatResponse:
        """Process periodic agent heartbeat and update status."""
        agent = await self.authenticate_agent(payload.agent_id)

        now = datetime.now(timezone.utc)
        meta_update = {
            "uptime": payload.uptime,
            "health_status": payload.health_status,
            "last_heartbeat_at": now.isoformat(),
        }
        if payload.metadata:
            meta_update.update(payload.metadata)

        updated_agent = await self.agent_repo.update_last_seen(
            agent_id_str=agent.agent_id,
            seen_at=now,
            metadata_update=meta_update,
            new_status="Online",
        )

        logger.info(
            "agent_heartbeat_received",
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            uptime=payload.uptime,
        )

        return AgentHeartbeatResponse(
            agent_id=agent.agent_id,
            status=updated_agent.status if updated_agent else "Online",
            last_seen=now,
            next_heartbeat_seconds=60,
        )

    # ── Telemetry Ingestion & Security Rules ─────────────────────────────────

    async def ingest_telemetry(self, batch: AgentTelemetryBatchCreate) -> Dict[str, Any]:
        """
        Ingest telemetry batch from an authenticated endpoint agent.
        Normalizes security events, persists to sentinelx.agent_telemetry,
        forwards into sentinelx.log_entries, and triggers Threat Detection rules.
        """
        agent = await self.authenticate_agent(batch.agent_id)

        # Get or resolve associated LogSource ID
        source_name = f"Endpoint Agent: {agent.hostname}"
        log_source = await self.log_source_service.repo.get_by_name(source_name)
        source_id = log_source.id if log_source else None

        ingested_count = 0
        log_entries_count = 0
        threats_triggered = 0

        now = datetime.now(timezone.utc)
        telemetry_dicts: List[Dict[str, Any]] = []
        log_creates: List[LogEntryCreate] = []

        # Process each telemetry item
        for item in batch.telemetry:
            event_ts = item.event_timestamp
            if event_ts.tzinfo is None:
                event_ts = event_ts.replace(tzinfo=timezone.utc)

            payload = dict(item.payload or {})
            if item.is_simulated:
                payload["is_simulated"] = True
                payload["tag"] = "SIMULATED_TEST_EVENT"

            telemetry_dicts.append({
                "agent_id": agent.id,
                "event_type": item.event_type,
                "event_timestamp": event_ts,
                "severity": item.severity,
                "payload": payload,
                "source": item.source or f"Agent-{agent.hostname}",
            })

            # Check if this telemetry event should be forwarded into sentinelx.log_entries
            if source_id and self._should_convert_to_log_entry(item.event_type, payload):
                log_create = self._build_log_entry(source_id, agent, item, payload, event_ts)
                log_creates.append(log_create)

        # 1. Batch save to sentinelx.agent_telemetry
        if telemetry_dicts:
            await self.telemetry_repo.create_batch(telemetry_dicts)
            ingested_count = len(telemetry_dicts)

        # 2. Update agent last_seen timestamp & metadata
        await self.agent_repo.update_last_seen(
            agent_id_str=agent.agent_id,
            seen_at=now,
            new_status="Online",
        )

        # 3. Forward to sentinelx.log_entries
        if log_creates:
            try:
                res = await self.log_entry_service.bulk_ingest_logs(log_creates)
                log_entries_count = res.get("ingested", 0)
            except Exception as exc:
                logger.warning("agent_log_pipeline_forwarding_failed", error=str(exc))

        # 4. Trigger Threat Detection logic for security events
        threats_triggered = await self._evaluate_threat_detection_rules(agent, batch.telemetry)

        logger.info(
            "agent_telemetry_ingested",
            agent_id=agent.agent_id,
            hostname=agent.hostname,
            telemetry_count=ingested_count,
            log_entries_count=log_entries_count,
            threats_triggered=threats_triggered,
        )

        return {
            "status": "success",
            "agent_id": agent.agent_id,
            "telemetry_ingested": ingested_count,
            "log_entries_created": log_entries_count,
            "threats_triggered": threats_triggered,
        }

    @staticmethod
    def _should_convert_to_log_entry(event_type: str, payload: Dict[str, Any]) -> bool:
        """Determine if a telemetry record represents a security log entry."""
        security_event_types = {
            "windows_event",
            "security_event",
            "process_creation",
            "failed_logon",
            "successful_logon",
            "account_lockout",
            "privilege_escalation",
            "service_creation",
            "network_connection",
        }
        return event_type.lower() in security_event_types or "event_id" in payload or "process_name" in payload

    def _build_log_entry(
        self,
        source_id: UUID,
        agent: EndpointAgent,
        item: AgentTelemetryCreate,
        payload: Dict[str, Any],
        event_ts: datetime,
    ) -> LogEntryCreate:
        """Construct a LogEntryCreate object from endpoint agent telemetry."""
        event_id = str(payload.get("event_id", "")) or None
        username = payload.get("username") or payload.get("user") or agent.agent_metadata.get("username")
        process_name = payload.get("process_name") or payload.get("executable_path")
        category = payload.get("category", "Endpoint Security")
        message = payload.get("message") or f"Endpoint {item.event_type} on {agent.hostname}"

        if item.is_simulated:
            message = f"[SIMULATED TEST EVENT] {message}"

        return LogEntryCreate(
            source_id=source_id,
            event_timestamp=event_ts,
            log_level=item.severity if item.severity in {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"} else "INFO",
            event_type=item.event_type,
            category=category,
            message=message,
            raw_log=payload,
            source_ip=payload.get("local_address") or payload.get("remote_address") or agent.agent_metadata.get("local_ip"),
            username=username,
            process_name=process_name,
            event_id=event_id,
        )

    async def _evaluate_threat_detection_rules(
        self, agent: EndpointAgent, items: List[AgentTelemetryCreate]
    ) -> int:
        """
        Evaluate incoming telemetry against SentinelX threat detection rules.
        Creates Threat / Alert records when suspicious security patterns are detected.
        """
        threats_created = 0

        for item in items:
            payload = item.payload or {}
            event_id = str(payload.get("event_id", ""))
            event_type = item.event_type.lower()

            # Rule 1: Windows Failed Logon (Event ID 4625) or repeated failed logons
            if event_id == "4625" or event_type == "failed_logon":
                target_user = payload.get("username", "Unknown User")
                threat_res = await self.threat_service.create_threat(
                    payload=ThreatCreate(
                        title=f"Failed Logon Attempt on {agent.hostname}",
                        description=f"Multiple or suspicious failed authentication attempt for user '{target_user}' on endpoint {agent.hostname}.",
                        severity="Medium" if not item.is_simulated else "Low",
                        status="New",
                        category="Authentication Anomaly",
                        source_ip=payload.get("remote_address") or agent.agent_metadata.get("local_ip"),
                        detected_at=item.event_timestamp,
                        details={
                            "agent_id": agent.agent_id,
                            "hostname": agent.hostname,
                            "event_id": "4625",
                            "username": target_user,
                            "is_simulated": item.is_simulated,
                        },
                    ),
                    created_by="Endpoint Detection Engine",
                )
                threats_created += 1

            # Rule 2: Account Lockout (Event ID 4740)
            elif event_id == "4740" or event_type == "account_lockout":
                target_user = payload.get("username", "Unknown User")
                await self.threat_service.create_threat(
                    payload=ThreatCreate(
                        title=f"Account Lockout Event on {agent.hostname}",
                        description=f"User account '{target_user}' locked out on host {agent.hostname}.",
                        severity="High" if not item.is_simulated else "Low",
                        status="New",
                        category="Brute Force / Account Lockout",
                        detected_at=item.event_timestamp,
                        details={
                            "agent_id": agent.agent_id,
                            "hostname": agent.hostname,
                            "event_id": "4740",
                            "username": target_user,
                            "is_simulated": item.is_simulated,
                        },
                    ),
                    created_by="Endpoint Detection Engine",
                )
                threats_created += 1

            # Rule 3: Suspicious Process Execution (e.g., encoded powershell, cmd abuse, mimikatz)
            elif event_type in ("process", "process_creation") or event_id == "4688":
                cmdline = str(payload.get("command_line", "") or payload.get("process_name", "")).lower()
                suspicious_keywords = ["powershell -enc", "mimikatz", "vssadmin delete", "cmd.exe /c powershell", "base64"]
                if any(kw in cmdline for kw in suspicious_keywords):
                    await self.threat_service.create_threat(
                        payload=ThreatCreate(
                            title=f"Suspicious Process Execution on {agent.hostname}",
                            description=f"Potentially malicious command line detected on {agent.hostname}: {cmdline[:200]}",
                            severity="High" if not item.is_simulated else "Medium",
                            status="New",
                            category="Execution / Malware",
                            detected_at=item.event_timestamp,
                            details={
                                "agent_id": agent.agent_id,
                                "hostname": agent.hostname,
                                "command_line": cmdline,
                                "process_name": payload.get("process_name"),
                                "is_simulated": item.is_simulated,
                            },
                        ),
                        created_by="Endpoint Detection Engine",
                    )
                    threats_created += 1

        return threats_created

    # ── Agent Query & Management Endpoints ────────────────────────────────────

    async def list_agents(
        self,
        page: int = 1,
        page_size: int = 25,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> EndpointAgentListResponse:
        """Return paginated endpoint agents with summary metrics."""
        skip = (page - 1) * page_size
        agents = await self.agent_repo.get_list(skip=skip, limit=page_size, status=status, search=search)
        total = await self.agent_repo.count_filtered(status=status, search=search)

        items: List[EndpointAgentSummary] = []
        for a in agents:
            t_count = await self.telemetry_repo.count_by_agent_id(a.id)
            # Calculate updated dynamic status
            calculated_status = self._calculate_agent_status(a)
            risk_score = 15.0 if calculated_status == "Offline" else (5.0 if calculated_status == "Stale" else 0.0)

            items.append(
                EndpointAgentSummary(
                    id=a.id,
                    agent_id=a.agent_id,
                    hostname=a.hostname,
                    platform=a.platform,
                    os_version=a.os_version,
                    agent_version=a.agent_version,
                    status=calculated_status,
                    enrolled_at=a.enrolled_at,
                    last_seen=a.last_seen,
                    local_ip=a.agent_metadata.get("local_ip"),
                    risk_score=risk_score,
                    telemetry_count=t_count,
                )
            )

        return EndpointAgentListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=items,
        )

    async def get_agent(self, agent_id_or_uuid: str) -> EndpointAgentResponse:
        """Retrieve single agent model by UUID or string agent_id."""
        agent = await self._resolve_agent(agent_id_or_uuid)
        if not agent:
            raise EntityNotFoundError(entity="EndpointAgent", entity_id=str(agent_id_or_uuid))
        return EndpointAgentResponse.model_validate(agent)

    async def get_agent_details(self, agent_id_or_uuid: str) -> EndpointDetailsResponse:
        """
        Return comprehensive agent details payload (System Info, Health, Heartbeat,
        Recent Telemetry, Security Events, Threats, Network, Processes, Timeline).
        """
        agent = await self._resolve_agent(agent_id_or_uuid)
        if not agent:
            raise EntityNotFoundError(entity="EndpointAgent", entity_id=str(agent_id_or_uuid))

        # Recent Telemetry
        recent_telemetry_models = await self.telemetry_repo.get_by_agent_id(agent.id, limit=50)
        recent_telemetry = [AgentTelemetryResponse.model_validate(t) for t in recent_telemetry_models]

        # Filter recent processes and network connections from telemetry
        running_processes = []
        network_connections = []
        recent_sec_events = []
        timeline = []

        for t in recent_telemetry:
            payload = t.payload or {}
            ts_str = t.event_timestamp.isoformat()

            if t.event_type in ("process", "processes", "process_creation") or "process_name" in payload:
                running_processes.append({
                    "pid": payload.get("pid"),
                    "process_name": payload.get("process_name") or payload.get("name"),
                    "executable_path": payload.get("executable_path") or payload.get("path"),
                    "username": payload.get("username"),
                    "start_time": payload.get("start_time"),
                })
            elif t.event_type in ("network", "network_connection", "sockets") or "remote_address" in payload:
                network_connections.append({
                    "local_address": payload.get("local_address"),
                    "local_port": payload.get("local_port"),
                    "remote_address": payload.get("remote_address"),
                    "remote_port": payload.get("remote_port"),
                    "protocol": payload.get("protocol"),
                    "state": payload.get("connection_state") or payload.get("state"),
                })
            elif t.event_type in ("windows_event", "security_event", "failed_logon", "account_lockout"):
                recent_sec_events.append({
                    "event_id": payload.get("event_id"),
                    "event_type": t.event_type,
                    "severity": t.severity,
                    "timestamp": ts_str,
                    "message": payload.get("message") or f"Security event {t.event_type}",
                })

            timeline.append({
                "timestamp": ts_str,
                "type": t.event_type,
                "severity": t.severity,
                "summary": f"{t.event_type.replace('_', ' ').title()}: {payload.get('message', 'Telemetry recorded')}",
            })

        # Recent threats linked to this agent
        threats_res = await self.session.execute(
            select(Threat)
            .where(
                or_(
                    Threat.source.ilike(f"%{agent.hostname}%"),
                    Threat.source.ilike(f"%{agent.agent_id}%"),
                    Threat.description.ilike(f"%{agent.hostname}%"),
                    Threat.description.ilike(f"%{agent.agent_id}%"),
                    Threat.title.ilike(f"%{agent.hostname}%"),
                )
            )
            .limit(10)
        )
        recent_threats_models = threats_res.scalars().all()
        recent_threats = [
            {
                "id": str(t.id),
                "title": t.title,
                "severity": t.severity,
                "status": t.status,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            }
            for t in recent_threats_models
        ]

        calculated_status = self._calculate_agent_status(agent)
        risk_score = 25.0 if len(recent_threats) > 0 else (10.0 if calculated_status == "Stale" else 0.0)

        system_info = {
            "hostname": agent.hostname,
            "platform": agent.platform,
            "os_version": agent.os_version,
            "agent_version": agent.agent_version,
            "architecture": agent.agent_metadata.get("architecture", "x64"),
            "local_ip": agent.agent_metadata.get("local_ip", "127.0.0.1"),
            "username": agent.agent_metadata.get("username", "N/A"),
        }

        agent_health = {
            "status": calculated_status,
            "health_status": agent.agent_metadata.get("health_status", "Healthy"),
            "uptime_seconds": agent.agent_metadata.get("uptime", 0),
            "enrolled_at": agent.enrolled_at.isoformat(),
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
        }

        return EndpointDetailsResponse(
            agent=EndpointAgentResponse.model_validate(agent),
            system_info=system_info,
            agent_health=agent_health,
            last_heartbeat=agent.last_seen,
            recent_telemetry=recent_telemetry[:20],
            recent_security_events=recent_sec_events[:20],
            recent_threats=recent_threats,
            risk_score=risk_score,
            network_connections=network_connections[:20],
            running_processes=running_processes[:20],
            timeline=timeline[:30],
        )

    async def disable_agent(self, agent_id_or_uuid: str) -> EndpointAgentResponse:
        """Disable agent authorization."""
        updated = await self.agent_repo.set_agent_status(agent_id_or_uuid, "Disabled")
        if not updated:
            raise EntityNotFoundError(entity="EndpointAgent", entity_id=str(agent_id_or_uuid))
        logger.warning("agent_disabled_by_admin", agent_id=updated.agent_id, hostname=updated.hostname)
        return EndpointAgentResponse.model_validate(updated)

    async def revoke_agent(self, agent_id_or_uuid: str) -> EndpointAgentResponse:
        """Revoke agent enrollment authorization permanently."""
        updated = await self.agent_repo.set_agent_status(agent_id_or_uuid, "Revoked")
        if not updated:
            raise EntityNotFoundError(entity="EndpointAgent", entity_id=str(agent_id_or_uuid))
        logger.warning("agent_revoked_by_admin", agent_id=updated.agent_id, hostname=updated.hostname)
        return EndpointAgentResponse.model_validate(updated)

    async def get_statistics(self) -> EndpointAgentStatsResponse:
        """Compute live endpoint dashboard metrics."""
        agents = await self.agent_repo.get_all(limit=1000)

        total = len(agents)
        online = 0
        offline = 0
        stale = 0

        for a in agents:
            st = self._calculate_agent_status(a)
            if st == "Online":
                online += 1
            elif st == "Offline":
                offline += 1
            elif st == "Stale":
                stale += 1

        telemetry_today = await self.telemetry_repo.count_today()

        # Count total endpoint threats
        threat_count_res = await self.session.execute(
            select(func.count(Threat.id)).where(
                or_(
                    Threat.source.ilike("%agent%"),
                    Threat.source.ilike("%endpoint%"),
                    Threat.source.ilike("%telemetry%"),
                )
            )
        )
        endpoint_threats = threat_count_res.scalar_one() or 0

        highest_risk_hostname = agents[0].hostname if agents else None

        return EndpointAgentStatsResponse(
            total_endpoints=total,
            online_endpoints=online,
            offline_endpoints=offline,
            stale_endpoints=stale,
            telemetry_events_today=telemetry_today,
            endpoint_threats=endpoint_threats,
            highest_risk_endpoint=highest_risk_hostname,
        )

    async def _resolve_agent(self, agent_id_or_uuid: str) -> Optional[EndpointAgent]:
        """Resolve agent model by internal UUID or string agent_id."""
        try:
            agent_uuid = UUID(agent_id_or_uuid)
            agent = await self.agent_repo.get_by_id(agent_uuid)
            if agent:
                return agent
        except (ValueError, TypeError):
            pass

        return await self.agent_repo.get_by_agent_id(agent_id_or_uuid)

    @staticmethod
    def _calculate_agent_status(agent: EndpointAgent) -> str:
        """Calculate dynamic status based on last_seen timestamp threshold."""
        if agent.status in ("Disabled", "Revoked"):
            return agent.status
        if not agent.last_seen:
            return "Never Seen"

        now = datetime.now(timezone.utc)
        diff_seconds = (now - agent.last_seen).total_seconds()

        if diff_seconds <= 120:
            return "Online"
        elif diff_seconds <= 300:
            return "Stale"
        else:
            return "Offline"
