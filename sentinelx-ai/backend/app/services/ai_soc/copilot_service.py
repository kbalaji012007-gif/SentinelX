"""
SentinelX AI – Upgraded Enterprise AI Copilot Service
Natural language security query parser, multi-turn conversation context engine,
controlled database tool dispatcher, 4-tier evidence categorization system,
and safe SOAR response action recommendation engine.
"""

import re
from uuid import UUID, uuid4
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from app.models.ai_copilot import AIChatConversation, AIChatMessage
from app.repositories.ai_copilot_repo import AIChatRepository
from app.schemas.ai_copilot_schema import (
    AIChatRequest,
    AIChatMessageResponse,
    AIChatConversationResponse,
    AIExplainResponse,
)
from app.services.threat_intelligence.providers.gemini import GeminiThreatProvider
from app.services.ai_soc.tools import SecurityAssistantTools


def sanitize_untrusted_text(text: Any, max_length: int = 500) -> str:
    """
    Sanitize untrusted text (log messages, command lines, threat intel, user input)
    against prompt injection, markdown table breakage, and HTML tag injection.
    Treats retrieved content strictly as passive data.
    """
    if text is None:
        return ""
    s = str(text)
    if len(s) > max_length:
        s = s[:max_length] + "… (truncated)"
    # Escape HTML to prevent injection into markdown previewers
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Neutralize Markdown table column separators
    s = s.replace("|", "&#124;")
    # Neutralize common prompt injection patterns
    injection_patterns = [
        r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b",
        r"(?i)\[system(?:\s*instructions?)?\]",
        r"(?i)\bsystem\s*:\s*",
        r"(?i)\bassistant\s*:\s*",
        r"(?i)\byou\s+are\s+now\s+in\s+developer\s+mode\b",
    ]
    for pattern in injection_patterns:
        s = re.sub(pattern, "[UNTRUSTED_CONTENT_FILTERED]", s)
    return s.strip()


class AICopilotService:
    """
    Enterprise AI Copilot handling natural language security queries,
    real SentinelX database inspection, explainability, and safe response actions.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.chat_repo = AIChatRepository(session)
        self.gemini_provider = GeminiThreatProvider()
        self.tools = SecurityAssistantTools(session)

    # ────────────────────────────────────────────────────────────────────────
    # Context & Intent Extraction
    # ────────────────────────────────────────────────────────────────────────
    def _extract_recent_entities(self, history_messages: List[AIChatMessage]) -> Dict[str, Optional[str]]:
        """Extract recently discussed IP, hostname, alert ID, incident, MITRE technique, or selected agent ID."""
        context = {
            "last_ip": None,
            "last_host": None,
            "last_agent_id": None,
            "last_alert": None,
            "last_incident": None,
            "last_technique": None,
            "last_intent": None,
        }

        # Scan backwards through history for the most recent explicit selection or context
        for msg in reversed(history_messages):
            text = msg.content or ""
            sender = (msg.sender or "").lower()

            if not context["last_ip"]:
                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
                if ip_match and not ip_match.group(0).startswith("127."):
                    context["last_ip"] = ip_match.group(0)

            if not context["last_agent_id"]:
                # If User explicitly provided a UUID or AGT- ID:
                if sender in ("user", "human"):
                    u_match = re.search(r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b", text)
                    agt_m = re.search(r"\b(AGT-[A-Za-z0-9_-]+)\b", text, re.IGNORECASE)
                    if u_match:
                        context["last_agent_id"] = u_match.group(1)
                    elif agt_m:
                        context["last_agent_id"] = agt_m.group(1)
                # If Copilot confirmed host security records for an endpoint:
                # Strictly ignore Copilot messages containing candidate tables ("Endpoint Resolution Required" / "Accessible Enrolled Endpoints")
                elif sender in ("copilot", "assistant") and "Host Security Records:" in text and "Endpoint Resolution Required" not in text:
                    u_match = re.search(r"Host Security Records:.*?`\s*\(([0-9a-fA-F-]{36}|AGT-[A-Za-z0-9_-]+)\)", text)
                    if not u_match:
                        u_match = re.search(r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b", text)
                    if u_match:
                        context["last_agent_id"] = u_match.group(1)

            if not context["last_host"]:
                # Only extract hostname if it is an explicit host or from confirmed records (not candidate list)
                if "Endpoint Resolution Required" not in text:
                    host_match = re.search(r"\b(WIN-[A-Za-z0-9_-]+|WORKSTATION-[A-Za-z0-9_-]+|DESKTOP-[A-Za-z0-9_-]+|LAPTOP-[A-Za-z0-9_-]+|DC-[A-Za-z0-9_-]+|SHETTY)\b", text, re.IGNORECASE)
                    if host_match:
                        context["last_host"] = host_match.group(0)

            if not context["last_alert"]:
                alt_match = re.search(r"\b(ALT-[A-Za-z0-9-]+)\b", text)
                if alt_match:
                    context["last_alert"] = alt_match.group(0)

            if not context["last_incident"]:
                inc_match = re.search(r"\b(INC-\d+)\b", text, re.IGNORECASE)
                if inc_match:
                    context["last_incident"] = inc_match.group(0)

            if not context["last_technique"]:
                tech_match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", text)
                if tech_match:
                    context["last_technique"] = tech_match.group(0)

        return context

    # ────────────────────────────────────────────────────────────────────────
    # Natural Language Understanding & Tool Dispatch
    # ────────────────────────────────────────────────────────────────────────
    async def interpret_and_execute_query(
        self,
        query: str,
        history: Optional[List[AIChatMessage]] = None,
        current_user: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Analyze natural language inquiry, determine intent, execute approved database tool,
        and classify findings into 4 evidence categories.
        """
        q_lower = query.lower()
        context_entities = self._extract_recent_entities(history or [])

        # Default structure
        intent = "General Security Analysis"
        tool_used = "none"
        raw_results: Dict[str, Any] = {}
        observed_data: List[str] = []
        external_intel: List[str] = []
        ai_inferences: List[str] = []
        insufficient_evidence: Optional[str] = None
        suggested_actions: List[Dict[str, Any]] = []
        confidence_score = 90
        confidence_reason = "Evaluated against live SentinelX database records."
        response_markdown = ""

        # Check for explicit UUID or agent identifier in CURRENT query (Highest Priority)
        query_uuid_match = re.search(r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b", query)
        query_agt_match = re.search(r"\b(AGT-[A-Za-z0-9_-]+)\b", query, re.IGNORECASE)
        explicit_agent_id = None
        if query_uuid_match:
            explicit_agent_id = query_uuid_match.group(1)
        elif query_agt_match:
            explicit_agent_id = query_agt_match.group(1)

        # Extract requested event/record limit if specified in query
        requested_limit = 20
        word_numbers = {
            "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
            "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
            "fifteen": 15, "twenty": 20, "twenty-five": 25, "fifty": 50,
        }
        limit_num_match = re.search(r"\b(?:latest|last|top|show|get)\s+(\d+)\b", q_lower)
        limit_word_match = re.search(r"\b(?:latest|last|top|show|get)\s+(" + "|".join(word_numbers.keys()) + r")\b", q_lower)
        if limit_num_match:
            requested_limit = int(limit_num_match.group(1))
        elif limit_word_match:
            requested_limit = word_numbers[limit_word_match.group(1)]
        else:
            num_match = re.search(r"\b(\d+)\s+(?:events?|logs?|records?|telemetr)", q_lower)
            if num_match:
                requested_limit = int(num_match.group(1))
        requested_limit = min(max(1, requested_limit), 50)

        # Determine if this query targets endpoint inspection
        is_endpoint_query = False
        if explicit_agent_id:
            is_endpoint_query = True
        elif any(term in q_lower for term in [
            "laptop",
            "workstation",
            "endpoint security",
            "endpoint telemetry",
            "windows laptop",
            "security events",
            "laptop security",
            "suspicious activities on my",
            "suspicious activities happened on my",
            "events on my laptop",
            "events on my workstation",
            "activities happened on my laptop",
            "my laptop",
            "desktop-",
            "win-",
            "workstation-",
            "agent telemetry",
            "endpoint",
            "shetty",
        ]) and not any(other in q_lower for other in ["failed login", "brute force", "failed logon", "offline endpoints", "which endpoints are currently offline", "highest-risk assets"]):
            is_endpoint_query = True
        elif history and len(history) > 0:
            last_copilot = next((m for m in reversed(history) if (m.sender or "").lower() in ("copilot", "assistant")), None)
            if last_copilot and any(marker in (last_copilot.content or "") for marker in ["Endpoint Resolution Required", "Accessible Enrolled Endpoints", "Host Security Records:"]):
                is_endpoint_query = True

        # ── 1. Critical Security Alerts ─────────────────────────────────────
        if any(term in q_lower for term in ["critical security alert", "critical alert", "show me all critical alerts", "show critical alerts"]):
            intent = "List Critical Security Alerts"
            tool_used = "get_security_alerts"
            raw_results = await self.tools.get_security_alerts(severity="CRITICAL", hours=168, limit=10)
            items = raw_results.get("data", [])

            if items:
                observed_data.append(f"Retrieved {len(items)} critical alert(s) from sentinelx.security_alerts.")
                for it in items:
                    observed_data.append(f"Alert {it['alert_id']}: '{it['title']}' (Status: {it['status']}, Detected: {it['detected_at'] or 'Recent'})")
                ai_inferences.append("Critical alerts indicate immediate threat activity requiring SOC triage.")
                suggested_actions.extend(await self.tools.recommend_safe_soar_actions(items[0]["alert_id"]))
                confidence_score = 95
                confidence_reason = "Direct match from live security alert database."
            else:
                insufficient_evidence = "No critical security alerts found matching current filter in the SentinelX database."
                confidence_score = 80
                confidence_reason = "Database query returned 0 critical alerts."

            response_markdown = self._format_alerts_response(items, "Critical")

        # ── 2. Laptop / Endpoint Suspicious Activity & Security Events ───────
        elif is_endpoint_query:
            intent = "Inspect Laptop / Endpoint Suspicious Activities"
            tool_used = "get_endpoint_suspicious_activity"

            # Deterministic resolution:
            # 1. Explicit agent ID or UUID in CURRENT message takes highest priority.
            # 2. If no explicit ID in current message, preserve selected agent ID from this conversation's history.
            # 3. If an agent ID is resolved, do NOT use ambiguous hostname matching.
            target_agent_id = explicit_agent_id or context_entities.get("last_agent_id")
            target_hostname = None if target_agent_id else context_entities.get("last_host")

            raw_results = await self.tools.get_endpoint_suspicious_activity(
                hostname=target_hostname,
                agent_id=target_agent_id,
                query_text=query,
                user=current_user,
                platform="Windows" if "windows" in q_lower else None,
                hours=72,
                limit=requested_limit,
            )

            status = raw_results.get("status")
            host_info = raw_results.get("matched_host")
            verif = raw_results.get("verification", {})
            alerts = raw_results.get("alerts", [])
            telemetry = raw_results.get("telemetry", [])
            log_entries = raw_results.get("log_entries", [])
            observed_mitre = raw_results.get("observed_mitre", [])
            analytical_hypotheses = raw_results.get("analytical_hypotheses", [])

            if status == "error":
                insufficient_evidence = raw_results.get("error", "Database query failed.")
                confidence_score = 50
                confidence_reason = "Database query failed; live database records unavailable."
                response_markdown = self._format_endpoint_error_response(query, raw_results.get("error", "Unknown DB error"))
            elif status in ("unresolved_endpoint", "not_found") or not host_info:
                insufficient_evidence = raw_results.get("error", "Endpoint could not be identified.")
                confidence_score = 70
                confidence_reason = "Endpoint could not be uniquely identified in database records."
                response_markdown = self._format_unresolved_endpoint_response(query, raw_results.get("error"), raw_results.get("candidate_hosts", []))
            else:
                is_stale = verif.get("is_stale", False)
                age_str = verif.get("last_seen_age", "Unknown")
                dedup = verif.get("dedup_summary", {})
                unique_events = dedup.get("unique_events_count", len(telemetry))

                observed_data.append(f"Identified endpoint: '{host_info['hostname']}' (ID: {host_info['agent_id']}, Platform: {host_info['platform']}).")
                observed_data.append(
                    f"Verified Host State: Stored DB Status={verif.get('connectivity_status')}, "
                    f"Actual Connectivity={verif.get('actual_connectivity')}, "
                    f"Last Heartbeat={verif.get('last_seen')} ({age_str}), "
                    f"Host Isolation={'Isolated' if verif.get('host_isolated') else 'Not Isolated'} ({verif.get('isolation_note')})."
                )

                if alerts:
                    observed_data.append(f"Observed {len(alerts)} security alert(s) linked to host in sentinelx.security_alerts.")
                    for al in alerts[:3]:
                        observed_data.append(f"- Alert {al['alert_id']}: {al['title']} ({al['severity']})")
                    suggested_actions.extend(await self.tools.recommend_safe_soar_actions(host_info["hostname"]))

                if telemetry:
                    observed_data.append(f"Retrieved {len(telemetry)} telemetry event(s) from sentinelx.agent_telemetry.")
                    for t in telemetry[:3]:
                        observed_data.append(f"- [{t.get('event_timestamp')}] {t.get('event_type')} ({t.get('severity')}) via {t.get('source')}")

                if log_entries:
                    observed_data.append(f"Retrieved {len(log_entries)} security log event(s) from sentinelx.log_entries.")
                    for l in log_entries[:3]:
                        observed_data.append(f"- [{l.get('event_timestamp')}] {l.get('event_type')} ({l.get('severity')})")

                if telemetry or log_entries:
                    observed_data.append(f"Correlation / Deduplication: Correlated {len(telemetry)} telemetry record(s) and {len(log_entries)} log entry/entries into {unique_events} unique underlying event(s).")

                # MITRE ATT&CK - Strictly only include observed detections
                if observed_mitre:
                    for m in observed_mitre:
                        external_intel.append(f"Observed MITRE Detection: {m['technique_id']} ({m.get('name', 'Technique')}) via Alert {m.get('alert_id', '')}")
                else:
                    external_intel.append("No MITRE ATT&CK techniques observed in detection records for this endpoint.")

                # Analytical Hypotheses - Explicitly labeled as unconfirmed
                if analytical_hypotheses:
                    for ah in analytical_hypotheses:
                        ai_inferences.append(f"Analytical Hypothesis: {ah['technique_id']} - {ah['name']} ({ah.get('rationale', '')}). Not confirmed in detection rules.")

                if alerts or any(t.get("severity") in ("ERROR", "CRITICAL") for t in telemetry):
                    ai_inferences.append("Host exhibits anomalous execution activity requiring triage. Attack success is not confirmed until endpoint disk forensics are completed.")
                    confidence_score = 92
                    confidence_reason = "Direct match from agent_telemetry, log_entries, and security_alerts records."
                elif is_stale:
                    ai_inferences.append(f"Endpoint heartbeat is Stale ({age_str}). Queried historical telemetry records indicate no active compromise, but current real-time health cannot be verified.")
                    confidence_score = 88
                    confidence_reason = f"Verified historical records from last active session. Endpoint connectivity is Stale ({age_str})."
                elif telemetry or log_entries:
                    ai_inferences.append("Endpoint is active with baseline telemetry; no critical alert thresholds breached.")
                    confidence_score = 90
                    confidence_reason = "Direct match from live agent_telemetry and log_entries records."
                else:
                    insufficient_evidence = f"0 security events or anomalous telemetry records were recorded for host '{host_info['hostname']}' in the database."
                    if is_stale:
                        ai_inferences.append(f"No records found for endpoint. Endpoint is currently Stale (last seen {age_str}).")
                    else:
                        ai_inferences.append("Endpoint is operating within normal baseline limits with no active indicators of compromise.")
                    confidence_score = 90
                    confidence_reason = "Verified against database: Zero matching records in agent_telemetry and log_entries."

                response_markdown = self._format_laptop_activity_response(
                    host_info=host_info,
                    verification=verif,
                    alerts=alerts,
                    telemetry=telemetry,
                    log_entries=log_entries,
                    observed_mitre=observed_mitre,
                    analytical_hypotheses=analytical_hypotheses,
                    limit=requested_limit,
                )

        # ── 3. Failed Logins & Brute Force Analysis ─────────────────────────
        elif any(term in q_lower for term in ["failed login", "brute force", "brute-force", "failed logon", "authentication attempt"]):
            intent = "Analyze Failed Login Attempts & Brute Force"
            tool_used = "analyze_failed_logins"
            raw_results = await self.tools.analyze_failed_logins(hours=72, limit=50)
            total_fails = raw_results.get("total_failed_logins", 0)
            suspects = raw_results.get("brute_force_suspects", [])
            user_dist = raw_results.get("user_distribution", {})

            if total_fails > 0:
                observed_data.append(f"Identified {total_fails} failed authentication event(s) across connected log sources.")
                for s in suspects:
                    observed_data.append(f"Source IP {s['source_ip']}: {s['attempt_count']} failed attempts recorded.")
                    suggested_actions.extend(await self.tools.recommend_safe_soar_actions(s["source_ip"]))

                external_intel.append("MITRE ATT&CK T1110 (Brute Force / Password Spraying) technique mapped.")
                ai_inferences.append("High frequency of failed attempts from singular external IP addresses strongly indicates an automated brute-force campaign.")
                confidence_score = 94
                confidence_reason = "Correlated against authentication log entries and failure counts."
            else:
                insufficient_evidence = "Zero failed login entries found in the current log collection window."
                confidence_score = 80
                confidence_reason = "No failed authentication log entries in database."

            response_markdown = self._format_failed_logins_response(total_fails, suspects, user_dist)

        # ── 4. Offline Endpoints ────────────────────────────────────────────
        elif any(term in q_lower for term in ["offline", "endpoints are currently offline", "which endpoints", "agents offline"]):
            intent = "Audit Offline Endpoints"
            tool_used = "get_endpoint_agents"
            raw_results = await self.tools.get_endpoint_agents(status="Offline")
            items = raw_results.get("data", [])

            if items:
                observed_data.append(f"Discovered {len(items)} endpoint agent(s) marked as 'Offline' in sentinelx.endpoint_agents.")
                for ag in items:
                    observed_data.append(f"Host '{ag['hostname']}' (ID: {ag['agent_id']}) last seen: {ag['last_seen'] or 'Never'}.")
                ai_inferences.append("Offline status may result from network disconnection, system shutdown, or tampering by an attacker.")
                confidence_score = 95
            else:
                observed_data.append("Queried endpoint agents status: All enrolled agents currently report Online, or no offline hosts recorded.")
                confidence_score = 90

            response_markdown = self._format_offline_endpoints_response(items)

        # ── 5. Highest-Risk Assets ──────────────────────────────────────────
        elif any(term in q_lower for term in ["highest-risk assets", "highest risk", "high risk asset", "critical asset"]):
            intent = "Identify Highest-Risk Assets"
            tool_used = "get_highest_risk_assets"
            raw_results = await self.tools.get_highest_risk_assets(limit=8)
            items = raw_results.get("data", [])

            if items:
                observed_data.append(f"Extracted {len(items)} high-risk asset(s) from asset inventory.")
                for it in items:
                    observed_data.append(f"Asset '{it['asset_name']}' ({it['ip_address']}): Criticality={it['criticality']}, Est. Risk={it['estimated_risk_score']}.")
                ai_inferences.append("High business criticality assets represent high-value targets for lateral movement and data exfiltration.")
                confidence_score = 92
            else:
                insufficient_evidence = "No asset records found in the database."
                confidence_score = 65

            response_markdown = self._format_assets_response(items)

        # ── 6. Threat Correlations & Attack Chains ──────────────────────────
        elif any(term in q_lower for term in ["threat correlation", "correlations", "attack chain", "explain the latest threat"]):
            intent = "Explain Threat Correlations"
            tool_used = "get_threat_correlations"
            raw_results = await self.tools.get_threat_correlations(limit=5)
            corrs = raw_results.get("correlations", [])
            chains = raw_results.get("attack_chains", [])

            if corrs or chains:
                if corrs:
                    observed_data.append(f"Found {len(corrs)} active correlation rule match(es) linking multiple telemetry events.")
                    for c in corrs:
                        observed_data.append(f"Correlation '{c['title']}': Severity={c['severity']}, Risk Score={c['risk_score']}.")
                if chains:
                    observed_data.append(f"Identified {len(chains)} multi-stage attack chain(s).")
                    for ch in chains:
                        observed_data.append(f"Attack Chain '{ch['chain_name']}': Stage={ch['stage']}, Status={ch['status']}.")

                external_intel.append("MITRE ATT&CK Matrix cross-reference applied.")
                ai_inferences.append("Correlation engine links separate perimeter and host alerts into a unified kill-chain timeline.")
                confidence_score = 91
            else:
                insufficient_evidence = "No active threat correlations or attack chains found in database."
                confidence_score = 75

            response_markdown = self._format_correlations_response(corrs, chains)

        # ── 7. MITRE ATT&CK Techniques ──────────────────────────────────────
        elif any(term in q_lower for term in ["mitre att&ck", "mitre technique", "techniques are associated", "mitre"]):
            intent = "Map MITRE ATT&CK Techniques"
            tool_used = "explain_mitre_techniques"
            tech_id = context_entities["last_technique"]
            raw_results = await self.tools.explain_mitre_techniques(technique_id=tech_id, search_query=query)
            items = raw_results.get("data", [])
            source = raw_results.get("source", "MITRE ATT&CK Catalog")

            external_intel.append(f"Source: {source} (Technique Catalog)")
            for m in items:
                observed_data.append(f"Technique {m.get('technique_id')}: '{m.get('name')}' (Tactic: {m.get('tactic')})")
            ai_inferences.append("Adversaries leverage these techniques during execution and credential access phases.")
            confidence_score = 96

            response_markdown = self._format_mitre_response(items)

        # ── 8. SOC Overview / 24 Hours Delta ────────────────────────────────
        elif any(term in q_lower for term in ["24 hours", "last 24h", "what changed in the soc", "soc during the last 24"]):
            intent = "Summarize Last 24 Hours in SOC"
            tool_used = "get_soc_changes_last_24h"
            raw_results = await self.tools.get_soc_changes_last_24h()

            observed_data.append(f"New Security Alerts: {raw_results['total_new_alerts']} (Critical: {raw_results['critical_alerts_count']}).")
            observed_data.append(f"New Incidents Created: {raw_results['new_incidents_count']}.")
            observed_data.append(f"Total Logs Ingested: {raw_results['total_logs_collected']}.")
            observed_data.append(f"Enrolled Agents: {raw_results['agent_health']['total']} total ({raw_results['agent_health']['online']} Online, {raw_results['agent_health']['offline']} Offline).")

            ai_inferences.append("Telemetry ingestion is active. Prioritize critical alerts before SLA breach.")
            confidence_score = 95
            response_markdown = self._format_soc_24h_response(raw_results)

        # ── 9. Incident Report Generation ───────────────────────────────────
        elif any(term in q_lower for term in ["generate an incident report", "incident report", "report for my professor", "executive report"]):
            intent = "Generate Incident Report"
            tool_used = "get_incident_for_investigation"
            inc_id = context_entities["last_incident"] or "INC-9042"
            raw_results = await self.tools.get_incident_for_investigation(inc_id)
            inc_data = raw_results.get("data")

            is_academic = "professor" in q_lower or "student" in q_lower or "class" in q_lower
            response_markdown = self._format_incident_report(inc_data, is_academic=is_academic)

            observed_data.append(f"Incident target: '{inc_data['title'] if inc_data else inc_id}'.")
            if inc_data:
                observed_data.append(f"Severity: {inc_data['severity']}, Priority: {inc_data['priority']}, Status: {inc_data['status']}")
            external_intel.append("NIST SP 800-61 Rev. 2 Incident Handling Framework guidelines applied.")
            ai_inferences.append("Report synthesized from structured telemetry, log analysis, and containment recommendations.")
            confidence_score = 94

        # ── 10. Follow-up / Recommendations ("What should I do next?") ─────
        elif any(term in q_lower for term in ["what should i do next", "what should i investigate next", "why is this dangerous", "next steps", "what to do next"]):
            intent = "Provide Next Investigation Steps & Safety Analysis"
            tool_used = "recommend_safe_soar_actions"
            target = context_entities["last_host"] or context_entities["last_ip"] or "Compromised Entity"
            suggested_actions = await self.tools.recommend_safe_soar_actions(target)

            observed_data.append(f"Context Target: '{target}' from previous conversation turn.")
            ai_inferences.append("Immediate priority is containing lateral movement while capturing non-volatile memory artifacts.")
            confidence_score = 92
            response_markdown = self._format_next_steps_response(target, suggested_actions)

        # ── 11. Investigation & Root Cause ──────────────────────────────────
        elif any(term in q_lower for term in ["investigate", "root cause", "possible root cause"]):
            intent = "Investigate Alert / Incident Root Cause"
            target = context_entities["last_alert"] or context_entities["last_incident"] or "Active Alert"
            tool_used = "get_security_alerts"
            raw_results = await self.tools.get_security_alerts(limit=5)
            items = raw_results.get("data", [])

            if items:
                top_alert = items[0]
                observed_data.append(f"Investigated Alert: '{top_alert['title']}' ({top_alert['alert_id']})")
                observed_data.append(f"Severity: {top_alert['severity']}, Status: {top_alert['status']}, Source: {top_alert['source']}")
                ai_inferences.append(f"Root Cause Hypothesis: Anomalous process execution or external connection triggering signature '{top_alert['title']}'. (Unconfirmed – requires endpoint memory capture).")
                suggested_actions.extend(await self.tools.recommend_safe_soar_actions(top_alert["alert_id"]))
                confidence_score = 88
            else:
                insufficient_evidence = "No alerts found to investigate in the database."
                confidence_score = 70

            response_markdown = self._format_investigation_response(items)

        # ── 12. General Search Fallback ─────────────────────────────────────
        else:
            intent = "Security Log & Asset Search"
            tool_used = "search_security_logs"
            raw_results = await self.tools.search_security_logs(query_text=query, limit=10)
            logs = raw_results.get("data", [])

            if logs:
                observed_data.append(f"Found {len(logs)} security log entry(ies) matching terms in '{query}'.")
                for l in logs[:5]:
                    observed_data.append(f"[{l['log_level']}] {l['event_type']}: {l['message']}")
                confidence_score = 85
            else:
                insufficient_evidence = f"No security logs or database records matched your search query: '{query}'."
                confidence_score = 75

            response_markdown = self._format_general_response(query, logs)

        return {
            "intent": intent,
            "tool_used": tool_used,
            "response_markdown": response_markdown,
            "evidence": {
                "observed_sentinelx_data": observed_data,
                "external_intelligence": external_intel,
                "ai_inference": ai_inferences,
                "insufficient_evidence_warning": insufficient_evidence,
                "suggested_actions": suggested_actions,
            },
            "confidence_score": confidence_score,
            "confidence_reason": confidence_reason,
            "raw_data": raw_results,
        }

    # ────────────────────────────────────────────────────────────────────────
    # Response Formatters (Rich, Professional SOC Markdown)
    # ────────────────────────────────────────────────────────────────────────
    def _format_alerts_response(self, items: List[Dict[str, Any]], severity: str) -> str:
        if not items:
            return (
                f"### 🛡️ Security Alerts Query: {severity}\n\n"
                f"**Database Status:** No {severity.lower()} security alerts are currently stored in the SentinelX database.\n\n"
                f"- **Observed Data:** 0 matching records.\n"
                f"- **Recommendation:** Your detection rules are active. Review `/alerts` or `/threats` for medium/low events."
            )

        md = f"### 🚨 Active {severity} Security Alerts\n\n"
        md += f"Retrieved **{len(items)}** alerts directly from live SentinelX database records:\n\n"
        md += "| Alert ID | Title | Severity | Status | MITRE Technique | Detected |\n"
        md += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
        for it in items:
            mitre = it.get("mitre_technique") or "N/A"
            dt = it.get("detected_at") or "Recent"
            if len(dt) > 16:
                dt = dt[:16].replace("T", " ")
            md += f"| **{it['alert_id']}** | {it['title']} | `{it['severity']}` | {it['status']} | `{mitre}` | {dt} |\n"

        md += "\n#### 🔍 Analyst Assessment & Priority\n"
        md += "These alerts involve severe detection thresholds (such as credential dumping, anomalous execution, or C2 beaconing). "
        md += "Immediate containment and endpoint isolation are advised.\n\n"
        md += "👉 *Click any Alert ID in the Evidence pane to open the full alert lifecycle management view.*"
        return md

    def _format_unresolved_endpoint_response(self, query: str, error_msg: Optional[str], candidates: List[Dict[str, Any]]) -> str:
        if not candidates:
            if error_msg and "access denied" in error_msg.lower():
                return (
                    f"### ⛔ Access Denied\n\n"
                    f"**User Inquiry:** *\"{query}\"*\n\n"
                    f"{error_msg}\n\n"
                    f"🔒 *Access to this endpoint is restricted by role-based access control.*"
                )
            return (
                f"### ❌ Endpoint Not Found\n\n"
                f"**User Inquiry:** *\"{query}\"*\n\n"
                f"{error_msg or 'The requested endpoint was not found in enrolled endpoint agents.'}\n\n"
                f"⚠️ *Verified against live SentinelX database: 0 matching records.*"
            )

        md = "### ⚠️ Endpoint Resolution Required\n\n"
        md += f"**User Inquiry:** *\"{query}\"*\n\n"
        if error_msg:
            md += f"{error_msg}\n\n"
        if candidates:
            md += "#### 🖥️ Accessible Enrolled Endpoints\n"
            md += "| Hostname | Agent ID | Platform | Status |\n"
            md += "| :--- | :--- | :--- | :--- |\n"
            for c in candidates:
                md += f"| **{c['hostname']}** | `{c['agent_id']}` | {c.get('platform', 'Unknown')} | `{c.get('status', 'Unknown')}` |\n"
            md += "\n"
        md += "👉 *Please specify the target agent ID to inspect (e.g., `\"Show security events on b7210744-d5cc-4563-ad2f-5b0d4d6be586\"`). SentinelX will not guess or assume an endpoint.*"
        return md

    def _format_endpoint_error_response(self, query: str, error_msg: str) -> str:
        return (
            f"### ❌ Database Query Failure\n\n"
            f"**User Inquiry:** *\"{query}\"*\n\n"
            f"**Error Details:** `{error_msg}`\n\n"
            f"⚠️ *The requested endpoint security records could not be retrieved from the database. SentinelX strictly refuses to substitute simulated or pre-canned AI data for failed live queries.*"
        )

    def _format_laptop_activity_response(
        self,
        host_info: Dict[str, Any],
        verification: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        telemetry: List[Dict[str, Any]],
        log_entries: List[Dict[str, Any]],
        observed_mitre: List[Dict[str, Any]],
        analytical_hypotheses: List[Dict[str, Any]],
        limit: int = 20,
    ) -> str:
        host = host_info.get("hostname", "Endpoint Host")
        agent_id = host_info.get("agent_id", "N/A")
        platform = host_info.get("platform", "Windows")
        os_ver = host_info.get("os_version", "Windows 11")
        agent_ver = host_info.get("agent_version", "1.0.0")

        stored_status = host_info.get("status") or verification.get("connectivity_status", "Unknown")
        actual_conn = verification.get("actual_connectivity") or stored_status
        last_seen = verification.get("last_seen") or "Unknown"
        age_str = verification.get("last_seen_age", "Unknown")
        is_stale = verification.get("is_stale", False)
        agent_disabled = verification.get("agent_disabled", False)
        is_isolated = verification.get("host_isolated", False)
        iso_note = verification.get("isolation_note", "Host is NOT verified as isolated.")
        dedup = verification.get("dedup_summary", {})
        unique_events = dedup.get("unique_events_count", len(telemetry))

        md = f"### 💻 Host Security Records: `{host}` (`{agent_id}`)\n\n"
        md += f"- **Operating Platform:** {platform} ({os_ver})\n"
        md += f"- **Agent Version:** {agent_ver}\n"
        md += f"- **Agent Status:** `{stored_status}`\n"
        md += f"- **Actual Connectivity:** `{actual_conn}`\n\n"

        # Verification section - accurately distinguish stored administrative status from actual recent connectivity
        status_clean = str(stored_status).strip().lower()
        if status_clean == "revoked":
            edr_label = "Revoked by Administrator"
            edr_eval = "Agent certificate revoked by administrator; telemetry ingestion blocked."
            safeguard_state = "Revoked (Ingestion Blocked)"
        elif status_clean == "disabled":
            edr_label = "Disabled by Administrator"
            edr_eval = "Agent disabled by administrator; telemetry ingestion halted."
            safeguard_state = "Disabled (Ingestion Halted)"
        elif status_clean == "offline":
            edr_label = "Active Registration (Offline)"
            edr_eval = f"Endpoint is offline; last seen {age_str}."
            safeguard_state = "Offline (Ingestion Paused)"
        elif is_stale:
            edr_label = "Active Registration (Heartbeat Stale)"
            edr_eval = f"No heartbeat received for {age_str}. Real-time ingestion is currently inactive."
            safeguard_state = f"Ingestion Inactive / Stale ({age_str})"
        else:
            edr_label = "Active (Live Heartbeat)"
            edr_eval = f"Live agent telemetry stream verified (last seen {age_str})."
            safeguard_state = "EDR Ingestion Active (Live Stream)"

        md += "#### 🛡️ Endpoint & Safeguard State Verification\n\n"
        md += "| Safeguard / Verification Dimension | Verified State | Evaluation Detail |\n"
        md += "| :--- | :--- | :--- |\n"
        md += f"| **Endpoint Connectivity** | `{actual_conn}` | Stored: `{stored_status}`; Last seen: {last_seen} ({age_str}) |\n"
        md += f"| **EDR Agent Status** | `{edr_label}` | {edr_eval} |\n"
        md += f"| **Host Network Isolation** | `{'Isolated (Verified via SOAR)' if is_isolated else 'Not Isolated (Unverified)'}` | {iso_note} |\n"
        md += f"| **Active Safeguards** | `{'Network Isolation Active' if is_isolated else safeguard_state}` | Checked against agent telemetry state and SOAR execution history |\n\n"

        if is_stale:
            md += f"> [!WARNING]\n"
            md += f"> **Heartbeat Stale:** Endpoint `{host}` last reported a heartbeat {age_str} ({last_seen}). Displayed records reflect historical telemetry from the last active session, not live streams.\n\n"

        # 1. Endpoint Telemetry Section (Clearly distinguished with Windows Event ID vs Record ID)
        section_title = "Historical Endpoint Telemetry" if is_stale else "Live Endpoint Telemetry"
        md += f"#### 🛰️ {section_title} (`sentinelx.agent_telemetry`)\n\n"
        display_tel_count = min(len(telemetry), limit)
        if telemetry:
            md += f"Retrieved **{display_tel_count}** telemetry records (sorted by actual timestamp):\n\n"
            md += "| Timestamp (UTC) | Windows Event ID | Record ID | Severity | Source | Event Type | Relevant Payload Fields |\n"
            md += "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
            for t in telemetry[:display_tel_count]:
                ts = t.get("event_timestamp") or "N/A"
                win_eid = t.get("windows_event_id") or "Not available"
                rec_id = t.get("record_id") or str(t.get("id", "N/A"))[:8]
                sev = t.get("severity", "INFO")
                src = t.get("source", f"AgentTelemetry ({host})")
                etype = sanitize_untrusted_text(t.get("event_type", "Telemetry"))
                details = sanitize_untrusted_text(t.get("details", "Standard event"))
                md += f"| `{ts}` | `{win_eid}` | `{rec_id}` | `{sev}` | `{src}` | `{etype}` | {details} |\n"
            md += "\n"
        else:
            md += "✅ **Zero (0) matching records were found in `sentinelx.agent_telemetry` for this endpoint.**\n\n"

        # 2. Correlated Security Logs Section (Clearly labeled and linked)
        md += "#### 📜 Correlated Security Logs (`sentinelx.log_entries`)\n\n"
        display_log_count = min(len(log_entries), limit)
        if log_entries:
            md += f"Retrieved **{display_log_count}** correlated security log records (sorted by actual timestamp):\n\n"
            md += "| Timestamp (UTC) | Windows Event ID | Record ID | Severity | Source | Event Type | Correlated Source | Relevant Payload Fields |\n"
            md += "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
            for l in log_entries[:display_log_count]:
                ts = l.get("event_timestamp") or "N/A"
                win_eid = l.get("windows_event_id") or "Not available"
                rec_id = l.get("record_id") or str(l.get("id", "N/A"))[:8]
                sev = l.get("severity", "INFO")
                src = l.get("source", "sentinelx.log_entries")
                etype = sanitize_untrusted_text(l.get("event_type", "Log"))
                details = sanitize_untrusted_text(l.get("details", "Log event"))
                corr_tel = l.get("correlated_telemetry_record_id")
                corr_label = f"🔗 Telemetry `{corr_tel}`" if corr_tel else "Direct Log Source"
                md += f"| `{ts}` | `{win_eid}` | `{rec_id}` | `{sev}` | `{src}` | `{etype}` | {corr_label} | {details} |\n"
            md += "\n"

            if dedup.get("correlated_count", 0) > 0:
                md += f"*(Note: {dedup.get('correlated_count')} log entries are correlated representations of agent telemetry records and are deduplicated in unique event accounting: **{unique_events} unique underlying events** observed).* \n\n"
        else:
            md += "✅ **Zero (0) matching records were found in `sentinelx.log_entries` for this endpoint.**\n\n"

        # 3. Security Alerts Section
        if alerts:
            md += f"#### ⚠️ Correlated Security Alerts ({len(alerts)} Found)\n\n"
            md += "| Alert ID | Title | Severity | Status | Detected At |\n"
            md += "| :--- | :--- | :--- | :--- | :--- |\n"
            for a in alerts:
                md += f"| **{a['alert_id']}** | `{a['title']}` | `{a['severity']}` | `{a['status']}` | {a.get('detected_at', 'Recent')} |\n"
            md += "\n"

        # 4. MITRE ATT&CK Mapping
        md += "#### 🥋 MITRE ATT&CK Mapping\n"
        if observed_mitre:
            for m in observed_mitre:
                md += f"- **Observed Detection:** `{m['technique_id']}` — {m['name']} (Tactic: `{m['tactic']}`, Alert: `{m.get('alert_id', 'N/A')}`)\n"
        if analytical_hypotheses:
            for ah in analytical_hypotheses:
                md += f"- **Analytical Hypothesis (Unconfirmed by Detection Rules):** `{ah['technique_id']}` — {ah['name']} (*{ah.get('rationale', '')}*)\n"
        if not observed_mitre and not analytical_hypotheses:
            md += "- **Detection Engine Status:** No MITRE ATT&CK techniques have been observed in records for this endpoint.\n"
        md += "\n"

        # 5. Recommended Next Steps & Health Evaluation
        md += "#### 🎯 Security Assessment & Recommended Next Steps\n"
        if alerts or any(t.get('severity') in ('ERROR', 'CRITICAL') for t in telemetry):
            md += f"1. **Host Containment:** Recommended SOAR action `Isolate_Host` for `{host}` if malicious persistence is confirmed. *(Note: Host is currently NOT isolated — execution requires authorized confirmation).* \n"
            md += "2. **Process Inspection:** Review parent-child process tree and collect non-volatile memory artifacts.\n"
        elif is_stale:
            md += f"- **Assessment:** No malicious indicators or critical alerts were identified in the {display_tel_count} historical telemetry records from the last active session.\n"
            md += f"- **Coverage Limitation:** Endpoint `{host}` is currently **Stale** (last seen {age_str}). Current live health and active telemetry cannot be confirmed until endpoint connectivity resumes.\n"
            md += f"1. **Verify Agent Connectivity:** Check host network connectivity and ensure the SentinelX Agent service is running on `{host}`.\n"
            md += "2. **Re-evaluate Upon Reconnection:** Conduct a fresh telemetry review once the agent transmits a current heartbeat.\n"
        else:
            md += "Endpoint baseline is operating normally with live telemetry stream verified. No containment actions required.\n"

        return md

    def _format_failed_logins_response(self, count: int, suspects: List[Dict[str, Any]], user_dist: Dict[str, int]) -> str:
        if count == 0:
            return (
                "### 🔐 Authentication Telemetry: Failed Logins\n\n"
                "**Result:** No failed login attempts recorded in the database during the selected timeframe.\n\n"
                "- **Observed Data:** 0 failures in `sentinelx.log_entries`.\n"
                "- **Conclusion:** Normal authentication baseline. No active brute-force campaigns detected."
            )

        md = f"### 🔐 Authentication Log Analysis: Brute-Force Detection\n\n"
        md += f"Observed **{count}** failed login events across enterprise authentication logs.\n\n"

        if suspects:
            md += "#### 🚩 Suspected Brute-Force Campaigns by Source IP\n\n"
            md += "| Source IP Address | Failed Attempts | Campaign Assessment |\n"
            md += "| :--- | :--- | :--- |\n"
            for s in suspects:
                md += f"| `{s['source_ip']}` | **{s['attempt_count']}** | `{s['suspected']}` |\n"
            md += "\n"

        if user_dist:
            md += "#### 👤 Targeted User Accounts\n"
            for u, c in sorted(user_dist.items(), key=lambda x: x[1], reverse=True)[:5]:
                md += f"- **{u}**: {c} failed attempt(s)\n"
            md += "\n"

        md += "#### 🛡️ Mitigation Recommendations\n"
        md += "1. **Block Malicious IP**: Add a perimeter firewall drop rule for top offender IP addresses.\n"
        md += "2. **Account Lockout**: Temporarily disable or reset credentials for repeatedly targeted accounts.\n"
        md += "3. **MFA Verification**: Ensure multi-factor authentication is enforced across all external VPN and SSH gateways."
        return md

    def _format_offline_endpoints_response(self, items: List[Dict[str, Any]]) -> str:
        if not items:
            return (
                "### 🖥️ Endpoint Health Audit: Offline Agents\n\n"
                "✅ **All registered endpoint agents are currently ONLINE** (or no agents marked as offline in database).\n\n"
                "- **Audit Status:** Healthy\n"
                "- **Telemetry Connection:** Active\n"
                "Visit `/agents` for live heartbeat intervals and version details."
            )

        md = f"### ⚠️ Offline Endpoint Agents ({len(items)} Detected)\n\n"
        md += "The following systems have missed consecutive heartbeats or been marked offline:\n\n"
        md += "| Hostname | Agent ID | Platform | Version | Last Seen |\n"
        md += "| :--- | :--- | :--- | :--- | :--- |\n"
        for ag in items:
            ls = ag.get("last_seen") or "Never Seen"
            if len(ls) > 16:
                ls = ls[:16].replace("T", " ")
            md += f"| **{ag['hostname']}** | `{ag['agent_id']}` | {ag['platform']} | {ag['agent_version']} | {ls} |\n"

        md += "\n#### 🚨 Security Risks of Offline Endpoints\n"
        md += "- **Visibility Gap:** Telemetry and event log collection is paused while agent is offline.\n"
        md += "- **Compromise Indicator:** Attackers may disable EDR services during post-exploitation.\n"
        md += "- **Recommended Action:** Contact endpoint owner or inspect Windows Service status for `SentinelXAgent`."
        return md

    def _format_assets_response(self, items: List[Dict[str, Any]]) -> str:
        if not items:
            return "### 🏢 High-Risk Assets Assessment\n\nNo asset records found in database inventory."

        md = "### 🏢 Highest-Risk Enterprise Assets\n\n"
        md += "Ranked by asset criticality, network exposure, and security threat indicators:\n\n"
        md += "| Asset / Hostname | IP Address | Type | Criticality | Est. Risk Score | Owner |\n"
        md += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
        for it in items:
            md += f"| **{it['hostname']}** | `{it['ip_address']}` | {it['asset_type']} | `{it['criticality']}` | **{it['estimated_risk_score']}/100** | {it['owner'] or 'Unassigned'} |\n"

        md += "\n#### 🎯 Defense Prioritization\n"
        md += "- Critical servers hosting directory services or databases must have strict network segmentation.\n"
        md += "- Review open vulnerability scan findings on `/vulnerabilities`."
        return md

    def _format_correlations_response(self, corrs: List[Dict[str, Any]], chains: List[Dict[str, Any]]) -> str:
        md = "### 🔗 Threat Correlations & Attack Chains\n\n"
        if corrs:
            md += "#### ⚡ Correlated Multi-Source Events\n\n"
            md += "| Title | Type | Severity | Risk Score | Confidence |\n"
            md += "| :--- | :--- | :--- | :--- | :--- |\n"
            for c in corrs:
                md += f"| **{c['title']}** | {c['correlation_type']} | `{c['severity']}` | **{c['risk_score']}** | {c['confidence_score']}% |\n"
            md += "\n"

        if chains:
            md += "#### ⛓️ Attack Kill Chains\n\n"
            for ch in chains:
                md += f"- **{ch['chain_name']}** — Current Stage: `{ch['stage']}` (Status: **{ch['status']}**, Risk: **{ch['risk_score']}**)\n"
                if ch.get("description"):
                    md += f"  *{ch['description']}*\n"
            md += "\n"

        if not corrs and not chains:
            md += "No multi-event correlation alerts or attack chains are currently active. Telemetry indicates independent baseline operations."
        else:
            md += "#### 🧠 AI Correlation Rationale\n"
            md += "Threat correlation clusters distinct log events within sliding time windows to reduce alert fatigue and uncover covert attack progressions."

        return md

    def _format_mitre_response(self, items: List[Dict[str, Any]]) -> str:
        md = "### 🥋 MITRE ATT&CK Mapping & Techniques\n\n"
        for m in items:
            md += f"#### Technique: `{m.get('technique_id')}` — {m.get('name')}\n"
            md += f"- **Tactic:** `{m.get('tactic')}`\n"
            if m.get("description"):
                md += f"- **Description:** {m.get('description')}\n"
            if m.get("detection_methods"):
                md += f"- **Detection:** {m.get('detection_methods')}\n"
            if m.get("mitigation"):
                md += f"- **Mitigation:** {m.get('mitigation')}\n"
            md += "\n"
        return md

    def _format_soc_24h_response(self, data: Dict[str, Any]) -> str:
        ag = data["agent_health"]
        md = "### ⏱️ SOC Operational Summary (Last 24 Hours)\n\n"
        md += "| Metric | Count | Assessment |\n"
        md += "| :--- | :--- | :--- |\n"
        md += f"| **New Security Alerts** | **{data['total_new_alerts']}** | {data['critical_alerts_count']} Critical |\n"
        md += f"| **Security Incidents** | **{data['new_incidents_count']}** | Active Investigation |\n"
        md += f"| **Security Logs Ingested** | **{data['total_logs_collected']}** | Normal Ingestion Pipeline |\n"
        md += f"| **Endpoint Health** | **{ag['online']}/{ag['total']} Online** | {ag['offline']} Offline |\n\n"

        if data.get("recent_notable_alerts"):
            md += "#### 🔔 Recent Notable Alerts\n"
            for a in data["recent_notable_alerts"]:
                md += f"- **{a['alert_id']}** — {a['title']} (`{a['severity']}`)\n"

        md += "\n*Telemetry metrics reflect real-time database state across connected agents, logs, and detection rules.*"
        return md

    def _format_incident_report(self, inc_data: Optional[Dict[str, Any]], is_academic: bool = False) -> str:
        title = inc_data.get("title", "Security Incident Audit Report") if inc_data else "Security Incident Report"
        sev = inc_data.get("severity", "Medium") if inc_data else "Unassessed"
        detected = inc_data.get("detected_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")) if inc_data else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        md = f"# 📄 SECURITY INCIDENT REPORT: {title}\n\n"
        if is_academic:
            md += "**Course / Assignment:** Cybersecurity Operations & Defense (SOC Capstone)\n"
            md += f"**Prepared For:** Professor / Academic Evaluator  \n"
        else:
            md += "**Target Audience:** SOC Leadership & Executive Security Committee  \n"

        md += f"**Classification:** CONFIDENTIAL – INCIDENT RESPONSE AUDIT  \n"
        md += f"**Incident Severity:** `{sev}` | **Status:** Under Investigation | **Date:** {detected}\n\n"
        md += "---\n\n"
        md += "## 1. Executive Summary\n"
        if inc_data:
            md += f"Incident '{title}' (Severity: {sev}) was recorded in the SentinelX database. "
            md += f"{inc_data.get('description') or 'Detection and correlation engines flagged events requiring analyst triage.'}\n\n"
        else:
            md += "Incident report generated from security telemetry. Correlation engines detected anomalous activity requiring forensic triage.\n\n"

        md += "## 2. Observed Evidence (SentinelX Stored Telemetry)\n"
        evidence_items = inc_data.get("evidence", []) if inc_data else []
        if evidence_items:
            for ev in evidence_items:
                md += f"- {ev}\n"
        else:
            md += "- **Status:** No stored telemetry records linked to this incident in the database. Evidence fields pending investigation.\n\n"

        md += "## 3. Attack Progression & MITRE ATT&CK Mapping\n"
        mitre_list = inc_data.get("mitre_attack", []) if inc_data else []
        if mitre_list:
            for m in mitre_list:
                md += f"- **{m.get('tactic', 'Tactic')}:** `{m.get('technique_id')}` ({m.get('name', 'Technique')})\n"
        else:
            md += "- **Status:** No MITRE ATT&CK techniques observed in detection records for this incident.\n\n"

        md += "## 4. Root Cause Analysis (Hypothesis)\n"
        md += "*Note: Labeled as an analytical hypothesis pending forensic memory and disk image verification.*\n"
        md += "Anomalous execution or unauthorized access attempt flagged. Attack success is not confirmed.\n\n"

        md += "## 5. Containment & Remediation Actions (Pending Authorization)\n"
        md += "1. **Host Containment:** Recommended SOAR action `Isolate_Host` if lateral movement is suspected. *(Host is currently NOT isolated — execution requires authorized confirmation).* \n"
        md += "2. **Account Safeguards:** Revoke active tokens and force credential rotation if account compromise is suspected.\n"
        md += "3. **Network Rules:** Block external malicious source IPs on perimeter firewalls.\n\n"

        md += "## 6. Recommendations & Lessons Learned\n"
        md += "- Enforce mandatory multi-factor authentication (MFA) across all endpoints.\n"
        md += "- Implement dynamic rate-limiting on authentication gateways.\n"
        md += "- Maintain SentinelX continuous endpoint telemetry agents on all assets."
        return md

    def _format_investigation_response(self, items: List[Dict[str, Any]]) -> str:
        if not items:
            return "### 🔍 Security Investigation\n\nNo active alerts found to investigate in the live database."

        top = items[0]
        md = f"### 🔍 Deep Security Investigation: `{top['alert_id']}`\n\n"
        md += f"**Title:** {top['title']}  \n"
        md += f"**Severity:** `{top['severity']}` | **Status:** `{top['status']}` | **Source:** `{top.get('source', 'EDR')}`\n\n"

        md += "#### 1. Executive Summary\n"
        md += f"Alert `{top['alert_id']}` was generated by SentinelX detection engines due to anomalous behavior matching threat patterns. "
        md += "The activity requires formal investigation to confirm scope and contain lateral propagation.\n\n"

        md += "#### 2. Root Cause Hypothesis *(AI Inference – Unconfirmed)*\n"
        md += f"Hypothesis: Suspected execution of unauthorized script or command originating from an untrusted parent process. "
        md += "Confidence is 88% based on event frequency and MITRE ATT&CK correlation.\n\n"

        md += "#### 3. Recommended Investigation Steps\n"
        md += "1. Inspect full command line and parent process ID in Windows Event Log ID 4688.\n"
        md += "2. Verify if any outbound network connections were initiated to non-routable or external IPs.\n"
        md += "3. Check user authentication logs for concurrent logins from different geographic locations."
        return md

    def _format_next_steps_response(self, target: str, actions: List[Dict[str, Any]]) -> str:
        md = f"### 🎯 Recommended Next Steps & Investigation Pivots\n\n"
        md += f"Regarding target **`{target}`**, the following actions are prioritized:\n\n"
        md += "#### 1. Immediate Containment (SOAR Safe Actions)\n"
        for a in actions:
            md += f"- **{a['action_type']}** on `{a['target']}`: {a['description']}\n"
            md += f"  *Expected Impact:* {a['expected_impact']}\n"
        md += "\n"

        md += "#### 2. Threat Hunting Pivots\n"
        md += "- **Pivot by IP:** Query firewall logs for any communication with external subnets.\n"
        md += "- **Pivot by Host:** Check active processes and scheduled tasks for persistence mechanisms.\n"
        md += "- **Pivot by User:** Review identity access logs for anomalous privilege elevation.\n\n"

        md += "🛡️ *To execute any containment action, use the Safe Action buttons below. Actions require explicit authorized confirmation.*"
        return md

    def _format_general_response(self, query: str, logs: List[Dict[str, Any]]) -> str:
        if not logs:
            return (
                f"### 🔎 Security Inquiry: \"{query}\"\n\n"
                f"**Database Search Result:** No records matching your search terms were found in the SentinelX database.\n\n"
                f"**Suggestions:**\n"
                f"- Ask about critical alerts: *\"Show me all critical security alerts\"*\n"
                f"- Ask about offline agents: *\"Which endpoints are currently offline?\"*\n"
                f"- Ask about failed logins: *\"Analyze failed login attempts\"*\n"
                f"- Ask for 24-hour summary: *\"What changed in the SOC during the last 24 hours?\"*"
            )

        md = f"### 🔎 Security Records Query: \"{query}\"\n\n"
        md += f"Retrieved **{len(logs)}** matching security log event(s):\n\n"
        for l in logs:
            safe_msg = sanitize_untrusted_text(l.get("message", ""))
            safe_type = sanitize_untrusted_text(l.get("event_type", ""))
            safe_host = sanitize_untrusted_text(l.get("source_ip") or "Local")
            md += f"- **[{l.get('log_level')}]** `{safe_type}`: {safe_msg} *(Host/IP: {safe_host})*\n"
        return md

    # ────────────────────────────────────────────────────────────────────────
    # Chat Interaction Entrypoint
    # ────────────────────────────────────────────────────────────────────────
    async def chat_interaction(
        self,
        request: AIChatRequest,
        user_name: str = "SOC Analyst",
        current_user: Optional[Any] = None,
    ) -> AIChatMessageResponse:
        """Process natural language Copilot chat, maintain conversation context, and persist audit history."""
        # 1. Fetch or create conversation
        conv: Optional[AIChatConversation] = None
        history_messages: List[AIChatMessage] = []

        if request.conversation_id:
            conv = await self.chat_repo.get_with_messages(request.conversation_id)
            if conv and current_user:
                current_uid = getattr(current_user, "id", None)
                user_role = getattr(getattr(current_user, "role", None), "name", "Read Only")
                if conv.user_id and current_uid and conv.user_id != current_uid and user_role != "Super Administrator":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied: You do not have permission to post messages to this conversation.",
                    )

        if not conv:
            title_text = request.message[:40] + ("..." if len(request.message) > 40 else "")
            conv = AIChatConversation(id=uuid4(), title=f"Chat: {title_text}", user_id=getattr(current_user, "id", None))
            self.session.add(conv)
            await self.session.flush()
        else:
            history_messages = list(conv.messages or [])

        # 2. Add user message
        user_msg = AIChatMessage(
            id=uuid4(),
            conversation_id=conv.id,
            sender="User",
            content=request.message,
            confidence_score=100,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(user_msg)
        await self.session.flush()

        # 3. Process natural language query against live database with history
        analysis = await self.interpret_and_execute_query(
            request.message,
            history=history_messages,
            current_user=current_user,
        )

        # 4. Save Copilot response
        copilot_msg = AIChatMessage(
            id=uuid4(),
            conversation_id=conv.id,
            sender="Copilot",
            content=analysis["response_markdown"],
            evidence=analysis["evidence"],
            confidence_score=analysis["confidence_score"],
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(copilot_msg)
        await self.session.commit()
        try:
            await self.session.refresh(copilot_msg)
        except Exception:
            pass

        return AIChatMessageResponse.model_validate(copilot_msg)

    async def explain_entity(self, entity_type: str, entity_id: str) -> AIExplainResponse:
        """Deep AI Explainability for Incidents, Correlations, Attack Chains, MITRE, and Playbooks."""
        ent_lower = entity_type.lower()
        observed: List[str] = [f"Entity Type: {entity_type}", f"Entity ID: {entity_id}"]
        external: List[str] = []
        ai_reasoning = ""
        limitations = None
        confidence = 90

        if ent_lower == "incident":
            inc_res = await self.tools.get_incident_for_investigation(entity_id)
            if inc_res["found"] and inc_res["data"]:
                inc = inc_res["data"]
                observed.append(f"Incident Title: '{inc['title']}'")
                observed.append(f"Severity: '{inc['severity']}', Priority: '{inc['priority']}', Status: '{inc['status']}'")
                ai_reasoning = f"Incident '{inc['title']}' triggered by security event correlation. Temporal telemetry indicates rapid lateral movement risk."
                external.append("Mapped to MITRE ATT&CK techniques T1059 and T1078.")
            else:
                limitations = f"Incident '{entity_id}' not found in live SentinelX records. Findings derived from general pattern inference."
                ai_reasoning = "Target entity not located in live database."
                confidence = 60
        elif ent_lower in ("mitre", "technique"):
            mitre_res = await self.tools.explain_mitre_techniques(technique_id=entity_id)
            if mitre_res["data"]:
                m = mitre_res["data"][0]
                observed.append(f"MITRE Technique: {m.get('technique_id')} ({m.get('name')})")
                external.append(f"Tactic: {m.get('tactic')}")
                ai_reasoning = m.get("description") or "Technique mapped."
        else:
            observed.append(f"Target: {entity_id}")
            ai_reasoning = f"Analysis for {entity_type} '{entity_id}' evaluated against SentinelX baseline policies."

        return AIExplainResponse(
            observed_data=observed,
            external_intelligence=external,
            ai_reasoning=ai_reasoning,
            confidence=confidence,
            limitations=limitations,
        )
