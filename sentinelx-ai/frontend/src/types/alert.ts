/**
 * SentinelX AI – Security Alert TypeScript Types (Phase 6.4)
 * Matches backend SecurityAlert ORM model and Pydantic schemas.
 */

// ── Enumerations ──────────────────────────────────────────────────────────────

export type AlertSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type AlertStatus =
  | "NEW"
  | "ACKNOWLEDGED"
  | "INVESTIGATING"
  | "RESOLVED"
  | "DISMISSED";
export type AlertType =
  | "failed_login"
  | "account_lockout"
  | "suspicious_process"
  | "malware_detected"
  | "network_anomaly"
  | "data_exfiltration"
  | "privilege_escalation"
  | "lateral_movement"
  | "ransomware"
  | "test_event"
  | string;

// ── Core Model ────────────────────────────────────────────────────────────────

export interface SecurityAlert {
  id: string;
  alert_id: string;
  title: string;
  description: string | null;
  alert_type: AlertType;
  severity: AlertSeverity;
  status: AlertStatus;
  source: string | null;
  agent_id: string | null;
  log_id: string | null;
  threat_id: string | null;
  incident_id: string | null;
  correlation_id: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  evidence: Record<string, unknown>;
  alert_metadata: Record<string, unknown>;
  detected_at: string; // ISO 8601
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecurityAlertSummary {
  id: string;
  alert_id: string;
  title: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  status: AlertStatus;
  source: string | null;
  agent_id: string | null;
  hostname: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  detected_at: string;
  updated_at: string;
  occurrence_count: number;
}

export interface SecurityAlertListResponse {
  total: number;
  page: number;
  page_size: number;
  items: SecurityAlertSummary[];
}

export interface SecurityAlertStatistics {
  total_alerts: number;
  new_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  alerts_today: number;
  active_investigations: number;
  resolved_today: number;
  acknowledged_alerts: number;
  dismissed_alerts: number;
}

// ── Real-Time WebSocket Event ─────────────────────────────────────────────────

export interface RealtimeEvent {
  event: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

// Alert-specific broadcast payloads
export interface AlertCreatedPayload {
  id: string;
  alert_id: string;
  title: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  status: AlertStatus;
  source: string | null;
  hostname: string | null;
  agent_id: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  detected_at: string;
  occurrence_count: number;
}

export interface TelemetryReceivedPayload {
  agent_id: string;
  hostname: string;
  event_count: number;
  event_types: string[];
}

export interface EndpointStatusPayload {
  agent_id: string;
  hostname: string;
  old_status: string;
  new_status: string;
}

// ── Alert Action Request Payloads ─────────────────────────────────────────────

export interface AlertAcknowledgeRequest {
  notes?: string;
}

export interface AlertInvestigateRequest {
  notes?: string;
}

export interface AlertResolveRequest {
  resolution_notes?: string;
}

export interface AlertDismissRequest {
  reason?: string;
}

// ── UI Helpers ────────────────────────────────────────────────────────────────

export const SEVERITY_ORDER: Record<AlertSeverity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

export const SEVERITY_COLORS: Record<AlertSeverity, string> = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
};

export const STATUS_COLORS: Record<AlertStatus, string> = {
  NEW:           "#60a5fa",
  ACKNOWLEDGED:  "#a78bfa",
  INVESTIGATING: "#f59e0b",
  RESOLVED:      "#22c55e",
  DISMISSED:     "#6b7280",
};
