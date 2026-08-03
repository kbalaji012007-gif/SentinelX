/**
 * SentinelX AI – Threat Detection TypeScript Types
 * Aligned with backend Pydantic schemas for Threat, Alert, and IOC.
 */

// ────────────────────────────────────────────────────────────────────────
// Enums
// ────────────────────────────────────────────────────────────────────────

export type ThreatSeverity = "Critical" | "High" | "Medium" | "Low";
export type ThreatStatus = "New" | "Investigating" | "Mitigated" | "Closed";
export type IOCType = "IP" | "Domain" | "URL" | "Hash" | "Email";

// ────────────────────────────────────────────────────────────────────────
// Alert
// ────────────────────────────────────────────────────────────────────────

export interface Alert {
  id: string;
  threat_id: string;
  alert_name: string;
  alert_type: string | null;
  alert_source: string | null;
  severity: ThreatSeverity;
  message: string | null;
  raw_event: Record<string, unknown>;
  acknowledged: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertCreate {
  threat_id: string;
  alert_name: string;
  alert_type?: string;
  alert_source?: string;
  severity?: ThreatSeverity;
  message?: string;
  raw_event?: Record<string, unknown>;
  acknowledged?: boolean;
}

// ────────────────────────────────────────────────────────────────────────
// IOC
// ────────────────────────────────────────────────────────────────────────

export interface IOC {
  id: string;
  threat_id: string;
  type: IOCType;
  value: string;
  reputation: string | null;
  confidence: number | null;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string;
  updated_at: string;
}

export interface IOCCreate {
  threat_id: string;
  type: IOCType;
  value: string;
  reputation?: string;
  confidence?: number;
  first_seen?: string;
  last_seen?: string;
}

// ────────────────────────────────────────────────────────────────────────
// Threat
// ────────────────────────────────────────────────────────────────────────

export interface ThreatSummary {
  id: string;
  asset_id: string | null;
  title: string;
  severity: ThreatSeverity;
  confidence_score: number | null;
  status: ThreatStatus;
  source: string | null;
  mitre_technique_id: string | null;
  detected_at: string;
  created_at: string;
  updated_at: string;
}

export interface Threat extends ThreatSummary {
  description: string | null;
  alerts: Alert[];
  iocs: IOC[];
}

export interface ThreatCreate {
  asset_id?: string;
  title: string;
  description?: string;
  severity?: ThreatSeverity;
  confidence_score?: number;
  status?: ThreatStatus;
  source?: string;
  mitre_technique_id?: string;
  detected_at: string;
}

export interface ThreatUpdate {
  asset_id?: string;
  title?: string;
  description?: string;
  severity?: ThreatSeverity;
  confidence_score?: number;
  status?: ThreatStatus;
  source?: string;
  mitre_technique_id?: string;
  detected_at?: string;
}

// ────────────────────────────────────────────────────────────────────────
// Paginated List
// ────────────────────────────────────────────────────────────────────────

export interface ThreatListResponse {
  total: number;
  page: number;
  page_size: number;
  items: ThreatSummary[];
}

export interface ThreatStatsResponse {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
}

// ────────────────────────────────────────────────────────────────────────
// Query Params
// ────────────────────────────────────────────────────────────────────────

export interface ThreatListParams {
  page?: number;
  page_size?: number;
  severity?: ThreatSeverity | "";
  status?: ThreatStatus | "";
  search?: string;
  asset_id?: string;
}
