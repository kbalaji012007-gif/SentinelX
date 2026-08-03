/**
 * SentinelX AI – Incident Response TypeScript Types
 * Aligned with backend Pydantic schemas for Incidents, Timeline, Notes, Evidence, and Stats.
 */

export type IncidentSeverity = "Critical" | "High" | "Medium" | "Low";
export type IncidentPriority = "P0" | "P1" | "P2" | "P3" | "P4";
export type IncidentStatus = "Open" | "In Progress" | "Contained" | "Resolved" | "Closed";

export interface IncidentTimelineEvent {
  id: string;
  incident_id: string;
  event_type: string;
  description: string;
  created_by: string | null;
  created_at: string;
}

export interface IncidentNote {
  id: string;
  incident_id: string;
  author_id: string | null;
  note: string;
  created_at: string;
}

export interface IncidentEvidence {
  id: string;
  incident_id: string;
  evidence_name: string;
  evidence_type: string | null;
  file_path: string;
  uploaded_by: string | null;
  uploaded_at: string;
}

export interface IncidentSummary {
  id: string;
  threat_id: string | null;
  title: string;
  severity: IncidentSeverity;
  priority: IncidentPriority;
  status: IncidentStatus;
  assigned_user_id: string | null;
  reported_by: string | null;
  detected_at: string;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Incident extends IncidentSummary {
  description: string | null;
  assigned_user?: { id: string; first_name: string; last_name: string; email: string } | null;
  timeline_events: IncidentTimelineEvent[];
  notes: IncidentNote[];
  evidence: IncidentEvidence[];
}

export interface IncidentCreate {
  threat_id?: string;
  title: string;
  description?: string;
  severity?: IncidentSeverity;
  priority?: IncidentPriority;
  status?: IncidentStatus;
  assigned_user_id?: string;
  reported_by?: string;
  detected_at: string;
}

export interface IncidentUpdate {
  threat_id?: string;
  title?: string;
  description?: string;
  severity?: IncidentSeverity;
  priority?: IncidentPriority;
  status?: IncidentStatus;
  assigned_user_id?: string;
  reported_by?: string;
  detected_at?: string;
  resolved_at?: string;
}

export interface IncidentListParams {
  page?: number;
  page_size?: number;
  severity?: IncidentSeverity | "";
  priority?: IncidentPriority | "";
  status?: IncidentStatus | "";
  assigned_user_id?: string;
  search?: string;
}

export interface IncidentListResponse {
  total: number;
  page: number;
  page_size: number;
  items: IncidentSummary[];
}

export interface IncidentStatsResponse {
  open_incidents_count: number;
  critical_incidents_count: number;
  assigned_to_me_count: number;
  recently_resolved_count: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
}
