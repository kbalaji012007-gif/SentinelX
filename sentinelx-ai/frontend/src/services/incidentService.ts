/**
 * SentinelX AI – Incident Response Frontend Service
 * Axios calls to all incident management API endpoints.
 */

import apiClient from "./apiClient";
import type {
  Incident,
  IncidentCreate,
  IncidentUpdate,
  IncidentListParams,
  IncidentListResponse,
  IncidentStatsResponse,
  IncidentTimelineEvent,
  IncidentNote,
  IncidentEvidence,
} from "../types/incident";

export async function fetchIncidents(
  params: IncidentListParams = {}
): Promise<IncidentListResponse> {
  const query: Record<string, string | number> = {};

  if (params.page) query.page = params.page;
  if (params.page_size) query.page_size = params.page_size;
  if (params.severity) query.severity = params.severity;
  if (params.priority) query.priority = params.priority;
  if (params.status) query.status = params.status;
  if (params.assigned_user_id) query.assigned_user_id = params.assigned_user_id;
  if (params.search) query.search = params.search;

  const response = await apiClient.get<IncidentListResponse>("/incidents", {
    params: query,
  });
  return response.data;
}

export async function fetchIncidentStats(): Promise<IncidentStatsResponse> {
  const response = await apiClient.get<IncidentStatsResponse>("/incidents/stats");
  return response.data;
}

export async function fetchIncidentById(id: string): Promise<Incident> {
  const response = await apiClient.get<Incident>(`/incidents/${id}`);
  return response.data;
}

export async function createIncident(payload: IncidentCreate): Promise<Incident> {
  const response = await apiClient.post<Incident>("/incidents", payload);
  return response.data;
}

export async function updateIncident(
  id: string,
  payload: IncidentUpdate
): Promise<Incident> {
  const response = await apiClient.put<Incident>(`/incidents/${id}`, payload);
  return response.data;
}

export async function deleteIncident(id: string): Promise<void> {
  await apiClient.delete(`/incidents/${id}`);
}

export async function assignAnalyst(
  incidentId: string,
  assignedUserId: string | null
): Promise<Incident> {
  const response = await apiClient.post<Incident>(
    `/incidents/${incidentId}/assign`,
    { assigned_user_id: assignedUserId }
  );
  return response.data;
}

export async function updateIncidentStatus(
  incidentId: string,
  status: string
): Promise<Incident> {
  const response = await apiClient.post<Incident>(
    `/incidents/${incidentId}/status`,
    { status }
  );
  return response.data;
}

export async function addIncidentNote(
  incidentId: string,
  note: string
): Promise<IncidentNote> {
  const response = await apiClient.post<IncidentNote>(
    `/incidents/${incidentId}/notes`,
    { note }
  );
  return response.data;
}

export async function fetchIncidentTimeline(
  incidentId: string
): Promise<IncidentTimelineEvent[]> {
  const response = await apiClient.get<IncidentTimelineEvent[]>(
    `/incidents/${incidentId}/timeline`
  );
  return response.data;
}

export async function fetchIncidentEvidence(
  incidentId: string
): Promise<IncidentEvidence[]> {
  const response = await apiClient.get<IncidentEvidence[]>(
    `/incidents/${incidentId}/evidence`
  );
  return response.data;
}

export async function attachIncidentEvidence(
  incidentId: string,
  payload: { evidence_name: string; evidence_type?: string; file_path: string }
): Promise<IncidentEvidence> {
  const response = await apiClient.post<IncidentEvidence>(
    `/incidents/${incidentId}/evidence`,
    payload
  );
  return response.data;
}
