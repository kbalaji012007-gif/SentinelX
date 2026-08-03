/**
 * SentinelX AI – Threat Detection Service
 * Axios calls to all threat, alert, and IOC API endpoints.
 */

import apiClient from "./apiClient";
import type {
  Threat,
  ThreatListResponse,
  ThreatListParams,
  ThreatCreate,
  ThreatUpdate,
  ThreatStatsResponse,
  Alert,
  AlertCreate,
  IOC,
  IOCCreate,
} from "../types/threat";

// ────────────────────────────────────────────────────────────────────────
// Threat API
// ────────────────────────────────────────────────────────────────────────

export async function fetchThreats(
  params: ThreatListParams = {}
): Promise<ThreatListResponse> {
  const query: Record<string, string | number> = {};

  if (params.page) query.page = params.page;
  if (params.page_size) query.page_size = params.page_size;
  if (params.severity) query.severity = params.severity;
  if (params.status) query.status = params.status;
  if (params.search) query.search = params.search;
  if (params.asset_id) query.asset_id = params.asset_id;

  const response = await apiClient.get<ThreatListResponse>("/threats", {
    params: query,
  });
  return response.data;
}

export async function fetchThreatById(id: string): Promise<Threat> {
  const response = await apiClient.get<Threat>(`/threats/${id}`);
  return response.data;
}

export async function createThreat(payload: ThreatCreate): Promise<Threat> {
  const response = await apiClient.post<Threat>("/threats", payload);
  return response.data;
}

export async function updateThreat(
  id: string,
  payload: ThreatUpdate
): Promise<Threat> {
  const response = await apiClient.put<Threat>(`/threats/${id}`, payload);
  return response.data;
}

export async function deleteThreat(id: string): Promise<void> {
  await apiClient.delete(`/threats/${id}`);
}

export async function fetchThreatStats(): Promise<ThreatStatsResponse> {
  const response = await apiClient.get<ThreatStatsResponse>("/threats/stats");
  return response.data;
}

// ────────────────────────────────────────────────────────────────────────
// Alert API
// ────────────────────────────────────────────────────────────────────────

export interface AlertListParams {
  threat_id?: string;
  severity?: string;
  acknowledged?: boolean;
  page?: number;
  page_size?: number;
}

export async function fetchAlerts(
  params: AlertListParams = {}
): Promise<Alert[]> {
  const response = await apiClient.get<Alert[]>("/alerts", { params });
  return response.data;
}

export async function createAlert(payload: AlertCreate): Promise<Alert> {
  const response = await apiClient.post<Alert>("/alerts", payload);
  return response.data;
}

export async function acknowledgeAlert(alertId: string): Promise<Alert> {
  const response = await apiClient.patch<Alert>(
    `/alerts/${alertId}/acknowledge`
  );
  return response.data;
}

// ────────────────────────────────────────────────────────────────────────
// IOC API
// ────────────────────────────────────────────────────────────────────────

export interface IOCListParams {
  threat_id?: string;
  type?: string;
  page?: number;
  page_size?: number;
}

export async function fetchIOCs(params: IOCListParams = {}): Promise<IOC[]> {
  const response = await apiClient.get<IOC[]>("/ioc", { params });
  return response.data;
}

export async function createIOC(payload: IOCCreate): Promise<IOC> {
  const response = await apiClient.post<IOC>("/ioc", payload);
  return response.data;
}
