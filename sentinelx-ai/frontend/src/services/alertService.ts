/**
 * SentinelX AI – Alert Service (Phase 6.4)
 * API client functions for the real-time SOC security alert system.
 */

import apiClient from "./apiClient";
import type {
  SecurityAlert,
  SecurityAlertListResponse,
  SecurityAlertStatistics,
  SecurityAlertSummary,
  AlertAcknowledgeRequest,
  AlertInvestigateRequest,
  AlertResolveRequest,
  AlertDismissRequest,
} from "../types/alert";

// ── Query Parameter Interfaces ────────────────────────────────────────────────

export interface AlertListParams {
  page?: number;
  page_size?: number;
  severity?: string;
  status?: string;
  alert_type?: string;
  agent_id?: string;
  search?: string;
  since?: string;
  until?: string;
}

// ── Read Operations ───────────────────────────────────────────────────────────

/**
 * Fetch paginated security alerts with optional filters.
 */
export async function getAlerts(
  params: AlertListParams = {}
): Promise<SecurityAlertListResponse> {
  const { data } = await apiClient.get<SecurityAlertListResponse>(
    "/api/v1/alerts",
    { params }
  );
  return data;
}

/**
 * Fetch full details for a single security alert by UUID.
 */
export async function getAlert(alertUuid: string): Promise<SecurityAlert> {
  const { data } = await apiClient.get<SecurityAlert>(
    `/api/v1/alerts/${alertUuid}`
  );
  return data;
}

/**
 * Fetch aggregate statistics for the SOC dashboard.
 */
export async function getAlertStatistics(): Promise<SecurityAlertStatistics> {
  const { data } = await apiClient.get<SecurityAlertStatistics>(
    "/api/v1/alerts/statistics"
  );
  return data;
}

/**
 * Fetch the most recent N security alerts for live feed.
 */
export async function getRecentAlerts(
  limit = 20
): Promise<SecurityAlertSummary[]> {
  const { data } = await apiClient.get<SecurityAlertSummary[]>(
    "/api/v1/alerts/recent",
    { params: { limit } }
  );
  return data;
}

// ── Status Transitions ────────────────────────────────────────────────────────

/**
 * Acknowledge a security alert (marks it as seen by an analyst).
 */
export async function acknowledgeAlert(
  alertUuid: string,
  body: AlertAcknowledgeRequest = {}
): Promise<SecurityAlert> {
  const { data } = await apiClient.post<SecurityAlert>(
    `/api/v1/alerts/${alertUuid}/acknowledge`,
    body
  );
  return data;
}

/**
 * Move alert to INVESTIGATING status.
 */
export async function investigateAlert(
  alertUuid: string,
  body: AlertInvestigateRequest = {}
): Promise<SecurityAlert> {
  const { data } = await apiClient.post<SecurityAlert>(
    `/api/v1/alerts/${alertUuid}/investigate`,
    body
  );
  return data;
}

/**
 * Resolve a security alert.
 */
export async function resolveAlert(
  alertUuid: string,
  body: AlertResolveRequest = {}
): Promise<SecurityAlert> {
  const { data } = await apiClient.post<SecurityAlert>(
    `/api/v1/alerts/${alertUuid}/resolve`,
    body
  );
  return data;
}

/**
 * Dismiss a security alert as false positive or known benign.
 */
export async function dismissAlert(
  alertUuid: string,
  body: AlertDismissRequest = {}
): Promise<SecurityAlert> {
  const { data } = await apiClient.post<SecurityAlert>(
    `/api/v1/alerts/${alertUuid}/dismiss`,
    body
  );
  return data;
}
