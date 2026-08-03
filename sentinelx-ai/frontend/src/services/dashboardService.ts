import apiClient from "./apiClient";

export interface DashboardSummary {
  active_threats_count: number;
  critical_alerts_count: number;
  open_incidents_count: number;
  asset_count: number;
  vulnerability_count: number;
  current_risk_score: number;
  system_status: string;
}

export interface ActivityItemApi {
  id: string;
  name: string;
  severity: string;
  source_ip: string;
  target_asset: string;
  mitre_id: string;
  status: string;
  detected_at: string;
}

export interface DashboardStatistics {
  timeline: { time: string; threats: number; alerts: number; incidents: number }[];
  severity_distribution: { name: string; value: number; color: string }[];
  top_attacker_ips: { ip: string; country: string; attempts: number; threatScore: number }[];
}

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  const response = await apiClient.get<DashboardSummary>("/dashboard/summary");
  return response.data;
}

export async function fetchDashboardStatistics(): Promise<DashboardStatistics> {
  const response = await apiClient.get<DashboardStatistics>("/dashboard/statistics");
  return response.data;
}

export async function fetchRecentActivity(): Promise<ActivityItemApi[]> {
  const response = await apiClient.get<ActivityItemApi[]>("/dashboard/recent-activity");
  return response.data;
}
