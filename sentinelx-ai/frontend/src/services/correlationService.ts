import apiClient from "./apiClient";

export interface ThreatCorrelation {
  id: string;
  title: string;
  correlation_type: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  risk_score: number;
  confidence_score: number;
  evidence: Record<string, any>;
  asset_id?: string | null;
  incident_id?: string | null;
  threat_id?: string | null;
  ioc_value?: string | null;
  rule_id?: string | null;
  correlation_metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface ThreatCorrelationListResponse {
  total: number;
  page: number;
  page_size: number;
  items: ThreatCorrelation[];
}

export interface AttackChainStage {
  stage_order: number;
  stage_name: string;
  mitre_technique_id?: string | null;
  tactic?: string | null;
  description?: string | null;
  timestamp?: string | null;
  evidence_snippet?: Record<string, any>;
}

export interface AttackChain {
  id: string;
  chain_name: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  overall_risk_score: number;
  overall_confidence_score: number;
  entry_point?: string | null;
  target_asset_id?: string | null;
  stages_json: AttackChainStage[];
  status: string;
  created_at: string;
  updated_at: string;
}

export interface AttackChainListResponse {
  total: number;
  page: number;
  page_size: number;
  items: AttackChain[];
}

export interface MitreMapping {
  id: string;
  entity_type: string;
  entity_id: string;
  technique_id: string;
  tactic: string;
  confidence_score: number;
  evidence: Record<string, any>;
  created_at: string;
}

export interface MitreMappingListResponse {
  total: number;
  page: number;
  page_size: number;
  items: MitreMapping[];
}

export interface CorrelationRunResponse {
  correlations_generated: number;
  attack_chains_created: number;
  mitre_mappings_added: number;
  execution_time_seconds: number;
  message: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: "Asset" | "Threat" | "Incident" | "IOC" | "Log" | "MITRE";
  severity?: string | null;
  details: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  confidence_score: number;
}

export interface CorrelationGraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TimelineEvent {
  id: string;
  title: string;
  correlation_type: string;
  severity: string;
  risk_score: number;
  confidence_score: number;
  timestamp: string;
  evidence_summary: string;
}

export interface CorrelationTimelineResponse {
  total: number;
  events: TimelineEvent[];
}

export interface CorrelationStatsResponse {
  total_correlations: number;
  critical_correlations: number;
  high_correlations: number;
  active_attack_chains: number;
  total_mitre_mappings: number;
  avg_risk_score: number;
  avg_confidence_score: number;
  by_type: Record<string, number>;
}

// ── API Service Functions ─────────────────────────────────────────

export async function fetchCorrelations(params?: any): Promise<ThreatCorrelationListResponse> {
  const { data } = await apiClient.get<ThreatCorrelationListResponse>("/correlation", { params });
  return data;
}

export async function fetchCorrelationById(id: string): Promise<ThreatCorrelation> {
  const { data } = await apiClient.get<ThreatCorrelation>(`/correlation/${id}`);
  return data;
}

export async function runCorrelationEngine(timeWindowHours = 24, minConfidence = 50): Promise<CorrelationRunResponse> {
  const { data } = await apiClient.post<CorrelationRunResponse>("/correlation/run", {
    time_window_hours: timeWindowHours,
    min_confidence: minConfidence,
  });
  return data;
}

export async function fetchCorrelationStats(): Promise<CorrelationStatsResponse> {
  const { data } = await apiClient.get<CorrelationStatsResponse>("/correlation/statistics");
  return data;
}

export async function fetchCorrelationTimeline(limit = 50): Promise<CorrelationTimelineResponse> {
  const { data } = await apiClient.get<CorrelationTimelineResponse>("/correlation/timeline", { params: { limit } });
  return data;
}

export async function fetchCorrelationGraph(): Promise<CorrelationGraphResponse> {
  const { data } = await apiClient.get<CorrelationGraphResponse>("/correlation/graph");
  return data;
}

export async function fetchMitreMappings(params?: any): Promise<MitreMappingListResponse> {
  const { data } = await apiClient.get<MitreMappingListResponse>("/correlation/mitre", { params });
  return data;
}

export async function fetchAttackChains(params?: any): Promise<AttackChainListResponse> {
  const { data } = await apiClient.get<AttackChainListResponse>("/correlation/attack-chain/list", { params });
  return data;
}

export async function fetchAttackChainById(id: string): Promise<AttackChain> {
  const { data } = await apiClient.get<AttackChain>(`/correlation/attack-chain/${id}`);
  return data;
}
