import apiClient from "./apiClient";

export interface EvidenceSources {
  observed_sentinelx_data: string[];
  external_intelligence: string[];
  ai_inference: string[];
  insufficient_evidence_warning?: string | null;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  explanation?: string;
}

export interface InvestigationResponse {
  id?: string;
  investigation_type: string;
  target_id: string;
  executive_summary: string;
  technical_summary: string;
  root_cause?: string | null;
  mitre_mapping: MitreMapping[];
  severity: string;
  confidence_score: number;
  recommended_actions: string[];
  evidence_sources: EvidenceSources;
  created_at?: string;
}

export interface ThreatHuntResponse {
  id?: string;
  hunt_type: string;
  query_value: string;
  findings_summary: string;
  threat_level: string;
  matched_artifacts: Array<{ artifact: string; details: string }>;
  recommended_playbook_id?: string | null;
  created_at?: string;
}

export interface HighRiskAsset {
  asset_name: string;
  ip_address: string;
  risk_score: number;
  reason: string;
}

export interface PrioritizedAlert {
  alert_id: string;
  title: string;
  severity: string;
  priority_score: number;
}

export interface RiskAssessmentResponse {
  business_risk_score: number;
  severity_prediction: string;
  attack_spread_prediction: string;
  high_risk_assets: HighRiskAsset[];
  prioritized_alerts: PrioritizedAlert[];
}

export interface PlaybookRecommendation {
  playbook_name: string;
  category: string;
  confidence_score: number;
  reason: string;
}

export interface RecommendationResponse {
  playbook_recommendations: PlaybookRecommendation[];
  remediation_recommendations: string[];
  investigation_steps: string[];
  containment_recommendations: string[];
  recovery_recommendations: string[];
}

export interface InvestigationListResponse {
  total: number;
  items: InvestigationResponse[];
}

export interface AIChatMessage {
  id: string;
  conversation_id: string;
  sender: "User" | "Copilot";
  content: string;
  evidence: Record<string, any>;
  confidence_score: number;
  created_at: string;
}

export interface AIExplainResponse {
  observed_data: string[];
  external_intelligence: string[];
  ai_reasoning: string;
  confidence: number;
  limitations?: string | null;
}

export interface AIReportResponse {
  id?: string;
  report_type: string;
  title: string;
  markdown_content: string;
  json_content: Record<string, any>;
  created_by: string;
  created_at?: string;
}

// ── API Functions ─────────────────────────────────────────────

export async function sendCopilotChat(message: string, conversationId?: string): Promise<AIChatMessage> {
  const { data } = await apiClient.post<AIChatMessage>("/ai/chat", {
    message,
    conversation_id: conversationId,
  });
  return data;
}

export async function fetchAIExplanation(entityType: string, entityId: string): Promise<AIExplainResponse> {
  const { data } = await apiClient.post<AIExplainResponse>("/ai/explain", {
    entity_type: entityType,
    entity_id: entityId,
  });
  return data;
}

export async function generateAIReport(reportType: string, title?: string, outputFormat = "markdown"): Promise<AIReportResponse> {
  const { data } = await apiClient.post<AIReportResponse>("/ai/report", {
    report_type: reportType,
    title,
    output_format: outputFormat,
  });
  return data;
}

export async function triggerAIInvestigation(investigationType: string, targetId: string): Promise<InvestigationResponse> {
  const { data } = await apiClient.post<InvestigationResponse>("/ai/investigate", {
    investigation_type: investigationType,
    target_id: targetId,
  });
  return data;
}

export async function executeAIThreatHunt(huntType: string, queryValue: string): Promise<ThreatHuntResponse> {
  const { data } = await apiClient.post<ThreatHuntResponse>("/ai/hunt", {
    hunt_type: huntType,
    query_value: queryValue,
  });
  return data;
}

export async function fetchAIRiskAssessment(): Promise<RiskAssessmentResponse> {
  const { data } = await apiClient.post<RiskAssessmentResponse>("/ai/risk-assessment");
  return data;
}

export async function fetchAIRecommendations(): Promise<RecommendationResponse> {
  const { data } = await apiClient.post<RecommendationResponse>("/ai/recommend");
  return data;
}

export async function fetchAIHistory(page = 1, pageSize = 25): Promise<InvestigationListResponse> {
  const { data } = await apiClient.get<InvestigationListResponse>("/ai/history", {
    params: { page, page_size: pageSize },
  });
  return data;
}

export async function deleteAIHistoryItem(id: string): Promise<void> {
  await apiClient.delete(`/ai/history/${id}`);
}
