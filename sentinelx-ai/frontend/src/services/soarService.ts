import apiClient from "./apiClient";

export interface PlaybookStep {
  id?: string;
  step_order: number;
  step_name: string;
  action_type: string;
  target_type: string;
  parameters: Record<string, any>;
  requires_approval: boolean;
}

export interface SOARPlaybook {
  id: string;
  name: string;
  description?: string | null;
  trigger_type: string;
  category: string;
  is_active: boolean;
  author: string;
  steps: PlaybookStep[];
  created_at: string;
  updated_at: string;
}

export interface PlaybookListResponse {
  total: number;
  page: number;
  page_size: number;
  items: SOARPlaybook[];
}

export interface SOARRule {
  id: string;
  rule_name: string;
  trigger_event: string;
  condition_logic: Record<string, any>;
  playbook_id?: string | null;
  is_active: boolean;
  description?: string | null;
  execution_count: number;
  created_at: string;
}

export interface RuleListResponse {
  total: number;
  page: number;
  page_size: number;
  items: SOARRule[];
}

export interface ExecutionLog {
  id: string;
  execution_id: string;
  step_id?: string | null;
  log_level: string;
  message: string;
  output_data: Record<string, any>;
  created_at: string;
}

export interface SOARExecution {
  id: string;
  playbook_id?: string | null;
  rule_id?: string | null;
  trigger_source: string;
  status: "Pending_Approval" | "In_Progress" | "Completed" | "Failed" | "Rejected";
  started_at: string;
  completed_at?: string | null;
  execution_metadata: Record<string, any>;
  logs: ExecutionLog[];
  created_at: string;
}

export interface ExecutionListResponse {
  total: number;
  page: number;
  page_size: number;
  items: SOARExecution[];
}

export interface SOARApprovalRequest {
  id: string;
  execution_id: string;
  step_id?: string | null;
  status: "Pending" | "Approved" | "Rejected";
  requested_by: string;
  approved_by?: string | null;
  reason?: string | null;
  requested_at: string;
  decided_at?: string | null;
}

export interface ApprovalListResponse {
  total: number;
  page: number;
  page_size: number;
  items: SOARApprovalRequest[];
}

export interface ConnectorStatus {
  id: string;
  connector_name: string;
  connector_type: string;
  status: "Online" | "Offline" | "Degraded" | "Unavailable";
  last_heartbeat: string;
  details: Record<string, any>;
}

export interface ConnectorListResponse {
  total: number;
  items: ConnectorStatus[];
}

export interface NotificationLog {
  id: string;
  channel: string;
  recipient: string;
  subject?: string | null;
  message_body: string;
  status: string;
  created_at: string;
}

export interface NotificationListResponse {
  total: number;
  page: number;
  page_size: number;
  items: NotificationLog[];
}

export interface ExecutionStep {
  id: string;
  execution_id: string;
  step_id?: string | null;
  step_name: string;
  action_type: string;
  status: string;
  is_dry_run: boolean;
  parameters: Record<string, any>;
  created_at: string;
}

export interface ExecutionStepListResponse {
  total: number;
  items: ExecutionStep[];
}

export interface SOARMetricsResponse {
  running_playbooks: number;
  successful_executions: number;
  failed_executions: number;
  average_execution_time_ms: number;
  connector_health: Record<string, number>;
  notifications_sent: number;
  rollbacks_performed: number;
  pending_approvals: number;
}

export interface SOARStatsResponse {
  total_playbooks: number;
  active_rules: number;
  pending_approvals: number;
  executions_today: number;
  successful_executions: number;
  failed_executions: number;
  by_category: Record<string, number>;
}

// ── API Service Functions ─────────────────────────────────────────

export async function fetchPlaybooks(params?: any): Promise<PlaybookListResponse> {
  const { data } = await apiClient.get<PlaybookListResponse>("/soar/playbooks", { params });
  return data;
}

export async function fetchPlaybookById(id: string): Promise<SOARPlaybook> {
  const { data } = await apiClient.get<SOARPlaybook>(`/soar/playbooks/${id}`);
  return data;
}

export async function createPlaybook(payload: any): Promise<SOARPlaybook> {
  const { data } = await apiClient.post<SOARPlaybook>("/soar/playbooks", payload);
  return data;
}

export async function executePlaybook(id: string, isDryRun = false, parameters: Record<string, any> = {}): Promise<SOARExecution> {
  const { data } = await apiClient.post<SOARExecution>(`/soar/playbooks/${id}/execute`, {
    is_dry_run: isDryRun,
    parameters,
  });
  return data;
}

export async function cancelExecution(id: string): Promise<SOARExecution> {
  const { data } = await apiClient.post<SOARExecution>(`/soar/executions/${id}/cancel`);
  return data;
}

export async function resumeExecution(id: string): Promise<SOARExecution> {
  const { data } = await apiClient.post<SOARExecution>(`/soar/executions/${id}/resume`);
  return data;
}

export async function rollbackStep(executionId: string, stepId: string): Promise<ExecutionStep> {
  const { data } = await apiClient.post<ExecutionStep>(`/soar/executions/${executionId}/rollback`, null, {
    params: { step_id: stepId },
  });
  return data;
}

export async function fetchExecutionSteps(executionId: string): Promise<ExecutionStepListResponse> {
  const { data } = await apiClient.get<ExecutionStepListResponse>(`/soar/executions/${executionId}/steps`);
  return data;
}

export async function fetchSOARRules(params?: any): Promise<RuleListResponse> {
  const { data } = await apiClient.get<RuleListResponse>("/soar/rules", { params });
  return data;
}

export async function fetchSOARExecutions(params?: any): Promise<ExecutionListResponse> {
  const { data } = await apiClient.get<ExecutionListResponse>("/soar/executions", { params });
  return data;
}

export async function approveExecution(id: string, reason?: string): Promise<SOARExecution> {
  const { data } = await apiClient.post<SOARExecution>(`/soar/executions/${id}/approve`, { reason });
  return data;
}

export async function rejectExecution(id: string, reason?: string): Promise<SOARExecution> {
  const { data } = await apiClient.post<SOARExecution>(`/soar/executions/${id}/reject`, { reason });
  return data;
}

export async function fetchSOARApprovals(params?: any): Promise<ApprovalListResponse> {
  const { data } = await apiClient.get<ApprovalListResponse>("/soar/approvals", { params });
  return data;
}

export async function fetchConnectorsStatus(): Promise<ConnectorListResponse> {
  const { data } = await apiClient.get<ConnectorListResponse>("/soar/connectors");
  return data;
}

export async function fetchNotificationLogs(params?: any): Promise<NotificationListResponse> {
  const { data } = await apiClient.get<NotificationListResponse>("/soar/notifications", { params });
  return data;
}

export async function fetchSOARMetrics(): Promise<SOARMetricsResponse> {
  const { data } = await apiClient.get<SOARMetricsResponse>("/soar/metrics");
  return data;
}

export async function fetchSOARStats(): Promise<SOARStatsResponse> {
  const { data } = await apiClient.get<SOARStatsResponse>("/soar/statistics");
  return data;
}
