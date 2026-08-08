import apiClient from "./apiClient";
import type {
  EndpointAgentListResponse,
  EndpointAgentStatsResponse,
  EndpointDetailsResponse,
  AgentTelemetryListResponse,
  EndpointAgentResponse,
} from "../types/agent";

export interface FetchAgentsParams {
  page?: number;
  page_size?: number;
  status?: string;
  search?: string;
}

export const fetchAgents = async (params?: FetchAgentsParams): Promise<EndpointAgentListResponse> => {
  const response = await apiClient.get<EndpointAgentListResponse>("/agents", { params });
  return response.data;
};

export const fetchAgentDetails = async (idOrAgentId: string): Promise<EndpointDetailsResponse> => {
  const response = await apiClient.get<EndpointDetailsResponse>(`/agents/${idOrAgentId}`);
  return response.data;
};

export const fetchAgentStatistics = async (): Promise<EndpointAgentStatsResponse> => {
  const response = await apiClient.get<EndpointAgentStatsResponse>("/agents/statistics");
  return response.data;
};

export const fetchAgentTelemetry = async (
  idOrAgentId: string,
  params?: { page?: number; page_size?: number; event_type?: string; severity?: string }
): Promise<AgentTelemetryListResponse> => {
  const response = await apiClient.get<AgentTelemetryListResponse>(`/agents/${idOrAgentId}/telemetry`, { params });
  return response.data;
};

export const disableAgent = async (idOrAgentId: string): Promise<EndpointAgentResponse> => {
  const response = await apiClient.post<EndpointAgentResponse>(`/agents/${idOrAgentId}/disable`);
  return response.data;
};

export const revokeAgent = async (idOrAgentId: string): Promise<EndpointAgentResponse> => {
  const response = await apiClient.post<EndpointAgentResponse>(`/agents/${idOrAgentId}/revoke`);
  return response.data;
};
