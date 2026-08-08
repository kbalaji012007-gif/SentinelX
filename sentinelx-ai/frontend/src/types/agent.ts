export interface EndpointAgentSummary {
  id: string;
  agent_id: string;
  hostname: string;
  platform: string;
  os_version?: string;
  agent_version: string;
  status: "Online" | "Offline" | "Stale" | "Disabled" | "Revoked" | "Never Seen";
  enrolled_at: string;
  last_seen?: string;
  local_ip?: string;
  risk_score: number;
  telemetry_count: number;
}

export interface EndpointAgentResponse {
  id: string;
  agent_id: string;
  hostname: string;
  platform: string;
  os_version?: string;
  agent_version: string;
  status: string;
  enrolled_at: string;
  last_seen?: string;
  agent_metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface EndpointAgentListResponse {
  total: number;
  page: number;
  page_size: number;
  items: EndpointAgentSummary[];
}

export interface EndpointAgentStatsResponse {
  total_endpoints: number;
  online_endpoints: number;
  offline_endpoints: number;
  stale_endpoints: number;
  telemetry_events_today: number;
  endpoint_threats: number;
  highest_risk_endpoint?: string;
}

export interface AgentTelemetryResponse {
  id: string;
  agent_id: string;
  event_type: string;
  event_timestamp: string;
  severity: "TRACE" | "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL";
  payload: Record<string, any>;
  source?: string;
  created_at: string;
}

export interface AgentTelemetryListResponse {
  total: number;
  page: number;
  page_size: number;
  items: AgentTelemetryResponse[];
}

export interface EndpointDetailsResponse {
  agent: EndpointAgentResponse;
  system_info: {
    hostname: string;
    platform: string;
    os_version?: string;
    agent_version: string;
    architecture?: string;
    local_ip?: string;
    username?: string;
  };
  agent_health: {
    status: string;
    health_status: string;
    uptime_seconds: number;
    enrolled_at: string;
    last_seen?: string;
  };
  last_heartbeat?: string;
  recent_telemetry: AgentTelemetryResponse[];
  recent_security_events: Array<{
    event_id?: string;
    event_type: string;
    severity: string;
    timestamp: string;
    message: string;
  }>;
  recent_threats: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    detected_at?: string;
  }>;
  risk_score: number;
  network_connections: Array<{
    local_address?: string;
    local_port?: number;
    remote_address?: string;
    remote_port?: number;
    protocol?: string;
    state?: string;
  }>;
  running_processes: Array<{
    pid?: number;
    process_name?: string;
    executable_path?: string;
    username?: string;
    start_time?: string;
  }>;
  timeline: Array<{
    timestamp: string;
    type: string;
    severity: string;
    summary: string;
  }>;
}
