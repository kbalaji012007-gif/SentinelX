/**
 * SentinelX AI – Log Collection Types
 * TypeScript interfaces matching the backend Pydantic v2 schemas for logs & log sources.
 */

export type LogSourceType =
  | "Syslog"
  | "Windows Event"
  | "Cloud Trail"
  | "Firewall"
  | "IDS/IPS"
  | "Endpoint"
  | "Application"
  | "Network"
  | "Other";

export type LogSourceStatus = "Active" | "Inactive" | "Error" | "Maintenance";

export type LogProtocol = "UDP" | "TCP" | "TLS" | "HTTPS" | "HTTP";

export type LogLevel = "TRACE" | "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL";

export interface LogSource {
  id: string;
  name: string;
  source_type: LogSourceType;
  vendor?: string | null;
  description?: string | null;
  hostname?: string | null;
  ip_address?: string | null;
  protocol?: LogProtocol | null;
  port?: number | null;
  status: LogSourceStatus;
  last_seen?: string | null;
  created_at: string;
  updated_at: string;
}

export interface LogSourceSummary {
  id: string;
  name: string;
  source_type: string;
  vendor?: string | null;
  hostname?: string | null;
  ip_address?: string | null;
  status: string;
  last_seen?: string | null;
  created_at: string;
  updated_at: string;
}

export interface LogSourceListResponse {
  total: number;
  page: number;
  page_size: number;
  items: LogSourceSummary[];
}

export interface LogEntry {
  id: string;
  source_id: string;
  asset_id?: string | null;
  event_timestamp: string;
  log_level: LogLevel;
  event_type: string;
  category?: string | null;
  message?: string | null;
  raw_log: Record<string, unknown>;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  process_name?: string | null;
  event_id?: string | null;
  correlation_id?: string | null;
  created_at: string;
}

export interface LogEntrySummary {
  id: string;
  source_id: string;
  asset_id?: string | null;
  event_timestamp: string;
  log_level: LogLevel | string;
  event_type: string;
  category?: string | null;
  message?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  event_id?: string | null;
  created_at: string;
}

export interface LogEntryListResponse {
  total: number;
  page: number;
  page_size: number;
  items: LogEntrySummary[];
}

export interface LogEntryStatsResponse {
  total_entries: number;
  by_level: Record<string, number>;
  by_event_type: Record<string, number>;
  by_category: Record<string, number>;
}

export interface LogQueryParams {
  page?: number;
  page_size?: number;
  keyword?: string;
  level?: string;
  source_id?: string;
  asset_id?: string;
  username?: string;
  event_type?: string;
  category?: string;
  start_time?: string;
  end_time?: string;
}

export interface TopLogSourceItem {
  source_id: string;
  name: string;
  source_type: string;
  entry_count: number;
}

export interface LogVolumeBucket {
  time_bucket: string;
  count: number;
}
