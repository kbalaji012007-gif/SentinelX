/**
 * SentinelX AI – Log Collection Service
 * Axios API client calls for log sources, log entries, search, and statistics.
 */

import apiClient from "./apiClient";
import type {
  LogSource,
  LogSourceListResponse,
  LogEntry,
  LogEntryListResponse,
  LogEntryStatsResponse,
  LogQueryParams,
  TopLogSourceItem,
  LogVolumeBucket,
} from "../types/log";

// ────────────────────────────────────────────────────────────────────────
// Log Source API
// ────────────────────────────────────────────────────────────────────────

export async function fetchLogSources(params: {
  page?: number;
  page_size?: number;
  source_type?: string;
  status?: string;
  search?: string;
} = {}): Promise<LogSourceListResponse> {
  const response = await apiClient.get<LogSourceListResponse>("/logs/sources", { params });
  return response.data;
}

export async function fetchLogSourceById(sourceId: string): Promise<LogSource> {
  const response = await apiClient.get<LogSource>(`/logs/sources/${sourceId}`);
  return response.data;
}

// ────────────────────────────────────────────────────────────────────────
// Log Entry & Search API
// ────────────────────────────────────────────────────────────────────────

export async function fetchLogEntries(
  params: LogQueryParams = {}
): Promise<LogEntryListResponse> {
  const query: Record<string, string | number> = {};

  if (params.page) query.page = params.page;
  if (params.page_size) query.page_size = params.page_size;

  // Use search endpoint if search params are present, else base list endpoint
  const hasSearchParams =
    params.keyword ||
    params.username ||
    params.start_time ||
    params.end_time;

  if (hasSearchParams) {
    if (params.keyword) query.keyword = params.keyword;
    if (params.level && params.level !== "ALL") query.level = params.level;
    if (params.source_id && params.source_id !== "ALL") query.source = params.source_id;
    if (params.asset_id) query.asset = params.asset_id;
    if (params.username) query.username = params.username;
    if (params.event_type) query.event_type = params.event_type;
    if (params.category) query.category = params.category;
    if (params.start_time) query.start_time = params.start_time;
    if (params.end_time) query.end_time = params.end_time;

    const response = await apiClient.get<LogEntryListResponse>("/logs/search", { params: query });
    return response.data;
  } else {
    if (params.level && params.level !== "ALL") query.log_level = params.level;
    if (params.source_id && params.source_id !== "ALL") query.source_id = params.source_id;
    if (params.asset_id) query.asset_id = params.asset_id;
    if (params.event_type) query.event_type = params.event_type;
    if (params.category) query.category = params.category;

    const response = await apiClient.get<LogEntryListResponse>("/logs", { params: query });
    return response.data;
  }
}

export async function fetchLogEntryById(entryId: string): Promise<LogEntry> {
  const response = await apiClient.get<LogEntry>(`/logs/${entryId}`);
  return response.data;
}

// ────────────────────────────────────────────────────────────────────────
// Log Statistics API
// ────────────────────────────────────────────────────────────────────────

export async function fetchLogStats(): Promise<LogEntryStatsResponse> {
  const response = await apiClient.get<LogEntryStatsResponse>("/logs/statistics");
  return response.data;
}

export async function fetchTopLogSources(limit: number = 10): Promise<TopLogSourceItem[]> {
  const response = await apiClient.get<TopLogSourceItem[]>("/logs/statistics/top-sources", {
    params: { limit },
  });
  return response.data;
}

export async function fetchLogVolume(
  interval: "hour" | "day" | "week" = "hour",
  limit: number = 24
): Promise<LogVolumeBucket[]> {
  const response = await apiClient.get<LogVolumeBucket[]>("/logs/statistics/volume", {
    params: { interval, limit },
  });
  return response.data;
}
