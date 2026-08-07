import apiClient from "./apiClient";

export interface ProviderResultData {
  verdict?: string;
  threat_score?: number;
  malicious_count?: number;
  suspicious_count?: number;
  harmless_count?: number;
  total_engines?: number;
  reputation?: number | string;
  tags?: string[];
  abuse_confidence_score?: number;
  country_code?: string;
  country_name?: string;
  isp?: string;
  usage_type?: string;
  domain?: string;
  total_reports?: number;
  open_ports?: number[];
  vulnerabilities?: string[];
  services?: any[];
  organization?: string;
  asn?: string;
  [key: string]: any;
}

export interface ProviderResultItem {
  provider: string;
  status: "available" | "unavailable" | "not_found";
  reason?: string | null;
  data?: ProviderResultData | null;
}

export interface GeminiSummaryData {
  threat_summary?: string;
  ioc_explanation?: string;
  mitre_attack?: Array<{
    technique_id: string;
    name: string;
    tactic: string;
    explanation?: string;
  }>;
  remediation_recommendations?: string[];
  ai_confidence_score?: number;
  severity_assessment?: string;
}

export interface IOCLookupResponse {
  ioc_value: string;
  ioc_type: string;
  verdict: "Malicious" | "Suspicious" | "Harmless" | "Unknown";
  threat_score: number;
  confidence: number;
  reputation: string;
  cache_hit: boolean;
  cached_at?: string | null;
  expires_at?: string | null;
  providers: Record<string, ProviderResultItem>;
  gemini_summary?: GeminiSummaryData | null;
  mitre_mapping: Array<Record<string, any>>;
  timeline: Array<{ event: string; timestamp: string }>;
}

export interface ProviderStatusItem {
  name: string;
  configured: boolean;
  status: "ready" | "unavailable";
  reason?: string | null;
  supported_types: string[];
}

export interface ProviderStatusListResponse {
  providers: ProviderStatusItem[];
}

export interface CacheStatsResponse {
  total_cached: number;
  active_cached: number;
  cache_hit_ratio: number;
  recent_keys: string[];
}

export interface ThreatIntelStats {
  total_feeds: number;
  active_feeds: number;
  total_iocs: number;
  iocs_by_type: Record<string, number>;
  iocs_by_severity: Record<string, number>;
  mitre_technique_count: number;
  cached_query_count: number;
  cache_hit_ratio: number;
}

// ── API Service Functions ─────────────────────────────────────────

export async function lookupIpAddress(ip: string, forceRefresh = false): Promise<IOCLookupResponse> {
  const { data } = await apiClient.post<IOCLookupResponse>("/threat-intelligence/lookup/ip", {
    value: ip,
    force_refresh: forceRefresh,
  });
  return data;
}

export async function lookupDomainName(domain: string, forceRefresh = false): Promise<IOCLookupResponse> {
  const { data } = await apiClient.post<IOCLookupResponse>("/threat-intelligence/lookup/domain", {
    value: domain,
    force_refresh: forceRefresh,
  });
  return data;
}

export async function lookupUrlLink(url: string, forceRefresh = false): Promise<IOCLookupResponse> {
  const { data } = await apiClient.post<IOCLookupResponse>("/threat-intelligence/lookup/url", {
    value: url,
    force_refresh: forceRefresh,
  });
  return data;
}

export async function lookupFileHash(fileHash: string, forceRefresh = false): Promise<IOCLookupResponse> {
  const { data } = await apiClient.post<IOCLookupResponse>("/threat-intelligence/lookup/hash", {
    value: fileHash,
    force_refresh: forceRefresh,
  });
  return data;
}

export async function lookupHostDetails(host: string, forceRefresh = false): Promise<IOCLookupResponse> {
  const { data } = await apiClient.post<IOCLookupResponse>("/threat-intelligence/lookup/host", {
    value: host,
    force_refresh: forceRefresh,
  });
  return data;
}

export async function enrichIoc(iocType: string, value: string, forceRefresh = false): Promise<IOCLookupResponse> {
  const { data } = await apiClient.post<IOCLookupResponse>("/threat-intelligence/enrich", {
    ioc_type: iocType,
    value: value,
    force_refresh: forceRefresh,
  });
  return data;
}

export async function fetchProviderStatuses(): Promise<ProviderStatusListResponse> {
  const { data } = await apiClient.get<ProviderStatusListResponse>("/threat-intelligence/providers");
  return data;
}

export async function fetchCacheStats(): Promise<CacheStatsResponse> {
  const { data } = await apiClient.get<CacheStatsResponse>("/threat-intelligence/cache");
  return data;
}

export async function fetchThreatIntelStats(): Promise<ThreatIntelStats> {
  const { data } = await apiClient.get<ThreatIntelStats>("/threat-intelligence/stats");
  return data;
}

export async function fetchThreatFeeds(params?: any) {
  const { data } = await apiClient.get("/threat-intelligence/feeds", { params });
  return data;
}

export async function fetchIocList(params?: any) {
  const { data } = await apiClient.get("/threat-intelligence/ioc", { params });
  return data;
}

export async function fetchMitreTechniques(params?: any) {
  const { data } = await apiClient.get("/threat-intelligence/mitre", { params });
  return data;
}
