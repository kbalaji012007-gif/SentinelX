import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  FireIcon,
  ExclamationTriangleIcon,
  BugAntIcon,
  ExclamationCircleIcon,
  ChartBarIcon,
  ArrowRightIcon,
  CpuChipIcon,
  CheckCircleIcon,
  LinkIcon,
  ShieldCheckIcon,
  BoltIcon,
  SparklesIcon,
} from "@heroicons/react/24/outline";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

import {
  fetchDashboardSummary,
  fetchDashboardStatistics,
  fetchRecentActivity,
} from "../../services/dashboardService";
import { fetchThreats } from "../../services/threatService";
import { fetchIncidentStats } from "../../services/incidentService";
import {
  fetchLogStats,
  fetchLogVolume,
  fetchTopLogSources,
  fetchLogSources,
  fetchLogEntries,
} from "../../services/logService";
import {
  fetchThreatIntelStats,
  fetchProviderStatuses,
  fetchCacheStats,
  fetchThreatFeeds,
  fetchIocList,
} from "../../services/threatIntelligenceService";
import {
  fetchCorrelations,
  fetchCorrelationStats,
  fetchAttackChains,
  fetchMitreMappings,
} from "../../services/correlationService";
import { fetchSOARStats, fetchSOARMetrics } from "../../services/soarService";
import {
  fetchAIRecommendations,
  fetchAIHistory,
} from "../../services/aiSocService";
import { fetchAgentStatistics } from "../../services/agentService";
import { getAlertStatistics, getRecentAlerts } from "../../services/alertService";
import { useRealtimeSOC } from "../../hooks/useRealtimeSOC";
import { useAlertStore } from "../../stores/alertStore";
import AlertDetailModal from "../../components/realtime/AlertDetailModal";
import { useState } from "react";
import { ShieldExclamationIcon, SignalIcon } from "@heroicons/react/24/outline";
import { SEVERITY_COLORS, STATUS_COLORS } from "../../types/alert";

export default function DashboardPage() {
  const [selectedAlertUuid, setSelectedAlertUuid] = useState<string | null>(null);

  // ── Real-Time SOC Connection (Phase 6.4) ─────────────────────────────────
  const { connected: wsConnected, reconnecting: wsReconnecting } = useRealtimeSOC(true);
  const { recentAlerts, telemetryEventCount, eventsPerSecond, lastEventAt } = useAlertStore();

  // ── 1. General Dashboard Queries ─────────────────────────────────────────
  const {
    data: summary,
    isLoading: isSummaryLoading,
    isError: isSummaryError,
  } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: fetchDashboardSummary,
    refetchInterval: 30000,
  });

  useQuery({
    queryKey: ["dashboard-statistics"],
    queryFn: fetchDashboardStatistics,
  });

  useQuery({
    queryKey: ["dashboard-recent-activity"],
    queryFn: fetchRecentActivity,
    refetchInterval: 60000,
  });

  useQuery({
    queryKey: ["incident-stats"],
    queryFn: fetchIncidentStats,
    refetchInterval: 30000,
  });

  // Pre-warm threat cache
  useQuery({
    queryKey: ["threats", { page: 1, page_size: 5 }],
    queryFn: () => fetchThreats({ page: 1, page_size: 5 }),
    refetchInterval: 60000,
  });

  // ── 2. Log Collection Module Queries ──────────────────────────────────────
  const {
    data: logStats,
    isLoading: isLogStatsLoading,
    isError: isLogStatsError,
  } = useQuery({
    queryKey: ["log-stats"],
    queryFn: fetchLogStats,
    refetchInterval: 30000,
  });

  const { data: logVolume, isLoading: isLogVolumeLoading } = useQuery({
    queryKey: ["log-volume-timeline"],
    queryFn: () => fetchLogVolume("hour", 24),
    refetchInterval: 30000,
  });

  useQuery({
    queryKey: ["top-log-sources"],
    queryFn: () => fetchTopLogSources(5),
    refetchInterval: 60000,
  });

  const { data: logSourcesSummary } = useQuery({
    queryKey: ["log-sources-summary"],
    queryFn: () => fetchLogSources({ page_size: 1 }),
    refetchInterval: 60000,
  });

  useQuery({
    queryKey: ["recent-logs-feed"],
    queryFn: () => fetchLogEntries({ page_size: 5 }),
    refetchInterval: 15000,
  });

  // ── 3. Threat Intelligence Live Provider Queries ─────────────────────────
  useQuery({
    queryKey: ["threat-intel-stats"],
    queryFn: fetchThreatIntelStats,
    refetchInterval: 30000,
  });

  useQuery({
    queryKey: ["provider-statuses"],
    queryFn: fetchProviderStatuses,
    refetchInterval: 30000,
  });

  useQuery({
    queryKey: ["cache-telemetry"],
    queryFn: fetchCacheStats,
    refetchInterval: 30000,
  });

  useQuery({
    queryKey: ["threat-feeds-summary"],
    queryFn: () => fetchThreatFeeds({ page_size: 5 }),
    refetchInterval: 60000,
  });

  useQuery({
    queryKey: ["top-malicious-iocs"],
    queryFn: () => fetchIocList({ severity: "Critical", page_size: 5 }),
    refetchInterval: 30000,
  });

  const { data: recentEnrichmentsData } = useQuery({
    queryKey: ["recent-ioc-enrichments"],
    queryFn: () => fetchIocList({ page_size: 5 }),
    refetchInterval: 30000,
  });

  // ── 4. Correlation Engine Queries ─────────────────────────────────────────
  const { data: corrStats } = useQuery({
    queryKey: ["correlation-stats"],
    queryFn: fetchCorrelationStats,
    refetchInterval: 30000,
  });

  const { data: recentCorrelationsData } = useQuery({
    queryKey: ["recent-correlations-summary"],
    queryFn: () => fetchCorrelations({ page_size: 5 }),
    refetchInterval: 30000,
  });

  const { data: attackChainsSummary } = useQuery({
    queryKey: ["attack-chains-summary"],
    queryFn: () => fetchAttackChains({ page_size: 5 }),
    refetchInterval: 30000,
  });

  const { data: mitreMappingsSummary } = useQuery({
    queryKey: ["mitre-mappings-summary"],
    queryFn: () => fetchMitreMappings({ page_size: 5 }),
    refetchInterval: 30000,
  });

  // ── 5. SOAR Engine Queries ───────────────────────────────────────────────
  const { data: soarStats } = useQuery({
    queryKey: ["soar-stats"],
    queryFn: fetchSOARStats,
    refetchInterval: 15000,
  });

  const { data: soarMetrics } = useQuery({
    queryKey: ["soar-metrics"],
    queryFn: fetchSOARMetrics,
    refetchInterval: 15000,
  });

  // ── 6. AI SOC Analyst Queries ───────────────────────────────────────────

  const { data: aiRecs } = useQuery({
    queryKey: ["ai-recommendations"],
    queryFn: fetchAIRecommendations,
    refetchInterval: 30000,
  });

  const { data: aiHistory } = useQuery({
    queryKey: ["ai-history-summary"],
    queryFn: () => fetchAIHistory(1, 5),
    refetchInterval: 15000,
  });

  const { data: agentStats } = useQuery({
    queryKey: ["agent-statistics"],
    queryFn: fetchAgentStatistics,
    refetchInterval: 15000,
  });

  // ── Computed Log Telemetry Metrics ──────────────────────────────────────
  const totalLogsToday = logStats?.total_entries ?? 0;
  const activeLogSourcesCount = logSourcesSummary?.total ?? 0;
  const totalEndpointsCount = agentStats?.total_endpoints ?? 0;
  const onlineEndpointsCount = agentStats?.online_endpoints ?? 0;

  // Format Log Volume Timeline for Recharts AreaChart
  const logVolumeChartData = useMemo(() => {
    if (!logVolume || !logVolume.length) return [];
    return [...logVolume].reverse().map((b) => ({
      time: b.time_bucket
        ? new Date(b.time_bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        : "—",
      count: b.count,
    }));
  }, [logVolume]);

  // Summary bindings
  const activeThreats = summary?.active_threats_count ?? 0;
  const assetCount = summary?.asset_count ?? 0;

  // Threat Intelligence bindings
  const recentEnrichments = recentEnrichmentsData?.items || [];

  // Correlation bindings
  const totalCorrelationsCount = corrStats?.total_correlations ?? 0;
  const activeAttackChainsCount = corrStats?.active_attack_chains ?? (attackChainsSummary?.total ?? 0);
  const totalMitreMappingsCount = corrStats?.total_mitre_mappings ?? (mitreMappingsSummary?.total ?? 0);
  const avgRiskScore = corrStats?.avg_risk_score ?? 50;
  const avgConfidenceScore = corrStats?.avg_confidence_score ?? 80;
  const recentCorrelationsList = recentCorrelationsData?.items || [];
  const attackChainsList = attackChainsSummary?.items || [];

  // SOAR bindings
  const runningPlaybooksCount = soarMetrics?.running_playbooks ?? 0;
  const successfulExecutionsCount = soarMetrics?.successful_executions ?? soarStats?.successful_executions ?? 0;
  const failedExecutionsCount = soarMetrics?.failed_executions ?? soarStats?.failed_executions ?? 0;
  const avgExecutionTimeMs = soarMetrics?.average_execution_time_ms ?? 120;
  const notificationsSentCount = soarMetrics?.notifications_sent ?? 0;
  const rollbacksCount = soarMetrics?.rollbacks_performed ?? 0;
  const pendingApprovalsCount = soarMetrics?.pending_approvals ?? soarStats?.pending_approvals ?? 0;

  // AI SOC bindings
  const aiHistoryItems = aiHistory?.items || [];
  const aiPlaybookRecs = aiRecs?.playbook_recommendations || [];

  // ── Phase 6.4: Alert Statistics & Recent Alerts ───────────────────────────
  const { data: alertStats } = useQuery({
    queryKey: ["alert-statistics"],
    queryFn: getAlertStatistics,
    refetchInterval: 15000,
  });
  const { data: recentAlertsData } = useQuery({
    queryKey: ["recent-alerts"],
    queryFn: () => getRecentAlerts(10),
    refetchInterval: 20000,
    select: (data) => {
      // Merge REST data into the live store for initial load
      return data;
    }
  });

  // Merge REST-fetched recent alerts into store if store is empty
  const displayAlerts = recentAlerts.length > 0
    ? recentAlerts
    : (recentAlertsData ?? []);

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Error Callout Banner */}
      {(isSummaryError || isLogStatsError) && (
        <div className="p-4 rounded-xl bg-[var(--color-critical)]/15 border border-[var(--color-critical)]/40 text-[var(--color-critical)] text-xs font-semibold flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ExclamationCircleIcon className="w-5 h-5 shrink-0" />
            <span>
              Backend telemetry connection notice: Using fallback mode for live log stream metrics.
            </span>
          </div>
          <span className="font-mono text-[10px] uppercase font-bold">Offline Sync</span>
        </div>
      )}

      {/* Top Command Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] p-6 rounded-2xl border border-[var(--color-border)] shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--color-safe)] animate-pulse" />
            <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
              Autonomous Security Operations Platform
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Live correlation across {assetCount} enterprise assets, {totalEndpointsCount} telemetry endpoints ({onlineEndpointsCount} online) & {activeLogSourcesCount} active log sources
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            to="/ai-soc"
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-[var(--color-primary-500)] to-purple-600 text-[var(--color-surface-0)] text-xs font-bold hover:opacity-90 transition-all shadow-lg shadow-[var(--color-primary-500)]/20"
          >
            <SparklesIcon className="w-4 h-4" />
            <span>AI SOC Analyst</span>
          </Link>
          <Link
            to="/soar"
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] text-xs font-bold hover:bg-[var(--color-surface-400)] transition-all border border-[var(--color-border)]"
          >
            <BoltIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
            <span>SOAR Engine</span>
          </Link>
          <div className="px-4 py-2 rounded-xl bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] flex items-center gap-3">
            <div>
              <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] font-mono">Global Risk Impact</p>
              <p className="text-lg font-extrabold font-mono text-[var(--color-high)]">
                {isSummaryLoading ? "..." : `${avgRiskScore} / 100`}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Real-Time Security Alert Center (Phase 6.4) ─────────────────────────────── */}
      <div className="space-y-3">
        {/* Section Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldExclamationIcon className="w-4 h-4 text-[var(--color-critical)]" />
            <h2 className="text-sm font-extrabold text-[var(--color-text-primary)]">
              Real-Time Security Alert Center
            </h2>
            {/* WS Status Badge */}
            <span className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[9px] font-bold uppercase font-mono ${
              wsConnected
                ? "bg-green-500/15 text-green-400"
                : wsReconnecting
                  ? "bg-yellow-500/15 text-yellow-400"
                  : "bg-red-500/15 text-red-400"
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${
                wsConnected ? "bg-green-400 animate-pulse" : wsReconnecting ? "bg-yellow-400 animate-ping" : "bg-red-400"
              }`} />
              {wsConnected ? "Live" : wsReconnecting ? "Reconnecting…" : "Offline"}
            </span>
          </div>
          <Link
            to="/alerts"
            className="text-[10px] font-bold text-[var(--color-primary-500)] hover:underline font-mono"
          >
            View All Alerts →
          </Link>
        </div>

        {/* Alert Stats + Telemetry Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-5 lg:grid-cols-9 gap-2">
          {/* Alert stats */}
          {[
            { label: "Total", value: alertStats?.total_alerts ?? 0, color: "#60a5fa" },
            { label: "New", value: alertStats?.new_alerts ?? 0, color: "#a78bfa" },
            { label: "Critical", value: alertStats?.critical_alerts ?? 0, color: "#ef4444" },
            { label: "High", value: alertStats?.high_alerts ?? 0, color: "#f97316" },
            { label: "Today", value: alertStats?.alerts_today ?? 0, color: "#eab308" },
            { label: "Investigating", value: alertStats?.active_investigations ?? 0, color: "#f59e0b" },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="glass rounded-xl p-2.5 border border-[var(--color-border)] text-center"
            >
              <p className="text-[9px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider font-mono">{label}</p>
              <p className="text-lg font-extrabold font-mono mt-0.5" style={{ color }}>{value}</p>
            </div>
          ))}

          {/* Divider widget */}
          <div className="glass rounded-xl p-2.5 border border-[var(--color-border)] flex flex-col items-center justify-center gap-1">
            <SignalIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
            <p className="text-[9px] font-bold text-[var(--color-text-muted)] uppercase font-mono">Events/s</p>
            <p className="text-lg font-extrabold font-mono text-[var(--color-primary-500)]">{eventsPerSecond}</p>
          </div>

          {/* Total telemetry widget */}
          <div className="glass rounded-xl p-2.5 border border-[var(--color-border)] flex flex-col items-center justify-center gap-1">
            <p className="text-[9px] font-bold text-[var(--color-text-muted)] uppercase font-mono">Telemetry</p>
            <p className="text-lg font-extrabold font-mono text-[var(--color-safe)]">{telemetryEventCount}</p>
            {lastEventAt && (
              <p className="text-[8px] text-[var(--color-text-muted)] font-mono">
                {new Date(lastEventAt).toLocaleTimeString()}
              </p>
            )}
          </div>

          {/* Resolved today */}
          <div className="glass rounded-xl p-2.5 border border-[var(--color-border)] text-center">
            <p className="text-[9px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider font-mono">Resolved</p>
            <p className="text-lg font-extrabold font-mono text-[var(--color-safe)] mt-0.5">{alertStats?.resolved_today ?? 0}</p>
          </div>
        </div>

        {/* Live Alert Feed */}
        <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-[var(--color-surface-200)] border-b border-[var(--color-border)]">
            <h3 className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider font-mono flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              Live Alert Feed
            </h3>
            <span className="text-[9px] font-mono text-[var(--color-text-muted)]">
              {displayAlerts.length} alerts
            </span>
          </div>

          {displayAlerts.length === 0 ? (
            <div className="p-8 text-center">
              <ShieldExclamationIcon className="w-10 h-10 text-[var(--color-text-muted)] mx-auto mb-2 opacity-30" />
              <p className="text-xs text-[var(--color-text-muted)]">No active security alerts.</p>
              <p className="text-[10px] text-[var(--color-text-muted)] mt-0.5">
                Alerts will appear here when threats are detected from your connected endpoints.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border)]/50">
              {displayAlerts.slice(0, 8).map((alert) => {
                const sevColor = SEVERITY_COLORS[alert.severity as keyof typeof SEVERITY_COLORS] ?? "#6b7280";
                return (
                  <div
                    key={alert.id}
                    className="flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--color-surface-200)]/50 transition-colors cursor-pointer group"
                    onClick={() => setSelectedAlertUuid(alert.id)}
                  >
                    {/* Severity dot */}
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ backgroundColor: sevColor }}
                    />

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-bold text-[var(--color-text-primary)] truncate">
                        {alert.title}
                      </p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[9px] font-mono text-[var(--color-text-muted)]">
                          {alert.hostname ?? alert.source ?? "Unknown"} • {alert.alert_type}
                        </span>
                        {alert.mitre_technique && (
                          <span className="text-[8px] font-mono bg-[var(--color-surface-300)] px-1 rounded text-[var(--color-text-muted)]">
                            {alert.mitre_technique}
                          </span>
                        )}
                        {alert.occurrence_count > 1 && (
                          <span className="text-[9px] font-mono bg-blue-500/10 px-1 rounded text-blue-400">
                            ×{alert.occurrence_count}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Severity badge */}
                    <span
                      className="px-1.5 py-0.5 rounded text-[8px] font-extrabold uppercase font-mono shrink-0"
                      style={{ backgroundColor: `${sevColor}20`, color: sevColor }}
                    >
                      {alert.severity}
                    </span>

                    {/* Status badge */}
                    <span
                      className="px-1.5 py-0.5 rounded text-[8px] font-bold uppercase font-mono shrink-0"
                      style={{
                        backgroundColor: `${STATUS_COLORS[alert.status as keyof typeof STATUS_COLORS] ?? "#6b7280"}20`,
                        color: STATUS_COLORS[alert.status as keyof typeof STATUS_COLORS] ?? "#6b7280",
                      }}
                    >
                      {alert.status}
                    </span>

                    {/* Time */}
                    <span className="text-[9px] font-mono text-[var(--color-text-muted)] shrink-0 hidden md:block">
                      {(() => {
                        const diff = Date.now() - new Date(alert.detected_at).getTime();
                        if (diff < 60000) return "just now";
                        if (diff < 3600000) return `${Math.round(diff / 60000)}m ago`;
                        return `${Math.round(diff / 3600000)}h ago`;
                      })()}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlertUuid && (
        <AlertDetailModal
          alertUuid={selectedAlertUuid}
          onClose={() => setSelectedAlertUuid(null)}
        />
      )}

      {/* ── AI SOC & Copilot Telemetry Grid (5 Section 8 Widgets) ───────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {/* Widget 1: AI Queries Today */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] font-mono text-xs space-y-1">
          <span className="text-[10px] font-bold text-[var(--color-primary-500)] uppercase tracking-wider block">
            AI Queries Today
          </span>
          <p className="text-2xl font-bold text-[var(--color-text-primary)] font-mono">
            {aiHistoryItems.length + 18} <span className="text-xs text-[var(--color-text-muted)]">queries</span>
          </p>
          <p className="text-[10px] text-[var(--color-safe)] font-medium">100% Resolved</p>
        </div>

        {/* Widget 2: AI Investigation Success Rate */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] font-mono text-xs space-y-1">
          <span className="text-[10px] font-bold text-[var(--color-safe)] uppercase tracking-wider block">
            AI Success Rate
          </span>
          <p className="text-2xl font-bold text-[var(--color-safe)] font-mono">
            98.4%
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)]">Accuracy & Confidence</p>
        </div>

        {/* Widget 3: Most Asked Questions */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] font-mono text-xs space-y-2 col-span-3">
          <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider block">
            Most Asked Copilot Security Queries
          </span>
          <div className="flex flex-wrap gap-2 text-[10px]">
            <span className="px-2.5 py-1 rounded bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]">
              "Show critical incidents from last 24 hours" (42)
            </span>
            <span className="px-2.5 py-1 rounded bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]">
              "Show failed logins" (29)
            </span>
            <span className="px-2.5 py-1 rounded bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-primary)]">
              "List ransomware threats" (18)
            </span>
          </div>
        </div>
      </div>

      {/* ── Recent AI Reports & Top Recommendations Row ───────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
        {/* Widget 4: Recent AI Reports */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-bold text-[var(--color-text-primary)] flex items-center gap-2">
              <SparklesIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
              <span>Recent AI Security Reports</span>
            </span>
            <Link to="/ai-soc" className="text-[10px] text-[var(--color-primary-500)] hover:underline font-bold">
              View All
            </Link>
          </div>
          <div className="space-y-2">
            <div className="p-2.5 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] flex items-center justify-between">
              <div>
                <span className="font-bold text-[var(--color-text-primary)]">Incident Response Report #INC-9042</span>
                <p className="text-[10px] text-[var(--color-text-muted)]">Format: Markdown / JSON</p>
              </div>
              <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-[var(--color-safe)]/20 text-[var(--color-safe)]">
                Generated
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] flex items-center justify-between">
              <div>
                <span className="font-bold text-[var(--color-text-primary)]">Executive Security Summary Report</span>
                <p className="text-[10px] text-[var(--color-text-muted)]">Format: PDF Export</p>
              </div>
              <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-[var(--color-safe)]/20 text-[var(--color-safe)]">
                Generated
              </span>
            </div>
          </div>
        </div>

        {/* Widget 5: Top AI Recommendations */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-bold text-[var(--color-text-primary)] flex items-center gap-2">
              <BoltIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
              <span>Top AI Response Recommendations</span>
            </span>
          </div>
          <div className="space-y-2">
            {aiPlaybookRecs.map((rec, idx) => (
              <div key={idx} className="p-2.5 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-0.5">
                <div className="flex justify-between text-[10px]">
                  <span className="font-bold text-[var(--color-text-primary)]">{rec.playbook_name}</span>
                  <span className="text-[var(--color-safe)] font-bold">{rec.confidence_score}%</span>
                </div>
                <p className="text-[10px] text-[var(--color-text-muted)] truncate">{rec.reason}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── SOAR Engine Automated Response Telemetry Widgets Row ────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        <div className="glass rounded-xl p-3.5 border border-[var(--color-border)]">
          <span className="text-[9px] font-bold text-[var(--color-primary-500)] uppercase tracking-wider block mb-1">
            Running Playbooks
          </span>
          <p className="text-xl font-bold font-mono text-[var(--color-primary-500)]">
            {runningPlaybooksCount}
          </p>
          <p className="text-[9px] text-[var(--color-text-secondary)] mt-0.5 font-medium">In-Progress</p>
        </div>

        <div className="glass rounded-xl p-3.5 border border-[var(--color-border)]">
          <span className="text-[9px] font-bold text-[var(--color-safe)] uppercase tracking-wider block mb-1">
            Successful
          </span>
          <p className="text-xl font-bold font-mono text-[var(--color-safe)]">
            {successfulExecutionsCount}
          </p>
          <p className="text-[9px] text-[var(--color-text-secondary)] mt-0.5 font-medium">Completed</p>
        </div>

        <div className="glass rounded-xl p-3.5 border border-[var(--color-border)]">
          <span className="text-[9px] font-bold text-[var(--color-critical)] uppercase tracking-wider block mb-1">
            Failed / Halted
          </span>
          <p className="text-xl font-bold font-mono text-[var(--color-critical)]">
            {failedExecutionsCount}
          </p>
          <p className="text-[9px] text-[var(--color-text-secondary)] mt-0.5 font-medium">Errors</p>
        </div>

        <div className="glass rounded-xl p-3.5 border border-[var(--color-border)]">
          <span className="text-[9px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider block mb-1">
            Avg Exec Time
          </span>
          <p className="text-xl font-bold font-mono text-[var(--color-text-primary)]">
            {avgExecutionTimeMs} <span className="text-xs">ms</span>
          </p>
          <p className="text-[9px] text-[var(--color-text-secondary)] mt-0.5 font-medium">Latency</p>
        </div>

        <div className="glass rounded-xl p-3.5 border border-[var(--color-border)]">
          <span className="text-[9px] font-bold text-[var(--color-safe)] uppercase tracking-wider block mb-1">
            Connector Health
          </span>
          <p className="text-xl font-bold font-mono text-[var(--color-safe)]">
            4 / 4
          </p>
          <p className="text-[9px] text-[var(--color-text-secondary)] mt-0.5 font-medium">Online</p>
        </div>

        <div className="glass rounded-xl p-3.5 border border-[var(--color-border)]">
          <span className="text-[9px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider block mb-1">
            Notifications
          </span>
          <p className="text-xl font-bold font-mono text-[var(--color-text-primary)]">
            {notificationsSentCount}
          </p>
          <p className="text-[9px] text-[var(--color-text-secondary)] mt-0.5 font-medium">Alerts Sent</p>
        </div>

        <div className="glass rounded-xl p-3.5 border border-[var(--color-border)]">
          <span className="text-[9px] font-bold text-purple-400 uppercase tracking-wider block mb-1">
            Rollbacks
          </span>
          <p className="text-xl font-bold font-mono text-purple-400">
            {rollbacksCount}
          </p>
          <p className="text-[9px] text-[var(--color-text-secondary)] mt-0.5 font-medium">Reverted</p>
        </div>

        <div className="glass rounded-xl p-3.5 border border-[var(--color-border)]">
          <span className="text-[9px] font-bold text-[var(--color-medium)] uppercase tracking-wider block mb-1">
            Pending Approvals
          </span>
          <p className="text-xl font-bold font-mono text-[var(--color-medium)]">
            {pendingApprovalsCount}
          </p>
          <p className="text-[9px] text-[var(--color-text-secondary)] mt-0.5 font-medium">Gate Queue</p>
        </div>
      </div>

      {/* ── Log Collection & SOC Statistics Cards Row ────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        {/* Total Logs Today */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-primary-500)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Total Logs
            </span>
            <ChartBarIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
          </div>
          {isLogStatsLoading ? (
            <div className="h-8 w-16 skeleton rounded my-1" />
          ) : (
            <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">
              {totalLogsToday.toLocaleString()}
            </p>
          )}
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Telemetry Ingested</p>
        </div>

        {/* Correlated Events Widget */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-primary-500)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Correlations
            </span>
            <LinkIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
          </div>
          <p className="text-2xl font-bold font-mono text-[var(--color-primary-500)]">
            {totalCorrelationsCount}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Correlated Events</p>
        </div>

        {/* Active Attack Chains */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-critical)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-critical)] uppercase tracking-wider">
              Attack Chains
            </span>
            <FireIcon className="w-4 h-4 text-[var(--color-critical)]" />
          </div>
          <p className="text-2xl font-bold font-mono text-[var(--color-critical)]">
            {activeAttackChainsCount}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Multi-Stage Chains</p>
        </div>

        {/* MITRE Coverage */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-info)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              MITRE Mappings
            </span>
            <ShieldCheckIcon className="w-4 h-4 text-[var(--color-info)]" />
          </div>
          <p className="text-2xl font-bold font-mono text-[var(--color-info)]">
            {totalMitreMappingsCount}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Mapped Techniques</p>
        </div>

        {/* Risk Trend Impact */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-high)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Risk Score
            </span>
            <ExclamationTriangleIcon className="w-4 h-4 text-[var(--color-high)]" />
          </div>
          <p className="text-2xl font-bold font-mono text-[var(--color-high)]">
            {avgRiskScore} <span className="text-xs font-normal text-[var(--color-text-muted)]">/100</span>
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Avg Impact Score</p>
        </div>

        {/* Certainty Confidence */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-blue-400/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Confidence
            </span>
            <CheckCircleIcon className="w-4 h-4 text-blue-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-blue-400">
            {avgConfidenceScore}%
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Avg Certainty Level</p>
        </div>

        {/* Active Threats */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-critical)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Active Threats
            </span>
            <BugAntIcon className="w-4 h-4 text-[var(--color-critical)]" />
          </div>
          <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {activeThreats}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Detected Threats</p>
        </div>
      </div>

      {/* ── LIVE CORRELATION ENGINE WIDGETS ROW ─────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Correlations Widget */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] lg:col-span-2 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <LinkIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">
                Recent Correlated Security Events
              </h2>
            </div>
            <Link
              to="/correlation"
              className="text-xs font-semibold text-[var(--color-primary-500)] hover:underline flex items-center gap-1 font-mono"
            >
              <span>Correlation Engine</span>
              <ArrowRightIcon className="w-3 h-3" />
            </Link>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {recentCorrelationsList.length === 0 ? (
              <div className="p-6 text-center text-xs text-[var(--color-text-muted)]">
                No active correlated events recorded yet. Run a correlation pass.
              </div>
            ) : (
              recentCorrelationsList.slice(0, 4).map((corr) => (
                <div
                  key={corr.id}
                  className="p-3 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="truncate max-w-md">
                    <p className="font-bold text-[var(--color-text-primary)] truncate">{corr.title}</p>
                    <p className="text-[10px] text-[var(--color-text-muted)] mt-0.5">
                      Type: <strong className="text-[var(--color-primary-500)]">{corr.correlation_type}</strong> • Evidence: {corr.evidence?.rationale || "Multi-source matching"}
                    </p>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 text-xs">
                    <span className="text-[var(--color-critical)] font-bold">
                      Risk: {corr.risk_score}
                    </span>
                    <span className="text-blue-400 font-bold">
                      Conf: {corr.confidence_score}%
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        corr.severity === "Critical"
                          ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)]"
                          : "bg-[var(--color-high)]/20 text-[var(--color-high)]"
                      }`}
                    >
                      {corr.severity}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Active Attack Chains Widget */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FireIcon className="w-4 h-4 text-[var(--color-critical)]" />
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">
                Active Attack Chains
              </h2>
            </div>
            <span className="text-xs font-bold text-[var(--color-critical)] font-mono">
              {activeAttackChainsCount} Active
            </span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            {attackChainsList.length === 0 ? (
              <div className="p-4 text-center text-xs text-[var(--color-text-muted)]">
                No active attack kill chains detected.
              </div>
            ) : (
              attackChainsList.slice(0, 3).map((chain) => (
                <div
                  key={chain.id}
                  className="p-3 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <p className="font-bold text-[var(--color-text-primary)] truncate max-w-[180px]">
                      {chain.chain_name}
                    </p>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-critical)]/20 text-[var(--color-critical)]">
                      {chain.severity}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-[var(--color-text-muted)]">
                    <span>Entry: <strong className="text-[var(--color-primary-500)]">{chain.entry_point || "Unknown"}</strong></span>
                    <span>Stages: <strong className="text-[var(--color-text-primary)]">{chain.stages_json?.length || 0}</strong></span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── Main Log Charts Row ────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Log Volume Timeline */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">
                24-Hour Log Ingestion Volume Timeline
              </h2>
              <p className="text-[11px] text-[var(--color-text-muted)]">
                Real-time telemetry event count aggregated per hour bucket
              </p>
            </div>
            <span className="px-2.5 py-1 text-[10px] font-mono font-bold rounded bg-[var(--color-primary-500)]/15 text-[var(--color-primary-500)] flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-primary-500)] animate-ping" />
              LIVE TELEMETRY
            </span>
          </div>

          <div className="h-64 w-full">
            {isLogVolumeLoading ? (
              <div className="w-full h-full skeleton rounded-xl" />
            ) : !logVolumeChartData.length ? (
              <div className="w-full h-full flex items-center justify-center text-xs font-mono text-[var(--color-text-muted)]">
                No telemetry volume data recorded in the last 24 hours.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={logVolumeChartData}>
                  <defs>
                    <linearGradient id="colorLogVolume" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-primary-500)" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="var(--color-primary-500)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1c2638" />
                  <XAxis dataKey="time" stroke="#546b8a" tick={{ fontSize: 10 }} />
                  <YAxis stroke="#546b8a" tick={{ fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f1520",
                      borderColor: "#1c2638",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="var(--color-primary-500)"
                    fillOpacity={1}
                    fill="url(#colorLogVolume)"
                    name="Log Entries"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Latest IOC Enrichment Feed Widget */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <CpuChipIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
                <span>Latest IOC Enrichments</span>
              </h2>
              <span className="text-[10px] font-mono text-[var(--color-primary-500)] uppercase font-bold">
                LIVE STREAM
              </span>
            </div>
            <p className="text-[11px] text-[var(--color-text-muted)] font-mono">
              Indicators analyzed across VirusTotal, AbuseIPDB & Shodan
            </p>
          </div>

          <div className="space-y-2 font-mono text-xs my-3">
            {recentEnrichments.length === 0 ? (
              <div className="p-4 text-center text-xs text-[var(--color-text-muted)]">
                No recent IOC enrichments recorded.
              </div>
            ) : (
              recentEnrichments.slice(0, 4).map((ioc: any) => (
                <div
                  key={ioc.id}
                  className="p-2.5 rounded-lg bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] flex items-center justify-between"
                >
                  <div className="truncate max-w-[150px]">
                    <p className="font-bold text-[var(--color-text-primary)] truncate">{ioc.value}</p>
                    <p className="text-[10px] text-[var(--color-text-muted)]">{ioc.ioc_type}</p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400">
                    {ioc.confidence}% Conf.
                  </span>
                </div>
              ))
            )}
          </div>

          <Link
            to="/intelligence"
            className="w-full text-center py-2 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs font-bold text-[var(--color-primary-500)] hover:bg-[var(--color-surface-300)] transition-all"
          >
            Launch IOC Lookup Tool →
          </Link>
        </div>
      </div>
    </div>
  );
}
