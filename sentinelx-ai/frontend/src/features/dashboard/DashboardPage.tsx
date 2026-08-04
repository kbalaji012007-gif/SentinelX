import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  FireIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ServerIcon,
  BugAntIcon,
  SparklesIcon,
  GlobeAmericasIcon,
  ExclamationCircleIcon,
  Bars3BottomLeftIcon,
  ClockIcon,
  ChartBarIcon,
  ArrowRightIcon,
  ListBulletIcon,
} from "@heroicons/react/24/outline";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
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
import type { LogEntrySummary } from "../../types/log";

// ─────────────────────────────────────────────────────────────────────────────
// Severity Color Tokens
// ─────────────────────────────────────────────────────────────────────────────

const LOG_LEVEL_STYLES: Record<string, string> = {
  CRITICAL: "bg-[var(--color-critical)]/15 text-[var(--color-critical)] border border-[var(--color-critical)]/40",
  ERROR: "bg-[var(--color-high)]/15 text-[var(--color-high)] border border-[var(--color-high)]/40",
  WARNING: "bg-[var(--color-medium)]/15 text-[var(--color-medium)] border border-[var(--color-medium)]/40",
  WARN: "bg-[var(--color-medium)]/15 text-[var(--color-medium)] border border-[var(--color-medium)]/40",
  INFO: "bg-[var(--color-info)]/15 text-[var(--color-info)] border border-[var(--color-info)]/40",
  DEBUG: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  TRACE: "bg-purple-500/15 text-purple-400 border border-purple-500/30",
};

export default function DashboardPage() {
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

  const { data: stats } = useQuery({
    queryKey: ["dashboard-statistics"],
    queryFn: fetchDashboardStatistics,
  });

  const { data: activity, isLoading: isActivityLoading } = useQuery({
    queryKey: ["dashboard-recent-activity"],
    queryFn: fetchRecentActivity,
    refetchInterval: 60000,
  });

  const { data: incStats } = useQuery({
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

  const { data: topSources, isLoading: isTopSourcesLoading } = useQuery({
    queryKey: ["top-log-sources"],
    queryFn: () => fetchTopLogSources(5),
    refetchInterval: 60000,
  });

  const { data: logSourcesSummary } = useQuery({
    queryKey: ["log-sources-summary"],
    queryFn: () => fetchLogSources({ page_size: 1 }),
    refetchInterval: 60000,
  });

  const { data: recentLogsData, isLoading: isRecentLogsLoading } = useQuery({
    queryKey: ["recent-logs-feed"],
    queryFn: () => fetchLogEntries({ page_size: 5 }),
    refetchInterval: 15000,
  });

  // ── Computed Log Telemetry Metrics ──────────────────────────────────────
  const totalLogsToday = logStats?.total_entries ?? 0;
  const criticalLogCount = logStats?.by_level?.CRITICAL ?? 0;
  const errorLogCount = logStats?.by_level?.ERROR ?? 0;
  const activeLogSourcesCount = logSourcesSummary?.total ?? 0;

  // Compute Logs Last Hour from latest volume bucket
  const logsLastHour = useMemo(() => {
    if (!logVolume || logVolume.length === 0) return 0;
    return logVolume[0]?.count ?? 0;
  }, [logVolume]);

  // Compute Error Rate (% of ERROR + CRITICAL logs / total logs)
  const errorRateStr = useMemo(() => {
    if (!totalLogsToday) return "0.0%";
    const badCount = criticalLogCount + errorLogCount;
    return ((badCount / totalLogsToday) * 100).toFixed(1) + "%";
  }, [totalLogsToday, criticalLogCount, errorLogCount]);

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

  // Format Log Severity Distribution for Recharts PieChart
  const logSeverityPieData = useMemo(() => {
    if (!logStats?.by_level) return [];
    const levels = logStats.by_level;
    const items = [
      { name: "CRITICAL", value: levels.CRITICAL || 0, color: "var(--color-critical)" },
      { name: "ERROR", value: levels.ERROR || 0, color: "var(--color-high)" },
      { name: "WARNING", value: (levels.WARNING || levels.WARN || 0), color: "var(--color-medium)" },
      { name: "INFO", value: levels.INFO || 0, color: "var(--color-info)" },
      { name: "DEBUG", value: levels.DEBUG || 0, color: "#3b82f6" },
      { name: "TRACE", value: levels.TRACE || 0, color: "#a855f7" },
    ];
    return items.filter((i) => i.value > 0);
  }, [logStats]);

  // Top Sources max count for progress bars
  const maxSourceCount = useMemo(() => {
    if (!topSources || !topSources.length) return 1;
    return Math.max(...topSources.map((s) => s.entry_count));
  }, [topSources]);

  // Summary bindings
  const activeThreats = summary?.active_threats_count ?? 0;
  const openIncidents = incStats?.open_incidents_count ?? (summary?.open_incidents_count ?? 0);
  const riskScore = summary?.current_risk_score ?? 10;
  const assetCount = summary?.asset_count ?? 0;
  const topAttackerIps = stats?.top_attacker_ips ?? [];
  const activityList = activity ?? [];
  const recentLogsList: LogEntrySummary[] = recentLogsData?.items ?? [];

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
            Live ingestion monitoring across {assetCount} enterprise assets & {activeLogSourcesCount} active log sources
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            to="/logs"
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold hover:bg-[var(--color-primary-600)] transition-all shadow-lg shadow-[var(--color-primary-500)]/20"
          >
            <Bars3BottomLeftIcon className="w-4 h-4" />
            <span>Open Log Viewer</span>
          </Link>
          <div className="px-4 py-2 rounded-xl bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] flex items-center gap-3">
            <div>
              <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">Global Risk Score</p>
              <p className="text-lg font-extrabold font-mono text-[var(--color-high)]">
                {isSummaryLoading ? "..." : `${riskScore} / 100`}
              </p>
            </div>
          </div>
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

        {/* Logs Last Hour */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-info)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Last Hour Volume
            </span>
            <ClockIcon className="w-4 h-4 text-[var(--color-info)]" />
          </div>
          {isLogVolumeLoading ? (
            <div className="h-8 w-16 skeleton rounded my-1" />
          ) : (
            <p className="text-2xl font-bold font-mono text-[var(--color-info)]">
              {logsLastHour.toLocaleString()}
            </p>
          )}
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Recent Velocity</p>
        </div>

        {/* Error Rate */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-high)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Error Rate
            </span>
            <ExclamationTriangleIcon className="w-4 h-4 text-[var(--color-high)]" />
          </div>
          {isLogStatsLoading ? (
            <div className="h-8 w-16 skeleton rounded my-1" />
          ) : (
            <p className="text-2xl font-bold font-mono text-[var(--color-high)]">
              {errorRateStr}
            </p>
          )}
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Error & Critical %</p>
        </div>

        {/* Critical Events */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-critical)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-critical)] uppercase tracking-wider">
              Critical Logs
            </span>
            <FireIcon className="w-4 h-4 text-[var(--color-critical)]" />
          </div>
          {isLogStatsLoading ? (
            <div className="h-8 w-16 skeleton rounded my-1" />
          ) : (
            <p className="text-2xl font-bold font-mono text-[var(--color-critical)]">
              {criticalLogCount.toLocaleString()}
            </p>
          )}
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Requires Inspection</p>
        </div>

        {/* Active Log Sources */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-safe)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Log Sources
            </span>
            <ServerIcon className="w-4 h-4 text-[var(--color-safe)]" />
          </div>
          <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {activeLogSourcesCount}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Connected Feeds</p>
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

        {/* Open Incidents */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-medium)]/50 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">
              Open Incidents
            </span>
            <ShieldExclamationIcon className="w-4 h-4 text-[var(--color-medium)]" />
          </div>
          <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {openIncidents}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Active Tickets</p>
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

        {/* Log Severity Distribution */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold text-[var(--color-text-primary)]">
              Log Severity Distribution
            </h2>
            <p className="text-[11px] text-[var(--color-text-muted)] font-mono">
              Classification by severity level
            </p>
          </div>

          <div className="h-48 w-full flex items-center justify-center my-2">
            {isLogStatsLoading ? (
              <div className="w-32 h-32 skeleton rounded-full" />
            ) : !logSeverityPieData.length ? (
              <div className="text-xs font-mono text-[var(--color-text-muted)]">
                No log data available
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={logSeverityPieData}
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {logSeverityPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f1520",
                      borderColor: "#1c2638",
                      borderRadius: "8px",
                      fontSize: "11px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            {logSeverityPieData.map((item) => (
              <div key={item.name} className="flex items-center gap-2 font-mono">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-[11px] font-medium text-[var(--color-text-secondary)]">
                  {item.name}: <span className="font-bold text-[var(--color-text-primary)]">{item.value.toLocaleString()}</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Secondary Section: Top Log Sources & AI Insights ────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Log Sources Widget */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">
                Top Log Sources by Entry Volume
              </h2>
              <p className="text-[11px] text-[var(--color-text-muted)]">
                Highest throughput telemetry feeds in the enterprise
              </p>
            </div>
            <Link
              to="/logs"
              className="text-xs font-semibold text-[var(--color-primary-500)] hover:underline flex items-center gap-1"
            >
              <span>Manage Sources</span>
              <ArrowRightIcon className="w-3 h-3" />
            </Link>
          </div>

          {isTopSourcesLoading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((n) => (
                <div key={n} className="h-10 w-full skeleton rounded-lg" />
              ))}
            </div>
          ) : !topSources?.length ? (
            <div className="p-8 text-center text-xs font-mono text-[var(--color-text-muted)]">
              No log sources registered yet.
            </div>
          ) : (
            <div className="space-y-3">
              {topSources.map((source) => {
                const percent = Math.round((source.entry_count / maxSourceCount) * 100);
                return (
                  <div
                    key={source.source_id}
                    className="p-3 rounded-lg bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <ServerIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
                        <span className="font-bold text-[var(--color-text-primary)]">
                          {source.name}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-[var(--color-surface-300)] text-[var(--color-text-muted)]">
                          {source.source_type}
                        </span>
                      </div>
                      <span className="font-bold text-[var(--color-text-primary)]">
                        {source.entry_count.toLocaleString()} logs
                      </span>
                    </div>
                    {/* Progress Bar */}
                    <div className="w-full h-1.5 bg-[var(--color-surface-300)] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-[var(--color-primary-500)] transition-all duration-500"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* AI Insights & Security Health */}
        <div className="space-y-6">
          <div className="glass rounded-xl p-5 border border-[var(--color-secondary-500)]/30 bg-gradient-to-b from-[var(--color-secondary-500)]/5 to-transparent">
            <div className="flex items-center gap-2 mb-3">
              <SparklesIcon className="w-5 h-5 text-[var(--color-secondary-500)] animate-pulse" />
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">AI Telemetry Insights</h2>
            </div>
            <div className="space-y-3 text-xs">
              <div className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)]">
                <p className="font-semibold text-[var(--color-primary-500)] mb-1">
                  Log Stream Correlation
                </p>
                <p className="text-[var(--color-text-secondary)] text-[11px]">
                  Ingestion rate for Syslog and Windows Events is operating normally across all connected log agents.
                </p>
              </div>
            </div>
          </div>

          <div className="glass rounded-xl p-5 border border-[var(--color-border)]">
            <div className="flex items-center gap-2 mb-3">
              <GlobeAmericasIcon className="w-4 h-4 text-[var(--color-critical)]" />
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Top Attacker IPs</h2>
            </div>
            <div className="space-y-2">
              {topAttackerIps.slice(0, 3).map((item) => (
                <div key={item.ip} className="flex items-center justify-between p-2 rounded bg-[var(--color-surface-200)] text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--color-surface-300)] text-[var(--color-text-muted)]">{item.country}</span>
                    <span className="text-[var(--color-text-primary)]">{item.ip}</span>
                  </div>
                  <span className="font-bold text-[var(--color-critical)]">{item.attempts} reqs</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Feeds Row: Recent Log Events & Activity Stream ────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Log Events Live Feed */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)]">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ListBulletIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">
                Recent Log Events Stream
              </h2>
            </div>
            <Link
              to="/logs"
              className="text-xs font-semibold text-[var(--color-primary-500)] hover:underline flex items-center gap-1"
            >
              <span>View All Logs</span>
              <ArrowRightIcon className="w-3.5 h-3.5" />
            </Link>
          </div>

          {isRecentLogsLoading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4, 5].map((n) => (
                <div key={n} className="h-10 w-full skeleton rounded-lg" />
              ))}
            </div>
          ) : !recentLogsList.length ? (
            <div className="p-8 text-center text-xs font-mono text-[var(--color-text-muted)]">
              No recent log events available.
            </div>
          ) : (
            <div className="space-y-2 font-mono text-xs">
              {recentLogsList.map((log) => (
                <div
                  key={log.id}
                  className="p-2.5 rounded-lg bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] hover:bg-[var(--color-surface-200)] transition-all"
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                          LOG_LEVEL_STYLES[log.log_level] || LOG_LEVEL_STYLES.INFO
                        }`}
                      >
                        {log.log_level}
                      </span>
                      <span className="font-bold text-[var(--color-text-primary)]">
                        {log.event_type}
                      </span>
                      {log.username && (
                        <span className="text-[11px] text-[var(--color-text-muted)]">
                          @{log.username}
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] text-[var(--color-text-muted)]">
                      {new Date(log.event_timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-[11px] font-sans text-[var(--color-text-secondary)] truncate">
                    {log.message || "(Raw log payload)"}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* System Activity Feed / Recent Threats */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)]">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-[var(--color-text-primary)]">
              System Activity & Active Threats
            </h2>
            <span className="text-xs font-semibold text-[var(--color-primary-500)] font-mono">
              LIVE FEED
            </span>
          </div>

          {isActivityLoading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4, 5].map((n) => (
                <div key={n} className="h-10 w-full skeleton rounded-lg" />
              ))}
            </div>
          ) : !activityList.length ? (
            <div className="p-8 text-center text-xs font-mono text-[var(--color-text-muted)]">
              No active security threats in feed. All systems clear.
            </div>
          ) : (
            <div className="space-y-2 text-xs">
              {activityList.slice(0, 5).map((t: any) => (
                <div
                  key={t.id}
                  className="p-2.5 rounded-lg bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] flex items-center justify-between"
                >
                  <div className="space-y-0.5">
                    <p className="font-semibold text-[var(--color-text-primary)]">{t.name}</p>
                    <p className="text-[11px] font-mono text-[var(--color-text-muted)]">
                      IP: {t.sourceIp || t.source_ip || "—"} • MITRE: {t.mitreId || t.mitre_id || "—"}
                    </p>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      t.severity === "Critical"
                        ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)]"
                        : t.severity === "High"
                        ? "bg-[var(--color-high)]/20 text-[var(--color-high)]"
                        : "bg-[var(--color-medium)]/20 text-[var(--color-medium)]"
                    }`}
                  >
                    {t.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
