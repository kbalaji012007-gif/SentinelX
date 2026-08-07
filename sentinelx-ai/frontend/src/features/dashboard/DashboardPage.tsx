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

  // ── Computed Log Telemetry Metrics ──────────────────────────────────────
  const totalLogsToday = logStats?.total_entries ?? 0;
  const activeLogSourcesCount = logSourcesSummary?.total ?? 0;

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
            Live correlation across {assetCount} enterprise assets & {activeLogSourcesCount} active log sources
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            to="/correlation"
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold hover:bg-[var(--color-primary-600)] transition-all shadow-lg shadow-[var(--color-primary-500)]/20"
          >
            <LinkIcon className="w-4 h-4" />
            <span>Correlation Engine</span>
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
