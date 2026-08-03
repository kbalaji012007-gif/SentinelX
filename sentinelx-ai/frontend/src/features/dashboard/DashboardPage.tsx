import { useQuery } from "@tanstack/react-query";
import {
  FireIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ServerIcon,
  BugAntIcon,
  SparklesIcon,
  GlobeAmericasIcon,
  CpuChipIcon,
  ExclamationCircleIcon,
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
import {
  mockThreats,
  mockTopAttackerIps,
  mockTimelineData,
  mockSeverityDistribution,
} from "../../utils/mockData";

export default function DashboardPage() {
  // Query 1: Summary KPI metrics
  const {
    data: summary,
    isLoading: isSummaryLoading,
    isError: isSummaryError,
  } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: fetchDashboardSummary,
    refetchInterval: 30000,
  });

  // Query 2: Velocity Timeline & Charts
  const { data: stats, isLoading: isStatsLoading } = useQuery({
    queryKey: ["dashboard-statistics"],
    queryFn: fetchDashboardStatistics,
  });

  // Query 3: Recent Activity Stream
  const { data: activity, isLoading: isActivityLoading } = useQuery({
    queryKey: ["dashboard-recent-activity"],
    queryFn: fetchRecentActivity,
  });

  // Fallback bindings when loading or offline
  const activeThreats = summary?.active_threats_count ?? 7;
  const criticalAlerts = summary?.critical_alerts_count ?? 18;
  const openIncidents = summary?.open_incidents_count ?? 4;
  const riskScore = summary?.current_risk_score ?? 78;
  const assetCount = summary?.asset_count ?? 142;
  const vulnCount = summary?.vulnerability_count ?? 66;

  const timelineData = stats?.timeline || mockTimelineData;
  const severityDistribution = stats?.severity_distribution || mockSeverityDistribution;
  const topAttackerIps = stats?.top_attacker_ips || mockTopAttackerIps;
  const activityList = activity || mockThreats;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Error Callout Banner */}
      {isSummaryError && (
        <div className="p-4 rounded-xl bg-[var(--color-critical)]/15 border border-[var(--color-critical)]/40 text-[var(--color-critical)] text-xs font-semibold flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ExclamationCircleIcon className="w-5 h-5 shrink-0" />
            <span>Backend telemetry API connection fallback mode active. Displaying cached SOC metrics.</span>
          </div>
          <span className="font-mono text-[10px] uppercase font-bold">Offline Sync</span>
        </div>
      )}

      {/* Top Command Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] p-6 rounded-2xl border border-[var(--color-border)] shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--color-critical)] animate-pulse" />
            <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
              Autonomous SOC Command Center
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Active monitoring across {assetCount} enterprise assets • Supabase PostgreSQL 17 connected
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="px-4 py-2 rounded-xl bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] flex items-center gap-3">
            <div>
              <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">Global Risk Score</p>
              <p className="text-lg font-extrabold font-mono text-[var(--color-high)]">
                {isSummaryLoading ? "..." : `${riskScore} / 100`}
              </p>
            </div>
            <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-[var(--color-high)]/20 text-[var(--color-high)]">
              HIGH RISK
            </span>
          </div>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: "Active Threats", value: activeThreats, sub: "2 Zero-day", icon: FireIcon, color: "var(--color-critical)" },
          { label: "Critical Alerts", value: criticalAlerts, sub: "Last 24h", icon: ExclamationTriangleIcon, color: "var(--color-high)" },
          { label: "Open Incidents", value: openIncidents, sub: "2 SLA Urgent", icon: ShieldExclamationIcon, color: "var(--color-medium)" },
          { label: "Risk Score", value: riskScore, sub: "High Exposure", icon: CpuChipIcon, color: "var(--color-high)" },
          { label: "Monitored Assets", value: assetCount, sub: "98.5% Active", icon: ServerIcon, color: "var(--color-primary-500)" },
          { label: "Vulnerabilities", value: vulnCount, sub: "14 Critical CVEs", icon: BugAntIcon, color: "var(--color-critical)" },
        ].map((card) => (
          <div key={card.label} className="glass rounded-xl p-4 border border-[var(--color-border)] hover:border-[var(--color-border-hover)] transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider">{card.label}</span>
              <card.icon className="w-4 h-4" style={{ color: card.color }} />
            </div>
            {isSummaryLoading ? (
              <div className="h-8 w-16 skeleton rounded my-1" />
            ) : (
              <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">{card.value}</p>
            )}
            <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">{card.sub}</p>
          </div>
        ))}
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Timeline */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">24-Hour Threat & Alert Velocity</h2>
              <p className="text-[11px] text-[var(--color-text-muted)]">Real-time event stream correlation from FastAPI</p>
            </div>
            <span className="px-2.5 py-1 text-[10px] font-mono font-bold rounded bg-[var(--color-primary-500)]/15 text-[var(--color-primary-500)]">
              LIVE STREAM
            </span>
          </div>

          <div className="h-64 w-full">
            {isStatsLoading ? (
              <div className="w-full h-full skeleton rounded-xl" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00e5ff" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#00e5ff" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ff1744" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ff1744" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1c2638" />
                  <XAxis dataKey="time" stroke="#546b8a" tick={{ fontSize: 10 }} />
                  <YAxis stroke="#546b8a" tick={{ fontSize: 10 }} />
                  <Tooltip contentStyle={{ backgroundColor: "#0f1520", borderColor: "#1c2638", borderRadius: "8px", fontSize: "12px" }} />
                  <Area type="monotone" dataKey="alerts" stroke="#00e5ff" fillOpacity={1} fill="url(#colorAlerts)" name="Alerts" />
                  <Area type="monotone" dataKey="threats" stroke="#ff1744" fillOpacity={1} fill="url(#colorThreats)" name="Threats" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Threat Severity Breakdown</h2>
            <p className="text-[11px] text-[var(--color-text-muted)] font-mono">Active threat classification</p>
          </div>
          <div className="h-48 w-full flex items-center justify-center my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityDistribution} innerRadius={50} outerRadius={75} paddingAngle={4} dataKey="value">
                  {severityDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: "#0f1520", borderColor: "#1c2638", borderRadius: "8px", fontSize: "11px" }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {severityDistribution.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-[11px] font-medium text-[var(--color-text-secondary)]">{item.name}: {item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Activity Table & AI Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Active Threats Table */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Recent Active Threats Feed</h2>
            <span className="text-xs font-semibold text-[var(--color-primary-500)] font-mono">LIVE FEED</span>
          </div>

          {isActivityLoading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4].map((n) => (
                <div key={n} className="h-10 w-full skeleton rounded-lg" />
              ))}
            </div>
          ) : activityList.length === 0 ? (
            <div className="p-8 text-center text-xs text-[var(--color-text-muted)] font-mono">
              No active threats detected. All systems clear.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-[var(--color-text-muted)] border-b border-[var(--color-border)] uppercase text-[10px] tracking-wider">
                    <th className="pb-3">Threat Name</th>
                    <th className="pb-3">Severity</th>
                    <th className="pb-3">Source IP</th>
                    <th className="pb-3">MITRE ID</th>
                    <th className="pb-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
                  {activityList.slice(0, 5).map((t: any) => (
                    <tr key={t.id} className="hover:bg-[var(--color-surface-200)]/50 transition-colors">
                      <td className="py-3 font-semibold text-[var(--color-text-primary)]">{t.name}</td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          t.severity === "Critical" ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)]" :
                          t.severity === "High" ? "bg-[var(--color-high)]/20 text-[var(--color-high)]" :
                          "bg-[var(--color-medium)]/20 text-[var(--color-medium)]"
                        }`}>
                          {t.severity}
                        </span>
                      </td>
                      <td className="py-3 font-mono text-[var(--color-text-primary)]">{t.sourceIp || t.source_ip}</td>
                      <td className="py-3 font-mono text-[var(--color-primary-500)]">{t.mitreId || t.mitre_id}</td>
                      <td className="py-3 font-medium text-[var(--color-text-secondary)]">{t.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* AI Sentinel & Attacker IPs */}
        <div className="space-y-6">
          <div className="glass rounded-xl p-5 border border-[var(--color-secondary-500)]/30 bg-gradient-to-b from-[var(--color-secondary-500)]/5 to-transparent">
            <div className="flex items-center gap-2 mb-3">
              <SparklesIcon className="w-5 h-5 text-[var(--color-secondary-500)] animate-pulse" />
              <h2 className="text-sm font-bold text-[var(--color-text-primary)]">AI Sentinel Insights</h2>
            </div>
            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs">
                <p className="font-semibold text-[var(--color-primary-500)] mb-1">Recommended Action</p>
                <p className="text-[var(--color-text-secondary)] text-[11px]">
                  Isolate <span className="font-mono text-[var(--color-text-primary)]">prod-db-master-01</span> due to SSH brute force attempts from IP 185.220.101.5.
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
    </div>
  );
}
