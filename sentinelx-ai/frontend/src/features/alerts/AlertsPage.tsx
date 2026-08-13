/**
 * SentinelX AI – Alerts History Page (Phase 6.4)
 * Full-featured security alert management table with filters, RBAC actions,
 * and integration with the real-time alert store.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldExclamationIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  ArrowPathIcon,
  EyeIcon,
  CheckCircleIcon,
} from "@heroicons/react/24/outline";

import {
  getAlerts,
  getAlertStatistics,
  acknowledgeAlert,
  investigateAlert,
} from "../../services/alertService";
import AlertDetailModal from "../../components/realtime/AlertDetailModal";
import type { SecurityAlertSummary, AlertSeverity } from "../../types/alert";
import { SEVERITY_COLORS } from "../../types/alert";

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 ring-1 ring-red-500/30",
  HIGH:     "bg-orange-500/15 text-orange-400 ring-1 ring-orange-500/30",
  MEDIUM:   "bg-yellow-500/15 text-yellow-400 ring-1 ring-yellow-500/30",
  LOW:      "bg-green-500/15 text-green-400 ring-1 ring-green-500/30",
};

const STATUS_BADGE: Record<string, string> = {
  NEW:           "bg-blue-500/15 text-blue-400",
  ACKNOWLEDGED:  "bg-purple-500/15 text-purple-400",
  INVESTIGATING: "bg-yellow-500/15 text-yellow-400",
  RESOLVED:      "bg-green-500/15 text-green-400",
  DISMISSED:     "bg-slate-500/15 text-slate-400",
};

function SevDot({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity as AlertSeverity] ?? "#6b7280";
  return <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color }} />;
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60000) return "just now";
  if (diff < 3600000) return `${Math.round(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.round(diff / 3600000)}h ago`;
  return `${Math.round(diff / 86400000)}d ago`;
}

// ── Page Component ────────────────────────────────────────────────────────────

export default function AlertsPage() {
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [selectedAlertUuid, setSelectedAlertUuid] = useState<string | null>(null);

  // Queries
  const { data: alertsData, isLoading, refetch } = useQuery({
    queryKey: ["alerts", { page, search, severity: sevFilter, status: statusFilter }],
    queryFn: () => getAlerts({
      page,
      page_size: 25,
      search: search || undefined,
      severity: sevFilter || undefined,
      status: statusFilter || undefined,
    }),
    refetchInterval: 30000,
  });

  const { data: stats } = useQuery({
    queryKey: ["alert-statistics"],
    queryFn: getAlertStatistics,
    refetchInterval: 15000,
  });

  // Quick-action mutations
  const ackMut = useMutation({
    mutationFn: (uuid: string) => acknowledgeAlert(uuid),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["alerts"] });
      void qc.invalidateQueries({ queryKey: ["alert-statistics"] });
    },
  });
  const invMut = useMutation({
    mutationFn: (uuid: string) => investigateAlert(uuid),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["alerts"] });
      void qc.invalidateQueries({ queryKey: ["alert-statistics"] });
    },
  });

  const alerts = alertsData?.items ?? [];
  const total = alertsData?.total ?? 0;
  const totalPages = Math.ceil(total / 25);

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] p-6 rounded-2xl border border-[var(--color-border)] shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <ShieldExclamationIcon className="w-5 h-5 text-[var(--color-critical)]" />
            <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
              Security Alert Center
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Real-time SOC alerts from endpoint detection, threat correlation, and behavioral analytics
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[var(--color-surface-300)] border border-[var(--color-border)] text-xs font-bold text-[var(--color-primary-500)] hover:bg-[var(--color-surface-400)] transition-all"
        >
          <ArrowPathIcon className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Statistics Row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          {[
            { label: "Total", value: stats.total_alerts, color: "#60a5fa" },
            { label: "New", value: stats.new_alerts, color: "#a78bfa" },
            { label: "Critical", value: stats.critical_alerts, color: "#ef4444" },
            { label: "High", value: stats.high_alerts, color: "#f97316" },
            { label: "Today", value: stats.alerts_today, color: "#eab308" },
            { label: "Investigating", value: stats.active_investigations, color: "#f59e0b" },
            { label: "Resolved Today", value: stats.resolved_today, color: "#22c55e" },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="glass rounded-xl p-3 border border-[var(--color-border)] text-center"
            >
              <p className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider font-mono mb-0.5">
                {label}
              </p>
              <p className="text-xl font-extrabold font-mono" style={{ color }}>
                {value}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--color-text-muted)]" />
          <input
            type="text"
            placeholder="Search alerts…"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary-500)] transition-colors"
          />
        </div>

        {/* Severity filter */}
        <div className="relative">
          <FunnelIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--color-text-muted)]" />
          <select
            value={sevFilter}
            onChange={(e) => { setSevFilter(e.target.value); setPage(1); }}
            className="pl-8 pr-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-primary-500)] transition-colors appearance-none cursor-pointer"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* Status filter */}
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          className="px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-primary-500)] transition-colors appearance-none cursor-pointer"
        >
          <option value="">All Statuses</option>
          <option value="NEW">New</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
          <option value="DISMISSED">Dismissed</option>
        </select>
      </div>

      {/* Alert Table */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
        {isLoading ? (
          <div className="p-10 text-center text-[var(--color-text-muted)] text-sm">
            <div className="w-8 h-8 border-2 border-[var(--color-primary-500)] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            Loading alerts…
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-10 text-center">
            <ShieldExclamationIcon className="w-12 h-12 text-[var(--color-text-muted)] mx-auto mb-3 opacity-50" />
            <p className="text-sm text-[var(--color-text-muted)]">No security alerts found.</p>
            <p className="text-xs text-[var(--color-text-muted)] mt-1">
              Alerts are generated automatically from endpoint telemetry and threat detection.
            </p>
          </div>
        ) : (
          <>
            {/* Table header */}
            <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 px-4 py-2.5 bg-[var(--color-surface-200)] border-b border-[var(--color-border)] text-[9px] font-bold text-[var(--color-text-muted)] uppercase tracking-widest font-mono">
              <span />
              <span>Alert</span>
              <span>Severity</span>
              <span>Status</span>
              <span>Detected</span>
              <span>Actions</span>
            </div>

            {/* Table rows */}
            {alerts.map((alert: SecurityAlertSummary) => (
              <div
                key={alert.id}
                className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 items-center px-4 py-3 border-b border-[var(--color-border)]/50 hover:bg-[var(--color-surface-200)]/50 transition-colors group"
              >
                {/* Severity dot */}
                <SevDot severity={alert.severity} />

                {/* Title + meta */}
                <div className="min-w-0">
                  <p className="text-xs font-bold text-[var(--color-text-primary)] truncate">
                    {alert.title}
                  </p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[9px] font-mono text-[var(--color-text-muted)] truncate">
                      {alert.hostname ?? "Unknown Host"} • {alert.alert_type}
                    </span>
                    {alert.mitre_technique && (
                      <span className="text-[9px] font-mono bg-[var(--color-surface-300)] px-1 rounded text-[var(--color-text-muted)]">
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

                {/* Severity */}
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-extrabold uppercase font-mono ${SEV_BADGE[alert.severity] ?? ""}`}>
                  {alert.severity}
                </span>

                {/* Status */}
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase font-mono ${STATUS_BADGE[alert.status] ?? ""}`}>
                  {alert.status}
                </span>

                {/* Timestamp */}
                <span className="text-[10px] font-mono text-[var(--color-text-muted)] whitespace-nowrap">
                  {relativeTime(alert.detected_at)}
                </span>

                {/* Action buttons */}
                <div className="flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                  {/* View Details */}
                  <button
                    onClick={() => setSelectedAlertUuid(alert.id)}
                    title="View details"
                    className="p-1 rounded hover:bg-[var(--color-surface-300)] text-[var(--color-text-muted)] hover:text-[var(--color-primary-500)] transition-colors"
                  >
                    <EyeIcon className="w-3.5 h-3.5" />
                  </button>
                  {/* Quick Acknowledge */}
                  {alert.status === "NEW" && (
                    <button
                      onClick={() => ackMut.mutate(alert.id)}
                      title="Acknowledge"
                      disabled={ackMut.isPending}
                      className="p-1 rounded hover:bg-blue-500/10 text-[var(--color-text-muted)] hover:text-blue-400 transition-colors disabled:opacity-50"
                    >
                      <CheckCircleIcon className="w-3.5 h-3.5" />
                    </button>
                  )}
                  {/* Quick Investigate */}
                  {(alert.status === "NEW" || alert.status === "ACKNOWLEDGED") && (
                    <button
                      onClick={() => invMut.mutate(alert.id)}
                      title="Investigate"
                      disabled={invMut.isPending}
                      className="p-1 rounded hover:bg-yellow-500/10 text-[var(--color-text-muted)] hover:text-yellow-400 transition-colors disabled:opacity-50"
                    >
                      <MagnifyingGlassIcon className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            ))}

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-[var(--color-border)] text-xs font-mono text-[var(--color-text-muted)]">
                <span>{total} total alerts</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="px-3 py-1 rounded bg-[var(--color-surface-300)] border border-[var(--color-border)] hover:bg-[var(--color-surface-400)] disabled:opacity-40 transition-colors"
                  >
                    Prev
                  </button>
                  <span>Page {page} / {totalPages}</span>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="px-3 py-1 rounded bg-[var(--color-surface-300)] border border-[var(--color-border)] hover:bg-[var(--color-surface-400)] disabled:opacity-40 transition-colors"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Alert Detail Modal */}
      {selectedAlertUuid && (
        <AlertDetailModal
          alertUuid={selectedAlertUuid}
          onClose={() => setSelectedAlertUuid(null)}
        />
      )}
    </div>
  );
}
