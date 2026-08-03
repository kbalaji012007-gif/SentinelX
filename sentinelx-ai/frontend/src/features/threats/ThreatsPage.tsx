import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  ShieldExclamationIcon,
  XMarkIcon,
  ExclamationCircleIcon,
  ArrowPathIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  BoltIcon,
  LinkIcon,
  ClockIcon,
  CpuChipIcon,
  ServerIcon,
  EyeIcon,
} from "@heroicons/react/24/outline";
import {
  fetchThreats,
  fetchThreatById,
  updateThreat,
} from "../../services/threatService";
import type {
  ThreatSummary,
  ThreatStatus,
  ThreatSeverity,
  IOCType,
  ThreatListParams,
} from "../../types/threat";

// ─── Severity / Status helpers ───────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  Critical:
    "bg-[var(--color-critical)]/15 text-[var(--color-critical)] border border-[var(--color-critical)]/40",
  High: "bg-[var(--color-high)]/15 text-[var(--color-high)] border border-[var(--color-high)]/40",
  Medium:
    "bg-[var(--color-medium)]/15 text-[var(--color-medium)] border border-[var(--color-medium)]/40",
  Low: "bg-[var(--color-low)]/15 text-[var(--color-low)] border border-[var(--color-low)]/40",
};

const SEVERITY_DOT: Record<string, string> = {
  Critical: "bg-[var(--color-critical)]",
  High: "bg-[var(--color-high)]",
  Medium: "bg-[var(--color-medium)]",
  Low: "bg-[var(--color-low)]",
};

const STATUS_STYLES: Record<string, string> = {
  New: "bg-[var(--color-primary-500)]/10 text-[var(--color-primary-500)] border border-[var(--color-primary-500)]/30",
  Investigating:
    "bg-[var(--color-high)]/10 text-[var(--color-high)] border border-[var(--color-high)]/30",
  Mitigated:
    "bg-[var(--color-safe)]/10 text-[var(--color-safe)] border border-[var(--color-safe)]/30",
  Closed:
    "bg-[var(--color-surface-400)]/50 text-[var(--color-text-muted)] border border-[var(--color-border)]",
};

const IOC_TYPE_COLORS: Record<IOCType, string> = {
  IP: "text-[var(--color-critical)] bg-[var(--color-critical)]/10",
  Domain: "text-[var(--color-high)] bg-[var(--color-high)]/10",
  URL: "text-[var(--color-medium)] bg-[var(--color-medium)]/10",
  Hash: "text-[var(--color-primary-500)] bg-[var(--color-primary-500)]/10",
  Email: "text-[var(--color-secondary-500)] bg-[var(--color-secondary-500)]/10",
};

const SEVERITIES: Array<ThreatSeverity | ""> = [
  "",
  "Critical",
  "High",
  "Medium",
  "Low",
];
const STATUSES: Array<ThreatStatus | ""> = [
  "",
  "New",
  "Investigating",
  "Mitigated",
  "Closed",
];

function formatDetectedAt(iso: string): string {
  try {
    const d = new Date(iso);
    const now = Date.now();
    const diff = now - d.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return d.toLocaleDateString();
  } catch {
    return iso;
  }
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold ${SEVERITY_STYLES[severity] ?? ""}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${SEVERITY_DOT[severity] ?? "bg-gray-500"}`}
      />
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold ${STATUS_STYLES[status] ?? ""}`}
    >
      {status}
    </span>
  );
}

// ─── Loading State ────────────────────────────────────────────────────────────

function TableSkeleton() {
  return (
    <div className="space-y-1">
      {Array.from({ length: 8 }).map((_, i) => (
        <div
          key={i}
          className="h-14 w-full skeleton rounded-lg opacity-60"
          style={{ animationDelay: `${i * 80}ms` }}
        />
      ))}
    </div>
  );
}

// ─── Empty State ─────────────────────────────────────────────────────────────

function EmptyState({ hasFilters }: { hasFilters: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="w-16 h-16 rounded-2xl bg-[var(--color-surface-200)] border border-[var(--color-border)] flex items-center justify-center mb-4">
        <ShieldExclamationIcon className="w-8 h-8 text-[var(--color-text-muted)]" />
      </div>
      <p className="text-sm font-bold text-[var(--color-text-secondary)]">
        {hasFilters ? "No threats match your filters" : "No threats detected"}
      </p>
      <p className="text-xs text-[var(--color-text-muted)] mt-1 max-w-xs">
        {hasFilters
          ? "Try clearing the filters or broadening your search."
          : "All systems are clear. Threats will appear here as they are detected."}
      </p>
    </div>
  );
}

// ─── Error State ─────────────────────────────────────────────────────────────

function ErrorBanner({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="p-4 rounded-xl bg-[var(--color-critical)]/10 border border-[var(--color-critical)]/30 flex items-center justify-between">
      <div className="flex items-center gap-2 text-[var(--color-critical)] text-xs font-semibold">
        <ExclamationCircleIcon className="w-4 h-4 shrink-0" />
        <span>Failed to load threats. Backend may be unreachable.</span>
      </div>
      <button
        onClick={onRetry}
        className="flex items-center gap-1 text-xs font-bold text-[var(--color-critical)] hover:opacity-80 transition-opacity"
      >
        <ArrowPathIcon className="w-3.5 h-3.5" />
        Retry
      </button>
    </div>
  );
}

// ─── Threat Detail Drawer ─────────────────────────────────────────────────────

interface ThreatDrawerProps {
  threatId: string;
  onClose: () => void;
}

function ThreatDrawer({ threatId, onClose }: ThreatDrawerProps) {
  const queryClient = useQueryClient();

  const { data: threat, isLoading } = useQuery({
    queryKey: ["threat", threatId],
    queryFn: () => fetchThreatById(threatId),
    staleTime: 30_000,
  });

  const updateMutation = useMutation({
    mutationFn: (status: ThreatStatus) =>
      updateThreat(threatId, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["threat", threatId] });
      queryClient.invalidateQueries({ queryKey: ["threats"] });
    },
  });

  const drawerBody = () => {
    if (isLoading) {
      return (
        <div className="space-y-4 p-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-10 skeleton rounded-lg" />
          ))}
        </div>
      );
    }
    if (!threat) return null;

    return (
      <div className="flex flex-col h-full">
        {/* Drawer Header */}
        <div className="px-6 py-5 border-b border-[var(--color-border)] flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <ShieldExclamationIcon className="w-4 h-4 text-[var(--color-primary-500)] shrink-0" />
              <span className="text-[10px] font-mono text-[var(--color-text-muted)] uppercase tracking-widest">
                Threat Detail
              </span>
            </div>
            <h2 className="text-sm font-extrabold text-[var(--color-text-primary)] leading-snug">
              {threat.title}
            </h2>
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              <SeverityBadge severity={threat.severity} />
              <StatusBadge status={threat.status} />
              {threat.confidence_score !== null &&
                threat.confidence_score !== undefined && (
                  <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
                    {threat.confidence_score}% confidence
                  </span>
                )}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-300)] transition-all"
          >
            <XMarkIcon className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Description */}
          {threat.description && (
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold mb-1.5">
                Description
              </p>
              <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                {threat.description}
              </p>
            </div>
          )}

          {/* MITRE ATT&CK Section */}
          <div className="p-4 rounded-xl bg-[var(--color-secondary-500)]/5 border border-[var(--color-secondary-500)]/20">
            <div className="flex items-center gap-2 mb-3">
              <CpuChipIcon className="w-4 h-4 text-[var(--color-secondary-500)]" />
              <p className="text-[10px] uppercase font-bold text-[var(--color-secondary-500)] tracking-widest">
                MITRE ATT&CK
              </p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-[10px] text-[var(--color-text-muted)] mb-0.5">
                  Technique ID
                </p>
                <p className="text-sm font-mono font-bold text-[var(--color-secondary-400)]">
                  {threat.mitre_technique_id || "—"}
                </p>
              </div>
              <div>
                <p className="text-[10px] text-[var(--color-text-muted)] mb-0.5">
                  Source
                </p>
                <p className="text-xs font-mono text-[var(--color-text-primary)] truncate">
                  {threat.source || "—"}
                </p>
              </div>
            </div>
          </div>

          {/* Asset Information */}
          {threat.asset_id && (
            <div className="p-4 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)]">
              <div className="flex items-center gap-2 mb-3">
                <ServerIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
                <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] tracking-widest">
                  Asset Information
                </p>
              </div>
              <p className="text-xs font-mono text-[var(--color-primary-400)]">
                {threat.asset_id}
              </p>
            </div>
          )}

          {/* Timeline */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <ClockIcon className="w-4 h-4 text-[var(--color-text-muted)]" />
              <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] tracking-widest">
                Timeline
              </p>
            </div>
            <div className="space-y-2">
              {[
                {
                  label: "Detected",
                  time: threat.detected_at,
                  color: "var(--color-critical)",
                },
                {
                  label: "Created",
                  time: threat.created_at,
                  color: "var(--color-primary-500)",
                },
                {
                  label: "Updated",
                  time: threat.updated_at,
                  color: "var(--color-text-muted)",
                },
              ].map(({ label, time, color }) => (
                <div key={label} className="flex items-center gap-3 text-xs">
                  <div
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ backgroundColor: color }}
                  />
                  <span className="text-[var(--color-text-muted)] w-16 shrink-0">
                    {label}
                  </span>
                  <span className="font-mono text-[var(--color-text-secondary)]">
                    {new Date(time).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Alerts List */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <BoltIcon className="w-4 h-4 text-[var(--color-high)]" />
                <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] tracking-widest">
                  Alerts
                </p>
              </div>
              <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
                {threat.alerts.length} total
              </span>
            </div>

            {threat.alerts.length === 0 ? (
              <p className="text-xs text-[var(--color-text-muted)] italic">
                No alerts linked to this threat.
              </p>
            ) : (
              <div className="space-y-2">
                {threat.alerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-1"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-xs font-semibold text-[var(--color-text-primary)] leading-tight">
                        {alert.alert_name}
                      </p>
                      <SeverityBadge severity={alert.severity} />
                    </div>
                    <div className="flex items-center gap-3 text-[10px] text-[var(--color-text-muted)]">
                      {alert.alert_type && <span>{alert.alert_type}</span>}
                      {alert.alert_source && (
                        <>
                          <span>·</span>
                          <span className="font-mono">{alert.alert_source}</span>
                        </>
                      )}
                      <span>·</span>
                      <span
                        className={
                          alert.acknowledged
                            ? "text-[var(--color-safe)]"
                            : "text-[var(--color-high)]"
                        }
                      >
                        {alert.acknowledged ? "Acknowledged" : "Unacknowledged"}
                      </span>
                    </div>
                    {alert.message && (
                      <p className="text-[10px] text-[var(--color-text-secondary)] leading-relaxed mt-1">
                        {alert.message}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* IOC Panel */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <LinkIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
                <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] tracking-widest">
                  Indicators of Compromise
                </p>
              </div>
              <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
                {threat.iocs.length} total
              </span>
            </div>

            {threat.iocs.length === 0 ? (
              <p className="text-xs text-[var(--color-text-muted)] italic">
                No IOCs linked to this threat.
              </p>
            ) : (
              <div className="space-y-2">
                {threat.iocs.map((ioc) => (
                  <div
                    key={ioc.id}
                    className="flex items-center gap-3 p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)]"
                  >
                    <span
                      className={`text-[9px] font-bold px-2 py-0.5 rounded font-mono uppercase ${IOC_TYPE_COLORS[ioc.type as IOCType] ?? ""}`}
                    >
                      {ioc.type}
                    </span>
                    <span className="text-xs font-mono text-[var(--color-text-primary)] flex-1 truncate">
                      {ioc.value}
                    </span>
                    {ioc.confidence !== null && ioc.confidence !== undefined && (
                      <span className="text-[10px] text-[var(--color-text-muted)] shrink-0">
                        {ioc.confidence}%
                      </span>
                    )}
                    {ioc.reputation && (
                      <span
                        className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                          ioc.reputation === "Malicious"
                            ? "text-[var(--color-critical)] bg-[var(--color-critical)]/10"
                            : ioc.reputation === "Suspicious"
                            ? "text-[var(--color-high)] bg-[var(--color-high)]/10"
                            : "text-[var(--color-text-muted)] bg-[var(--color-surface-300)]"
                        }`}
                      >
                        {ioc.reputation}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Drawer Footer – Status Actions */}
        <div className="px-6 py-4 border-t border-[var(--color-border)] space-y-2">
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold tracking-wider mb-2">
            Update Status
          </p>
          <div className="grid grid-cols-2 gap-2">
            {(["Investigating", "Mitigated", "Closed"] as ThreatStatus[])
              .filter((s) => s !== threat.status)
              .map((s) => (
                <button
                  key={s}
                  onClick={() => updateMutation.mutate(s)}
                  disabled={updateMutation.isPending}
                  className={`py-2 rounded-lg text-xs font-bold transition-all disabled:opacity-50 ${
                    s === "Mitigated"
                      ? "bg-[var(--color-safe)]/10 text-[var(--color-safe)] border border-[var(--color-safe)]/30 hover:bg-[var(--color-safe)]/20"
                      : s === "Closed"
                      ? "bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] border border-[var(--color-border)] hover:bg-[var(--color-surface-400)]"
                      : "bg-[var(--color-high)]/10 text-[var(--color-high)] border border-[var(--color-high)]/30 hover:bg-[var(--color-high)]/20"
                  }`}
                >
                  {updateMutation.isPending ? "…" : `Mark ${s}`}
                </button>
              ))}
          </div>
        </div>
      </div>
    );
  };

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm animate-fade-in"
        onClick={onClose}
      />
      {/* Drawer panel */}
      <div className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-lg bg-[var(--color-surface-100)] border-l border-[var(--color-border)] flex flex-col animate-slide-in shadow-2xl">
        {drawerBody()}
      </div>
    </>
  );
}

// ─── Pagination Controls ──────────────────────────────────────────────────────

interface PaginationProps {
  page: number;
  total: number;
  pageSize: number;
  onPageChange: (p: number) => void;
}

function Pagination({ page, total, pageSize, onPageChange }: PaginationProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-between pt-4 border-t border-[var(--color-border)]">
      <p className="text-xs text-[var(--color-text-muted)]">
        Page <span className="font-bold text-[var(--color-text-secondary)]">{page}</span> of{" "}
        <span className="font-bold text-[var(--color-text-secondary)]">{totalPages}</span>
        {" "}·{" "}
        <span className="font-bold text-[var(--color-text-secondary)]">{total}</span> total
      </p>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-300)] disabled:opacity-30 disabled:cursor-not-allowed transition-all"
        >
          <ChevronLeftIcon className="w-4 h-4" />
        </button>
        {Array.from({ length: Math.min(5, totalPages) }).map((_, i) => {
          const pageNum = Math.max(1, Math.min(page - 2, totalPages - 4)) + i;
          return (
            <button
              key={pageNum}
              onClick={() => onPageChange(pageNum)}
              className={`w-7 h-7 rounded-lg text-xs font-bold transition-all ${
                pageNum === page
                  ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                  : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-300)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {pageNum}
            </button>
          );
        })}
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
          className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-300)] disabled:opacity-30 disabled:cursor-not-allowed transition-all"
        >
          <ChevronRightIcon className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

// ─── Main Threats Page ────────────────────────────────────────────────────────

export default function ThreatsPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<ThreatSeverity | "">("");
  const [threatStatus, setThreatStatus] = useState<ThreatStatus | "">("");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 20;

  const params: ThreatListParams = {
    page,
    page_size: PAGE_SIZE,
    ...(severity ? { severity } : {}),
    ...(threatStatus ? { status: threatStatus } : {}),
    ...(search ? { search } : {}),
  };

  const {
    data,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["threats", params],
    queryFn: () => fetchThreats(params),
    staleTime: 30_000,
    placeholderData: (prev) => prev,
  });

  const handleSearch = useCallback(
    (value: string) => {
      setSearch(value);
      setPage(1);
    },
    []
  );

  const handleSeverity = useCallback((s: ThreatSeverity | "") => {
    setSeverity(s);
    setPage(1);
  }, []);

  const handleStatus = useCallback((s: ThreatStatus | "") => {
    setThreatStatus(s);
    setPage(1);
  }, []);

  const hasFilters = !!severity || !!threatStatus || !!search;
  const criticalCount =
    data?.items.filter((t) => t.severity === "Critical").length ?? 0;

  return (
    <div className="space-y-5 animate-fade-in relative">
      {/* ── Page Header ──────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
            Threat Detection &amp; Analysis
          </h1>
          <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
            Real-time threat monitoring and MITRE ATT&amp;CK correlation
          </p>
        </div>
        <div className="flex items-center gap-2">
          {criticalCount > 0 && (
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--color-critical)]/10 text-[var(--color-critical)] border border-[var(--color-critical)]/30 text-xs font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-critical)] animate-pulse" />
              {criticalCount} Critical Active
            </span>
          )}
          {data && (
            <span className="px-3 py-1.5 rounded-lg bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] border border-[var(--color-border)] text-xs font-semibold">
              {data.total} Total Threats
            </span>
          )}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 rounded-lg bg-[var(--color-surface-200)] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] transition-all disabled:opacity-50"
            title="Refresh"
          >
            <ArrowPathIcon
              className={`w-4 h-4 ${isFetching ? "animate-spin" : ""}`}
            />
          </button>
        </div>
      </div>

      {/* ── Error Banner ─────────────────────────────────────────── */}
      {isError && <ErrorBanner onRetry={() => refetch()} />}

      {/* ── Filter Bar ───────────────────────────────────────────── */}
      <div className="glass rounded-xl p-4 space-y-3 border border-[var(--color-border)]">
        {/* Search */}
        <div className="relative">
          <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            id="threat-search"
            type="text"
            placeholder="Search by title, source, or MITRE technique…"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-lg pl-9 pr-4 py-2.5 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)] transition-colors"
          />
          {search && (
            <button
              onClick={() => handleSearch("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
            >
              <XMarkIcon className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Filter pills row */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Severity filter */}
          <div className="flex items-center gap-1.5">
            <FunnelIcon className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />
            <span className="text-[10px] text-[var(--color-text-muted)] font-bold uppercase tracking-wider">
              Severity:
            </span>
            <div className="flex items-center gap-1">
              {SEVERITIES.map((s) => (
                <button
                  key={s || "all"}
                  onClick={() => handleSeverity(s)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all ${
                    severity === s
                      ? s
                        ? `${SEVERITY_STYLES[s]} !border-transparent`
                        : "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                      : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)]"
                  }`}
                >
                  {s || "All"}
                </button>
              ))}
            </div>
          </div>

          {/* Status filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-[var(--color-text-muted)] font-bold uppercase tracking-wider">
              Status:
            </span>
            <div className="flex items-center gap-1">
              {STATUSES.map((s) => (
                <button
                  key={s || "all"}
                  onClick={() => handleStatus(s)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all ${
                    threatStatus === s
                      ? s
                        ? `${STATUS_STYLES[s]} !border-transparent`
                        : "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                      : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)]"
                  }`}
                >
                  {s || "All"}
                </button>
              ))}
            </div>
          </div>

          {/* Clear filters */}
          {hasFilters && (
            <button
              onClick={() => {
                setSeverity("");
                setThreatStatus("");
                setSearch("");
                setPage(1);
              }}
              className="flex items-center gap-1 text-[10px] font-bold text-[var(--color-text-muted)] hover:text-[var(--color-critical)] transition-colors ml-auto"
            >
              <XMarkIcon className="w-3 h-3" />
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* ── Threats Table ─────────────────────────────────────────── */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
        {isLoading ? (
          <div className="p-4">
            <TableSkeleton />
          </div>
        ) : !data || data.items.length === 0 ? (
          <EmptyState hasFilters={hasFilters} />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-[var(--color-surface-200)]/70 text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider border-b border-[var(--color-border)]">
                    <th className="px-4 py-3 font-bold">Threat</th>
                    <th className="px-4 py-3 font-bold">Severity</th>
                    <th className="px-4 py-3 font-bold">Status</th>
                    <th className="px-4 py-3 font-bold">MITRE ID</th>
                    <th className="px-4 py-3 font-bold">Source</th>
                    <th className="px-4 py-3 font-bold">Confidence</th>
                    <th className="px-4 py-3 font-bold">Detected</th>
                    <th className="px-4 py-3 font-bold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border)]">
                  {data.items.map((threat: ThreatSummary) => (
                    <ThreatRow
                      key={threat.id}
                      threat={threat}
                      onInspect={() => setSelectedId(threat.id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="px-4 pb-4">
              <Pagination
                page={page}
                total={data.total}
                pageSize={PAGE_SIZE}
                onPageChange={setPage}
              />
            </div>
          </>
        )}
      </div>

      {/* ── Threat Detail Drawer ──────────────────────────────────── */}
      {selectedId && (
        <ThreatDrawer
          threatId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

// ─── Threat Table Row ─────────────────────────────────────────────────────────

interface ThreatRowProps {
  threat: ThreatSummary;
  onInspect: () => void;
}

function ThreatRow({ threat, onInspect }: ThreatRowProps) {
  return (
    <tr
      onClick={onInspect}
      className="hover:bg-[var(--color-surface-200)]/60 cursor-pointer transition-colors group"
    >
      {/* Title */}
      <td className="px-4 py-3.5 max-w-[240px]">
        <p className="font-semibold text-[var(--color-text-primary)] truncate group-hover:text-[var(--color-primary-400)] transition-colors">
          {threat.title}
        </p>
        {threat.asset_id && (
          <p className="text-[10px] font-mono text-[var(--color-text-muted)] mt-0.5 truncate">
            asset: {threat.asset_id.slice(0, 8)}…
          </p>
        )}
      </td>

      {/* Severity */}
      <td className="px-4 py-3.5">
        <SeverityBadge severity={threat.severity} />
      </td>

      {/* Status */}
      <td className="px-4 py-3.5">
        <StatusBadge status={threat.status} />
      </td>

      {/* MITRE ID */}
      <td className="px-4 py-3.5">
        <span className="font-mono font-bold text-[var(--color-secondary-400)] text-[11px]">
          {threat.mitre_technique_id || "—"}
        </span>
      </td>

      {/* Source */}
      <td className="px-4 py-3.5 font-mono text-[11px] text-[var(--color-primary-400)] max-w-[120px] truncate">
        {threat.source || "—"}
      </td>

      {/* Confidence */}
      <td className="px-4 py-3.5">
        {threat.confidence_score !== null &&
        threat.confidence_score !== undefined ? (
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-16 bg-[var(--color-surface-300)] rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${threat.confidence_score}%`,
                  backgroundColor:
                    threat.confidence_score >= 80
                      ? "var(--color-critical)"
                      : threat.confidence_score >= 50
                      ? "var(--color-high)"
                      : "var(--color-medium)",
                }}
              />
            </div>
            <span className="text-[10px] font-mono text-[var(--color-text-muted)]">
              {threat.confidence_score}%
            </span>
          </div>
        ) : (
          <span className="text-[var(--color-text-muted)]">—</span>
        )}
      </td>

      {/* Detected */}
      <td className="px-4 py-3.5 text-[var(--color-text-muted)] text-[11px] whitespace-nowrap">
        {formatDetectedAt(threat.detected_at)}
      </td>

      {/* Action */}
      <td className="px-4 py-3.5 text-right">
        <button
          onClick={(e) => {
            e.stopPropagation();
            onInspect();
          }}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-bold rounded-lg bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] border border-[var(--color-border)] hover:bg-[var(--color-primary-500)]/10 hover:text-[var(--color-primary-400)] hover:border-[var(--color-primary-500)]/40 transition-all"
        >
          <EyeIcon className="w-3 h-3" />
          Inspect
        </button>
      </td>
    </tr>
  );
}
