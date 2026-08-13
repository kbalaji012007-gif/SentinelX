/**
 * SentinelX AI – Alert Detail Modal (Phase 6.4)
 * Full security alert detail view with analyst action buttons.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldExclamationIcon,
  XMarkIcon,
  CheckCircleIcon,
  MagnifyingGlassIcon,
  CheckIcon,
  NoSymbolIcon,
  SparklesIcon,
  BoltIcon,
  ClockIcon,
  CpuChipIcon,
} from "@heroicons/react/24/outline";
import { Link } from "react-router-dom";

import {
  getAlert,
  acknowledgeAlert,
  investigateAlert,
  resolveAlert,
  dismissAlert,
} from "../../services/alertService";
import type { SecurityAlert } from "../../types/alert";
import { SEVERITY_COLORS, STATUS_COLORS } from "../../types/alert";

interface AlertDetailModalProps {
  alertUuid: string | null;
  onClose: () => void;
  /** The current user's role, used for RBAC display logic */
  userRole?: string;
}

const ANALYST_ROLES = new Set([
  "Super Administrator", "Administrator", "SOC Manager", "SOC Analyst",
  "Threat Hunter", "Incident Responder", "Admin", "Manager", "Analyst",
]);
const MANAGER_ROLES = new Set([
  "Super Administrator", "Administrator", "SOC Manager", "Admin", "Manager",
]);

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS] ?? "#6b7280";
  return (
    <span
      className="px-2 py-0.5 rounded text-[10px] font-extrabold uppercase font-mono tracking-wider border"
      style={{
        backgroundColor: `${color}20`,
        color,
        borderColor: `${color}40`,
      }}
    >
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color = STATUS_COLORS[status as keyof typeof STATUS_COLORS] ?? "#6b7280";
  return (
    <span
      className="px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono"
      style={{ backgroundColor: `${color}20`, color }}
    >
      {status}
    </span>
  );
}

export default function AlertDetailModal({
  alertUuid,
  onClose,
  userRole = "Read Only",
}: AlertDetailModalProps) {
  const qc = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);

  const { data: alert, isLoading } = useQuery<SecurityAlert>({
    queryKey: ["alert-detail", alertUuid],
    queryFn: () => getAlert(alertUuid!),
    enabled: !!alertUuid,
  });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["alerts"] });
    void qc.invalidateQueries({ queryKey: ["alert-statistics"] });
    void qc.invalidateQueries({ queryKey: ["alert-detail", alertUuid] });
  };

  const ackMut = useMutation({
    mutationFn: () => acknowledgeAlert(alertUuid!),
    onSuccess: invalidate,
    onError: (e: unknown) => setActionError(String(e)),
  });
  const invMut = useMutation({
    mutationFn: () => investigateAlert(alertUuid!),
    onSuccess: invalidate,
    onError: (e: unknown) => setActionError(String(e)),
  });
  const resMut = useMutation({
    mutationFn: () => resolveAlert(alertUuid!),
    onSuccess: invalidate,
    onError: (e: unknown) => setActionError(String(e)),
  });
  const disMut = useMutation({
    mutationFn: () => dismissAlert(alertUuid!),
    onSuccess: () => { invalidate(); onClose(); },
    onError: (e: unknown) => setActionError(String(e)),
  });

  const isAnalyst = ANALYST_ROLES.has(userRole);
  const isManager = MANAGER_ROLES.has(userRole);

  if (!alertUuid) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Security Alert Detail"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="bg-[#0f1520] border border-[var(--color-border)] rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">

        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-3">
            <ShieldExclamationIcon className="w-6 h-6 text-[var(--color-critical)] shrink-0" />
            <div>
              <h2 className="text-base font-bold text-[var(--color-text-primary)]">
                Security Alert Detail
              </h2>
              {alert && (
                <p className="text-[10px] font-mono text-[var(--color-text-muted)]">
                  {alert.alert_id}
                </p>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] transition-colors"
            aria-label="Close dialog"
          >
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        {isLoading && (
          <div className="p-10 text-center text-[var(--color-text-muted)] text-sm">
            <div className="w-8 h-8 border-2 border-[var(--color-primary-500)] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            Loading alert details…
          </div>
        )}

        {alert && (
          <div className="p-5 space-y-5">
            {/* Title + Badges */}
            <div>
              <p className="text-base font-bold text-[var(--color-text-primary)] mb-2">
                {alert.title}
              </p>
              <div className="flex flex-wrap gap-2 items-center">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
                <span className="text-[10px] font-mono bg-[var(--color-surface-200)] px-2 py-0.5 rounded border border-[var(--color-border)] text-[var(--color-text-muted)]">
                  {alert.alert_type}
                </span>
              </div>
            </div>

            {/* Description */}
            {alert.description && (
              <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                {alert.description}
              </p>
            )}

            {/* Grid: Key Fields */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              {[
                { label: "Source", value: alert.source ?? "—" },
                { label: "Hostname", value: (alert.alert_metadata?.hostname as string) ?? "—" },
                { label: "Platform", value: (alert.alert_metadata?.platform as string) ?? "—" },
                { label: "Occurrences", value: String((alert.evidence?.occurrence_count as number) ?? 1) },
                { label: "MITRE Tactic", value: alert.mitre_tactic ?? "—" },
                { label: "MITRE Technique", value: alert.mitre_technique ?? "—" },
              ].map(({ label, value }) => (
                <div key={label} className="p-2 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)]">
                  <p className="text-[9px] uppercase font-bold text-[var(--color-text-muted)] mb-0.5">{label}</p>
                  <p className="text-[var(--color-text-primary)] font-bold truncate">{value}</p>
                </div>
              ))}
            </div>

            {/* Timestamps */}
            <div className="grid grid-cols-2 gap-3 text-[10px] font-mono text-[var(--color-text-muted)]">
              <div className="flex items-center gap-1.5">
                <ClockIcon className="w-3.5 h-3.5" />
                <span>Detected: {new Date(alert.detected_at).toLocaleString()}</span>
              </div>
              {alert.acknowledged_at && (
                <div className="flex items-center gap-1.5">
                  <CheckCircleIcon className="w-3.5 h-3.5 text-blue-400" />
                  <span>ACK: {new Date(alert.acknowledged_at).toLocaleString()}</span>
                </div>
              )}
              {alert.resolved_at && (
                <div className="flex items-center gap-1.5">
                  <CheckIcon className="w-3.5 h-3.5 text-green-400" />
                  <span>Resolved: {new Date(alert.resolved_at).toLocaleString()}</span>
                </div>
              )}
            </div>

            {/* Evidence JSONB */}
            {Object.keys(alert.evidence).length > 0 && (
              <div>
                <p className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <CpuChipIcon className="w-3.5 h-3.5" />
                  Evidence
                </p>
                <pre className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[9px] font-mono text-[var(--color-text-secondary)] overflow-x-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(alert.evidence, null, 2)}
                </pre>
              </div>
            )}

            {/* Action error */}
            {actionError && (
              <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-[10px] font-mono">
                Error: {actionError}
              </div>
            )}

            {/* Actions */}
            <div className="flex flex-wrap gap-2 pt-2 border-t border-[var(--color-border)]">
              {/* Investigate with AI SOC */}
              <Link
                to={alert.threat_id ? `/ai-soc?threat_id=${alert.threat_id}` : "/ai-soc"}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold bg-gradient-to-r from-[var(--color-primary-500)] to-purple-600 text-white hover:opacity-90 transition-all"
              >
                <SparklesIcon className="w-3.5 h-3.5" />
                Investigate with AI SOC
              </Link>

              <Link
                to="/soar"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold bg-[var(--color-surface-300)] border border-[var(--color-border)] text-[var(--color-primary-500)] hover:bg-[var(--color-surface-400)] transition-all"
              >
                <BoltIcon className="w-3.5 h-3.5" />
                SOAR Playbooks
              </Link>

              {/* Analyst actions */}
              {isAnalyst && alert.status === "NEW" && (
                <button
                  onClick={() => ackMut.mutate()}
                  disabled={ackMut.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold bg-blue-500/10 border border-blue-500/30 text-blue-400 hover:bg-blue-500/20 transition-all disabled:opacity-50"
                >
                  <CheckCircleIcon className="w-3.5 h-3.5" />
                  Acknowledge
                </button>
              )}
              {isAnalyst && (alert.status === "NEW" || alert.status === "ACKNOWLEDGED") && (
                <button
                  onClick={() => invMut.mutate()}
                  disabled={invMut.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/20 transition-all disabled:opacity-50"
                >
                  <MagnifyingGlassIcon className="w-3.5 h-3.5" />
                  Investigate
                </button>
              )}
              {isManager && alert.status !== "RESOLVED" && alert.status !== "DISMISSED" && (
                <button
                  onClick={() => resMut.mutate()}
                  disabled={resMut.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20 transition-all disabled:opacity-50"
                >
                  <CheckIcon className="w-3.5 h-3.5" />
                  Resolve
                </button>
              )}
              {isManager && alert.status !== "DISMISSED" && (
                <button
                  onClick={() => disMut.mutate()}
                  disabled={disMut.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold bg-slate-500/10 border border-slate-500/30 text-slate-400 hover:bg-slate-500/20 transition-all disabled:opacity-50"
                >
                  <NoSymbolIcon className="w-3.5 h-3.5" />
                  Dismiss
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
