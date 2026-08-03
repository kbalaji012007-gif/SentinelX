import { useState } from "react";
import {
  ClockIcon,
  UserIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import { mockIncidents, type IncidentMock } from "../../utils/mockData";

export default function IncidentsPage() {
  const [activeIncident, setActiveIncident] = useState<IncidentMock | null>(null);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Incident Management</h1>
          <p className="text-xs text-[var(--color-text-secondary)]">SOC Incident Lifecycle, SLA tracking, and SOAR response execution</p>
        </div>
        <button className="px-4 py-2 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold shadow-lg shadow-[var(--color-primary-500)]/20 hover:opacity-90">
          + Create Security Incident
        </button>
      </div>

      {/* Grid of Incident Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {mockIncidents.map((inc) => (
          <div
            key={inc.id}
            onClick={() => setActiveIncident(inc)}
            className="glass rounded-xl p-5 border border-[var(--color-border)] hover:border-[var(--color-primary-500)]/50 transition-all cursor-pointer space-y-4 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="font-mono text-xs font-bold text-[var(--color-primary-500)]">{inc.id}</span>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                    inc.priority.includes("P0") ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)]" :
                    inc.priority.includes("P1") ? "bg-[var(--color-high)]/20 text-[var(--color-high)]" :
                    "bg-[var(--color-medium)]/20 text-[var(--color-medium)]"
                  }`}>
                    {inc.priority}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]">
                    {inc.status}
                  </span>
                </div>
              </div>

              <h2 className="text-sm font-bold text-[var(--color-text-primary)] leading-snug">{inc.title}</h2>
              <p className="text-xs text-[var(--color-text-secondary)] line-clamp-2 mt-1">{inc.description}</p>
            </div>

            <div className="pt-3 border-t border-[var(--color-border)] flex items-center justify-between text-xs text-[var(--color-text-muted)]">
              <div className="flex items-center gap-1.5">
                <UserIcon className="w-3.5 h-3.5 text-[var(--color-text-secondary)]" />
                <span className="text-[11px] text-[var(--color-text-secondary)]">{inc.assignee}</span>
              </div>
              <div className="flex items-center gap-1 text-[var(--color-high)] font-mono font-bold text-[11px]">
                <ClockIcon className="w-3.5 h-3.5" />
                <span>SLA: {inc.slaMinutesRemaining}m</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Incident Detail Modal */}
      {activeIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-2xl bg-[var(--color-surface-100)] rounded-2xl border border-[var(--color-border)] p-6 space-y-6 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-[var(--color-border)]">
              <div>
                <span className="font-mono text-xs font-bold text-[var(--color-primary-500)]">{activeIncident.id}</span>
                <h2 className="text-lg font-bold text-[var(--color-text-primary)]">{activeIncident.title}</h2>
              </div>
              <button onClick={() => setActiveIncident(null)} className="p-1 rounded text-[var(--color-text-muted)] hover:text-white">
                <XMarkIcon className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold mb-1">Incident Summary</p>
                <p className="text-[var(--color-text-secondary)] bg-[var(--color-surface-200)] p-3 rounded-lg border border-[var(--color-border)] leading-relaxed">
                  {activeIncident.description}
                </p>
              </div>

              {/* Timeline Events */}
              <div>
                <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold mb-3">Incident Timeline</p>
                <div className="space-y-3 relative pl-4 border-l border-[var(--color-border)]">
                  {activeIncident.timeline.map((event, idx) => (
                    <div key={idx} className="relative">
                      <span className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-[var(--color-primary-500)]" />
                      <div className="bg-[var(--color-surface-200)] p-2.5 rounded-lg border border-[var(--color-border)]">
                        <div className="flex items-center justify-between text-[10px] text-[var(--color-text-muted)] mb-1 font-mono">
                          <span>{event.time}</span>
                          <span className="font-bold text-[var(--color-secondary-500)]">{event.author}</span>
                        </div>
                        <p className="text-xs font-medium text-[var(--color-text-primary)]">{event.event}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-[var(--color-border)] flex justify-end gap-3">
              <button onClick={() => setActiveIncident(null)} className="px-4 py-2 text-xs font-bold rounded-lg bg-[var(--color-surface-300)] text-[var(--color-text-primary)]">
                Close View
              </button>
              <button className="px-4 py-2 text-xs font-bold rounded-lg bg-[var(--color-safe)] text-[var(--color-surface-0)]">
                Mark as Resolved
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
