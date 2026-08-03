import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  ShieldExclamationIcon,
  XMarkIcon,
  ExclamationCircleIcon,
  ArrowPathIcon,
  UserIcon,
  PlusIcon,
  DocumentTextIcon,
  ClockIcon,
  PaperClipIcon,
  EyeIcon,
  Squares2X2Icon,
  TableCellsIcon,
} from "@heroicons/react/24/outline";
import {
  fetchIncidents,
  fetchIncidentById,
  createIncident,
  updateIncidentStatus,
  addIncidentNote,
  attachIncidentEvidence,
} from "../../services/incidentService";
import type {
  IncidentSummary,
  IncidentSeverity,
  IncidentPriority,
  IncidentStatus,
  IncidentListParams,
  IncidentCreate,
} from "../../types/incident";

// ─── Badges & Colors ─────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-[var(--color-critical)]/15 text-[var(--color-critical)] border border-[var(--color-critical)]/40",
  High: "bg-[var(--color-high)]/15 text-[var(--color-high)] border border-[var(--color-high)]/40",
  Medium: "bg-[var(--color-medium)]/15 text-[var(--color-medium)] border border-[var(--color-medium)]/40",
  Low: "bg-[var(--color-low)]/15 text-[var(--color-low)] border border-[var(--color-low)]/40",
};

const PRIORITY_STYLES: Record<string, string> = {
  P0: "bg-[var(--color-critical)]/20 text-[var(--color-critical)] font-extrabold border border-[var(--color-critical)]/50",
  P1: "bg-[var(--color-high)]/20 text-[var(--color-high)] font-bold border border-[var(--color-high)]/40",
  P2: "bg-[var(--color-medium)]/20 text-[var(--color-medium)] font-bold border border-[var(--color-medium)]/40",
  P3: "bg-[var(--color-low)]/20 text-[var(--color-low)] font-semibold border border-[var(--color-low)]/30",
  P4: "bg-[var(--color-surface-300)] text-[var(--color-text-muted)] font-medium border border-[var(--color-border)]",
};

const STATUS_STYLES: Record<string, string> = {
  Open: "bg-[var(--color-primary-500)]/10 text-[var(--color-primary-500)] border border-[var(--color-primary-500)]/30",
  "In Progress": "bg-[var(--color-high)]/10 text-[var(--color-high)] border border-[var(--color-high)]/30",
  Contained: "bg-[var(--color-secondary-500)]/10 text-[var(--color-secondary-500)] border border-[var(--color-secondary-500)]/30",
  Resolved: "bg-[var(--color-safe)]/10 text-[var(--color-safe)] border border-[var(--color-safe)]/30",
  Closed: "bg-[var(--color-surface-400)]/50 text-[var(--color-text-muted)] border border-[var(--color-border)]",
};

const KANBAN_COLUMNS: IncidentStatus[] = ["Open", "In Progress", "Contained", "Resolved", "Closed"];

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${SEVERITY_STYLES[severity] ?? ""}`}>
      {severity}
    </span>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  return (
    <span className={`px-2 py-0.5 rounded font-mono text-[10px] ${PRIORITY_STYLES[priority] ?? ""}`}>
      {priority}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold ${STATUS_STYLES[status] ?? ""}`}>
      {status}
    </span>
  );
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

// ─── Incident Detail Drawer ───────────────────────────────────────────────────

interface DrawerProps {
  incidentId: string;
  onClose: () => void;
}

function IncidentDrawer({ incidentId, onClose }: DrawerProps) {
  const queryClient = useQueryClient();
  const [newNote, setNewNote] = useState("");
  const [evidenceName, setEvidenceName] = useState("");
  const [evidencePath, setEvidencePath] = useState("");
  const [showEvidenceForm, setShowEvidenceForm] = useState(false);

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => fetchIncidentById(incidentId),
    staleTime: 15_000,
  });

  const statusMutation = useMutation({
    mutationFn: (status: IncidentStatus) => updateIncidentStatus(incidentId, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["incident-stats"] });
    },
  });

  const noteMutation = useMutation({
    mutationFn: (note: string) => addIncidentNote(incidentId, note),
    onSuccess: () => {
      setNewNote("");
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
    },
  });

  const evidenceMutation = useMutation({
    mutationFn: (payload: { evidence_name: string; file_path: string }) =>
      attachIncidentEvidence(incidentId, payload),
    onSuccess: () => {
      setEvidenceName("");
      setEvidencePath("");
      setShowEvidenceForm(false);
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
    },
  });

  if (isLoading) {
    return (
      <>
        <div className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" onClick={onClose} />
        <div className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-xl bg-[var(--color-surface-100)] p-6 space-y-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-12 skeleton rounded-lg" />
          ))}
        </div>
      </>
    );
  }

  if (!incident) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <div className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-xl bg-[var(--color-surface-100)] border-l border-[var(--color-border)] flex flex-col animate-slide-in shadow-2xl">
        {/* Header */}
        <div className="px-6 py-5 border-b border-[var(--color-border)] flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <span className="font-mono text-xs font-bold text-[var(--color-primary-500)] uppercase">
                {incident.id.slice(0, 8)}
              </span>
              <PriorityBadge priority={incident.priority} />
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
            </div>
            <h2 className="text-base font-extrabold text-[var(--color-text-primary)] leading-snug">
              {incident.title}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-300)] transition-all"
          >
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Summary */}
          {incident.description && (
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold mb-1.5">
                Incident Description
              </p>
              <div className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-secondary)] leading-relaxed">
                {incident.description}
              </div>
            </div>
          )}

          {/* Status Transition Bar */}
          <div>
            <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold mb-2">
              Transition Status
            </p>
            <div className="flex items-center gap-1.5 flex-wrap">
              {KANBAN_COLUMNS.map((st) => (
                <button
                  key={st}
                  onClick={() => statusMutation.mutate(st)}
                  disabled={statusMutation.isPending || incident.status === st}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all disabled:opacity-40 ${
                    incident.status === st
                      ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                      : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)] hover:text-[var(--color-text-primary)]"
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {/* Details Metadata */}
          <div className="grid grid-cols-2 gap-3 p-3 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs">
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Assigned Analyst</p>
              <p className="font-semibold text-[var(--color-text-primary)] mt-0.5">
                {incident.assigned_user
                  ? `${incident.assigned_user.first_name} ${incident.assigned_user.last_name}`
                  : "Unassigned"}
              </p>
            </div>
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Reported By</p>
              <p className="font-semibold text-[var(--color-text-primary)] mt-0.5">
                {incident.reported_by || "Automated Detection"}
              </p>
            </div>
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Detected At</p>
              <p className="font-mono text-[var(--color-text-secondary)] mt-0.5">
                {formatDate(incident.detected_at)}
              </p>
            </div>
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase">Resolved At</p>
              <p className="font-mono text-[var(--color-text-secondary)] mt-0.5">
                {incident.resolved_at ? formatDate(incident.resolved_at) : "—"}
              </p>
            </div>
          </div>

          {/* Analyst Notes Panel */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <DocumentTextIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
                <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold tracking-wider">
                  Analyst Notes ({incident.notes.length})
                </p>
              </div>
            </div>

            <div className="space-y-2 mb-3">
              {incident.notes.map((note) => (
                <div key={note.id} className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs space-y-1">
                  <div className="flex items-center justify-between text-[10px] text-[var(--color-text-muted)]">
                    <span className="font-semibold text-[var(--color-primary-400)]">
                      {note.author_id ? "Analyst" : "System"}
                    </span>
                    <span className="font-mono">{formatDate(note.created_at)}</span>
                  </div>
                  <p className="text-[var(--color-text-secondary)] leading-relaxed">{note.note}</p>
                </div>
              ))}
            </div>

            <div className="space-y-2">
              <textarea
                rows={2}
                placeholder="Add investigation note…"
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-lg p-3 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
              />
              <button
                onClick={() => newNote.trim() && noteMutation.mutate(newNote.trim())}
                disabled={noteMutation.isPending || !newNote.trim()}
                className="px-3 py-1.5 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold hover:opacity-90 disabled:opacity-40 transition-all"
              >
                {noteMutation.isPending ? "Adding…" : "+ Add Note"}
              </button>
            </div>
          </div>

          {/* Evidence Panel */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <PaperClipIcon className="w-4 h-4 text-[var(--color-high)]" />
                <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold tracking-wider">
                  Attached Evidence ({incident.evidence.length})
                </p>
              </div>
              <button
                onClick={() => setShowEvidenceForm(!showEvidenceForm)}
                className="text-[11px] font-bold text-[var(--color-primary-400)] hover:underline"
              >
                {showEvidenceForm ? "Cancel" : "+ Attach Evidence"}
              </button>
            </div>

            {showEvidenceForm && (
              <div className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-2 mb-3">
                <input
                  type="text"
                  placeholder="Evidence file name (e.g. memory_dump.raw)"
                  value={evidenceName}
                  onChange={(e) => setEvidenceName(e.target.value)}
                  className="w-full bg-[var(--color-surface-100)] text-xs text-[var(--color-text-primary)] rounded px-3 py-1.5 border border-[var(--color-border)]"
                />
                <input
                  type="text"
                  placeholder="File path or URL"
                  value={evidencePath}
                  onChange={(e) => setEvidencePath(e.target.value)}
                  className="w-full bg-[var(--color-surface-100)] text-xs text-[var(--color-text-primary)] rounded px-3 py-1.5 border border-[var(--color-border)]"
                />
                <button
                  onClick={() =>
                    evidenceName.trim() &&
                    evidencePath.trim() &&
                    evidenceMutation.mutate({ evidence_name: evidenceName, file_path: evidencePath })
                  }
                  disabled={evidenceMutation.isPending || !evidenceName.trim() || !evidencePath.trim()}
                  className="px-3 py-1 rounded bg-[var(--color-high)] text-white text-xs font-bold disabled:opacity-40"
                >
                  Save Evidence
                </button>
              </div>
            )}

            <div className="space-y-2">
              {incident.evidence.map((ev) => (
                <div key={ev.id} className="flex items-center justify-between p-2.5 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs">
                  <div>
                    <p className="font-semibold text-[var(--color-text-primary)]">{ev.evidence_name}</p>
                    <p className="font-mono text-[10px] text-[var(--color-text-muted)]">{ev.file_path}</p>
                  </div>
                  <span className="font-mono text-[10px] text-[var(--color-text-muted)]">{formatDate(ev.uploaded_at)}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Timeline Panel */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <ClockIcon className="w-4 h-4 text-[var(--color-text-muted)]" />
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold tracking-wider">
                Audit Timeline ({incident.timeline_events.length})
              </p>
            </div>
            <div className="space-y-3 relative pl-4 border-l border-[var(--color-border)]">
              {incident.timeline_events.map((ev) => (
                <div key={ev.id} className="relative">
                  <span className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-[var(--color-primary-500)]" />
                  <div className="bg-[var(--color-surface-200)] p-2.5 rounded-lg border border-[var(--color-border)] space-y-0.5">
                    <div className="flex items-center justify-between text-[10px] text-[var(--color-text-muted)] font-mono">
                      <span className="font-bold text-[var(--color-primary-400)]">{ev.event_type}</span>
                      <span>{formatDate(ev.created_at)}</span>
                    </div>
                    <p className="text-xs text-[var(--color-text-secondary)]">{ev.description}</p>
                    {ev.created_by && (
                      <p className="text-[10px] text-[var(--color-text-muted)] italic">By: {ev.created_by}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Create Incident Modal ───────────────────────────────────────────────────

function CreateIncidentModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<IncidentSeverity>("Medium");
  const [priority, setPriority] = useState<IncidentPriority>("P2");
  const [reportedBy, setReportedBy] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: IncidentCreate) => createIncident(payload),
    onSuccess: () => {
      onSuccess();
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-lg bg-[var(--color-surface-100)] rounded-2xl border border-[var(--color-border)] p-6 space-y-4 shadow-2xl">
        <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
          <h2 className="text-base font-extrabold text-[var(--color-text-primary)]">
            Declare New Security Incident
          </h2>
          <button onClick={onClose} className="p-1 rounded text-[var(--color-text-muted)] hover:text-white">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-3 text-xs">
          <div>
            <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">
              Title *
            </label>
            <input
              type="text"
              placeholder="e.g. Unauthorized Administrative Access Detected"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] rounded-lg p-2.5 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
            />
          </div>

          <div>
            <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">
              Description
            </label>
            <textarea
              rows={3}
              placeholder="Incident details, scope, and initial findings…"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] rounded-lg p-2.5 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
                className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] rounded-lg p-2 border border-[var(--color-border)]"
              >
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">
                Priority
              </label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as IncidentPriority)}
                className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] rounded-lg p-2 border border-[var(--color-border)]"
              >
                <option value="P0">P0 (Emergency)</option>
                <option value="P1">P1 (Urgent)</option>
                <option value="P2">P2 (Standard)</option>
                <option value="P3">P3 (Minor)</option>
                <option value="P4">P4 (Informational)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] uppercase font-bold text-[var(--color-text-muted)] mb-1">
              Reported By
            </label>
            <input
              type="text"
              placeholder="Analyst Name / SOC Team"
              value={reportedBy}
              onChange={(e) => setReportedBy(e.target.value)}
              className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] rounded-lg p-2.5 border border-[var(--color-border)]"
            />
          </div>
        </div>

        <div className="pt-3 border-t border-[var(--color-border)] flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 rounded-lg bg-[var(--color-surface-300)] text-xs font-bold text-[var(--color-text-primary)]">
            Cancel
          </button>
          <button
            onClick={() =>
              title.trim() &&
              createMutation.mutate({
                title: title.trim(),
                description: description.trim() || undefined,
                severity,
                priority,
                reported_by: reportedBy.trim() || undefined,
                detected_at: new Date().toISOString(),
              })
            }
            disabled={createMutation.isPending || !title.trim()}
            className="px-4 py-2 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold disabled:opacity-40"
          >
            {createMutation.isPending ? "Declaring…" : "Declare Incident"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main Incidents Page Component ───────────────────────────────────────────

export default function IncidentsPage() {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<IncidentSeverity | "">("");
  const [priority, setPriority] = useState<IncidentPriority | "">("");
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | "">("");
  const [viewMode, setViewMode] = useState<"table" | "kanban">("table");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 20;

  const params: IncidentListParams = {
    page,
    page_size: PAGE_SIZE,
    ...(severity ? { severity } : {}),
    ...(priority ? { priority } : {}),
    ...(statusFilter ? { status: statusFilter } : {}),
    ...(search ? { search } : {}),
  };

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["incidents", params],
    queryFn: () => fetchIncidents(params),
    staleTime: 30_000,
    placeholderData: (prev) => prev,
  });

  const handleSearch = useCallback((val: string) => {
    setSearch(val);
    setPage(1);
  }, []);

  const hasFilters = !!severity || !!priority || !!statusFilter || !!search;

  return (
    <div className="space-y-5 animate-fade-in relative">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
            Incident Response Command
          </h1>
          <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
            SOC Incident lifecycle management, analyst notes, timeline audit, and evidence correlation
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* View Mode Switcher */}
          <div className="flex items-center p-1 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)]">
            <button
              onClick={() => setViewMode("table")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-bold transition-all ${
                viewMode === "table"
                  ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                  : "text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              <TableCellsIcon className="w-3.5 h-3.5" />
              Table
            </button>
            <button
              onClick={() => setViewMode("kanban")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-bold transition-all ${
                viewMode === "kanban"
                  ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                  : "text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              <Squares2X2Icon className="w-3.5 h-3.5" />
              Kanban
            </button>
          </div>

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 rounded-lg bg-[var(--color-surface-200)] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] transition-all disabled:opacity-50"
            title="Refresh"
          >
            <ArrowPathIcon className={`w-4 h-4 ${isFetching ? "animate-spin" : ""}`} />
          </button>

          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold shadow-lg shadow-[var(--color-primary-500)]/20 hover:opacity-90 transition-all"
          >
            <PlusIcon className="w-4 h-4" />
            Declare Incident
          </button>
        </div>
      </div>

      {/* Error Callout */}
      {isError && (
        <div className="p-4 rounded-xl bg-[var(--color-critical)]/10 border border-[var(--color-critical)]/30 flex items-center justify-between">
          <div className="flex items-center gap-2 text-[var(--color-critical)] text-xs font-semibold">
            <ExclamationCircleIcon className="w-4 h-4 shrink-0" />
            <span>Failed to connect to backend incident API. Showing offline mode.</span>
          </div>
          <button onClick={() => refetch()} className="text-xs font-bold text-[var(--color-critical)] hover:underline">
            Retry
          </button>
        </div>
      )}

      {/* Filter Bar */}
      <div className="glass rounded-xl p-4 space-y-3 border border-[var(--color-border)]">
        <div className="relative">
          <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by title, description, or reporter…"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-lg pl-9 pr-4 py-2.5 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
          />
          {search && (
            <button
              onClick={() => handleSearch("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)] hover:text-white"
            >
              <XMarkIcon className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5">
            <FunnelIcon className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />
            <span className="text-[10px] text-[var(--color-text-muted)] font-bold uppercase">Severity:</span>
            {["", "Critical", "High", "Medium", "Low"].map((s) => (
              <button
                key={s || "all"}
                onClick={() => setSeverity(s as IncidentSeverity | "")}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all ${
                  severity === s
                    ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                    : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)]"
                }`}
              >
                {s || "All"}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-[var(--color-text-muted)] font-bold uppercase">Status:</span>
            {["", "Open", "In Progress", "Contained", "Resolved", "Closed"].map((st) => (
              <button
                key={st || "all"}
                onClick={() => setStatusFilter(st as IncidentStatus | "")}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all ${
                  statusFilter === st
                    ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                    : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)]"
                }`}
              >
                {st || "All"}
              </button>
            ))}
          </div>

          {hasFilters && (
            <button
              onClick={() => {
                setSeverity("");
                setPriority("");
                setStatusFilter("");
                setSearch("");
                setPage(1);
              }}
              className="flex items-center gap-1 text-[10px] font-bold text-[var(--color-text-muted)] hover:text-[var(--color-critical)] ml-auto"
            >
              <XMarkIcon className="w-3 h-3" />
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Main View Display (Table vs Kanban) */}
      {viewMode === "table" ? (
        <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
          {isLoading ? (
            <div className="p-4 space-y-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="h-12 skeleton rounded-lg" />
              ))}
            </div>
          ) : !data || data.items.length === 0 ? (
            <div className="p-16 text-center text-xs text-[var(--color-text-muted)]">
              <ShieldExclamationIcon className="w-10 h-10 mx-auto mb-2 opacity-50" />
              No security incidents found matching criteria.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-[var(--color-surface-200)]/70 text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider border-b border-[var(--color-border)]">
                    <th className="px-4 py-3 font-bold">ID / Title</th>
                    <th className="px-4 py-3 font-bold">Severity</th>
                    <th className="px-4 py-3 font-bold">Priority</th>
                    <th className="px-4 py-3 font-bold">Status</th>
                    <th className="px-4 py-3 font-bold">Assigned Analyst</th>
                    <th className="px-4 py-3 font-bold">Detected</th>
                    <th className="px-4 py-3 font-bold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
                  {data.items.map((inc: IncidentSummary) => (
                    <tr
                      key={inc.id}
                      onClick={() => setSelectedId(inc.id)}
                      className="hover:bg-[var(--color-surface-200)]/60 cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-3.5 max-w-[280px]">
                        <span className="font-mono text-[10px] font-bold text-[var(--color-primary-500)] block">
                          {inc.id.slice(0, 8).toUpperCase()}
                        </span>
                        <p className="font-semibold text-[var(--color-text-primary)] truncate">{inc.title}</p>
                      </td>
                      <td className="px-4 py-3.5">
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td className="px-4 py-3.5">
                        <PriorityBadge priority={inc.priority} />
                      </td>
                      <td className="px-4 py-3.5">
                        <StatusBadge status={inc.status} />
                      </td>
                      <td className="px-4 py-3.5 flex items-center gap-1.5 text-xs text-[var(--color-text-muted)] mt-1">
                        <UserIcon className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />
                        <span>{inc.assigned_user_id ? "Analyst Assigned" : "Unassigned"}</span>
                      </td>
                      <td className="px-4 py-3.5 font-mono text-[11px] text-[var(--color-text-muted)]">
                        {formatDate(inc.detected_at)}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedId(inc.id);
                          }}
                          className="inline-flex items-center gap-1 px-3 py-1 text-[11px] font-bold rounded-lg bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] hover:bg-[var(--color-primary-500)] hover:text-black transition-all"
                        >
                          <EyeIcon className="w-3 h-3" />
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : (
        /* Kanban Board View */
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {KANBAN_COLUMNS.map((colStatus) => {
            const colItems = data?.items.filter((i) => i.status === colStatus) ?? [];
            return (
              <div key={colStatus} className="glass rounded-xl p-3 border border-[var(--color-border)] flex flex-col space-y-3 min-h-[400px]">
                <div className="flex items-center justify-between pb-2 border-b border-[var(--color-border)]">
                  <span className="text-xs font-bold text-[var(--color-text-primary)]">{colStatus}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[var(--color-surface-300)] text-[var(--color-text-muted)]">
                    {colItems.length}
                  </span>
                </div>

                <div className="space-y-3 flex-1 overflow-y-auto">
                  {colItems.map((inc) => (
                    <div
                      key={inc.id}
                      onClick={() => setSelectedId(inc.id)}
                      className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] hover:border-[var(--color-primary-500)]/40 transition-all cursor-pointer space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] font-bold text-[var(--color-primary-500)]">
                          {inc.id.slice(0, 8).toUpperCase()}
                        </span>
                        <PriorityBadge priority={inc.priority} />
                      </div>
                      <p className="text-xs font-bold text-[var(--color-text-primary)] line-clamp-2">{inc.title}</p>
                      <div className="flex items-center justify-between text-[10px] text-[var(--color-text-muted)] pt-2 border-t border-[var(--color-border)]">
                        <SeverityBadge severity={inc.severity} />
                        <span className="font-mono">{formatDate(inc.detected_at)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Drawer */}
      {selectedId && (
        <IncidentDrawer incidentId={selectedId} onClose={() => setSelectedId(null)} />
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <CreateIncidentModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ["incidents"] });
            queryClient.invalidateQueries({ queryKey: ["incident-stats"] });
          }}
        />
      )}
    </div>
  );
}
