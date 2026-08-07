import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  LinkIcon,
  PlayIcon,
  ShieldCheckIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  CpuChipIcon,
  XMarkIcon,
  FireIcon,
} from "@heroicons/react/24/outline";

import {
  fetchCorrelations,
  fetchCorrelationStats,
  fetchCorrelationTimeline,
  fetchCorrelationGraph,
  fetchMitreMappings,
  fetchAttackChains,
  runCorrelationEngine,
  type ThreatCorrelation,
} from "../../services/correlationService";

export default function CorrelationPage() {
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"correlations" | "chains" | "mitre" | "graph">("correlations");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [page, setPage] = useState(1);
  const [selectedCorrelation, setSelectedCorrelation] = useState<ThreatCorrelation | null>(null);

  // Queries
  const {
    data: correlationsData,
    isLoading: isCorrelationsLoading,
    isError: isCorrelationsError,
  } = useQuery({
    queryKey: ["threat-correlations", page, search, typeFilter, severityFilter],
    queryFn: () =>
      fetchCorrelations({
        page,
        page_size: 15,
        search: search || undefined,
        correlation_type: typeFilter || undefined,
        severity: severityFilter || undefined,
      }),
    refetchInterval: 30000,
  });

  const { data: stats } = useQuery({
    queryKey: ["correlation-stats"],
    queryFn: fetchCorrelationStats,
    refetchInterval: 30000,
  });

  useQuery({
    queryKey: ["correlation-timeline"],
    queryFn: () => fetchCorrelationTimeline(20),
    refetchInterval: 30000,
  });

  const { data: graphData } = useQuery({
    queryKey: ["correlation-graph"],
    queryFn: fetchCorrelationGraph,
  });

  const { data: mitreMappingsData } = useQuery({
    queryKey: ["mitre-mappings-list"],
    queryFn: () => fetchMitreMappings({ page_size: 25 }),
  });

  const { data: attackChainsData } = useQuery({
    queryKey: ["attack-chains-list"],
    queryFn: () => fetchAttackChains({ page_size: 10 }),
  });

  // Run Correlation Engine Mutation
  const runMutation = useMutation({
    mutationFn: () => runCorrelationEngine(24, 50),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["threat-correlations"] });
      queryClient.invalidateQueries({ queryKey: ["correlation-stats"] });
      queryClient.invalidateQueries({ queryKey: ["correlation-timeline"] });
      queryClient.invalidateQueries({ queryKey: ["attack-chains-list"] });
    },
  });

  const correlations = correlationsData?.items || [];
  const totalCorrelations = correlationsData?.total || 0;
  const totalPages = Math.ceil(totalCorrelations / 15) || 1;
  const attackChains = attackChainsData?.items || [];
  const mitreMappings = mitreMappingsData?.items || [];

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-[var(--color-critical)]/20 text-[var(--color-critical)] border-[var(--color-critical)]/40";
      case "High":
        return "bg-[var(--color-high)]/20 text-[var(--color-high)] border-[var(--color-high)]/40";
      case "Medium":
        return "bg-[var(--color-medium)]/20 text-[var(--color-medium)] border-[var(--color-medium)]/40";
      case "Low":
        return "bg-[var(--color-safe)]/20 text-[var(--color-safe)] border-[var(--color-safe)]/40";
      default:
        return "bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] border-[var(--color-border)]";
    }
  };

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] p-6 rounded-2xl border border-[var(--color-border)] shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--color-primary-500)] animate-pulse" />
            <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
              Threat Correlation Engine & Attack Chain Graph
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Cross-entity correlation linking Threats, Incidents, Assets, Logs, IOCs, and MITRE ATT&CK techniques
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => runMutation.mutate()}
            disabled={runMutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold hover:bg-[var(--color-primary-600)] transition-all shadow-lg shadow-[var(--color-primary-500)]/20 disabled:opacity-50 shrink-0"
          >
            {runMutation.isPending ? (
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
            ) : (
              <PlayIcon className="w-4 h-4 fill-current" />
            )}
            <span>{runMutation.isPending ? "Running Engine..." : "Run Correlation Pass"}</span>
          </button>
        </div>
      </div>

      {/* Execution Toast Callout */}
      {runMutation.isSuccess && runMutation.data && (
        <div className="p-4 rounded-xl bg-[var(--color-safe)]/15 border border-[var(--color-safe)]/40 text-[var(--color-safe)] text-xs font-semibold flex items-center justify-between animate-fade-in">
          <span>{runMutation.data.message}</span>
          <span className="font-mono text-[10px] uppercase font-bold">Execution Completed</span>
        </div>
      )}

      {/* Telemetry Overview Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        {/* Total Correlations */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
            Correlated Events
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {stats?.total_correlations ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Active Correlations</p>
        </div>

        {/* Critical Correlations */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-critical)] uppercase tracking-wider mb-1">
            Critical Events
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-critical)]">
            {stats?.critical_correlations ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Requires Immediate SOC Action</p>
        </div>

        {/* Active Attack Chains */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-high)] uppercase tracking-wider mb-1">
            Attack Chains
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-high)]">
            {stats?.active_attack_chains ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Multi-Stage Kill Chains</p>
        </div>

        {/* Average Risk Score */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
            Avg Risk Score
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-primary-500)]">
            {stats?.avg_risk_score ?? 50} <span className="text-xs font-normal text-[var(--color-text-muted)]">/ 100</span>
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Security Impact</p>
        </div>

        {/* Average Confidence Score */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
            Avg Confidence Score
          </p>
          <p className="text-2xl font-bold font-mono text-blue-400">
            {stats?.avg_confidence_score ?? 80}%
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Certainty Level</p>
        </div>

        {/* MITRE Technique Mappings */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
            MITRE Mappings
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {stats?.total_mitre_mappings ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Mapped Techniques</p>
        </div>
      </div>

      {/* Main Tabs Header */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-3">
        {[
          { id: "correlations", label: "Correlated Events", icon: LinkIcon },
          { id: "chains", label: "Multi-Stage Attack Chains", icon: FireIcon },
          { id: "mitre", label: "MITRE ATT&CK Mappings", icon: ShieldCheckIcon },
          { id: "graph", label: "Correlation Visual Graph", icon: CpuChipIcon },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all ${
              activeTab === tab.id
                ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)] shadow-lg shadow-[var(--color-primary-500)]/20"
                : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)] border border-[var(--color-border)]"
            }`}
          >
            <tab.icon className="w-4 h-4" />
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab 1: Correlated Events Table */}
      {activeTab === "correlations" && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="glass rounded-xl p-4 border border-[var(--color-border)] flex flex-col md:flex-row gap-3 items-center justify-between">
            <div className="relative w-full md:w-80">
              <input
                type="text"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                placeholder="Search correlation title, IOC..."
                className="w-full pl-9 pr-4 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary-500)]"
              />
              <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3 top-2.5" />
            </div>

            <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
              <select
                value={typeFilter}
                onChange={(e) => {
                  setTypeFilter(e.target.value);
                  setPage(1);
                }}
                className="px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-primary)] focus:outline-none"
              >
                <option value="">All Correlation Types</option>
                <option value="IOC_Correlation">IOC Correlation</option>
                <option value="Log_Anomaly">Log Anomaly</option>
                <option value="Asset_Multi_Threat">Asset Multi-Threat</option>
                <option value="Incident_Cascade">Incident Cascade</option>
              </select>

              <select
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  setPage(1);
                }}
                className="px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-primary)] focus:outline-none"
              >
                <option value="">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>

          {/* Table Container */}
          <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
            {isCorrelationsLoading ? (
              <div className="p-8 space-y-3">
                {[1, 2, 3, 4, 5].map((n) => (
                  <div key={n} className="h-12 w-full skeleton rounded-lg" />
                ))}
              </div>
            ) : isCorrelationsError ? (
              <div className="p-8 text-center text-xs font-mono text-[var(--color-critical)]">
                Failed to load threat correlation events from backend API.
              </div>
            ) : correlations.length === 0 ? (
              <div className="p-12 text-center text-xs font-mono text-[var(--color-text-muted)] space-y-2">
                <CpuChipIcon className="w-8 h-8 opacity-50 mx-auto" />
                <p>No correlation events matching current filters.</p>
                <button
                  onClick={() => runMutation.mutate()}
                  className="px-4 py-2 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold text-xs"
                >
                  Trigger Correlation Pass
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[var(--color-surface-200)]/80 text-[var(--color-text-muted)] border-b border-[var(--color-border)] font-bold uppercase">
                    <tr>
                      <th className="px-4 py-3">Event Title</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Severity</th>
                      <th className="px-4 py-3">Risk Impact</th>
                      <th className="px-4 py-3">Certainty Conf.</th>
                      <th className="px-4 py-3">Timestamp</th>
                      <th className="px-4 py-3 text-right">Evidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-border)]">
                    {correlations.map((corr) => (
                      <tr key={corr.id} className="hover:bg-[var(--color-surface-200)]/40 transition-colors">
                        <td className="px-4 py-3 font-bold text-[var(--color-text-primary)] max-w-xs truncate">
                          {corr.title}
                        </td>
                        <td className="px-4 py-3 text-[var(--color-primary-500)]">{corr.correlation_type}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                              corr.severity
                            )}`}
                          >
                            {corr.severity}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-bold">
                          <span
                            className={
                              corr.risk_score >= 75
                                ? "text-[var(--color-critical)]"
                                : corr.risk_score >= 50
                                ? "text-[var(--color-high)]"
                                : "text-[var(--color-safe)]"
                            }
                          >
                            {corr.risk_score} / 100
                          </span>
                        </td>
                        <td className="px-4 py-3 font-bold text-blue-400">
                          {corr.confidence_score}%
                        </td>
                        <td className="px-4 py-3 text-[var(--color-text-muted)]">
                          {new Date(corr.created_at).toLocaleTimeString()}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => setSelectedCorrelation(corr)}
                            className="px-3 py-1 rounded bg-[var(--color-surface-300)] text-[var(--color-primary-500)] hover:bg-[var(--color-primary-500)] hover:text-[var(--color-surface-0)] font-bold text-[10px] transition-all"
                          >
                            Inspect Evidence
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination Controls */}
            <div className="p-4 border-t border-[var(--color-border)] flex items-center justify-between text-xs font-mono">
              <span className="text-[var(--color-text-muted)]">
                Page {page} of {totalPages} ({totalCorrelations} total)
              </span>
              <div className="flex gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="px-3 py-1.5 rounded bg-[var(--color-surface-200)] border border-[var(--color-border)] disabled:opacity-40"
                >
                  Previous
                </button>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="px-3 py-1.5 rounded bg-[var(--color-surface-200)] border border-[var(--color-border)] disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Attack Chains */}
      {activeTab === "chains" && (
        <div className="space-y-6">
          {attackChains.map((chain) => (
            <div key={chain.id} className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-[var(--color-border)] pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded text-[10px] font-extrabold uppercase font-mono bg-[var(--color-critical)]/20 text-[var(--color-critical)] border border-[var(--color-critical)]/40">
                      {chain.severity} KILL CHAIN
                    </span>
                    <span className="text-xs font-mono text-[var(--color-text-muted)]">
                      Status: <strong className="text-[var(--color-safe)]">{chain.status}</strong>
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-[var(--color-text-primary)] mt-1">{chain.chain_name}</h2>
                  <p className="text-xs font-mono text-[var(--color-text-secondary)] mt-0.5">
                    Entry Vector: <strong className="text-[var(--color-primary-500)]">{chain.entry_point || "Unknown"}</strong>
                  </p>
                </div>

                <div className="flex items-center gap-4">
                  <div>
                    <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">Overall Risk</p>
                    <p className="text-xl font-bold font-mono text-[var(--color-critical)]">
                      {chain.overall_risk_score} / 100
                    </p>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">Overall Confidence</p>
                    <p className="text-xl font-bold font-mono text-blue-400">
                      {chain.overall_confidence_score}%
                    </p>
                  </div>
                </div>
              </div>

              {/* Stages Timeline */}
              <div className="space-y-3">
                <h3 className="text-xs font-bold text-[var(--color-text-primary)] uppercase tracking-wider font-mono">
                  Kill Chain Attack Stages ({chain.stages_json.length})
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                  {chain.stages_json.map((stage) => (
                    <div
                      key={stage.stage_order}
                      className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] space-y-2 font-mono text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)]">
                          Stage {stage.stage_order}
                        </span>
                        {stage.mitre_technique_id && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]">
                            {stage.mitre_technique_id}
                          </span>
                        )}
                      </div>
                      <h4 className="font-bold text-[var(--color-text-primary)]">{stage.stage_name}</h4>
                      <p className="text-[11px] font-sans text-[var(--color-text-muted)]">{stage.description}</p>
                      {stage.evidence_snippet && (
                        <div className="p-2 rounded bg-[var(--color-surface-300)]/60 text-[10px] space-y-0.5">
                          {Object.entries(stage.evidence_snippet).map(([k, v]) => (
                            <p key={k} className="truncate">
                              <strong className="text-[var(--color-text-secondary)]">{k}:</strong> {String(v)}
                            </p>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: MITRE ATT&CK Mappings */}
      {activeTab === "mitre" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)] font-mono flex items-center gap-2">
            <ShieldCheckIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
            <span>Correlated MITRE ATT&CK Technique Mappings ({mitreMappings.length})</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {mitreMappings.map((m) => (
              <div
                key={m.id}
                className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] font-mono text-xs space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[var(--color-primary-500)]">{m.technique_id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]">
                    {m.tactic}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[var(--color-text-muted)]">Entity:</span>
                  <span className="font-bold text-[var(--color-text-primary)]">{m.entity_type}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[var(--color-text-muted)]">Confidence:</span>
                  <span className="font-bold text-blue-400">{m.confidence_score}%</span>
                </div>
                {m.evidence?.rationale && (
                  <p className="text-[11px] font-sans text-[var(--color-text-secondary)] pt-1 border-t border-[var(--color-border)]">
                    {m.evidence.rationale}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Visual Correlation Graph */}
      {activeTab === "graph" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-[var(--color-text-primary)] font-mono flex items-center gap-2">
              <CpuChipIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
              <span>Multi-Entity Correlation Graph Dataset</span>
            </h2>
            <span className="text-xs font-mono text-[var(--color-primary-500)]">
              {(graphData?.nodes || []).length} Nodes • {(graphData?.edges || []).length} Edges
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Nodes Box */}
            <div className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] space-y-2">
              <h3 className="text-xs font-bold text-[var(--color-text-primary)] font-mono">Nodes (Entities)</h3>
              <div className="space-y-2 max-h-80 overflow-y-auto pr-2 font-mono text-xs">
                {(graphData?.nodes || []).map((node) => (
                  <div key={node.id} className="p-2.5 rounded bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] flex items-center justify-between">
                    <div>
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)] mr-2">
                        {node.type}
                      </span>
                      <span className="font-bold text-[var(--color-text-primary)]">{node.label}</span>
                    </div>
                    {node.severity && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]">
                        {node.severity}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Edges Box */}
            <div className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] space-y-2">
              <h3 className="text-xs font-bold text-[var(--color-text-primary)] font-mono">Edges (Relationships)</h3>
              <div className="space-y-2 max-h-80 overflow-y-auto pr-2 font-mono text-xs">
                {(graphData?.edges || []).map((edge, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] flex items-center justify-between">
                    <div>
                      <span className="text-[var(--color-text-primary)] font-bold">{edge.source}</span>
                      <span className="text-[var(--color-primary-500)] px-2">→ ({edge.relation}) →</span>
                      <span className="text-[var(--color-text-primary)] font-bold">{edge.target}</span>
                    </div>
                    <span className="text-[10px] font-bold text-blue-400">{edge.confidence_score}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Structured Evidence Inspector Modal */}
      {selectedCorrelation && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="glass rounded-2xl max-w-2xl w-full p-6 border border-[var(--color-border)] space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
              <div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(selectedCorrelation.severity)}`}>
                  {selectedCorrelation.severity} SEVERITY
                </span>
                <h2 className="text-base font-bold text-[var(--color-text-primary)] font-mono mt-1">
                  {selectedCorrelation.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedCorrelation(null)}
                className="p-1 rounded-lg bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            {/* Impact vs Certainty Metrics */}
            <div className="grid grid-cols-2 gap-4 p-3 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] font-mono text-xs">
              <div>
                <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">Risk Score (Security Impact)</p>
                <p className="text-lg font-bold text-[var(--color-critical)]">
                  {selectedCorrelation.risk_score} / 100
                </p>
              </div>

              <div>
                <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">Confidence Score (Certainty)</p>
                <p className="text-lg font-bold text-blue-400">
                  {selectedCorrelation.confidence_score}%
                </p>
              </div>
            </div>

            {/* Evidence Rationale Box */}
            {selectedCorrelation.evidence?.rationale && (
              <div className="p-3.5 rounded-xl bg-[var(--color-primary-500)]/10 border border-[var(--color-primary-500)]/30 text-xs">
                <p className="font-bold text-[var(--color-primary-500)] mb-1 font-mono">Correlation Rationale</p>
                <p className="text-[var(--color-text-primary)]">{selectedCorrelation.evidence.rationale}</p>
              </div>
            )}

            {/* Raw Structured Evidence JSON */}
            <div className="space-y-1.5 font-mono text-xs">
              <p className="font-bold text-[var(--color-text-muted)] uppercase">Structured Evidence Object</p>
              <pre className="p-4 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] overflow-x-auto text-[11px] leading-relaxed border border-[var(--color-border)]">
                {JSON.stringify(selectedCorrelation.evidence, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedCorrelation(null)}
                className="px-5 py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold text-xs"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
