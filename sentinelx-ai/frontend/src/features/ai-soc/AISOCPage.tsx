import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  SparklesIcon,
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ClockIcon,
  BoltIcon,
} from "@heroicons/react/24/outline";

import {
  triggerAIInvestigation,
  executeAIThreatHunt,
  fetchAIRiskAssessment,
  fetchAIRecommendations,
  fetchAIHistory,
  type InvestigationResponse,
  type ThreatHuntResponse,
} from "../../services/aiSocService";

export default function AISOCPage() {
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"investigate" | "hunting" | "risk" | "recommendations" | "history">("investigate");

  // Investigation Form State
  const [investigationType, setInvestigationType] = useState("Incident");
  const [targetId, setTargetId] = useState("INC-9042");
  const [activeInvestigation, setActiveInvestigation] = useState<InvestigationResponse | null>(null);

  // Threat Hunting Form State
  const [huntType, setHuntType] = useState("IP");
  const [queryValue, setQueryValue] = useState("185.220.101.5");
  const [activeHunt, setActiveHunt] = useState<ThreatHuntResponse | null>(null);

  // Queries
  const { data: riskAssessment } = useQuery({
    queryKey: ["ai-risk-assessment"],
    queryFn: fetchAIRiskAssessment,
    refetchInterval: 30000,
  });

  const { data: recommendations } = useQuery({
    queryKey: ["ai-recommendations"],
    queryFn: fetchAIRecommendations,
    refetchInterval: 30000,
  });

  const { data: historyData, isLoading: isHistoryLoading } = useQuery({
    queryKey: ["ai-history"],
    queryFn: () => fetchAIHistory(1, 20),
    refetchInterval: 15000,
  });

  // Investigation Mutation
  const investigateMutation = useMutation({
    mutationFn: () => triggerAIInvestigation(investigationType, targetId),
    onSuccess: (data) => {
      setActiveInvestigation(data);
      queryClient.invalidateQueries({ queryKey: ["ai-history"] });
    },
  });

  // Threat Hunt Mutation
  const huntMutation = useMutation({
    mutationFn: () => executeAIThreatHunt(huntType, queryValue),
    onSuccess: (data) => {
      setActiveHunt(data);
    },
  });

  const historyItems = historyData?.items || [];

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-[var(--color-critical)]/20 text-[var(--color-critical)] border-[var(--color-critical)]/40";
      case "high":
        return "bg-[var(--color-high)]/20 text-[var(--color-high)] border-[var(--color-high)]/40";
      case "medium":
        return "bg-[var(--color-medium)]/20 text-[var(--color-medium)] border-[var(--color-medium)]/40";
      default:
        return "bg-[var(--color-safe)]/20 text-[var(--color-safe)] border-[var(--color-safe)]/40";
    }
  };

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] p-6 rounded-2xl border border-[var(--color-border)] shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <SparklesIcon className="w-6 h-6 text-[var(--color-primary-500)] animate-pulse" />
            <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
              AI SOC Analyst & Autonomous Security Operations
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Generative AI reasoning engine cross-analyzing Threats, Incidents, Assets, Logs, IOCs, and SOAR execution history
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-4 py-2 rounded-xl bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] flex items-center gap-3">
            <div>
              <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] font-mono">AI Confidence Score</p>
              <p className="text-lg font-extrabold font-mono text-[var(--color-primary-500)]">
                94% Accuracy
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-3 overflow-x-auto">
        {[
          { id: "investigate", label: "AI Deep Investigation", icon: SparklesIcon },
          { id: "hunting", label: "Proactive Threat Hunting", icon: MagnifyingGlassIcon },
          { id: "risk", label: "Predictive Risk Assessment", icon: ShieldExclamationIcon },
          { id: "recommendations", label: "AI Recommendations", icon: BoltIcon },
          { id: "history", label: "Investigation Audit History", icon: ClockIcon },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all shrink-0 ${
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

      {/* Tab 1: AI Deep Investigation */}
      {activeTab === "investigate" && (
        <div className="space-y-6">
          <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4">
            <h2 className="text-xs font-bold text-[var(--color-text-primary)] font-mono flex items-center gap-2">
              <SparklesIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
              <span>Launch AI SOC Investigation Console</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
              <div>
                <label className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] block mb-1">
                  Investigation Target Type
                </label>
                <select
                  value={investigationType}
                  onChange={(e) => setInvestigationType(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none"
                >
                  <option value="Incident">Security Incident</option>
                  <option value="Threat">Threat Event</option>
                  <option value="Asset">Enterprise Asset</option>
                  <option value="IOC">IOC Intelligence</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] block mb-1">
                  Target Identifier / ID / IP / Hash
                </label>
                <input
                  type="text"
                  value={targetId}
                  onChange={(e) => setTargetId(e.target.value)}
                  placeholder="Enter target ID or value..."
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none"
                />
              </div>

              <div className="flex items-end">
                <button
                  onClick={() => investigateMutation.mutate()}
                  disabled={investigateMutation.isPending}
                  className="w-full py-2 px-4 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold text-xs hover:bg-[var(--color-primary-600)] transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {investigateMutation.isPending ? (
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                  ) : (
                    <SparklesIcon className="w-4 h-4" />
                  )}
                  <span>Run AI Investigation</span>
                </button>
              </div>
            </div>
          </div>

          {/* Investigation Results Display */}
          {activeInvestigation && (
            <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-6 font-mono text-xs animate-fade-in">
              <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
                <div>
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(activeInvestigation.severity)}`}>
                    {activeInvestigation.severity.toUpperCase()} SEVERITY
                  </span>
                  <h2 className="text-base font-bold text-[var(--color-text-primary)] mt-1">
                    AI Investigation Report: {activeInvestigation.target_id}
                  </h2>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-[var(--color-text-muted)] block">Confidence Score</span>
                  <span className="text-lg font-bold text-[var(--color-primary-500)]">
                    {activeInvestigation.confidence_score}%
                  </span>
                </div>
              </div>

              {/* Executive Summary & Root Cause */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] space-y-2">
                  <h3 className="font-bold text-[var(--color-primary-500)] uppercase text-[10px] tracking-wider">
                    Executive Summary
                  </h3>
                  <p className="text-[11px] text-[var(--color-text-primary)] font-sans leading-relaxed">
                    {activeInvestigation.executive_summary}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] space-y-2">
                  <h3 className="font-bold text-[var(--color-medium)] uppercase text-[10px] tracking-wider">
                    Root Cause Analysis
                  </h3>
                  <p className="text-[11px] text-[var(--color-text-primary)] font-sans leading-relaxed">
                    {activeInvestigation.root_cause || "Analyzing platform root cause indicators..."}
                  </p>
                </div>
              </div>

              {/* MITRE ATT&CK Mapping */}
              <div className="space-y-2">
                <h3 className="font-bold text-[var(--color-text-primary)] uppercase text-[10px] tracking-wider">
                  MITRE ATT&CK Correlation Mapping
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {activeInvestigation.mitre_mapping.map((m, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-[var(--color-surface-300)] border border-[var(--color-border)] flex items-center justify-between">
                      <div>
                        <span className="font-bold text-[var(--color-primary-500)] mr-2">{m.technique_id}</span>
                        <span className="text-[var(--color-text-primary)] font-bold">{m.technique_name}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-[var(--color-surface-200)] text-[var(--color-text-muted)]">
                        {m.tactic}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Rule 8: Safety & Evidence Breakdown */}
              <div className="p-4 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-3">
                <h3 className="font-bold text-[var(--color-text-primary)] uppercase text-[10px] tracking-wider flex items-center gap-2">
                  <CheckCircleIcon className="w-4 h-4 text-[var(--color-safe)]" />
                  <span>Evidence Source Attribution (AI Distinction Protocol)</span>
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[10px]">
                  <div className="p-2.5 rounded-lg bg-[var(--color-surface-300)] space-y-1">
                    <span className="font-bold text-[var(--color-safe)] uppercase block">Observed SentinelX Telemetry</span>
                    <ul className="list-disc pl-3 text-[var(--color-text-secondary)] space-y-0.5 font-sans">
                      {(activeInvestigation.evidence_sources?.observed_sentinelx_data || []).map((o, idx) => (
                        <li key={idx}>{o}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-2.5 rounded-lg bg-[var(--color-surface-300)] space-y-1">
                    <span className="font-bold text-[var(--color-primary-500)] uppercase block">External Threat Intelligence</span>
                    <ul className="list-disc pl-3 text-[var(--color-text-secondary)] space-y-0.5 font-sans">
                      {(activeInvestigation.evidence_sources?.external_intelligence || []).map((e, idx) => (
                        <li key={idx}>{e}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-2.5 rounded-lg bg-[var(--color-surface-300)] space-y-1">
                    <span className="font-bold text-purple-400 uppercase block">AI Inference & Reasoning</span>
                    <ul className="list-disc pl-3 text-[var(--color-text-secondary)] space-y-0.5 font-sans">
                      {(activeInvestigation.evidence_sources?.ai_inference || []).map((i, idx) => (
                        <li key={idx}>{i}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Proactive Threat Hunting */}
      {activeTab === "hunting" && (
        <div className="space-y-6">
          <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4">
            <h2 className="text-xs font-bold text-[var(--color-text-primary)] font-mono flex items-center gap-2">
              <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
              <span>Proactive Threat Hunting Engine</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
              <div>
                <label className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] block mb-1">
                  Hunt Pivot Type
                </label>
                <select
                  value={huntType}
                  onChange={(e) => setHuntType(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none"
                >
                  <option value="IP">IP Address</option>
                  <option value="Domain">Domain Name</option>
                  <option value="Hash">File Hash (MD5/SHA256)</option>
                  <option value="Username">Username</option>
                  <option value="Process">Process Name</option>
                  <option value="MITRE">MITRE Technique ID</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] block mb-1">
                  Hunt Value / Indicator Query
                </label>
                <input
                  type="text"
                  value={queryValue}
                  onChange={(e) => setQueryValue(e.target.value)}
                  placeholder="Target query value..."
                  className="w-full px-3 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none"
                />
              </div>

              <div className="flex items-end">
                <button
                  onClick={() => huntMutation.mutate()}
                  disabled={huntMutation.isPending}
                  className="w-full py-2 px-4 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold text-xs hover:bg-[var(--color-primary-600)] transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {huntMutation.isPending ? (
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                  ) : (
                    <MagnifyingGlassIcon className="w-4 h-4" />
                  )}
                  <span>Execute Threat Hunt</span>
                </button>
              </div>
            </div>
          </div>

          {activeHunt && (
            <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4 font-mono text-xs animate-fade-in">
              <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
                <div>
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(activeHunt.threat_level)}`}>
                    {activeHunt.threat_level.toUpperCase()} THREAT
                  </span>
                  <h2 className="text-base font-bold text-[var(--color-text-primary)] mt-1">
                    Threat Hunt Results for '{activeHunt.query_value}'
                  </h2>
                </div>
              </div>

              <p className="text-[11px] text-[var(--color-text-primary)] font-sans">{activeHunt.findings_summary}</p>

              <div className="space-y-2">
                <h3 className="font-bold text-[var(--color-text-primary)] uppercase text-[10px]">Matched Telemetry Artifacts</h3>
                <div className="space-y-2">
                  {activeHunt.matched_artifacts.map((art, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] flex items-center justify-between">
                      <span className="font-bold text-[var(--color-primary-500)]">[{art.artifact}]</span>
                      <span className="text-[var(--color-text-primary)] font-sans">{art.details}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Predictive Risk Assessment */}
      {activeTab === "risk" && (
        <div className="space-y-6 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-2">
              <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase">Enterprise Business Risk</span>
              <p className="text-3xl font-extrabold text-[var(--color-high)]">
                {riskAssessment?.business_risk_score ?? 78} / 100
              </p>
              <p className="text-[10px] text-[var(--color-text-secondary)] font-sans">Elevated risk due to lateral movement</p>
            </div>

            <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-2 col-span-2">
              <span className="text-[10px] font-bold text-[var(--color-primary-500)] uppercase">Predictive Spread Forecast</span>
              <p className="text-sm font-bold text-[var(--color-text-primary)]">
                {riskAssessment?.attack_spread_prediction}
              </p>
            </div>
          </div>

          {/* High Risk Assets */}
          <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
            <div className="p-4 border-b border-[var(--color-border)] font-bold text-[var(--color-text-primary)]">
              High Risk Enterprise Assets
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[var(--color-surface-200)] text-[var(--color-text-muted)] font-bold uppercase">
                  <tr>
                    <th className="px-4 py-3">Asset Name</th>
                    <th className="px-4 py-3">IP Address</th>
                    <th className="px-4 py-3">Risk Score</th>
                    <th className="px-4 py-3">Risk Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border)]">
                  {(riskAssessment?.high_risk_assets || []).map((ast, idx) => (
                    <tr key={idx} className="hover:bg-[var(--color-surface-200)]/40">
                      <td className="px-4 py-3 font-bold text-[var(--color-text-primary)]">{ast.asset_name}</td>
                      <td className="px-4 py-3 text-[var(--color-primary-500)]">{ast.ip_address}</td>
                      <td className="px-4 py-3 font-bold text-[var(--color-critical)]">{ast.risk_score}</td>
                      <td className="px-4 py-3 text-[var(--color-text-secondary)] font-sans">{ast.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: AI Recommendations */}
      {activeTab === "recommendations" && (
        <div className="space-y-6 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-3">
              <h3 className="font-bold text-[var(--color-primary-500)] uppercase text-[10px] flex items-center gap-2">
                <BoltIcon className="w-4 h-4" />
                <span>Recommended SOAR Playbooks</span>
              </h3>
              <div className="space-y-2">
                {(recommendations?.playbook_recommendations || []).map((pb, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-[var(--color-text-primary)]">{pb.playbook_name}</span>
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-[var(--color-safe)]/20 text-[var(--color-safe)]">
                        {pb.confidence_score}% Confidence
                      </span>
                    </div>
                    <p className="text-[10px] text-[var(--color-text-muted)] font-sans">{pb.reason}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-3">
              <h3 className="font-bold text-[var(--color-safe)] uppercase text-[10px] flex items-center gap-2">
                <CheckCircleIcon className="w-4 h-4" />
                <span>Actionable Remediation Checklist</span>
              </h3>
              <ul className="space-y-2">
                {(recommendations?.remediation_recommendations || []).map((rem, idx) => (
                  <li key={idx} className="p-2.5 rounded-lg bg-[var(--color-surface-200)] text-[11px] text-[var(--color-text-primary)] font-sans border border-[var(--color-border)] flex items-start gap-2">
                    <span className="font-bold text-[var(--color-primary-500)] shrink-0">•</span>
                    <span>{rem}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Tab 5: Investigation History Audit Trail */}
      {activeTab === "history" && (
        <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden font-mono text-xs">
          {isHistoryLoading ? (
            <div className="p-8 space-y-3">
              {[1, 2, 3].map((n) => (
                <div key={n} className="h-12 w-full skeleton rounded-lg" />
              ))}
            </div>
          ) : historyItems.length === 0 ? (
            <div className="p-12 text-center text-[var(--color-text-muted)]">No AI investigation logs recorded.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-[var(--color-surface-200)] text-[var(--color-text-muted)] font-bold uppercase border-b border-[var(--color-border)]">
                  <tr>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Target ID</th>
                    <th className="px-4 py-3">Executive Summary</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Confidence</th>
                    <th className="px-4 py-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border)]">
                  {historyItems.map((item, idx) => (
                    <tr key={idx} className="hover:bg-[var(--color-surface-200)]/40 transition-colors">
                      <td className="px-4 py-3 font-bold text-[var(--color-primary-500)]">{item.investigation_type}</td>
                      <td className="px-4 py-3 text-[var(--color-text-primary)]">{item.target_id}</td>
                      <td className="px-4 py-3 text-[var(--color-text-secondary)] font-sans max-w-xs truncate">
                        {item.executive_summary}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(item.severity)}`}>
                          {item.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-bold text-[var(--color-safe)]">{item.confidence_score}%</td>
                      <td className="px-4 py-3 text-[var(--color-text-muted)]">
                        {item.created_at ? new Date(item.created_at).toLocaleTimeString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
