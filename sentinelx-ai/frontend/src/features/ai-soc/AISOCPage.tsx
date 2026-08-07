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
  PaperAirplaneIcon,
  DocumentArrowDownIcon,
  TrashIcon,
} from "@heroicons/react/24/outline";

import {
  triggerAIInvestigation,
  executeAIThreatHunt,
  fetchAIRiskAssessment,
  fetchAIRecommendations,
  fetchAIHistory,
  sendCopilotChat,
  generateAIReport,
  deleteAIHistoryItem,
  type InvestigationResponse,
  type ThreatHuntResponse,
  type AIChatMessage,
} from "../../services/aiSocService";

export default function AISOCPage() {
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"copilot" | "investigate" | "hunting" | "risk" | "recommendations" | "history">("copilot");

  // Copilot Chat State
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState<Array<{ sender: "User" | "Copilot"; text: string; confidence?: number; evidence?: any }>>([
    {
      sender: "Copilot",
      text: "Hello SOC Analyst! I am your **SentinelX AI Copilot**. Ask me natural language questions like *'Show critical incidents from last 24 hours'* or *'List ransomware threats'*.",
      confidence: 98,
    },
  ]);
  const [activeConversationId, setActiveConversationId] = useState<string | undefined>(undefined);
  const [reportFormat, setReportFormat] = useState("markdown");

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

  // Copilot Chat Mutation
  const chatMutation = useMutation({
    mutationFn: (msg: string) => sendCopilotChat(msg, activeConversationId),
    onSuccess: (data: AIChatMessage) => {
      setActiveConversationId(data.conversation_id);
      setChatMessages((prev) => [
        ...prev,
        {
          sender: "Copilot",
          text: data.content,
          confidence: data.confidence_score,
          evidence: data.evidence,
        },
      ]);
      queryClient.invalidateQueries({ queryKey: ["ai-history"] });
    },
  });

  // Report Generator Mutation
  const reportMutation = useMutation({
    mutationFn: (reportType: string) => generateAIReport(reportType, undefined, reportFormat),
    onSuccess: (data) => {
      // Trigger browser download for generated report
      const blob = new Blob([data.markdown_content], { type: "text/markdown;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `sentinelx_${data.report_type.toLowerCase()}_report.md`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },
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

  // Delete History Item
  const deleteHistoryMutation = useMutation({
    mutationFn: (id: string) => deleteAIHistoryItem(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ai-history"] });
    },
  });

  const handleSendChat = (prompt?: string) => {
    const textToSend = prompt || chatInput;
    if (!textToSend.trim()) return;

    setChatMessages((prev) => [...prev, { sender: "User", text: textToSend }]);
    setChatInput("");
    chatMutation.mutate(textToSend);
  };

  const suggestedPrompts = [
    "Investigate latest incident",
    "Show critical incidents from last 24 hours",
    "Show failed logins",
    "Summarize attack chain",
    "Explain this IOC",
    "Recommend remediation",
    "Generate executive report",
    "Find suspicious users",
  ];

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
              SentinelX Enterprise AI Copilot & Natural Language Security Assistant
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Interact with natural language queries, multi-format security reports (PDF/Markdown/JSON), and AI explainability breakdowns
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => reportMutation.mutate("Executive")}
            disabled={reportMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-[var(--color-primary-500)] to-purple-600 text-[var(--color-surface-0)] text-xs font-bold hover:opacity-90 transition-all shadow-lg shadow-[var(--color-primary-500)]/20"
          >
            <DocumentArrowDownIcon className="w-4 h-4" />
            <span>Generate Executive Report</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-3 overflow-x-auto">
        {[
          { id: "copilot", label: "Enterprise AI Copilot", icon: SparklesIcon },
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

      {/* Tab 0: Enterprise AI Copilot Chat Console */}
      {activeTab === "copilot" && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Main Chat Thread Area */}
          <div className="lg:col-span-3 space-y-4">
            {/* Suggested Prompts Pills */}
            <div className="glass rounded-xl p-3 border border-[var(--color-border)] space-y-2">
              <span className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider block font-mono">
                Suggested Security Prompts
              </span>
              <div className="flex flex-wrap gap-2">
                {suggestedPrompts.map((p, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendChat(p)}
                    className="px-3 py-1 rounded-lg bg-[var(--color-surface-200)] text-[11px] font-mono text-[var(--color-text-primary)] hover:bg-[var(--color-primary-500)] hover:text-[var(--color-surface-0)] transition-all border border-[var(--color-border)]"
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            {/* Chat Thread Messages Box */}
            <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4 min-h-[420px] max-h-[500px] overflow-y-auto font-mono text-xs">
              {chatMessages.map((msg, idx) => (
                <div
                  key={idx}
                  className={`flex gap-3 ${msg.sender === "User" ? "justify-end" : "justify-start"}`}
                >
                  <div
                    className={`max-w-2xl p-4 rounded-2xl border space-y-2 ${
                      msg.sender === "User"
                        ? "bg-[var(--color-primary-500)]/20 text-[var(--color-text-primary)] border-[var(--color-primary-500)]/40 ml-12"
                        : "bg-[var(--color-surface-200)]/80 text-[var(--color-text-primary)] border-[var(--color-border)] mr-12"
                    }`}
                  >
                    <div className="flex items-center justify-between border-b border-[var(--color-border)]/40 pb-1 text-[10px]">
                      <span className="font-bold text-[var(--color-primary-500)]">
                        {msg.sender === "User" ? "SOC Analyst" : "SentinelX AI Copilot"}
                      </span>
                      {msg.confidence ? (
                        <span className="text-[var(--color-safe)] font-bold">
                          {msg.confidence}% Confidence
                        </span>
                      ) : null}
                    </div>

                    <div className="whitespace-pre-wrap font-sans text-xs leading-relaxed">
                      {msg.text}
                    </div>

                    {/* Evidence & Attribution Panel */}
                    {msg.evidence && (
                      <div className="p-2.5 rounded-lg bg-[var(--color-surface-300)] text-[10px] space-y-1 font-mono border border-[var(--color-border)]">
                        <span className="font-bold text-[var(--color-text-muted)] uppercase block">Observed Evidence & Attribution</span>
                        <p className="text-[var(--color-text-secondary)]">SQL Filter: <code>{msg.evidence.sql_filter}</code></p>
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {chatMutation.isPending && (
                <div className="flex gap-2 items-center text-xs font-mono text-[var(--color-primary-500)] animate-pulse">
                  <ArrowPathIcon className="w-4 h-4 animate-spin" />
                  <span>SentinelX Copilot analyzing platform telemetry...</span>
                </div>
              )}
            </div>

            {/* Chat Input Box */}
            <div className="glass rounded-xl p-3 border border-[var(--color-border)] flex items-center gap-3">
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSendChat()}
                placeholder="Ask AI Copilot: 'Show critical incidents from last 24 hours', 'Show failed logins'..."
                className="flex-1 px-4 py-2.5 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary-500)]"
              />
              <button
                onClick={() => handleSendChat()}
                disabled={chatMutation.isPending}
                className="px-5 py-2.5 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold text-xs hover:bg-[var(--color-primary-600)] transition-all flex items-center gap-2 shrink-0 disabled:opacity-50"
              >
                <PaperAirplaneIcon className="w-4 h-4" />
                <span>Send</span>
              </button>
            </div>
          </div>

          {/* Copilot Sidebar Panel */}
          <div className="space-y-4 font-mono text-xs">
            {/* Quick Report Download Box */}
            <div className="glass rounded-xl p-4 border border-[var(--color-border)] space-y-3">
              <h3 className="font-bold text-[var(--color-text-primary)] uppercase text-[10px] tracking-wider">
                Instant Report Exporter
              </h3>
              <div className="space-y-2">
                <select
                  value={reportFormat}
                  onChange={(e) => setReportFormat(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)]"
                >
                  <option value="markdown">Markdown (.md)</option>
                  <option value="json">JSON (.json)</option>
                  <option value="pdf">PDF Structure (.pdf)</option>
                </select>
                <button
                  onClick={() => reportMutation.mutate("Incident")}
                  disabled={reportMutation.isPending}
                  className="w-full py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold text-xs hover:bg-[var(--color-surface-400)] transition-all flex items-center justify-center gap-2"
                >
                  <DocumentArrowDownIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
                  <span>Download Incident Report</span>
                </button>
                <button
                  onClick={() => reportMutation.mutate("SOAR")}
                  disabled={reportMutation.isPending}
                  className="w-full py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold text-xs hover:bg-[var(--color-surface-400)] transition-all flex items-center justify-center gap-2"
                >
                  <DocumentArrowDownIcon className="w-4 h-4 text-purple-400" />
                  <span>Download SOAR Report</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

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

              {/* Evidence Breakdown */}
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
            </div>

            <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-2 col-span-2">
              <span className="text-[10px] font-bold text-[var(--color-primary-500)] uppercase">Predictive Spread Forecast</span>
              <p className="text-sm font-bold text-[var(--color-text-primary)]">
                {riskAssessment?.attack_spread_prediction}
              </p>
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
                  </div>
                ))}
              </div>
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
                    <th className="px-4 py-3 text-right">Delete</th>
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
                      <td className="px-4 py-3 text-right">
                        {item.id && (
                          <button
                            onClick={() => deleteHistoryMutation.mutate(item.id!)}
                            className="p-1 text-[var(--color-critical)] hover:bg-[var(--color-critical)]/20 rounded"
                          >
                            <TrashIcon className="w-4 h-4" />
                          </button>
                        )}
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
