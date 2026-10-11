import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  SparklesIcon,
  PaperAirplaneIcon,
  UserIcon,
  ShieldCheckIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  DocumentArrowDownIcon,
  ClipboardDocumentCheckIcon,
  TrashIcon,
  PlusIcon,
  ChatBubbleLeftRightIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  BoltIcon,
  InformationCircleIcon,
} from "@heroicons/react/24/outline";

import { useAuth } from "../../contexts/AuthContext";
import {
  sendCopilotChat,
  fetchAIConversations,
  fetchAIConversation,
  createAIConversation,
  deleteAIConversation,
  executeSafeResponseAction,
  type AIChatMessage,
  type AIChatConversation,
  type SuggestedAction,
  type SafeActionExecuteResponse,
} from "../../services/aiSocService";

export default function AiAssistantPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const firstName = user?.first_name?.trim() || user?.email?.split("@")[0] || "Analyst";
  const userDisplayName = user
    ? `${user.first_name} ${user.last_name}`.trim() || user.first_name || user.email
    : "Analyst";

  // State
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<AIChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [confirmActionModal, setConfirmActionModal] = useState<SuggestedAction | null>(null);
  const [actionFeedback, setActionFeedback] = useState<SafeActionExecuteResponse | null>(null);

  // Suggested Prompts based on User Requirements
  const suggestedPrompts = [
    { label: "Critical Alerts", prompt: "Show me all critical security alerts." },
    { label: "Laptop Activity", prompt: "What suspicious activities happened on my laptop?" },
    { label: "Brute Force Logins", prompt: "Analyze failed login attempts and identify possible brute-force attacks." },
    { label: "Offline Endpoints", prompt: "Which endpoints are currently offline?" },
    { label: "High-Risk Assets", prompt: "Show me the highest-risk assets." },
    { label: "Threat Correlations", prompt: "Explain the latest threat correlations." },
    { label: "24h SOC Delta", prompt: "Show me what changed in the SOC during the last 24 hours." },
    { label: "Academic Incident Report", prompt: "Generate an incident report for my professor." },
    { label: "Investigation Pivot", prompt: "What should I investigate next?" },
  ];

  // Queries
  const { data: convData, isLoading: isConvsLoading } = useQuery({
    queryKey: ["ai-conversations"],
    queryFn: () => fetchAIConversations(1, 30),
    refetchInterval: 30000,
  });

  const { data: activeConvDetails } = useQuery({
    queryKey: ["ai-conversation", activeConversationId],
    queryFn: () => (activeConversationId ? fetchAIConversation(activeConversationId) : null),
    enabled: !!activeConversationId,
  });

  // Sync loaded conversation messages
  useEffect(() => {
    if (activeConvDetails && activeConvDetails.messages) {
      setMessages(activeConvDetails.messages);
    }
  }, [activeConvDetails]);

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Mutations
  const chatMutation = useMutation({
    mutationFn: (msg: string) => sendCopilotChat(msg, activeConversationId || undefined),
    onSuccess: (newMsg: AIChatMessage) => {
      if (!activeConversationId) {
        setActiveConversationId(newMsg.conversation_id);
      }
      setMessages((prev) => [...prev, newMsg]);
      queryClient.invalidateQueries({ queryKey: ["ai-conversations"] });
    },
  });

  const newChatMutation = useMutation({
    mutationFn: (title?: string) => createAIConversation(title || "New Security Chat"),
    onSuccess: (newConv: AIChatConversation) => {
      setActiveConversationId(newConv.id);
      setMessages([]);
      queryClient.invalidateQueries({ queryKey: ["ai-conversations"] });
    },
  });

  const deleteChatMutation = useMutation({
    mutationFn: (id: string) => deleteAIConversation(id),
    onSuccess: (_, deletedId) => {
      if (activeConversationId === deletedId) {
        setActiveConversationId(null);
        setMessages([]);
      }
      queryClient.invalidateQueries({ queryKey: ["ai-conversations"] });
    },
  });

  const executeActionMutation = useMutation({
    mutationFn: (payload: { action: SuggestedAction; isDryRun: boolean; confirmed: boolean }) =>
      executeSafeResponseAction({
        action_type: payload.action.action_type,
        target: payload.action.target,
        parameters: payload.action.parameters,
        is_dry_run: payload.isDryRun,
        confirmed: payload.confirmed,
      }),
    onSuccess: (data: SafeActionExecuteResponse) => {
      setActionFeedback(data);
      setConfirmActionModal(null);
    },
    onError: (err: any) => {
      setActionFeedback({
        success: false,
        status: "Error",
        action_type: "Failed",
        target: "Target",
        is_dry_run: false,
        output: {},
        rollback_data: {},
        executed_by: userDisplayName,
        executed_at: new Date().toISOString(),
        error: err?.response?.data?.detail || "Execution failed. Action aborted.",
      });
      setConfirmActionModal(null);
    },
  });

  // Handlers
  const handleSend = (textToSend?: string) => {
    const query = textToSend || input;
    if (!query.trim() || chatMutation.isPending) return;

    // Optimistically show user message
    const tempUserMsg: AIChatMessage = {
      id: `temp-${Date.now()}`,
      conversation_id: activeConversationId || "",
      sender: "User",
      content: query,
      evidence: {},
      confidence_score: 100,
      created_at: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, tempUserMsg]);
    if (!textToSend) setInput("");
    chatMutation.mutate(query);
  };

  const toggleEvidence = (msgId: string) => {
    setExpandedEvidence((prev) => ({ ...prev, [msgId]: !prev[msgId] }));
  };

  const handleCopy = (msgId: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(msgId);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportMarkdown = (content: string, title = "SentinelX_Security_Report") => {
    const blob = new Blob([content], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `${title}_${Date.now()}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-[calc(100vh-85px)] gap-4 animate-fade-in">
      {/* ── Left Panel: Conversation History ──────────────────────────── */}
      <div
        className={`${
          isSidebarOpen ? "w-64" : "w-12"
        } transition-all duration-300 glass rounded-2xl border border-[var(--color-border)] flex flex-col p-3 shrink-0 relative`}
      >
        <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
          {isSidebarOpen ? (
            <>
              <div className="flex items-center gap-2">
                <ChatBubbleLeftRightIcon className="w-5 h-5 text-[var(--color-secondary-500)]" />
                <span className="text-xs font-bold uppercase tracking-wider text-[var(--color-text-primary)]">
                  Conversations
                </span>
              </div>
              <button
                onClick={() => newChatMutation.mutate("New Security Chat")}
                className="p-1.5 rounded-lg bg-[var(--color-surface-200)] hover:bg-[var(--color-secondary-500)]/20 text-[var(--color-text-secondary)] hover:text-[var(--color-secondary-500)] transition-colors"
                title="Start New Chat"
              >
                <PlusIcon className="w-4 h-4" />
              </button>
            </>
          ) : (
            <button
              onClick={() => setIsSidebarOpen(true)}
              className="w-full flex justify-center py-1 text-[var(--color-text-secondary)] hover:text-white"
            >
              <ChatBubbleLeftRightIcon className="w-5 h-5" />
            </button>
          )}
        </div>

        {isSidebarOpen && (
          <div className="flex-1 overflow-y-auto space-y-1 py-3 text-xs">
            {isConvsLoading ? (
              <div className="flex items-center justify-center p-4 text-[var(--color-text-muted)] animate-pulse">
                Loading history...
              </div>
            ) : convData?.items && convData.items.length > 0 ? (
              convData.items.map((c) => (
                <div
                  key={c.id}
                  onClick={() => setActiveConversationId(c.id)}
                  className={`group flex items-center justify-between p-2 rounded-xl cursor-pointer transition-all ${
                    activeConversationId === c.id
                      ? "bg-[var(--color-secondary-500)]/15 border border-[var(--color-secondary-500)]/40 text-[var(--color-text-primary)] font-semibold"
                      : "hover:bg-[var(--color-surface-200)] text-[var(--color-text-secondary)]"
                  }`}
                >
                  <span className="truncate pr-2">{c.title || "Untitled Session"}</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteChatMutation.mutate(c.id);
                    }}
                    className="opacity-0 group-hover:opacity-100 p-1 hover:text-[var(--color-danger)] transition-opacity"
                    title="Delete Chat"
                  >
                    <TrashIcon className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))
            ) : (
              <div className="text-center p-4 text-[var(--color-text-muted)] text-[11px]">
                No previous conversations. Start a new session!
              </div>
            )}
          </div>
        )}

        {isSidebarOpen && (
          <div className="pt-2 border-t border-[var(--color-border)]">
            <button
              onClick={() => setIsSidebarOpen(false)}
              className="w-full text-center text-[10px] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] transition-colors py-1"
            >
              Collapse Panel ←
            </button>
          </div>
        )}
      </div>

      {/* ── Main Chat Container ────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 glass rounded-2xl border border-[var(--color-border)] overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-[var(--color-border)] flex items-center justify-between bg-[var(--color-surface-100)]/60">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-[var(--color-secondary-500)] to-[var(--color-primary-500)] p-[1px] shadow-lg shadow-[var(--color-secondary-500)]/20">
              <div className="w-full h-full rounded-xl bg-[var(--color-surface-100)] flex items-center justify-center">
                <SparklesIcon className="w-5 h-5 text-[var(--color-secondary-500)] animate-pulse" />
              </div>
            </div>
            <div>
              <h1 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                SentinelX Enterprise AI Assistant
                <span className="px-2 py-0.5 text-[9px] font-mono rounded-full bg-[var(--color-primary-500)]/15 text-[var(--color-primary-500)] border border-[var(--color-primary-500)]/30">
                  v2.0 Real-Telemetry
                </span>
              </h1>
              <p className="text-[11px] text-[var(--color-text-secondary)]">
                Autonomous Security Intelligence • Database-Backed Telemetry • Verified Facts
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 text-[10px] font-mono font-bold rounded bg-[var(--color-safe)]/15 text-[var(--color-safe)] border border-[var(--color-safe)]/30 flex items-center gap-1.5">
              <ShieldCheckIcon className="w-3.5 h-3.5" />
              Live DB Synced
            </span>
            <button
              onClick={() => newChatMutation.mutate("New Security Chat")}
              className="px-3 py-1 text-[11px] font-medium rounded-lg bg-[var(--color-surface-200)] hover:bg-[var(--color-secondary-500)] hover:text-white transition-all border border-[var(--color-border)] flex items-center gap-1.5"
            >
              <PlusIcon className="w-3.5 h-3.5" />
              New Chat
            </button>
          </div>
        </div>

        {/* Action Feedback Banner (Dry-Run / Execution Result) */}
        {actionFeedback && (
          <div
            className={`p-3 mx-4 mt-3 rounded-xl border flex items-start justify-between text-xs animate-slide-down ${
              actionFeedback.success
                ? "bg-[var(--color-safe)]/10 border-[var(--color-safe)]/30 text-[var(--color-safe)]"
                : "bg-[var(--color-danger)]/10 border-[var(--color-danger)]/30 text-[var(--color-danger)]"
            }`}
          >
            <div className="space-y-1">
              <div className="font-bold flex items-center gap-2">
                {actionFeedback.success ? <CheckCircleIcon className="w-4 h-4" /> : <ExclamationTriangleIcon className="w-4 h-4" />}
                {actionFeedback.is_dry_run ? "Simulation (Dry-Run) Successful" : "Action Executed on Target"}
              </div>
              <p className="text-[11px] opacity-90">
                Action: <span className="font-mono font-bold">{actionFeedback.action_type}</span> on target{" "}
                <span className="font-mono font-bold">{actionFeedback.target}</span>. {actionFeedback.output?.message || actionFeedback.error}
              </p>
              {actionFeedback.rollback_data && Object.keys(actionFeedback.rollback_data).length > 0 && (
                <div className="text-[10px] font-mono opacity-80 pt-1">
                  Rollback Reference: {JSON.stringify(actionFeedback.rollback_data)}
                </div>
              )}
            </div>
            <button
              onClick={() => setActionFeedback(null)}
              className="p-1 hover:opacity-100 opacity-60 text-current"
            >
              ✕
            </button>
          </div>
        )}

        {/* Suggested Prompts Header Bar */}
        <div className="px-4 pt-3 flex gap-2 overflow-x-auto text-[11px] scrollbar-none">
          {suggestedPrompts.map((item) => (
            <button
              key={item.label}
              onClick={() => handleSend(item.prompt)}
              className="px-3 py-1.5 rounded-lg bg-[var(--color-surface-200)]/80 border border-[var(--color-border)] hover:border-[var(--color-secondary-500)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] whitespace-nowrap transition-all font-medium shrink-0 flex items-center gap-1.5"
            >
              <SparklesIcon className="w-3 h-3 text-[var(--color-secondary-500)]" />
              {item.label}
            </button>
          ))}
        </div>

        {/* Messages Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 ? (
            /* Empty State */
            <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-4">
              <div className="w-16 h-16 rounded-3xl bg-[var(--color-secondary-500)]/10 border border-[var(--color-secondary-500)]/20 flex items-center justify-center text-[var(--color-secondary-500)]">
                <SparklesIcon className="w-8 h-8 animate-pulse" />
              </div>
              <div className="max-w-md space-y-2">
                <h2 className="text-base font-bold text-[var(--color-text-primary)]">
                  Welcome, {firstName}. How can I assist your investigation?
                </h2>
                <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                  I query real-time SentinelX telemetry, endpoint agent health, security alerts, and threat correlations. Every finding is backed by observed database evidence.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-w-xl w-full pt-4 text-xs">
                {suggestedPrompts.slice(0, 4).map((p) => (
                  <button
                    key={p.label}
                    onClick={() => handleSend(p.prompt)}
                    className="p-3 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] hover:border-[var(--color-secondary-500)] text-left space-y-1 transition-all group"
                  >
                    <div className="font-semibold text-[var(--color-text-primary)] group-hover:text-[var(--color-secondary-500)]">
                      {p.label}
                    </div>
                    <div className="text-[11px] text-[var(--color-text-muted)] line-clamp-1">{p.prompt}</div>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            /* Message Stream */
            messages.map((msg) => {
              const isUser = msg.sender === "User";
              const ev = msg.evidence || {};
              const hasObserved = ev.observed_sentinelx_data && ev.observed_sentinelx_data.length > 0;
              const hasExternal = ev.external_intelligence && ev.external_intelligence.length > 0;
              const hasInference = ev.ai_inference && ev.ai_inference.length > 0;
              const warning = ev.insufficient_evidence_warning;
              const actions = ev.suggested_actions || [];

              return (
                <div
                  key={msg.id}
                  className={`flex items-start gap-3 ${isUser ? "flex-row-reverse" : ""}`}
                >
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
                      isUser
                        ? "bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)] font-bold text-xs"
                        : "bg-[var(--color-secondary-500)]/20 text-[var(--color-secondary-500)]"
                    }`}
                  >
                    {isUser ? <UserIcon className="w-4 h-4" /> : <SparklesIcon className="w-4 h-4" />}
                  </div>

                  <div
                    className={`max-w-[85%] rounded-2xl p-4 text-xs leading-relaxed space-y-3 ${
                      isUser
                        ? "bg-[var(--color-primary-500)]/15 border border-[var(--color-primary-500)]/30 text-[var(--color-text-primary)]"
                        : "bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-secondary)]"
                    }`}
                  >
                    {/* Header: Sender & Confidence Score */}
                    <div className="flex items-center justify-between text-[11px] text-[var(--color-text-muted)] border-b border-[var(--color-border)] pb-1.5 mb-2">
                      <span className="font-semibold text-[var(--color-text-primary)]">
                        {isUser ? userDisplayName : "SentinelX AI Copilot"}
                      </span>
                      <div className="flex items-center gap-2">
                        {!isUser && msg.confidence_score && (
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              msg.confidence_score >= 90
                                ? "bg-[var(--color-safe)]/15 text-[var(--color-safe)] border-[var(--color-safe)]/30"
                                : msg.confidence_score >= 75
                                ? "bg-[var(--color-warning)]/15 text-[var(--color-warning)] border-[var(--color-warning)]/30"
                                : "bg-[var(--color-danger)]/15 text-[var(--color-danger)] border-[var(--color-danger)]/30"
                            }`}
                          >
                            {msg.confidence_score}% Confidence
                          </span>
                        )}
                        <span className="text-[10px]">
                          {msg.created_at ? new Date(msg.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : ""}
                        </span>
                      </div>
                    </div>

                    {/* Content Markdown Body */}
                    <div className="prose prose-invert max-w-none text-xs leading-relaxed space-y-2 whitespace-pre-wrap font-sans text-[var(--color-text-primary)]">
                      {msg.content}
                    </div>

                    {/* Evidence & Confidence Breakdown (Copilot Responses) */}
                    {!isUser && (hasObserved || hasExternal || hasInference || warning) && (
                      <div className="pt-2 border-t border-[var(--color-border)]">
                        <button
                          onClick={() => toggleEvidence(msg.id)}
                          className="flex items-center justify-between w-full py-1 text-[11px] font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
                        >
                          <span className="flex items-center gap-1.5">
                            <InformationCircleIcon className="w-3.5 h-3.5 text-[var(--color-secondary-500)]" />
                            Evidence & Intelligence Classification
                          </span>
                          {expandedEvidence[msg.id] ? (
                            <ChevronDownIcon className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRightIcon className="w-3.5 h-3.5" />
                          )}
                        </button>

                        {expandedEvidence[msg.id] && (
                          <div className="mt-2 space-y-2.5 p-3 rounded-xl bg-[var(--color-surface-100)]/80 border border-[var(--color-border)] text-[11px]">
                            {/* 1. Observed SentinelX Data */}
                            {hasObserved && (
                              <div className="space-y-1">
                                <div className="font-bold text-[var(--color-safe)] flex items-center gap-1.5">
                                  <span>🟢</span> Observed SentinelX Data ({ev.observed_sentinelx_data?.length ?? 0} records)
                                </div>
                                <ul className="list-disc pl-5 space-y-0.5 text-[var(--color-text-muted)] font-mono text-[10px]">
                                  {ev.observed_sentinelx_data?.map((item: string, idx: number) => (
                                    <li key={idx}>{item}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {/* 2. External Threat Intelligence */}
                            {hasExternal && (
                              <div className="space-y-1">
                                <div className="font-bold text-[var(--color-primary-500)] flex items-center gap-1.5">
                                  <span>🔵</span> External Threat Intelligence
                                </div>
                                <ul className="list-disc pl-5 space-y-0.5 text-[var(--color-text-muted)] text-[10px]">
                                  {ev.external_intelligence?.map((item: string, idx: number) => (
                                    <li key={idx}>{item}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {/* 3. AI Inference */}
                            {hasInference && (
                              <div className="space-y-1">
                                <div className="font-bold text-[var(--color-secondary-500)] flex items-center gap-1.5">
                                  <span>🟣</span> AI Inference & Hypotheses *(Unconfirmed)*
                                </div>
                                <ul className="list-disc pl-5 space-y-0.5 text-[var(--color-text-muted)] text-[10px]">
                                  {ev.ai_inference?.map((item: string, idx: number) => (
                                    <li key={idx}>{item}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {/* 4. Insufficient Evidence */}
                            {warning && (
                              <div className="p-2 rounded-lg bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 text-[var(--color-warning)] text-[10px]">
                                ⚠️ <strong>Insufficient Evidence:</strong> {warning}
                              </div>
                            )}

                            {/* Direct Entity Links */}
                            <div className="pt-1.5 flex flex-wrap gap-2 text-[10px] font-medium border-t border-[var(--color-border)]">
                              <span className="text-[var(--color-text-muted)]">Pivots:</span>
                              <Link to="/alerts" className="text-[var(--color-primary-500)] hover:underline">
                                🔔 Alerts Center
                              </Link>
                              <Link to="/agents" className="text-[var(--color-primary-500)] hover:underline">
                                🖥️ Endpoints
                              </Link>
                              <Link to="/logs" className="text-[var(--color-primary-500)] hover:underline">
                                📜 Security Logs
                              </Link>
                              <Link to="/incidents" className="text-[var(--color-primary-500)] hover:underline">
                                📋 Incidents
                              </Link>
                              <Link to="/correlation" className="text-[var(--color-primary-500)] hover:underline">
                                🔗 Correlations
                              </Link>
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Safe Response Action Cards */}
                    {!isUser && actions.length > 0 && (
                      <div className="pt-2 border-t border-[var(--color-border)] space-y-2">
                        <div className="font-bold text-[11px] text-[var(--color-warning)] flex items-center gap-1.5">
                          <BoltIcon className="w-3.5 h-3.5" />
                          Recommended SOAR Response Actions (Requires Confirmation)
                        </div>

                        <div className="grid grid-cols-1 gap-2">
                          {actions.map((act: SuggestedAction, idx: number) => (
                            <div
                              key={idx}
                              className="p-3 rounded-xl bg-[var(--color-surface-100)] border border-[var(--color-border)] hover:border-[var(--color-warning)]/50 transition-all space-y-2"
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-mono font-bold text-xs text-[var(--color-text-primary)]">
                                  {act.action_type} → {act.target}
                                </span>
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[var(--color-warning)]/15 text-[var(--color-warning)]">
                                  Confirmation Required
                                </span>
                              </div>
                              <p className="text-[11px] text-[var(--color-text-secondary)]">{act.description}</p>
                              <div className="text-[10px] text-[var(--color-text-muted)] italic">
                                Expected Impact: {act.expected_impact}
                              </div>

                              <div className="flex items-center gap-2 pt-1">
                                {act.supports_dry_run && (
                                  <button
                                    onClick={() =>
                                      executeActionMutation.mutate({
                                        action: act,
                                        isDryRun: true,
                                        confirmed: false,
                                      })
                                    }
                                    disabled={executeActionMutation.isPending}
                                    className="px-2.5 py-1 rounded-lg bg-[var(--color-surface-200)] hover:bg-[var(--color-surface-300)] text-[var(--color-text-primary)] text-[10px] font-medium transition-colors"
                                  >
                                    🧪 Simulate (Dry-Run)
                                  </button>
                                )}
                                <button
                                  onClick={() => setConfirmActionModal(act)}
                                  disabled={executeActionMutation.isPending}
                                  className="px-2.5 py-1 rounded-lg bg-[var(--color-warning)] hover:bg-[var(--color-warning)]/80 text-black text-[10px] font-bold transition-colors flex items-center gap-1"
                                >
                                  ⚡ Authorize & Execute
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Bottom Utility Bar (Copy & Export) */}
                    {!isUser && (
                      <div className="flex items-center justify-end gap-2 pt-1 border-t border-[var(--color-border)]/60 text-[10px] text-[var(--color-text-muted)]">
                        <button
                          onClick={() => handleCopy(msg.id, msg.content)}
                          className="hover:text-[var(--color-text-primary)] flex items-center gap-1 transition-colors"
                        >
                          <ClipboardDocumentCheckIcon className="w-3.5 h-3.5" />
                          {copiedId === msg.id ? "Copied!" : "Copy Response"}
                        </button>
                        <span>•</span>
                        <button
                          onClick={() => handleExportMarkdown(msg.content)}
                          className="hover:text-[var(--color-text-primary)] flex items-center gap-1 transition-colors"
                        >
                          <DocumentArrowDownIcon className="w-3.5 h-3.5" />
                          Export Report (.md)
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}

          {chatMutation.isPending && (
            <div className="flex items-center gap-2 text-xs text-[var(--color-secondary-500)] font-mono animate-pulse pl-11 py-2">
              <SparklesIcon className="w-4 h-4" />
              <span>Querying SentinelX database & synthesizing telemetry facts...</span>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Controls */}
        <div className="p-3 border-t border-[var(--color-border)] bg-[var(--color-surface-100)]/60">
          <div className="glass rounded-xl p-1.5 border border-[var(--color-border)] flex items-center gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && handleSend()}
              placeholder="Ask SentinelX AI about alerts, offline endpoints, brute force logins, or laptop activity..."
              className="flex-1 bg-transparent px-3 py-2 text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none"
              disabled={chatMutation.isPending}
            />
            <button
              onClick={() => handleSend()}
              disabled={!input.trim() || chatMutation.isPending}
              className="p-2 rounded-lg bg-[var(--color-secondary-500)] text-white hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              title="Send Prompt"
            >
              <PaperAirplaneIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* ── Confirmation Modal for Impactful SOAR Actions ─────────────── */}
      {confirmActionModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass rounded-2xl p-6 border border-[var(--color-warning)]/40 max-w-md w-full space-y-4 shadow-2xl animate-scale-up bg-[var(--color-surface-100)]">
            <div className="flex items-center gap-3 text-[var(--color-warning)]">
              <ExclamationTriangleIcon className="w-6 h-6 shrink-0" />
              <h3 className="text-sm font-bold text-[var(--color-text-primary)]">
                Confirm Security Response Action
              </h3>
            </div>

            <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
              You are about to execute an authorized response action:
            </p>

            <div className="p-3 rounded-xl bg-black/40 border border-[var(--color-border)] font-mono text-xs space-y-1">
              <div>
                <strong>Action:</strong> <span className="text-[var(--color-warning)]">{confirmActionModal.action_type}</span>
              </div>
              <div>
                <strong>Target:</strong> {confirmActionModal.target}
              </div>
              <div>
                <strong>Expected Impact:</strong> {confirmActionModal.expected_impact}
              </div>
              <div>
                <strong>Rollback Supported:</strong> {confirmActionModal.rollback_available ? "Yes (Stored in audit log)" : "No"}
              </div>
            </div>

            <p className="text-[11px] text-[var(--color-text-muted)] italic">
              Safety Check: This action will be executed in live production. Actions are logged to SOC compliance audit history.
            </p>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setConfirmActionModal(null)}
                className="px-3 py-1.5 rounded-lg bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:text-white text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  executeActionMutation.mutate({
                    action: confirmActionModal,
                    isDryRun: false,
                    confirmed: true,
                  })
                }
                disabled={executeActionMutation.isPending}
                className="px-4 py-1.5 rounded-lg bg-[var(--color-warning)] hover:bg-[var(--color-warning)]/90 text-black text-xs font-bold transition-colors"
              >
                {executeActionMutation.isPending ? "Executing..." : "Confirm & Execute Now"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
