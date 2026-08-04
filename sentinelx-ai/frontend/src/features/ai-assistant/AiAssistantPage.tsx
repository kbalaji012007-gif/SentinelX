import { useState, useEffect } from "react";
import { SparklesIcon, PaperAirplaneIcon, UserIcon, ShieldCheckIcon } from "@heroicons/react/24/outline";
import { useAuth } from "../../contexts/AuthContext";

interface ChatMessage {
  id: string;
  sender: "user" | "gemini";
  text: string;
  timestamp: string;
  codeBlock?: string;
}

export default function AiAssistantPage() {
  const { user } = useAuth();

  // Extract first name (preferred), fallback to full name/email, fallback to "Analyst" when no user is logged in
  const firstName = user?.first_name?.trim() || user?.email?.split("@")[0] || "Analyst";
  const userDisplayName = user
    ? `${user.first_name} ${user.last_name}`.trim() || user.first_name || user.email
    : "Analyst";

  const getGreetingText = (name: string) =>
    `Greetings ${name}. I am Gemini Sentinel AI, your autonomous Security Operations assistant. How can I assist your investigation today?`;

  const [messages, setMessages] = useState<ChatMessage[]>(() => [
    {
      id: "1",
      sender: "gemini",
      text: getGreetingText(firstName),
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  // Dynamically update greeting if user changes / logs in
  useEffect(() => {
    setMessages((prev) => {
      if (prev.length > 0 && prev[0].id === "1" && prev[0].sender === "gemini") {
        const updated = [...prev];
        updated[0] = {
          ...updated[0],
          text: getGreetingText(firstName),
        };
        return updated;
      }
      return prev;
    });
  }, [firstName]);

  const suggestedPrompts = [
    "Summarize active threat THR-9021 (SSH Brute Force)",
    "Recommend playbook for host prod-db-master-01",
    "Show recent CVEs with CVSS score > 9.0",
    "Explain anomaly detection in log entry LOG-99402",
  ];

  const handleSend = (textToSend?: string) => {
    const query = textToSend || input;
    if (!query.trim()) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      sender: "user",
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInput("");
    setIsTyping(true);

    // Simulate AI response
    setTimeout(() => {
      let aiText = "Analyzing threat telemetry across SentinelX database...";
      let codeBlock: string | undefined = undefined;

      if (query.includes("THR-9021") || query.includes("SSH")) {
        aiText = `Threat THR-9021 involves a brute-force SSH campaign targeting prod-db-master-01 (10.0.1.10) from malicious Tor exit IP 185.220.101.5. Over 1,420 failed authentication attempts detected within a 15-minute sliding window.`;
        codeBlock = `PLAYBOOK EXECUTION RECOMMENDED:\n1. block_ip.py --ip "185.220.101.5"\n2. isolate_host.py --target "10.0.1.10"\n3. collect_logs.py --timeframe "last-1h"`;
      } else if (query.includes("CVE")) {
        aiText = "Identified 2 Critical CVEs requiring immediate patching:\n- CVE-2026-21048 (CVSS 9.8) Kernel eBPF Memory Write\n- CVE-2026-19022 (CVSS 9.1) Palo Alto PAN-OS Command Injection";
      } else {
        aiText = `Understood. Processing your inquiry regarding: "${query}". Cross-referencing MITRE ATT&CK techniques T1110 and T1071 across connected Supabase logs. All telemetry confirms active isolation safeguards are operating correctly.`;
      }

      const aiMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        sender: "gemini",
        text: aiText,
        codeBlock,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };

      setMessages((prev) => [...prev, aiMsg]);
      setIsTyping(false);
    }, 1200);
  };

  return (
    <div className="space-y-6 animate-fade-in flex flex-col h-[calc(100vh-100px)]">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[var(--color-secondary-500)] to-[var(--color-primary-500)] p-[1px] shadow-lg shadow-[var(--color-secondary-500)]/20">
            <div className="w-full h-full rounded-xl bg-[var(--color-surface-100)] flex items-center justify-center">
              <SparklesIcon className="w-5 h-5 text-[var(--color-secondary-500)] animate-pulse" />
            </div>
          </div>
          <div>
            <h1 className="text-base font-bold text-[var(--color-text-primary)]">Gemini AI SOC Assistant</h1>
            <p className="text-xs text-[var(--color-text-secondary)]">Google Gemini 2.0 Flash • Natural Language Security Intelligence</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 text-[10px] font-mono font-bold rounded bg-[var(--color-safe)]/15 text-[var(--color-safe)] border border-[var(--color-safe)]/30 flex items-center gap-1.5">
            <ShieldCheckIcon className="w-3.5 h-3.5" />
            Context Ready
          </span>
        </div>
      </div>

      {/* Suggested Prompts Bar */}
      <div className="flex gap-2 overflow-x-auto pb-2 text-xs">
        {suggestedPrompts.map((prompt) => (
          <button
            key={prompt}
            onClick={() => handleSend(prompt)}
            className="px-3 py-1.5 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] hover:border-[var(--color-secondary-500)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] whitespace-nowrap transition-all text-left font-medium"
          >
            💡 {prompt}
          </button>
        ))}
      </div>

      {/* Chat Messages Body */}
      <div className="flex-1 glass rounded-2xl p-6 border border-[var(--color-border)] overflow-y-auto space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex items-start gap-3 ${msg.sender === "user" ? "flex-row-reverse" : ""}`}
          >
            <div
              className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${
                msg.sender === "user"
                  ? "bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)] font-bold text-xs"
                  : "bg-[var(--color-secondary-500)]/20 text-[var(--color-secondary-500)]"
              }`}
            >
              {msg.sender === "user" ? <UserIcon className="w-4 h-4" /> : <SparklesIcon className="w-4 h-4" />}
            </div>

            <div
              className={`max-w-[75%] rounded-2xl p-4 text-xs leading-relaxed space-y-2 ${
                msg.sender === "user"
                  ? "bg-[var(--color-primary-500)]/15 border border-[var(--color-primary-500)]/30 text-[var(--color-text-primary)]"
                  : "bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[var(--color-text-secondary)]"
              }`}
            >
              <div className="flex items-center justify-between text-[10px] text-[var(--color-text-muted)] font-mono mb-1">
                <span>{msg.sender === "user" ? userDisplayName : "Gemini Sentinel"}</span>
                <span>{msg.timestamp}</span>
              </div>

              <p className="whitespace-pre-wrap">{msg.text}</p>

              {msg.codeBlock && (
                <pre className="font-mono text-[11px] bg-black/40 text-[var(--color-primary-500)] p-3 rounded-lg border border-[var(--color-border)] overflow-x-auto mt-2">
                  {msg.codeBlock}
                </pre>
              )}
            </div>
          </div>
        ))}

        {isTyping && (
          <div className="flex items-center gap-2 text-xs text-[var(--color-secondary-500)] font-mono animate-pulse pl-11">
            <SparklesIcon className="w-4 h-4" />
            <span>Gemini AI is generating security insights...</span>
          </div>
        )}
      </div>

      {/* Input Box */}
      <div className="glass rounded-xl p-2 border border-[var(--color-border)] flex items-center gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
          placeholder="Ask Gemini AI for threat analysis, playbook recommendations, or query logs..."
          className="flex-1 bg-transparent px-4 py-2 text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none"
        />
        <button
          onClick={() => handleSend()}
          className="p-2.5 rounded-lg bg-[var(--color-secondary-500)] text-white hover:opacity-90 transition-opacity"
        >
          <PaperAirplaneIcon className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
