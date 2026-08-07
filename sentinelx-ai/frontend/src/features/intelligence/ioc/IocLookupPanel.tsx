import { useState } from "react";
import {
  MagnifyingGlassIcon,
  ArrowPathIcon,
  ExclamationCircleIcon,
  ShieldCheckIcon,
  SparklesIcon,
  ClockIcon,
  CpuChipIcon,
  GlobeAltIcon,
  LinkIcon,
  DocumentDuplicateIcon,
  ServerIcon,
  CheckCircleIcon,
  XCircleIcon,
} from "@heroicons/react/24/outline";
import {
  lookupIpAddress,
  lookupDomainName,
  lookupUrlLink,
  lookupFileHash,
  lookupHostDetails,
  type IOCLookupResponse,
  type ProviderResultItem,
} from "../../../services/threatIntelligenceService";

type IocCategory = "IP" | "Domain" | "URL" | "Hash" | "Host";

const SAMPLE_IOCS: Record<IocCategory, string[]> = {
  IP: ["185.220.101.5", "8.8.8.8", "45.154.255.120"],
  Domain: ["malware-c2.net", "google.com", "phishing-bank.xyz"],
  URL: ["http://suspicious-download.org/payload.exe", "https://github.com"],
  Hash: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "44d88612fea8a8f36de82e1278abb02f"],
  Host: ["192.168.1.1", "185.220.101.5", "api.shodan.io"],
};

export default function IocLookupPanel() {
  const [activeTab, setActiveTab] = useState<IocCategory>("IP");
  const [inputValue, setInputValue] = useState<string>("185.220.101.5");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IOCLookupResponse | null>(null);
  const [forceRefresh, setForceRefresh] = useState<boolean>(false);

  const handleTabChange = (category: IocCategory) => {
    setActiveTab(category);
    setInputValue(SAMPLE_IOCS[category][0] || "");
    setResult(null);
    setError(null);
  };

  const handleLookup = async (overrideValue?: string) => {
    const val = (overrideValue || inputValue).trim();
    if (!val) return;

    setLoading(true);
    setError(null);

    try {
      let res: IOCLookupResponse;
      if (activeTab === "IP") {
        res = await lookupIpAddress(val, forceRefresh);
      } else if (activeTab === "Domain") {
        res = await lookupDomainName(val, forceRefresh);
      } else if (activeTab === "URL") {
        res = await lookupUrlLink(val, forceRefresh);
      } else if (activeTab === "Hash") {
        res = await lookupFileHash(val, forceRefresh);
      } else {
        res = await lookupHostDetails(val, forceRefresh);
      }
      setResult(res);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || "Threat Intelligence lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const getVerdictStyle = (verdict: string) => {
    switch (verdict) {
      case "Malicious":
        return "bg-[var(--color-critical)]/20 text-[var(--color-critical)] border-[var(--color-critical)]/40";
      case "Suspicious":
        return "bg-[var(--color-high)]/20 text-[var(--color-high)] border-[var(--color-high)]/40";
      case "Harmless":
        return "bg-[var(--color-safe)]/20 text-[var(--color-safe)] border-[var(--color-safe)]/40";
      default:
        return "bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] border-[var(--color-border)]";
    }
  };

  return (
    <div className="space-y-6">
      {/* Search Header & Category Selection Tabs */}
      <div className="glass rounded-2xl p-6 border border-[var(--color-border)] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
              <CpuChipIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
              <span>Multi-Provider IOC Threat Lookup</span>
            </h2>
            <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
              Live threat correlation across VirusTotal, AbuseIPDB, Shodan, and Google Gemini AI
            </p>
          </div>

          <div className="flex items-center gap-2">
            <label className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)] cursor-pointer select-none font-mono">
              <input
                type="checkbox"
                checked={forceRefresh}
                onChange={(e) => setForceRefresh(e.target.checked)}
                className="rounded border-[var(--color-border)] bg-[var(--color-surface-300)] text-[var(--color-primary-500)] focus:ring-0"
              />
              <span>Bypass Cache</span>
            </label>
          </div>
        </div>

        {/* Categories Tab Selector */}
        <div className="flex flex-wrap gap-2 pt-2 border-t border-[var(--color-border)]">
          {(["IP", "Domain", "URL", "Hash", "Host"] as IocCategory[]).map((tab) => (
            <button
              key={tab}
              onClick={() => handleTabChange(tab)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeTab === tab
                  ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)] shadow-lg shadow-[var(--color-primary-500)]/20"
                  : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)] border border-[var(--color-border)]"
              }`}
            >
              {tab === "IP" && <GlobeAltIcon className="w-4 h-4" />}
              {tab === "Domain" && <GlobeAltIcon className="w-4 h-4 text-blue-400" />}
              {tab === "URL" && <LinkIcon className="w-4 h-4 text-purple-400" />}
              {tab === "Hash" && <DocumentDuplicateIcon className="w-4 h-4 text-emerald-400" />}
              {tab === "Host" && <ServerIcon className="w-4 h-4 text-amber-400" />}
              <span>{tab} Lookup</span>
            </button>
          ))}
        </div>

        {/* Input Bar & Search Button */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLookup()}
              placeholder={`Enter ${activeTab} indicator (e.g. ${SAMPLE_IOCS[activeTab][0]})...`}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary-500)]"
            />
            <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3.5 top-3" />
          </div>

          <button
            onClick={() => handleLookup()}
            disabled={loading || !inputValue.trim()}
            className="flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold hover:bg-[var(--color-primary-600)] transition-all disabled:opacity-50 shadow-lg shadow-[var(--color-primary-500)]/20 shrink-0"
          >
            {loading ? (
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
            ) : (
              <MagnifyingGlassIcon className="w-4 h-4" />
            )}
            <span>{loading ? "Analyzing..." : "Analyze Indicator"}</span>
          </button>
        </div>

        {/* Sample Indicators Quick Bar */}
        <div className="flex items-center gap-2 text-[11px] font-mono text-[var(--color-text-muted)] pt-1">
          <span className="shrink-0">Sample Indicators:</span>
          <div className="flex flex-wrap gap-1.5">
            {SAMPLE_IOCS[activeTab].map((sample) => (
              <button
                key={sample}
                onClick={() => {
                  setInputValue(sample);
                  handleLookup(sample);
                }}
                className="px-2 py-0.5 rounded bg-[var(--color-surface-300)]/60 text-[var(--color-text-secondary)] hover:text-[var(--color-primary-500)] border border-[var(--color-border)] transition-colors truncate max-w-[200px]"
              >
                {sample}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error Callout State */}
      {error && (
        <div className="p-4 rounded-xl bg-[var(--color-critical)]/15 border border-[var(--color-critical)]/40 text-[var(--color-critical)] text-xs font-semibold flex items-center justify-between animate-fade-in">
          <div className="flex items-center gap-2">
            <ExclamationCircleIcon className="w-5 h-5 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => handleLookup()}
            className="px-3 py-1 rounded bg-[var(--color-critical)] text-[var(--color-surface-0)] text-[10px] font-bold"
          >
            Retry
          </button>
        </div>
      )}

      {/* Loading Skeleton State */}
      {loading && (
        <div className="space-y-4 animate-pulse">
          <div className="glass rounded-xl p-6 border border-[var(--color-border)] h-28 skeleton" />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((n) => (
              <div key={n} className="glass rounded-xl p-5 border border-[var(--color-border)] h-48 skeleton" />
            ))}
          </div>
        </div>
      )}

      {/* Empty State */}
      {!loading && !result && !error && (
        <div className="glass rounded-2xl p-12 border border-[var(--color-border)] text-center space-y-3">
          <CpuChipIcon className="w-12 h-12 text-[var(--color-text-muted)] mx-auto opacity-50" />
          <h3 className="text-sm font-bold text-[var(--color-text-primary)]">Ready for Threat Analysis</h3>
          <p className="text-xs text-[var(--color-text-muted)] max-w-md mx-auto">
            Select an indicator category above, enter an IP, domain, URL, file hash, or host, and click <strong>Analyze Indicator</strong> to fetch real-time intelligence.
          </p>
        </div>
      )}

      {/* Results View */}
      {!loading && result && (
        <div className="space-y-6 animate-fade-in">
          {/* Top Threat Overview Banner */}
          <div className="glass rounded-2xl p-6 border border-[var(--color-border)] bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={`px-2.5 py-0.5 rounded text-xs font-extrabold uppercase font-mono border ${getVerdictStyle(
                      result.verdict
                    )}`}
                  >
                    {result.verdict} VERDICT
                  </span>
                  {result.cache_hit ? (
                    <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/15 text-blue-400 border border-blue-500/30 flex items-center gap-1">
                      <ClockIcon className="w-3 h-3" />
                      CACHED RESPONSE
                    </span>
                  ) : (
                    <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-[var(--color-safe)]/15 text-[var(--color-safe)] border border-[var(--color-safe)]/30 flex items-center gap-1">
                      <CheckCircleIcon className="w-3 h-3" />
                      LIVE QUERY
                    </span>
                  )}
                </div>
                <h2 className="text-lg font-bold font-mono text-[var(--color-text-primary)] break-all">
                  {result.ioc_value}
                </h2>
                <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                  Type: <strong className="font-mono text-[var(--color-primary-500)]">{result.ioc_type}</strong> • Reputation: {result.reputation}
                </p>
              </div>

              {/* Threat Score & Confidence Gauge */}
              <div className="flex items-center gap-4 border-t sm:border-t-0 sm:border-l border-[var(--color-border)] pt-3 sm:pt-0 sm:pl-6">
                <div>
                  <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">Threat Score</p>
                  <p
                    className={`text-2xl font-extrabold font-mono ${
                      result.threat_score >= 70
                        ? "text-[var(--color-critical)]"
                        : result.threat_score >= 30
                        ? "text-[var(--color-high)]"
                        : "text-[var(--color-safe)]"
                    }`}
                  >
                    {result.threat_score} <span className="text-xs font-normal text-[var(--color-text-muted)]">/ 100</span>
                  </p>
                </div>

                <div>
                  <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">Confidence</p>
                  <p className="text-2xl font-extrabold font-mono text-[var(--color-primary-500)]">
                    {result.confidence}%
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Provider Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* 1. VirusTotal Card */}
            <ProviderCard
              title="VirusTotal"
              icon={GlobeAltIcon}
              providerItem={result.providers["VirusTotal"]}
            >
              {(data) => (
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Verdict:</span>
                    <span className="font-bold text-[var(--color-text-primary)]">{data.verdict || "N/A"}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Detections:</span>
                    <span className="font-bold text-[var(--color-critical)]">
                      {data.malicious_count ?? 0} / {data.total_engines ?? 0} engines
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Suspicious:</span>
                    <span className="font-bold text-[var(--color-high)]">{data.suspicious_count ?? 0}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Harmless:</span>
                    <span className="font-bold text-[var(--color-safe)]">{data.harmless_count ?? 0}</span>
                  </div>
                  {data.raw_attributes?.country && (
                    <div className="flex items-center justify-between">
                      <span className="text-[var(--color-text-muted)]">Country / ASN:</span>
                      <span className="text-[var(--color-text-primary)]">
                        {data.raw_attributes.country} {data.raw_attributes.asn ? `(AS${data.raw_attributes.asn})` : ""}
                      </span>
                    </div>
                  )}
                </div>
              )}
            </ProviderCard>

            {/* 2. AbuseIPDB Card */}
            <ProviderCard
              title="AbuseIPDB"
              icon={ExclamationCircleIcon}
              providerItem={result.providers["AbuseIPDB"]}
            >
              {(data) => (
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Abuse Confidence:</span>
                    <span
                      className={`font-bold ${
                        (data.abuse_confidence_score || 0) > 50
                          ? "text-[var(--color-critical)]"
                          : "text-[var(--color-safe)]"
                      }`}
                    >
                      {data.abuse_confidence_score ?? 0}%
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Total Reports:</span>
                    <span className="font-bold text-[var(--color-text-primary)]">{data.total_reports ?? 0}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Country:</span>
                    <span className="text-[var(--color-text-primary)]">
                      {data.country_name || data.country_code || "Unknown"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">ISP:</span>
                    <span className="text-[var(--color-text-primary)] truncate max-w-[150px]">
                      {data.isp || "N/A"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Usage Type:</span>
                    <span className="text-[var(--color-text-secondary)]">{data.usage_type || "N/A"}</span>
                  </div>
                </div>
              )}
            </ProviderCard>

            {/* 3. Shodan Card */}
            <ProviderCard
              title="Shodan"
              icon={ServerIcon}
              providerItem={result.providers["Shodan"]}
            >
              {(data) => (
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-muted)]">Organization:</span>
                    <span className="font-bold text-[var(--color-text-primary)] truncate max-w-[140px]">
                      {data.organization || data.isp || "N/A"}
                    </span>
                  </div>
                  <div>
                    <span className="text-[var(--color-text-muted)]">Open Ports:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {data.open_ports?.length ? (
                        data.open_ports.map((port: number) => (
                          <span
                            key={port}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-[var(--color-surface-300)] text-[var(--color-primary-500)] font-bold"
                          >
                            {port}
                          </span>
                        ))
                      ) : (
                        <span className="text-[var(--color-text-muted)]">None detected</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <span className="text-[var(--color-text-muted)]">Vulnerabilities (CVEs):</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {data.vulnerabilities?.length ? (
                        data.vulnerabilities.slice(0, 3).map((cve: string) => (
                          <span
                            key={cve}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-[var(--color-critical)]/20 text-[var(--color-critical)] font-bold"
                          >
                            {cve}
                          </span>
                        ))
                      ) : (
                        <span className="text-[var(--color-text-muted)]">No known CVEs</span>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </ProviderCard>
          </div>

          {/* Gemini AI Summary & MITRE Mapping Section */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Gemini AI Intelligence Card */}
            <div className="glass rounded-xl p-5 border border-[var(--color-secondary-500)]/30 lg:col-span-2 space-y-3 bg-gradient-to-b from-[var(--color-secondary-500)]/5 to-transparent">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <SparklesIcon className="w-5 h-5 text-[var(--color-secondary-500)]" />
                  <h3 className="text-sm font-bold text-[var(--color-text-primary)]">
                    Google Gemini AI Threat Summary & Analysis
                  </h3>
                </div>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[var(--color-secondary-500)]/20 text-[var(--color-secondary-500)]">
                  GenAI Synthesis
                </span>
              </div>

              {result.providers["Google Gemini AI"]?.status === "unavailable" ? (
                <div className="p-4 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-muted)]">
                  <p className="font-bold text-amber-400 mb-1">Provider Unavailable</p>
                  <p>{result.providers["Google Gemini AI"]?.reason || "Gemini API key not configured or unreachable."}</p>
                </div>
              ) : result.gemini_summary ? (
                <div className="space-y-3 text-xs">
                  <div className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-1">
                    <p className="font-bold text-[var(--color-primary-500)]">Executive Summary</p>
                    <p className="text-[var(--color-text-primary)]">
                      {result.gemini_summary.threat_summary || "No executive summary provided."}
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-1">
                    <p className="font-bold text-[var(--color-text-primary)]">Indicator Explanation</p>
                    <p className="text-[var(--color-text-secondary)]">
                      {result.gemini_summary.ioc_explanation || "No explanation recorded."}
                    </p>
                  </div>

                  {result.gemini_summary.remediation_recommendations?.length ? (
                    <div className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-1.5">
                      <p className="font-bold text-[var(--color-safe)]">Remediation Recommendations</p>
                      <ul className="list-disc list-inside space-y-1 text-[var(--color-text-secondary)]">
                        {result.gemini_summary.remediation_recommendations.map((rec, i) => (
                          <li key={i}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="p-4 text-xs font-mono text-[var(--color-text-muted)]">
                  AI analysis response unavailable.
                </div>
              )}
            </div>

            {/* MITRE ATT&CK & Timeline Column */}
            <div className="space-y-6">
              {/* MITRE Mapping */}
              <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-3">
                <div className="flex items-center gap-2">
                  <ShieldCheckIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
                  <h3 className="text-sm font-bold text-[var(--color-text-primary)]">MITRE ATT&CK Mapping</h3>
                </div>

                {!result.mitre_mapping?.length ? (
                  <p className="text-xs font-mono text-[var(--color-text-muted)]">
                    No explicit MITRE technique associations identified.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {result.mitre_mapping.map((m, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs font-mono space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[var(--color-primary-500)]">{m.technique_id}</span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]">
                            {m.tactic}
                          </span>
                        </div>
                        <p className="font-bold text-[var(--color-text-primary)]">{m.name}</p>
                        {m.explanation && (
                          <p className="text-[11px] font-sans text-[var(--color-text-muted)]">{m.explanation}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Timeline Card */}
              <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-3">
                <div className="flex items-center gap-2">
                  <ClockIcon className="w-5 h-5 text-[var(--color-info)]" />
                  <h3 className="text-sm font-bold text-[var(--color-text-primary)]">Analysis Timeline</h3>
                </div>

                <div className="space-y-2 font-mono text-xs">
                  {result.timeline.map((item, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-[11px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-primary-500)] mt-1 shrink-0" />
                      <div>
                        <p className="font-semibold text-[var(--color-text-primary)]">{item.event}</p>
                        <p className="text-[10px] text-[var(--color-text-muted)]">
                          {new Date(item.timestamp).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Reusable Provider Status Card Component ─────────────────────────

function ProviderCard({
  title,
  icon: Icon,
  providerItem,
  children,
}: {
  title: string;
  icon: any;
  providerItem?: ProviderResultItem;
  children: (data: any) => React.ReactNode;
}) {
  const isAvailable = providerItem && providerItem.status === "available" && providerItem.data;
  const isNotFound = providerItem && providerItem.status === "not_found";

  return (
    <div className="glass rounded-xl p-5 border border-[var(--color-border)] flex flex-col justify-between space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className="w-5 h-5 text-[var(--color-primary-500)]" />
          <h3 className="text-sm font-bold text-[var(--color-text-primary)]">{title}</h3>
        </div>

        {isAvailable ? (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-safe)]/20 text-[var(--color-safe)] flex items-center gap-1">
            <CheckCircleIcon className="w-3 h-3" /> Ready
          </span>
        ) : isNotFound ? (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-surface-300)] text-[var(--color-text-muted)]">
            Not Found
          </span>
        ) : (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-critical)]/20 text-[var(--color-critical)] flex items-center gap-1">
            <XCircleIcon className="w-3 h-3" /> Unavailable
          </span>
        )}
      </div>

      {isAvailable ? (
        children(providerItem.data)
      ) : isNotFound ? (
        <div className="p-3 rounded bg-[var(--color-surface-200)] text-xs font-mono text-[var(--color-text-muted)]">
          Indicator was not found in {title} dataset.
        </div>
      ) : (
        <div className="p-3 rounded bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs space-y-1">
          <p className="font-bold text-amber-400 font-mono">Provider Unavailable</p>
          <p className="text-[11px] text-[var(--color-text-muted)] font-mono">
            {providerItem?.reason || "API key not configured or provider unreachable."}
          </p>
        </div>
      )}
    </div>
  );
}
