import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  CpuChipIcon,
  ShieldCheckIcon,
  GlobeAltIcon,
  ServerIcon,
  SignalIcon,
} from "@heroicons/react/24/outline";

import IocLookupPanel from "./ioc/IocLookupPanel";
import {
  fetchThreatIntelStats,
  fetchProviderStatuses,
  fetchThreatFeeds,
  fetchMitreTechniques,
} from "../../services/threatIntelligenceService";

export default function IntelligencePage() {
  const [activeTab, setActiveTab] = useState<"lookup" | "feeds" | "mitre">("lookup");

  // Telemetry statistics query
  const { data: stats } = useQuery({
    queryKey: ["threat-intel-stats"],
    queryFn: fetchThreatIntelStats,
    refetchInterval: 30000,
  });

  // External Provider Statuses query
  const { data: providerStatuses } = useQuery({
    queryKey: ["provider-statuses"],
    queryFn: fetchProviderStatuses,
    refetchInterval: 30000,
  });

  // Threat Feeds query
  const { data: feedsData, isLoading: isFeedsLoading } = useQuery({
    queryKey: ["threat-feeds"],
    queryFn: () => fetchThreatFeeds({ page_size: 50 }),
    refetchInterval: 60000,
  });

  // MITRE Techniques query
  const { data: mitreData, isLoading: isMitreLoading } = useQuery({
    queryKey: ["mitre-techniques"],
    queryFn: () => fetchMitreTechniques({ page_size: 50 }),
  });

  const providers = providerStatuses?.providers || [];
  const readyProvidersCount = providers.filter((p) => p.configured).length;
  const feedsList = feedsData?.items || [];
  const mitreList = mitreData?.items || [];

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Banner Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] p-6 rounded-2xl border border-[var(--color-border)] shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--color-primary-500)] animate-pulse" />
            <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
              Threat Intelligence & External Provider Hub
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Multi-provider IOC enrichment, live cache telemetry, STIX/TAXII threat feeds, and MITRE ATT&CK correlation
          </p>
        </div>

        {/* Telemetry Quick Badges */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="px-3 py-1.5 rounded-xl bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] text-xs font-mono">
            <span className="text-[var(--color-text-muted)]">Active Feeds: </span>
            <strong className="text-[var(--color-primary-500)]">{stats?.active_feeds ?? 0}</strong>
          </div>

          <div className="px-3 py-1.5 rounded-xl bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] text-xs font-mono">
            <span className="text-[var(--color-text-muted)]">Ready Providers: </span>
            <strong className="text-[var(--color-safe)]">{readyProvidersCount} / 4</strong>
          </div>

          <div className="px-3 py-1.5 rounded-xl bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] text-xs font-mono">
            <span className="text-[var(--color-text-muted)]">Cache Hit Ratio: </span>
            <strong className="text-blue-400">{stats?.cache_hit_ratio ?? 0}%</strong>
          </div>
        </div>
      </div>

      {/* Main Tabs Navigation Header */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-3">
        {[
          { id: "lookup", label: "IOC Lookup & Live Enrichment", icon: CpuChipIcon },
          { id: "feeds", label: "Threat Feeds & Provider Status", icon: GlobeAltIcon },
          { id: "mitre", label: "MITRE ATT&CK Matrix Catalog", icon: ShieldCheckIcon },
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

      {/* Tab 1: IOC Lookup Panel */}
      {activeTab === "lookup" && <IocLookupPanel />}

      {/* Tab 2: Threat Feeds & External Providers Health */}
      {activeTab === "feeds" && (
        <div className="space-y-6">
          {/* External Providers Health Grid */}
          <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4">
            <h2 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
              <SignalIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
              <span>External Threat Intelligence Providers Health</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {providers.map((p) => (
                <div
                  key={p.name}
                  className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] space-y-2 font-mono text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[var(--color-text-primary)]">{p.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        p.configured
                          ? "bg-[var(--color-safe)]/20 text-[var(--color-safe)]"
                          : "bg-[var(--color-critical)]/20 text-[var(--color-critical)]"
                      }`}
                    >
                      {p.configured ? "READY" : "UNAVAILABLE"}
                    </span>
                  </div>
                  <p className="text-[11px] text-[var(--color-text-muted)] font-sans">
                    {p.configured ? "API Key loaded and active" : p.reason || "API key not configured"}
                  </p>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {p.supported_types.map((type) => (
                      <span key={type} className="px-1.5 py-0.5 rounded text-[9px] bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]">
                        {type}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Registered Threat Feeds Table */}
          <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4">
            <h2 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
              <ServerIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
              <span>Registered Threat Feeds ({feedsList.length})</span>
            </h2>

            {isFeedsLoading ? (
              <div className="space-y-3">
                {[1, 2, 3].map((n) => (
                  <div key={n} className="h-12 w-full skeleton rounded-lg" />
                ))}
              </div>
            ) : !feedsList.length ? (
              <div className="p-6 text-center text-xs font-mono text-[var(--color-text-muted)]">
                No threat feeds registered.
              </div>
            ) : (
              <div className="space-y-3">
                {feedsList.map((feed: any) => (
                  <div
                    key={feed.id}
                    className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] gap-2 text-xs"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-[var(--color-text-primary)]">{feed.feed_name}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[var(--color-surface-300)] text-[var(--color-primary-500)]">
                          {feed.feed_type}
                        </span>
                      </div>
                      <p className="text-[11px] text-[var(--color-text-muted)] mt-0.5">
                        Provider: {feed.provider} • Score: {feed.reliability_score}%
                      </p>
                    </div>

                    <div className="flex items-center gap-4 text-xs font-mono shrink-0">
                      <span className="text-[var(--color-text-secondary)]">
                        {feed.total_indicators} IOCs
                      </span>
                      <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-[var(--color-safe)]/20 text-[var(--color-safe)]">
                        {feed.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: MITRE ATT&CK Matrix Catalog */}
      {activeTab === "mitre" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
            <ShieldCheckIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
            <span>MITRE ATT&CK Techniques ({mitreList.length})</span>
          </h2>

          {isMitreLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[1, 2, 3, 4, 5, 6].map((n) => (
                <div key={n} className="h-24 skeleton rounded-lg" />
              ))}
            </div>
          ) : !mitreList.length ? (
            <div className="p-8 text-center text-xs font-mono text-[var(--color-text-muted)]">
              No MITRE techniques cached in dataset.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {mitreList.map((t: any) => (
                <div
                  key={t.id}
                  className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] hover:border-[var(--color-primary-500)] transition-all space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between font-mono">
                    <span className="font-bold text-[var(--color-primary-500)]">{t.technique_id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] font-bold">
                      {t.tactic}
                    </span>
                  </div>
                  <h3 className="font-bold text-[var(--color-text-primary)]">{t.name}</h3>
                  {t.description && (
                    <p className="text-[11px] text-[var(--color-text-muted)] line-clamp-2">
                      {t.description}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
