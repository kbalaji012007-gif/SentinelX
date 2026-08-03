import { useState } from "react";
import { CpuChipIcon, ShieldCheckIcon, BugAntIcon, GlobeAltIcon } from "@heroicons/react/24/outline";
import { mockIocs, mockCves } from "../../utils/mockData";

export default function IntelligencePage() {
  const [activeTab, setActiveTab] = useState<"iocs" | "mitre" | "cve" | "feeds">("iocs");

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Threat Intelligence & Cyber Recon</h1>
          <p className="text-xs text-[var(--color-text-secondary)]">STIX/TAXII threat feed aggregation, IoC correlation, and MITRE ATT&CK mapping</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-3 py-1 text-xs font-semibold rounded-lg bg-[var(--color-secondary-500)]/15 text-[var(--color-secondary-500)] border border-[var(--color-secondary-500)]/30">
            4 Threat Feeds Connected
          </span>
        </div>
      </div>

      {/* Tabs Header */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-3">
        {[
          { id: "iocs", label: "Indicators of Compromise (IoCs)", icon: CpuChipIcon },
          { id: "mitre", label: "MITRE ATT&CK Matrix", icon: ShieldCheckIcon },
          { id: "cve", label: "CVE Vulnerability Database", icon: BugAntIcon },
          { id: "feeds", label: "Threat Feeds", icon: GlobeAltIcon },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeTab === tab.id
                ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)] shadow-lg shadow-[var(--color-primary-500)]/20"
                : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)]"
            }`}
          >
            <tab.icon className="w-4 h-4" />
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab 1: Indicators of Compromise */}
      {activeTab === "iocs" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {mockIocs.map((ioc) => (
            <div key={ioc.id} className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-[var(--color-primary-500)]">{ioc.id}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-secondary-500)]/20 text-[var(--color-secondary-500)]">
                  {ioc.type}
                </span>
              </div>
              <p className="font-mono text-xs font-bold text-[var(--color-text-primary)] break-all">{ioc.value}</p>
              <div className="flex items-center justify-between text-xs">
                <span className="text-[var(--color-text-muted)] font-medium">Attributed Group:</span>
                <span className="font-semibold text-[var(--color-critical)]">{ioc.threatActor}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-[var(--color-text-muted)] font-medium">Confidence Score:</span>
                <span className="font-mono font-bold text-[var(--color-safe)]">{ioc.confidence}% Confidence</span>
              </div>
              <div className="flex flex-wrap gap-1.5 pt-2 border-t border-[var(--color-border)]">
                {ioc.tags.map((tag) => (
                  <span key={tag} className="px-2 py-0.5 rounded text-[10px] bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]">
                    #{tag}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 2: MITRE ATT&CK Matrix Grid */}
      {activeTab === "mitre" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Enterprise ATT&CK Matrix Coverage</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 text-xs">
            {[
              { tactic: "Initial Access", techniques: ["T1190 Exploit Public App", "T1566 Phishing", "T1078 Valid Accounts"] },
              { tactic: "Execution", techniques: ["T1059 Command Scripting", "T1204 User Execution", "T1047 WMI"] },
              { tactic: "Persistence", techniques: ["T1547 Boot AutoStart", "T1053 Scheduled Task", "T1136 Create Account"] },
              { tactic: "Privilege Escalation", techniques: ["T1548 Abuse Elevation", "T1068 Exploitation", "T1055 Process Injection"] },
              { tactic: "Credential Access", techniques: ["T1110 Brute Force", "T1003 OS Credential Dump", "T1555 Credentials in Files"] },
              { tactic: "Command & Control", techniques: ["T1071 App Layer Protocol", "T1095 Non-App Protocol", "T1573 Encrypted Channel"] },
            ].map((col) => (
              <div key={col.tactic} className="space-y-2">
                <div className="p-2 rounded bg-[var(--color-surface-300)] text-center font-bold text-[11px] text-[var(--color-primary-500)]">
                  {col.tactic}
                </div>
                <div className="space-y-1.5">
                  {col.techniques.map((t) => (
                    <div key={t} className="p-2 rounded bg-[var(--color-surface-200)] border border-[var(--color-border)] text-[10px] font-mono hover:border-[var(--color-primary-500)] cursor-pointer">
                      {t}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: CVE Cards */}
      {activeTab === "cve" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {mockCves.map((cve) => (
            <div key={cve.id} className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-bold text-[var(--color-critical)]">{cve.cveId}</span>
                <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-extrabold bg-[var(--color-critical)]/20 text-[var(--color-critical)]">
                  CVSS {cve.cvssScore}
                </span>
              </div>
              <h3 className="text-xs font-bold text-[var(--color-text-primary)]">{cve.title}</h3>
              <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
                <span>Affected Assets: <strong className="text-[var(--color-text-primary)] font-mono">{cve.affectedCount}</strong></span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-[var(--color-surface-300)]">{cve.patchStatus}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 4: Threat Feeds */}
      {activeTab === "feeds" && (
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Aggregated Intelligence Feeds</h2>
          <div className="space-y-3">
            {[
              { name: "AlienVault OTX Threat Stream", status: "Active • 2,410 IoCs", lastSync: "2 mins ago" },
              { name: "MISP Community Threat Sharing", status: "Active • 8,920 IoCs", lastSync: "10 mins ago" },
              { name: "CISA Known Exploited Vulnerabilities Catalog", status: "Active • 1,120 CVEs", lastSync: "1 hour ago" },
              { name: "VirusTotal Enterprise Feed", status: "Active • Real-time Hash Query", lastSync: "Just now" },
            ].map((feed) => (
              <div key={feed.name} className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-200)] text-xs border border-[var(--color-border)]">
                <div>
                  <p className="font-bold text-[var(--color-text-primary)]">{feed.name}</p>
                  <p className="text-[11px] text-[var(--color-text-secondary)] mt-0.5">{feed.status}</p>
                </div>
                <span className="text-[10px] font-mono text-[var(--color-text-muted)]">{feed.lastSync}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
