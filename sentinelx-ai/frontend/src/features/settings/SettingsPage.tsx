import { useState } from "react";
import { UserIcon, SwatchIcon, BellIcon, KeyIcon, AdjustmentsHorizontalIcon } from "@heroicons/react/24/outline";

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<"profile" | "theme" | "notifications" | "apikeys" | "preferences">("profile");

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold text-[var(--color-text-primary)]">System & Analyst Settings</h1>
        <p className="text-xs text-[var(--color-text-secondary)]">Manage profile preferences, API keys, notification webhooks, and theme overrides</p>
      </div>

      {/* Settings Navigation Tabs */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-3 overflow-x-auto">
        {[
          { id: "profile", label: "Profile", icon: UserIcon },
          { id: "theme", label: "Theme & Aesthetics", icon: SwatchIcon },
          { id: "notifications", label: "Notifications & Alerts", icon: BellIcon },
          { id: "apikeys", label: "API Keys & Tokens", icon: KeyIcon },
          { id: "preferences", label: "Preferences", icon: AdjustmentsHorizontalIcon },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold whitespace-nowrap transition-all ${
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

      {/* Tab 1: Profile */}
      {activeTab === "profile" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4 max-w-2xl">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Analyst Profile Settings</h2>
          <div className="space-y-3 text-xs">
            <div>
              <label className="block font-medium text-[var(--color-text-muted)] mb-1">Full Name</label>
              <input
                type="text"
                defaultValue="Alex Rivera"
                className="w-full bg-[var(--color-surface-200)] px-3 py-2 rounded-lg border border-[var(--color-border)] text-[var(--color-text-primary)]"
              />
            </div>
            <div>
              <label className="block font-medium text-[var(--color-text-muted)] mb-1">Email Address</label>
              <input
                type="email"
                defaultValue="alex.rivera@sentinelx.ai"
                className="w-full bg-[var(--color-surface-200)] px-3 py-2 rounded-lg border border-[var(--color-border)] text-[var(--color-text-primary)] font-mono"
              />
            </div>
            <button className="px-4 py-2 bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold rounded-lg hover:opacity-90">
              Save Profile Changes
            </button>
          </div>
        </div>
      )}

      {/* Tab 2: Theme */}
      {activeTab === "theme" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4 max-w-2xl">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Stitch Design System Tokens</h2>
          <div className="p-4 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-semibold">Current Color Mode:</span>
              <span className="px-2 py-1 rounded bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)] font-mono font-bold">DARK (SOC Default)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-semibold">Primary Accent:</span>
              <div className="flex items-center gap-2">
                <span className="w-4 h-4 rounded-full bg-[#00e5ff]" />
                <span className="font-mono text-[var(--color-primary-500)]">#00E5FF (Electric Cyan)</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Notifications */}
      {activeTab === "notifications" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4 max-w-2xl">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Real-Time Alert Dispatch</h2>
          <div className="space-y-3 text-xs">
            {[
              { title: "Critical Threat Push Notifications", desc: "Browser desktop alert on Critical severity threats", defaultChecked: true },
              { title: "Slack / PagerDuty Integration", desc: "Forward P0 incidents directly to SOC Slack channel", defaultChecked: true },
              { title: "Daily Executive Email Digest", desc: "Automated report sent every morning at 08:00 UTC", defaultChecked: false },
            ].map((n, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)]">
                <div>
                  <p className="font-bold text-[var(--color-text-primary)]">{n.title}</p>
                  <p className="text-[10px] text-[var(--color-text-muted)] mt-0.5">{n.desc}</p>
                </div>
                <input type="checkbox" defaultChecked={n.defaultChecked} className="w-4 h-4 accent-[var(--color-primary-500)]" />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: API Keys */}
      {activeTab === "apikeys" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4 max-w-2xl">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Ingestion & REST API Keys</h2>
            <button className="px-3 py-1.5 bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold rounded-lg">
              + Generate Key
            </button>
          </div>
          <div className="space-y-2">
            {[
              { name: "Default Ingestion Key", key: "snx_live_994a28f8101a4bc89...", created: "2026-07-04" },
              { name: "Read-Only Analytics Token", key: "snx_read_1104e7c99201a0f1...", created: "2026-07-28" },
            ].map((k) => (
              <div key={k.name} className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] flex items-center justify-between text-xs">
                <div>
                  <p className="font-bold text-[var(--color-text-primary)]">{k.name}</p>
                  <p className="font-mono text-[11px] text-[var(--color-primary-500)] mt-0.5">{k.key}</p>
                </div>
                <button className="text-[10px] font-bold text-[var(--color-critical)] hover:underline">Revoke</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 5: Preferences */}
      {activeTab === "preferences" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4 max-w-2xl">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">SOC Workspace Preferences</h2>
          <div className="space-y-3 text-xs">
            <div>
              <label className="block font-medium text-[var(--color-text-muted)] mb-1">Timezone Display</label>
              <select className="w-full bg-[var(--color-surface-200)] px-3 py-2 rounded-lg border border-[var(--color-border)] text-[var(--color-text-primary)] font-mono">
                <option>UTC (Universal Coordinated Time)</option>
                <option>Asia/Tokyo (JST)</option>
                <option>America/New_York (EST)</option>
              </select>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
