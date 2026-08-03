import { useState } from "react";
import {
  FunnelIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  ShieldExclamationIcon,
} from "@heroicons/react/24/outline";
import { mockThreats, type ThreatMock } from "../../utils/mockData";

export default function ThreatsPage() {
  const [selectedThreat, setSelectedThreat] = useState<ThreatMock | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");

  const filteredThreats = mockThreats.filter((t) => {
    const matchesSearch =
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.sourceIp.includes(search) ||
      t.targetAsset.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "All" || t.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6 animate-fade-in relative">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Threat Detection & Analysis</h1>
          <p className="text-xs text-[var(--color-text-secondary)]">Real-time threat monitoring and MITRE ATT&CK correlation</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-3 py-1 text-xs font-semibold rounded-lg bg-[var(--color-critical)]/15 text-[var(--color-critical)] border border-[var(--color-critical)]/30">
            {mockThreats.filter((t) => t.severity === "Critical").length} Critical Threats
          </span>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="glass rounded-xl p-4 flex flex-col md:flex-row gap-4 justify-between items-center border border-[var(--color-border)]">
        <div className="relative w-full md:w-80">
          <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter threats by name, IP, or asset..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[var(--color-surface-200)] text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-lg pl-9 pr-4 py-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="flex items-center gap-1.5 text-xs text-[var(--color-text-muted)]">
            <FunnelIcon className="w-4 h-4" />
            <span>Severity:</span>
          </div>
          {["All", "Critical", "High", "Medium"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                severityFilter === sev
                  ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                  : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)]"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Threats Table */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="bg-[var(--color-surface-200)]/80 text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider border-b border-[var(--color-border)]">
              <th className="p-4">Threat ID</th>
              <th className="p-4">Threat Details</th>
              <th className="p-4">Severity</th>
              <th className="p-4">Category</th>
              <th className="p-4">Source IP</th>
              <th className="p-4">Target Asset</th>
              <th className="p-4">MITRE ATT&CK</th>
              <th className="p-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
            {filteredThreats.map((threat) => (
              <tr
                key={threat.id}
                onClick={() => setSelectedThreat(threat)}
                className="hover:bg-[var(--color-surface-200)]/60 cursor-pointer transition-colors"
              >
                <td className="p-4 font-mono font-bold text-[var(--color-text-primary)]">{threat.id}</td>
                <td className="p-4 font-semibold text-[var(--color-text-primary)]">{threat.name}</td>
                <td className="p-4">
                  <span
                    className={`px-2.5 py-1 rounded-full text-[10px] font-bold ${
                      threat.severity === "Critical"
                        ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)] border border-[var(--color-critical)]/30"
                        : threat.severity === "High"
                        ? "bg-[var(--color-high)]/20 text-[var(--color-high)] border border-[var(--color-high)]/30"
                        : "bg-[var(--color-medium)]/20 text-[var(--color-medium)] border border-[var(--color-medium)]/30"
                    }`}
                  >
                    {threat.severity}
                  </span>
                </td>
                <td className="p-4">{threat.category}</td>
                <td className="p-4 font-mono text-[var(--color-primary-500)]">{threat.sourceIp}</td>
                <td className="p-4 font-mono text-[11px] truncate max-w-[150px]">{threat.targetAsset}</td>
                <td className="p-4 font-mono text-[var(--color-secondary-500)] font-bold">{threat.mitreId}</td>
                <td className="p-4 text-right">
                  <button className="px-3 py-1 text-[11px] font-bold rounded bg-[var(--color-surface-300)] text-[var(--color-text-primary)] hover:bg-[var(--color-primary-500)] hover:text-[var(--color-surface-0)] transition-all">
                    Inspect
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Threat Detail Slide-Over Drawer */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-lg bg-[var(--color-surface-100)] h-full border-l border-[var(--color-border)] p-6 overflow-y-auto space-y-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[var(--color-border)] mb-6">
                <div className="flex items-center gap-2">
                  <ShieldExclamationIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
                  <h2 className="text-base font-bold text-[var(--color-text-primary)]">{selectedThreat.id} Overview</h2>
                </div>
                <button onClick={() => setSelectedThreat(null)} className="p-1 rounded text-[var(--color-text-muted)] hover:text-white">
                  <XMarkIcon className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4 text-xs">
                <div>
                  <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold">Threat Name</p>
                  <p className="text-sm font-bold text-[var(--color-text-primary)] mt-0.5">{selectedThreat.name}</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold">Severity Score</p>
                    <p className="text-lg font-mono font-extrabold text-[var(--color-critical)]">{selectedThreat.score} / 100</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold">MITRE Technique</p>
                    <p className="text-sm font-mono font-bold text-[var(--color-secondary-500)]">{selectedThreat.mitreId}</p>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-2">
                  <div>
                    <span className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold">Source IP Address</span>
                    <p className="font-mono text-[var(--color-primary-500)] font-bold">{selectedThreat.sourceIp}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold">Targeted Asset</span>
                    <p className="font-mono text-[var(--color-text-primary)]">{selectedThreat.targetAsset}</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-[var(--color-border)] flex gap-3">
              <button className="flex-1 py-2 rounded-lg bg-[var(--color-critical)] text-white text-xs font-bold hover:opacity-90">
                Isolate Target Host
              </button>
              <button className="flex-1 py-2 rounded-lg bg-[var(--color-surface-300)] text-[var(--color-text-primary)] text-xs font-bold hover:bg-[var(--color-surface-400)]">
                Close Threat
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
