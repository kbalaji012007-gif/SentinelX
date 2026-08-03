import { ServerIcon, ComputerDesktopIcon, CloudIcon, CpuChipIcon } from "@heroicons/react/24/outline";
import { mockAssets } from "../../utils/mockData";

export default function AssetsPage() {

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Asset Management</h1>
          <p className="text-xs text-[var(--color-text-secondary)]">Complete network inventory, cloud resources, and asset criticality tracking</p>
        </div>
        <button className="px-4 py-2 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold shadow-lg shadow-[var(--color-primary-500)]/20 hover:opacity-90">
          + Register New Asset
        </button>
      </div>

      {/* Asset Type Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Servers", count: 48, icon: ServerIcon },
          { label: "Workstations", count: 72, icon: ComputerDesktopIcon },
          { label: "Cloud Resources", count: 18, icon: CloudIcon },
          { label: "Network Devices", count: 4, icon: CpuChipIcon },
        ].map((item) => (
          <div key={item.label} className="glass rounded-xl p-4 border border-[var(--color-border)] flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-[var(--color-primary-500)]/10 text-[var(--color-primary-500)]">
              <item.icon className="w-5 h-5" />
            </div>
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold">{item.label}</p>
              <p className="text-lg font-bold font-mono text-[var(--color-text-primary)]">{item.count}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Assets Inventory Table */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="bg-[var(--color-surface-200)]/80 text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider border-b border-[var(--color-border)]">
              <th className="p-4">Hostname / Asset</th>
              <th className="p-4">Type</th>
              <th className="p-4">IP Address</th>
              <th className="p-4">OS</th>
              <th className="p-4">Department</th>
              <th className="p-4">Criticality</th>
              <th className="p-4">Status</th>
              <th className="p-4 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
            {mockAssets.map((asset) => (
              <tr
                key={asset.id}
                className="hover:bg-[var(--color-surface-200)]/60 cursor-pointer transition-colors"
              >
                <td className="p-4">
                  <p className="font-mono font-bold text-[var(--color-text-primary)] text-xs">{asset.hostname}</p>
                  <p className="text-[11px] text-[var(--color-text-muted)]">{asset.assetName}</p>
                </td>
                <td className="p-4 font-medium">{asset.assetType}</td>
                <td className="p-4 font-mono text-[var(--color-primary-500)]">{asset.ipAddress}</td>
                <td className="p-4 text-[11px]">{asset.operatingSystem}</td>
                <td className="p-4 text-[11px]">{asset.department}</td>
                <td className="p-4">
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                    asset.criticality === "Critical" ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)]" :
                    asset.criticality === "High" ? "bg-[var(--color-high)]/20 text-[var(--color-high)]" :
                    "bg-[var(--color-medium)]/20 text-[var(--color-medium)]"
                  }`}>
                    {asset.criticality}
                  </span>
                </td>
                <td className="p-4">
                  <div className="flex items-center gap-1.5">
                    <span className={`w-2 h-2 rounded-full ${
                      asset.status === "Active" ? "bg-[var(--color-safe)] animate-pulse" : "bg-[var(--color-medium)]"
                    }`} />
                    <span className="text-[11px]">{asset.status}</span>
                  </div>
                </td>
                <td className="p-4 text-right">
                  <button className="px-3 py-1 text-[11px] font-bold rounded bg-[var(--color-surface-300)] text-[var(--color-text-primary)] hover:bg-[var(--color-primary-500)] hover:text-[var(--color-surface-0)] transition-all">
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
