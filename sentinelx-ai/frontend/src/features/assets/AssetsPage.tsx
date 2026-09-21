import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ServerIcon,
  ComputerDesktopIcon,
  CloudIcon,
  CpuChipIcon,
  MagnifyingGlassIcon,
  ArrowPathIcon,
  XMarkIcon,
  ShieldCheckIcon,
} from "@heroicons/react/24/outline";
import { fetchAssets } from "../../services/assetService";
import { fetchAgents } from "../../services/agentService";
import type { Asset } from "../../types/asset";

export default function AssetsPage() {
  const [search, setSearch] = useState("");
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

  // Fetch real assets from backend database
  const {
    data: dbAssets = [],
    isLoading: isAssetsLoading,
    isError: isAssetsError,
    refetch: refetchAssets,
  } = useQuery({
    queryKey: ["assets"],
    queryFn: () => fetchAssets(0, 100),
    refetchInterval: 15000,
  });

  // Fetch live enrolled endpoint agents (e.g. host machines reporting telemetry)
  const {
    data: agentsData,
    isLoading: isAgentsLoading,
    refetch: refetchAgents,
  } = useQuery({
    queryKey: ["agents", { page: 1, page_size: 100 }],
    queryFn: () => fetchAgents({ page: 1, page_size: 100 }),
    refetchInterval: 15000,
  });

  const isLoading = isAssetsLoading || isAgentsLoading;

  // Merge registered enterprise database assets + live enrolled endpoint telemetry agents
  const assets = useMemo<Asset[]>(() => {
    const list = [...dbAssets];
    if (agentsData?.items) {
      for (const agent of agentsData.items) {
        // Skip revoked duplicate agents
        if (agent.status === "Revoked") continue;
        // Avoid duplicate if already registered in dbAssets
        if (list.some((a) => a.hostname.toLowerCase() === agent.hostname.toLowerCase())) continue;

        list.push({
          id: agent.id || agent.agent_id,
          hostname: agent.hostname,
          asset_name: `${agent.hostname} (${agent.platform} Workstation)`,
          asset_type: "Workstation",
          operating_system: agent.os_version || agent.platform,
          ip_address: agent.local_ip || "127.0.0.1",
          department: "Endpoint Security Fleet",
          criticality: agent.risk_score > 20 ? "High" : "Medium",
          status:
            agent.status === "Online"
              ? "Active"
              : agent.status === "Stale"
              ? "Maintenance"
              : "Inactive",
          last_seen: agent.last_seen || undefined,
          created_at: agent.last_seen || new Date().toISOString(),
          updated_at: agent.last_seen || new Date().toISOString(),
          tags: ["Endpoint Agent", agent.status],
        });
      }
    }
    return list;
  }, [dbAssets, agentsData]);

  // Calculate live summary statistics from real active data
  const serversCount = assets.filter((a) => a.asset_type === "Server").length;
  const workstationsCount = assets.filter((a) => a.asset_type === "Workstation").length;
  const cloudCount = assets.filter((a) => a.asset_type === "Cloud Resource").length;
  const networkCount = assets.filter((a) =>
    ["Router", "Switch", "Firewall", "Network Device"].includes(a.asset_type)
  ).length;

  // Filter assets by search query
  const filteredAssets = assets.filter((asset) => {
    if (!search.trim()) return true;
    const query = search.toLowerCase();
    return (
      asset.hostname?.toLowerCase().includes(query) ||
      asset.asset_name?.toLowerCase().includes(query) ||
      asset.ip_address?.toLowerCase().includes(query) ||
      asset.department?.toLowerCase().includes(query) ||
      asset.asset_type?.toLowerCase().includes(query)
    );
  });

  const handleRefresh = () => {
    refetchAssets();
    refetchAgents();
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Asset Management</h1>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Live enterprise infrastructure inventory, network endpoints, and criticality tracking
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            className="p-2 rounded-lg bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
            title="Refresh assets"
          >
            <ArrowPathIcon className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Live Asset Type Cards (Computed from Real Data) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Servers", count: serversCount, icon: ServerIcon },
          { label: "Workstations", count: workstationsCount, icon: ComputerDesktopIcon },
          { label: "Cloud Resources", count: cloudCount, icon: CloudIcon },
          { label: "Network Devices", count: networkCount, icon: CpuChipIcon },
        ].map((item) => (
          <div
            key={item.label}
            className="glass rounded-xl p-4 border border-[var(--color-border)] flex items-center gap-3"
          >
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

      {/* Search Bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <MagnifyingGlassIcon className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by hostname, IP address, asset name, department..."
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-[var(--color-surface-100)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary-500)]"
          />
        </div>
      </div>

      {/* Real Assets Inventory Table */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="bg-[var(--color-surface-200)]/80 text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider border-b border-[var(--color-border)]">
              <th className="p-4">Hostname / Asset Name</th>
              <th className="p-4">Type</th>
              <th className="p-4">IP Address</th>
              <th className="p-4">OS</th>
              <th className="p-4">Department</th>
              <th className="p-4">Criticality</th>
              <th className="p-4">Status</th>
              <th className="p-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
            {isLoading ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-[var(--color-text-muted)]">
                  Loading real-time asset inventory...
                </td>
              </tr>
            ) : isAssetsError ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-[var(--color-critical)]">
                  Failed to load asset data from server. Please check backend connection.
                </td>
              </tr>
            ) : filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={8} className="p-12 text-center">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <ShieldCheckIcon className="w-8 h-8 text-[var(--color-text-muted)] opacity-60" />
                    <p className="text-xs font-semibold text-[var(--color-text-primary)]">
                      {search ? "No assets matching search filter" : "No Registered Assets in Database"}
                    </p>
                    <p className="text-[11px] text-[var(--color-text-muted)] max-w-sm">
                      {search
                        ? "Try clearing the search query to view all assets."
                        : "No mock data is being shown. Real assets registered through the API or endpoint agent will appear here."}
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              filteredAssets.map((asset) => (
                <tr
                  key={asset.id}
                  className="hover:bg-[var(--color-surface-200)]/60 cursor-pointer transition-colors"
                  onClick={() => setSelectedAsset(asset)}
                >
                  <td className="p-4">
                    <p className="font-mono font-bold text-[var(--color-text-primary)] text-xs">
                      {asset.hostname}
                    </p>
                    <p className="text-[11px] text-[var(--color-text-muted)]">{asset.asset_name}</p>
                  </td>
                  <td className="p-4 font-medium">{asset.asset_type}</td>
                  <td className="p-4 font-mono text-[var(--color-primary-500)]">{asset.ip_address}</td>
                  <td className="p-4 text-[11px]">{asset.operating_system || "Unknown"}</td>
                  <td className="p-4 text-[11px]">{asset.department || "N/A"}</td>
                  <td className="p-4">
                    <span
                      className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                        asset.criticality === "Critical"
                          ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)]"
                          : asset.criticality === "High"
                          ? "bg-[var(--color-high)]/20 text-[var(--color-high)]"
                          : "bg-[var(--color-medium)]/20 text-[var(--color-medium)]"
                      }`}
                    >
                      {asset.criticality}
                    </span>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          asset.status === "Active"
                            ? "bg-[var(--color-safe)] animate-pulse"
                            : "bg-[var(--color-medium)]"
                        }`}
                      />
                      <span className="text-[11px]">{asset.status}</span>
                    </div>
                  </td>
                  <td className="p-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedAsset(asset);
                      }}
                      className="px-3 py-1 text-[11px] font-bold rounded bg-[var(--color-surface-300)] text-[var(--color-text-primary)] hover:bg-[var(--color-primary-500)] hover:text-[var(--color-surface-0)] transition-all"
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Asset Detail Drawer / Modal */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end animate-fade-in">
          <div className="w-full max-w-lg bg-[var(--color-surface-100)] border-l border-[var(--color-border)] h-full overflow-y-auto flex flex-col p-6 space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-[var(--color-border)]">
              <div>
                <h2 className="text-base font-bold text-[var(--color-text-primary)]">
                  {selectedAsset.asset_name || selectedAsset.hostname}
                </h2>
                <p className="text-xs font-mono text-[var(--color-text-muted)]">{selectedAsset.hostname}</p>
              </div>
              <button
                onClick={() => setSelectedAsset(null)}
                className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-200)]"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="flex justify-between py-1.5 border-b border-[var(--color-border)]/50">
                <span className="text-[var(--color-text-muted)]">Type:</span>
                <span className="text-[var(--color-text-primary)] font-semibold">{selectedAsset.asset_type}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[var(--color-border)]/50">
                <span className="text-[var(--color-text-muted)]">IP Address:</span>
                <span className="text-[var(--color-primary-500)] font-bold">{selectedAsset.ip_address}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[var(--color-border)]/50">
                <span className="text-[var(--color-text-muted)]">Operating System:</span>
                <span className="text-[var(--color-text-primary)]">{selectedAsset.operating_system || "Unknown"}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[var(--color-border)]/50">
                <span className="text-[var(--color-text-muted)]">Department:</span>
                <span className="text-[var(--color-text-primary)]">{selectedAsset.department || "N/A"}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[var(--color-border)]/50">
                <span className="text-[var(--color-text-muted)]">Criticality:</span>
                <span className="text-[var(--color-text-primary)] font-bold">{selectedAsset.criticality}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-[var(--color-border)]/50">
                <span className="text-[var(--color-text-muted)]">Status:</span>
                <span className="text-[var(--color-safe)] font-bold">{selectedAsset.status}</span>
              </div>
              {selectedAsset.last_seen && (
                <div className="flex justify-between py-1.5 border-b border-[var(--color-border)]/50">
                  <span className="text-[var(--color-text-muted)]">Last Seen / Heartbeat:</span>
                  <span className="text-[var(--color-primary-500)] font-bold">
                    {new Date(selectedAsset.last_seen).toLocaleTimeString()}
                  </span>
                </div>
              )}
              <div className="flex justify-between py-1.5 border-b border-[var(--color-border)]/50">
                <span className="text-[var(--color-text-muted)]">Created At:</span>
                <span className="text-[var(--color-text-primary)]">
                  {new Date(selectedAsset.created_at).toLocaleString()}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
