import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ComputerDesktopIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ClockIcon,
  SignalIcon,
  ShieldAlertIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  CpuChipIcon,
  CommandLineIcon,
  GlobeAltIcon,
  NoSymbolIcon,
  EyeIcon,
} from "@heroicons/react/24/outline";

import {
  fetchAgents,
  fetchAgentStatistics,
  fetchAgentDetails,
  disableAgent,
  revokeAgent,
} from "../../services/agentService";
import { EndpointAgentSummary } from "../../types/agent";

export default function AgentsPage() {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<
    "overview" | "security" | "telemetry" | "threats" | "network" | "processes" | "timeline"
  >("overview");

  // Live Statistics Query
  const { data: statsData, isLoading: isStatsLoading } = useQuery({
    queryKey: ["agent-statistics"],
    queryFn: fetchAgentStatistics,
    refetchInterval: 10000,
  });

  // Endpoints Table Query
  const { data: agentsData, isLoading: isAgentsLoading, refetch: refetchAgents } = useQuery({
    queryKey: ["agents", { page, status: statusFilter, search }],
    queryFn: () => fetchAgents({ page, page_size: 25, status: statusFilter || undefined, search: search || undefined }),
    refetchInterval: 15000,
  });

  // Selected Endpoint Details Query
  const { data: detailsData, isLoading: isDetailsLoading } = useQuery({
    queryKey: ["agent-details", selectedAgentId],
    queryFn: () => (selectedAgentId ? fetchAgentDetails(selectedAgentId) : Promise.reject("No agent ID")),
    enabled: !!selectedAgentId,
    refetchInterval: 15000,
  });

  // Disable Agent Mutation
  const disableMutation = useMutation({
    mutationFn: (agentId: string) => disableAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      queryClient.invalidateQueries({ queryKey: ["agent-statistics"] });
      queryClient.invalidateQueries({ queryKey: ["agent-details"] });
    },
  });

  // Revoke Agent Mutation
  const revokeMutation = useMutation({
    mutationFn: (agentId: string) => revokeAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      queryClient.invalidateQueries({ queryKey: ["agent-statistics"] });
      queryClient.invalidateQueries({ queryKey: ["agent-details"] });
    },
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Online":
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-[var(--color-safe)]/20 text-[var(--color-safe)] border border-[var(--color-safe)]/30 flex items-center gap-1 w_fit">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-safe)] animate-pulse" />
            Online
          </span>
        );
      case "Stale":
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-[var(--color-medium)]/20 text-[var(--color-medium)] border border-[var(--color-medium)]/30 flex items-center gap-1 w_fit">
            <ClockIcon className="w-3 h-3" />
            Stale
          </span>
        );
      case "Disabled":
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-[var(--color-surface-300)] text-[var(--color-text-muted)] border border-[var(--color-border)] flex items-center gap-1 w_fit">
            <NoSymbolIcon className="w-3 h-3" />
            Disabled
          </span>
        );
      case "Revoked":
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-[var(--color-critical)]/20 text-[var(--color-critical)] border border-[var(--color-critical)]/30 flex items-center gap-1 w_fit">
            <NoSymbolIcon className="w-3 h-3" />
            Revoked
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-[var(--color-high)]/20 text-[var(--color-high)] border border-[var(--color-high)]/30 flex items-center gap-1 w_fit">
            <ExclamationCircleIcon className="w-3 h-3" />
            Offline
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)] flex items-center gap-2">
            <ComputerDesktopIcon className="w-6 h-6 text-[var(--color-primary-500)]" />
            Endpoint Management
          </h1>
          <p className="text-xs text-[var(--color-text-secondary)]">
            SentinelX Telemetry Agent monitoring, endpoint health, process inspection, and network socket telemetry
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetchAgents()}
            className="px-3 py-1.5 rounded-lg bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] text-xs font-semibold flex items-center gap-1.5 transition-all"
          >
            <ArrowPathIcon className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Live Statistics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {[
          { label: "Total Endpoints", value: statsData?.total_endpoints ?? 0, icon: ComputerDesktopIcon, color: "text-[var(--color-primary-500)]" },
          { label: "Online", value: statsData?.online_endpoints ?? 0, icon: CheckCircleIcon, color: "text-[var(--color-safe)]" },
          { label: "Offline", value: statsData?.offline_endpoints ?? 0, icon: ExclamationCircleIcon, color: "text-[var(--color-critical)]" },
          { label: "Stale", value: statsData?.stale_endpoints ?? 0, icon: ClockIcon, color: "text-[var(--color-medium)]" },
          { label: "Telemetry Today", value: statsData?.telemetry_events_today ?? 0, icon: SignalIcon, color: "text-[var(--color-secondary-500)]" },
          { label: "Endpoint Threats", value: statsData?.endpoint_threats ?? 0, icon: ShieldAlertIcon, color: "text-[var(--color-high)]" },
          { label: "Highest Risk", value: statsData?.highest_risk_endpoint || "None", icon: CpuChipIcon, color: "text-[var(--color-critical)]" },
        ].map((item) => (
          <div key={item.label} className="glass rounded-xl p-3 border border-[var(--color-border)] flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold tracking-wider">{item.label}</span>
              <item.icon className={`w-4 h-4 ${item.color}`} />
            </div>
            <p className="text-base font-bold font-mono text-[var(--color-text-primary)] mt-2 truncate">
              {isStatsLoading ? "..." : item.value}
            </p>
          </div>
        ))}
      </div>

      {/* Filter Bar */}
      <div className="glass rounded-xl p-4 border border-[var(--color-border)] flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-3 w-full sm:w-auto flex-1">
          <div className="relative flex-1 sm:max-w-xs">
            <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search hostname, agent ID, platform..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary-500)]"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-primary-500)]"
          >
            <option value="">All Statuses</option>
            <option value="Online">Online</option>
            <option value="Offline">Offline</option>
            <option value="Stale">Stale</option>
            <option value="Disabled">Disabled</option>
            <option value="Revoked">Revoked</option>
          </select>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[var(--color-surface-200)]/80 text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider border-b border-[var(--color-border)]">
                <th className="p-4">Hostname / Agent ID</th>
                <th className="p-4">OS & Version</th>
                <th className="p-4">Agent Version</th>
                <th className="p-4">Status</th>
                <th className="p-4">IP Address</th>
                <th className="p-4">Last Seen</th>
                <th className="p-4">Risk Score</th>
                <th className="p-4">Telemetry</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
              {isAgentsLoading ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-[var(--color-text-muted)]">
                    Loading enrolled endpoint telemetry agents...
                  </td>
                </tr>
              ) : agentsData?.items.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-[var(--color-text-muted)]">
                    No endpoint agents enrolled matching filter criteria.
                  </td>
                </tr>
              ) : (
                agentsData?.items.map((agent: EndpointAgentSummary) => (
                  <tr
                    key={agent.id}
                    className="hover:bg-[var(--color-surface-200)]/60 transition-colors"
                  >
                    <td className="p-4">
                      <p className="font-bold text-[var(--color-text-primary)] text-xs flex items-center gap-1.5">
                        <ComputerDesktopIcon className="w-4 h-4 text-[var(--color-primary-500)]" />
                        {agent.hostname}
                      </p>
                      <p className="font-mono text-[10px] text-[var(--color-text-muted)] truncate max-w-[180px]">
                        {agent.agent_id}
                      </p>
                    </td>

                    <td className="p-4">
                      <p className="font-medium text-[var(--color-text-primary)] text-xs">{agent.platform}</p>
                      <p className="text-[10px] text-[var(--color-text-muted)]">{agent.os_version || "Windows"}</p>
                    </td>

                    <td className="p-4 font-mono text-xs">{agent.agent_version}</td>

                    <td className="p-4">{getStatusBadge(agent.status)}</td>

                    <td className="p-4 font-mono text-xs text-[var(--color-text-secondary)]">
                      {agent.local_ip || "127.0.0.1"}
                    </td>

                    <td className="p-4 text-[11px] text-[var(--color-text-muted)]">
                      {agent.last_seen ? new Date(agent.last_seen).toLocaleTimeString() : "Never"}
                    </td>

                    <td className="p-4">
                      <span
                        className={`font-mono font-bold text-xs ${
                          agent.risk_score > 20
                            ? "text-[var(--color-critical)]"
                            : agent.risk_score > 0
                            ? "text-[var(--color-medium)]"
                            : "text-[var(--color-safe)]"
                        }`}
                      >
                        {agent.risk_score.toFixed(1)}
                      </span>
                    </td>

                    <td className="p-4 font-mono text-xs text-[var(--color-primary-500)] font-bold">
                      {agent.telemetry_count}
                    </td>

                    <td className="p-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setSelectedAgentId(agent.agent_id)}
                          className="px-2.5 py-1 rounded bg-[var(--color-primary-500)]/15 text-[var(--color-primary-500)] hover:bg-[var(--color-primary-500)]/25 text-xs font-semibold flex items-center gap-1"
                        >
                          <EyeIcon className="w-3.5 h-3.5" />
                          View
                        </button>
                        {agent.status !== "Disabled" && agent.status !== "Revoked" && (
                          <button
                            onClick={() => disableMutation.mutate(agent.agent_id)}
                            className="px-2 py-1 rounded bg-[var(--color-surface-300)] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] text-xs font-medium"
                          >
                            Disable
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Endpoint Details Drawer/Modal */}
      {selectedAgentId && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end animate-fade-in">
          <div className="w-full max-w-4xl bg-[var(--color-surface-100)] border-l border-[var(--color-border)] h-full overflow-y-auto flex flex-col">
            {/* Drawer Header */}
            <div className="p-5 border-b border-[var(--color-border)] flex items-center justify-between bg-[var(--color-surface-50)]">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-[var(--color-primary-500)]/20 border border-[var(--color-primary-500)]/30 flex items-center justify-center">
                  <ComputerDesktopIcon className="w-6 h-6 text-[var(--color-primary-500)]" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                    {detailsData?.agent.hostname || selectedAgentId}
                    {detailsData && getStatusBadge(detailsData.agent.status)}
                  </h2>
                  <p className="text-xs font-mono text-[var(--color-text-muted)]">Agent ID: {selectedAgentId}</p>
                </div>
              </div>

              <button
                onClick={() => setSelectedAgentId(null)}
                className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-200)]"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-[var(--color-border)] px-5 bg-[var(--color-surface-100)] gap-2">
              {[
                { id: "overview", label: "System & Health", icon: CpuChipIcon },
                { id: "security", label: "Security Events", icon: ShieldAlertIcon },
                { id: "telemetry", label: "Telemetry Feed", icon: SignalIcon },
                { id: "threats", label: "Threats", icon: ExclamationCircleIcon },
                { id: "network", label: "Network Sockets", icon: GlobeAltIcon },
                { id: "processes", label: "Processes", icon: CommandLineIcon },
                { id: "timeline", label: "Timeline", icon: ClockIcon },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`py-3 px-3 text-xs font-semibold flex items-center gap-1.5 border-b-2 transition-all ${
                    activeTab === tab.id
                      ? "border-[var(--color-primary-500)] text-[var(--color-primary-500)]"
                      : "border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
                  }`}
                >
                  <tab.icon className="w-3.5 h-3.5" />
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="p-6 flex-1 space-y-6">
              {isDetailsLoading ? (
                <div className="text-center py-12 text-xs text-[var(--color-text-muted)]">
                  Loading detailed endpoint telemetry analysis...
                </div>
              ) : detailsData ? (
                <>
                  {/* Overview Tab */}
                  {activeTab === "overview" && (
                    <div className="space-y-6">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="glass rounded-xl p-4 border border-[var(--color-border)] space-y-3">
                          <h3 className="text-xs font-bold text-[var(--color-text-primary)] uppercase tracking-wider">
                            System Specifications
                          </h3>
                          <div className="space-y-2 text-xs font-mono">
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">Hostname:</span>
                              <span className="text-[var(--color-text-primary)]">{detailsData.system_info.hostname}</span>
                            </div>
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">Platform:</span>
                              <span className="text-[var(--color-text-primary)]">{detailsData.system_info.platform}</span>
                            </div>
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">OS Build:</span>
                              <span className="text-[var(--color-text-primary)]">{detailsData.system_info.os_version || "Windows"}</span>
                            </div>
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">Architecture:</span>
                              <span className="text-[var(--color-text-primary)]">{detailsData.system_info.architecture}</span>
                            </div>
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">IP Address:</span>
                              <span className="text-[var(--color-text-primary)]">{detailsData.system_info.local_ip}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-[var(--color-text-muted)]">User Context:</span>
                              <span className="text-[var(--color-text-primary)]">{detailsData.system_info.username}</span>
                            </div>
                          </div>
                        </div>

                        <div className="glass rounded-xl p-4 border border-[var(--color-border)] space-y-3">
                          <h3 className="text-xs font-bold text-[var(--color-text-primary)] uppercase tracking-wider">
                            Agent Health & Heartbeat
                          </h3>
                          <div className="space-y-2 text-xs font-mono">
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">Agent Version:</span>
                              <span className="text-[var(--color-text-primary)]">{detailsData.agent.agent_version}</span>
                            </div>
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">Health Status:</span>
                              <span className="text-[var(--color-safe)] font-bold">{detailsData.agent_health.health_status}</span>
                            </div>
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">System Uptime:</span>
                              <span className="text-[var(--color-text-primary)]">{detailsData.agent_health.uptime_seconds}s</span>
                            </div>
                            <div className="flex justify-between border-b border-[var(--color-border)]/50 pb-1">
                              <span className="text-[var(--color-text-muted)]">Enrolled At:</span>
                              <span className="text-[var(--color-text-primary)]">
                                {new Date(detailsData.agent_health.enrolled_at).toLocaleString()}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-[var(--color-text-muted)]">Last Heartbeat:</span>
                              <span className="text-[var(--color-primary-500)] font-bold">
                                {detailsData.last_heartbeat ? new Date(detailsData.last_heartbeat).toLocaleTimeString() : "N/A"}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Security Events Tab */}
                  {activeTab === "security" && (
                    <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="bg-[var(--color-surface-200)] text-[var(--color-text-muted)] uppercase text-[10px]">
                            <th className="p-3">Event ID</th>
                            <th className="p-3">Event Type</th>
                            <th className="p-3">Severity</th>
                            <th className="p-3">Timestamp</th>
                            <th className="p-3">Message</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[var(--color-border)] font-mono">
                          {detailsData.recent_security_events.length === 0 ? (
                            <tr>
                              <td colSpan={5} className="p-6 text-center text-[var(--color-text-muted)]">
                                No security events recorded.
                              </td>
                            </tr>
                          ) : (
                            detailsData.recent_security_events.map((ev, idx) => (
                              <tr key={idx} className="hover:bg-[var(--color-surface-200)]/40">
                                <td className="p-3 font-bold text-[var(--color-primary-500)]">{ev.event_id || "N/A"}</td>
                                <td className="p-3 text-[var(--color-text-primary)]">{ev.event_type}</td>
                                <td className="p-3 font-bold">{ev.severity}</td>
                                <td className="p-3 text-[var(--color-text-muted)]">{new Date(ev.timestamp).toLocaleTimeString()}</td>
                                <td className="p-3 text-[var(--color-text-secondary)]">{ev.message}</td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Telemetry Feed Tab */}
                  {activeTab === "telemetry" && (
                    <div className="space-y-3 font-mono">
                      {detailsData.recent_telemetry.map((item) => (
                        <div key={item.id} className="p-3 rounded-lg bg-[var(--color-surface-200)]/50 border border-[var(--color-border)] text-xs space-y-1">
                          <div className="flex justify-between text-[11px] text-[var(--color-text-muted)]">
                            <span className="font-bold text-[var(--color-primary-500)]">{item.event_type}</span>
                            <span>{new Date(item.event_timestamp).toLocaleString()}</span>
                          </div>
                          <pre className="text-[11px] text-[var(--color-text-secondary)] overflow-x-auto p-2 bg-[var(--color-surface-300)] rounded">
                            {JSON.stringify(item.payload, null, 2)}
                          </pre>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Processes Tab */}
                  {activeTab === "processes" && (
                    <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
                      <table className="w-full text-left text-xs font-mono">
                        <thead>
                          <tr className="bg-[var(--color-surface-200)] text-[var(--color-text-muted)] uppercase text-[10px]">
                            <th className="p-3">PID</th>
                            <th className="p-3">Process Name</th>
                            <th className="p-3">Executable Path</th>
                            <th className="p-3">User</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[var(--color-border)]">
                          {detailsData.running_processes.length === 0 ? (
                            <tr>
                              <td colSpan={4} className="p-6 text-center text-[var(--color-text-muted)]">
                                No active running process metadata ingested yet.
                              </td>
                            </tr>
                          ) : (
                            detailsData.running_processes.map((proc, idx) => (
                              <tr key={idx} className="hover:bg-[var(--color-surface-200)]/40">
                                <td className="p-3 text-[var(--color-primary-500)] font-bold">{proc.pid}</td>
                                <td className="p-3 text-[var(--color-text-primary)] font-bold">{proc.process_name}</td>
                                <td className="p-3 text-[var(--color-text-muted)] truncate max-w-xs">{proc.executable_path || "N/A"}</td>
                                <td className="p-3 text-[var(--color-text-secondary)]">{proc.username || "System"}</td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Network Tab */}
                  {activeTab === "network" && (
                    <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
                      <table className="w-full text-left text-xs font-mono">
                        <thead>
                          <tr className="bg-[var(--color-surface-200)] text-[var(--color-text-muted)] uppercase text-[10px]">
                            <th className="p-3">Local Address</th>
                            <th className="p-3">Remote Address</th>
                            <th className="p-3">Protocol</th>
                            <th className="p-3">State</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[var(--color-border)]">
                          {detailsData.network_connections.length === 0 ? (
                            <tr>
                              <td colSpan={4} className="p-6 text-center text-[var(--color-text-muted)]">
                                No active remote network sockets recorded.
                              </td>
                            </tr>
                          ) : (
                            detailsData.network_connections.map((net, idx) => (
                              <tr key={idx} className="hover:bg-[var(--color-surface-200)]/40">
                                <td className="p-3 text-[var(--color-text-primary)]">{net.local_address}:{net.local_port}</td>
                                <td className="p-3 text-[var(--color-primary-500)] font-bold">{net.remote_address}:{net.remote_port}</td>
                                <td className="p-3 text-[var(--color-text-muted)]">{net.protocol}</td>
                                <td className="p-3 text-[var(--color-safe)] font-bold">{net.state || "ESTABLISHED"}</td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Timeline Tab */}
                  {activeTab === "timeline" && (
                    <div className="space-y-4">
                      {detailsData.timeline.map((item, idx) => (
                        <div key={idx} className="flex items-start gap-3 text-xs">
                          <div className="w-2 h-2 rounded-full bg-[var(--color-primary-500)] mt-1.5 shrink-0" />
                          <div>
                            <p className="font-bold text-[var(--color-text-primary)]">{item.summary}</p>
                            <p className="text-[10px] text-[var(--color-text-muted)] font-mono">{new Date(item.timestamp).toLocaleString()}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
