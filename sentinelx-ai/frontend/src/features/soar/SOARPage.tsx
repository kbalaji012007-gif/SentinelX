import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  BoltIcon,
  CheckCircleIcon,
  ClockIcon,
  MagnifyingGlassIcon,
  DocumentTextIcon,
  XMarkIcon,
  ShieldCheckIcon,
} from "@heroicons/react/24/outline";

import {
  fetchPlaybooks,
  fetchSOARRules,
  fetchSOARExecutions,
  fetchSOARApprovals,
  fetchSOARStats,
  triggerExecution,
  approveExecution,
  rejectExecution,
  type SOARPlaybook,
  type SOARExecution,
} from "../../services/soarService";

export default function SOARPage() {
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"playbooks" | "rules" | "history" | "approvals">("playbooks");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selectedPlaybook, setSelectedPlaybook] = useState<SOARPlaybook | null>(null);
  const [selectedExecution, setSelectedExecution] = useState<SOARExecution | null>(null);
  const [approvalReason, setApprovalReason] = useState("");
  const [actionTargetId, setActionTargetId] = useState<string | null>(null);

  // Queries
  const { data: playbooksData, isLoading: isPlaybooksLoading } = useQuery({
    queryKey: ["soar-playbooks", page, search],
    queryFn: () => fetchPlaybooks({ page, page_size: 15, search: search || undefined }),
    refetchInterval: 30000,
  });

  const { data: rulesData } = useQuery({
    queryKey: ["soar-rules", page, search],
    queryFn: () => fetchSOARRules({ page, page_size: 15, search: search || undefined }),
    refetchInterval: 30000,
  });

  const { data: executionsData, isLoading: isExecutionsLoading } = useQuery({
    queryKey: ["soar-executions", page],
    queryFn: () => fetchSOARExecutions({ page, page_size: 15 }),
    refetchInterval: 15000,
  });

  const { data: approvalsData } = useQuery({
    queryKey: ["soar-approvals"],
    queryFn: () => fetchSOARApprovals({ status: "Pending" }),
    refetchInterval: 10000,
  });

  const { data: stats } = useQuery({
    queryKey: ["soar-stats"],
    queryFn: fetchSOARStats,
    refetchInterval: 15000,
  });

  // Trigger Execution Mutation
  const triggerMutation = useMutation({
    mutationFn: (playbookId: string) =>
      triggerExecution({
        playbook_id: playbookId,
        trigger_source: "Analyst Triggered Manual Execution",
        execution_metadata: {"initiated_by": "SOC Analyst"},
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["soar-executions"] });
      queryClient.invalidateQueries({ queryKey: ["soar-approvals"] });
      queryClient.invalidateQueries({ queryKey: ["soar-stats"] });
    },
  });

  // Approve Mutation
  const approveMutation = useMutation({
    mutationFn: (executionId: string) => approveExecution(executionId, approvalReason),
    onSuccess: () => {
      setActionTargetId(null);
      setApprovalReason("");
      queryClient.invalidateQueries({ queryKey: ["soar-executions"] });
      queryClient.invalidateQueries({ queryKey: ["soar-approvals"] });
      queryClient.invalidateQueries({ queryKey: ["soar-stats"] });
    },
  });

  // Reject Mutation
  const rejectMutation = useMutation({
    mutationFn: (executionId: string) => rejectExecution(executionId, approvalReason),
    onSuccess: () => {
      setActionTargetId(null);
      setApprovalReason("");
      queryClient.invalidateQueries({ queryKey: ["soar-executions"] });
      queryClient.invalidateQueries({ queryKey: ["soar-approvals"] });
      queryClient.invalidateQueries({ queryKey: ["soar-stats"] });
    },
  });

  const playbooks = playbooksData?.items || [];
  const totalPlaybooks = playbooksData?.total || 0;
  const rules = rulesData?.items || [];
  const executions = executionsData?.items || [];
  const approvals = approvalsData?.items || [];

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Completed":
        return "bg-[var(--color-safe)]/20 text-[var(--color-safe)] border-[var(--color-safe)]/40";
      case "Pending_Approval":
      case "Pending":
        return "bg-[var(--color-medium)]/20 text-[var(--color-medium)] border-[var(--color-medium)]/40";
      case "In_Progress":
        return "bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)] border-[var(--color-primary-500)]/40 animate-pulse";
      case "Failed":
      case "Rejected":
        return "bg-[var(--color-critical)]/20 text-[var(--color-critical)] border-[var(--color-critical)]/40";
      default:
        return "bg-[var(--color-surface-300)] text-[var(--color-text-secondary)] border-[var(--color-border)]";
    }
  };

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[var(--color-surface-100)] via-[var(--color-surface-200)] to-[var(--color-surface-100)] p-6 rounded-2xl border border-[var(--color-border)] shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--color-primary-500)] animate-ping" />
            <h1 className="text-xl font-extrabold text-[var(--color-text-primary)]">
              SOAR Automation Engine & Response Playbooks
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Security Orchestration, Automation & Response foundation managing automated playbooks, approval gates, and response audit trails
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-4 py-2 rounded-xl bg-[var(--color-surface-300)]/60 border border-[var(--color-border)] flex items-center gap-3">
            <div>
              <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] font-mono">Pending Approvals</p>
              <p className="text-lg font-extrabold font-mono text-[var(--color-medium)]">
                {stats?.pending_approvals ?? 0} Requests
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Telemetry Overview Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* Total Playbooks */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
            Total Playbooks
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {stats?.total_playbooks ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Active Response Catalog</p>
        </div>

        {/* Active Rules */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-primary-500)] uppercase tracking-wider mb-1">
            Active Rules
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-primary-500)]">
            {stats?.active_rules ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Trigger Automation</p>
        </div>

        {/* Pending Approvals */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-medium)] uppercase tracking-wider mb-1">
            Pending Approvals
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-medium)]">
            {stats?.pending_approvals ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Requires Analyst Review</p>
        </div>

        {/* Executions Today */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
            Executions Today
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {stats?.executions_today ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">24-Hour Automation Volume</p>
        </div>

        {/* Successful Executions */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-safe)] uppercase tracking-wider mb-1">
            Successful
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-safe)]">
            {stats?.successful_executions ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Completed Executions</p>
        </div>

        {/* Failed Executions */}
        <div className="glass rounded-xl p-4 border border-[var(--color-border)]">
          <p className="text-[10px] font-bold text-[var(--color-critical)] uppercase tracking-wider mb-1">
            Failed / Rejected
          </p>
          <p className="text-2xl font-bold font-mono text-[var(--color-critical)]">
            {stats?.failed_executions ?? 0}
          </p>
          <p className="text-[10px] text-[var(--color-text-secondary)] mt-1 font-medium">Halted Response Actions</p>
        </div>
      </div>

      {/* Main Tabs Header */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-3">
        {[
          { id: "playbooks", label: "Response Playbooks", icon: DocumentTextIcon },
          { id: "rules", label: "Automation Rules", icon: BoltIcon },
          { id: "history", label: "Execution Audit History", icon: ClockIcon },
          { id: "approvals", label: "Pending Analyst Approvals", icon: ShieldCheckIcon, badge: stats?.pending_approvals },
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
            {tab.badge ? (
              <span className="px-1.5 py-0.5 rounded text-[10px] bg-[var(--color-medium)] text-[var(--color-surface-0)] font-extrabold font-mono">
                {tab.badge}
              </span>
            ) : null}
          </button>
        ))}
      </div>

      {/* Tab 1: Playbooks Catalog Table */}
      {activeTab === "playbooks" && (
        <div className="space-y-4">
          <div className="glass rounded-xl p-4 border border-[var(--color-border)] flex flex-col md:flex-row gap-3 items-center justify-between">
            <div className="relative w-full md:w-80">
              <input
                type="text"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                placeholder="Search playbook name, category..."
                className="w-full pl-9 pr-4 py-2 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary-500)]"
              />
              <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3 top-2.5" />
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-[var(--color-text-muted)]">
                Total Catalog: <strong>{totalPlaybooks}</strong> Playbooks
              </span>
            </div>
          </div>

          <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
            {isPlaybooksLoading ? (
              <div className="p-8 space-y-3">
                {[1, 2, 3, 4].map((n) => (
                  <div key={n} className="h-12 w-full skeleton rounded-lg" />
                ))}
              </div>
            ) : playbooks.length === 0 ? (
              <div className="p-12 text-center text-xs font-mono text-[var(--color-text-muted)] space-y-2">
                <DocumentTextIcon className="w-8 h-8 opacity-50 mx-auto" />
                <p>No SOAR playbooks registered in system catalog.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[var(--color-surface-200)]/80 text-[var(--color-text-muted)] border-b border-[var(--color-border)] font-bold uppercase">
                    <tr>
                      <th className="px-4 py-3">Playbook Name</th>
                      <th className="px-4 py-3">Category</th>
                      <th className="px-4 py-3">Trigger Type</th>
                      <th className="px-4 py-3">Steps</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Author</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-border)]">
                    {playbooks.map((pb) => (
                      <tr key={pb.id} className="hover:bg-[var(--color-surface-200)]/40 transition-colors">
                        <td className="px-4 py-3 font-bold text-[var(--color-text-primary)] max-w-xs truncate">
                          {pb.name}
                        </td>
                        <td className="px-4 py-3 text-[var(--color-primary-500)]">{pb.category}</td>
                        <td className="px-4 py-3 text-[var(--color-text-secondary)]">{pb.trigger_type}</td>
                        <td className="px-4 py-3 font-bold text-[var(--color-text-primary)]">
                          {pb.steps?.length || 0} Steps
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              pb.is_active
                                ? "bg-[var(--color-safe)]/20 text-[var(--color-safe)] border-[var(--color-safe)]/40"
                                : "bg-[var(--color-surface-300)] text-[var(--color-text-muted)]"
                            }`}
                          >
                            {pb.is_active ? "Active" : "Inactive"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[var(--color-text-muted)]">{pb.author}</td>
                        <td className="px-4 py-3 text-right space-x-2">
                          <button
                            onClick={() => setSelectedPlaybook(pb)}
                            className="px-2.5 py-1 rounded bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold text-[10px] hover:bg-[var(--color-surface-400)] transition-all"
                          >
                            View Steps
                          </button>
                          <button
                            onClick={() => triggerMutation.mutate(pb.id)}
                            disabled={triggerMutation.isPending}
                            className="px-2.5 py-1 rounded bg-[var(--color-primary-500)] text-[var(--color-surface-0)] font-bold text-[10px] hover:bg-[var(--color-primary-600)] transition-all disabled:opacity-50"
                          >
                            Execute
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Automation Rules */}
      {activeTab === "rules" && (
        <div className="glass rounded-xl p-6 border border-[var(--color-border)] space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-[var(--color-text-primary)] font-mono flex items-center gap-2">
              <BoltIcon className="w-5 h-5 text-[var(--color-primary-500)]" />
              <span>Event-Driven SOAR Automation Rules ({rules.length})</span>
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {rules.map((rule) => (
              <div
                key={rule.id}
                className="p-4 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] font-mono text-xs space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[var(--color-text-primary)] truncate max-w-[180px]">
                    {rule.rule_name}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-safe)]/20 text-[var(--color-safe)]">
                    {rule.is_active ? "Active" : "Disabled"}
                  </span>
                </div>
                <div className="text-[11px] text-[var(--color-primary-500)]">
                  Trigger Event: <strong>{rule.trigger_event}</strong>
                </div>
                <div className="text-[11px] text-[var(--color-text-muted)]">
                  Executions Triggered: <strong>{rule.execution_count}</strong> times
                </div>
                {rule.description && (
                  <p className="text-[11px] font-sans text-[var(--color-text-secondary)] pt-1 border-t border-[var(--color-border)]">
                    {rule.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Execution Audit History */}
      {activeTab === "history" && (
        <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
          {isExecutionsLoading ? (
            <div className="p-8 space-y-3">
              {[1, 2, 3, 4].map((n) => (
                <div key={n} className="h-12 w-full skeleton rounded-lg" />
              ))}
            </div>
          ) : executions.length === 0 ? (
            <div className="p-12 text-center text-xs font-mono text-[var(--color-text-muted)] space-y-2">
              <ClockIcon className="w-8 h-8 opacity-50 mx-auto" />
              <p>No SOAR execution audit history recorded.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[var(--color-surface-200)]/80 text-[var(--color-text-muted)] border-b border-[var(--color-border)] font-bold uppercase">
                  <tr>
                    <th className="px-4 py-3">Execution ID</th>
                    <th className="px-4 py-3">Trigger Source</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Started At</th>
                    <th className="px-4 py-3">Completed At</th>
                    <th className="px-4 py-3 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border)]">
                  {executions.map((ex) => (
                    <tr key={ex.id} className="hover:bg-[var(--color-surface-200)]/40 transition-colors">
                      <td className="px-4 py-3 font-bold text-[var(--color-primary-500)]">
                        {ex.id.substring(0, 8)}...
                      </td>
                      <td className="px-4 py-3 text-[var(--color-text-primary)]">{ex.trigger_source}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(ex.status)}`}>
                          {ex.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[var(--color-text-muted)]">
                        {new Date(ex.started_at).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-3 text-[var(--color-text-muted)]">
                        {ex.completed_at ? new Date(ex.completed_at).toLocaleTimeString() : "In Progress"}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setSelectedExecution(ex)}
                          className="px-2.5 py-1 rounded bg-[var(--color-surface-300)] text-[var(--color-primary-500)] font-bold text-[10px] hover:bg-[var(--color-primary-500)] hover:text-[var(--color-surface-0)] transition-all"
                        >
                          Inspect Audit
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Pending Analyst Approvals */}
      {activeTab === "approvals" && (
        <div className="space-y-4">
          <div className="glass rounded-xl p-4 border border-[var(--color-border)] flex items-center justify-between">
            <h2 className="text-xs font-bold text-[var(--color-text-primary)] font-mono flex items-center gap-2">
              <ShieldCheckIcon className="w-5 h-5 text-[var(--color-medium)]" />
              <span>Pending Analyst Manual Approval Queue ({approvals.length})</span>
            </h2>
          </div>

          {approvals.length === 0 ? (
            <div className="glass rounded-xl p-12 text-center text-xs font-mono text-[var(--color-safe)] space-y-2 border border-[var(--color-border)]">
              <CheckCircleIcon className="w-8 h-8 mx-auto text-[var(--color-safe)]" />
              <p>No pending analyst approval requests. All response actions authorized.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {approvals.map((app) => (
                <div key={app.id} className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-[var(--color-medium)]/20 text-[var(--color-medium)] border border-[var(--color-medium)]/40">
                      PENDING APPROVAL
                    </span>
                    <span className="text-[10px] text-[var(--color-text-muted)]">
                      Requested: {new Date(app.requested_at).toLocaleTimeString()}
                    </span>
                  </div>

                  <h3 className="font-bold text-[var(--color-text-primary)]">
                    Execution ID: {app.execution_id.substring(0, 13)}...
                  </h3>
                  <p className="text-[11px] text-[var(--color-text-secondary)]">
                    Requested By: <strong>{app.requested_by}</strong>
                  </p>

                  {actionTargetId === app.execution_id ? (
                    <div className="p-3 rounded-xl bg-[var(--color-surface-200)] border border-[var(--color-border)] space-y-2">
                      <input
                        type="text"
                        value={approvalReason}
                        onChange={(e) => setApprovalReason(e.target.value)}
                        placeholder="Enter approval/rejection rationale..."
                        className="w-full px-3 py-1.5 rounded-lg bg-[var(--color-surface-300)] text-xs text-[var(--color-text-primary)] border border-[var(--color-border)] focus:outline-none"
                      />
                      <div className="flex gap-2 justify-end">
                        <button
                          onClick={() => rejectMutation.mutate(app.execution_id)}
                          disabled={rejectMutation.isPending}
                          className="px-3 py-1 rounded bg-[var(--color-critical)] text-[var(--color-surface-0)] font-bold text-[10px]"
                        >
                          Confirm Reject
                        </button>
                        <button
                          onClick={() => approveMutation.mutate(app.execution_id)}
                          disabled={approveMutation.isPending}
                          className="px-3 py-1 rounded bg-[var(--color-safe)] text-[var(--color-surface-0)] font-bold text-[10px]"
                        >
                          Confirm Approve
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex gap-2 justify-end pt-2 border-t border-[var(--color-border)]">
                      <button
                        onClick={() => setActionTargetId(app.execution_id)}
                        className="px-3 py-1.5 rounded bg-[var(--color-critical)]/20 text-[var(--color-critical)] font-bold text-[10px] hover:bg-[var(--color-critical)] hover:text-[var(--color-surface-0)] transition-all"
                      >
                        Reject Action
                      </button>
                      <button
                        onClick={() => setActionTargetId(app.execution_id)}
                        className="px-3 py-1.5 rounded bg-[var(--color-safe)] text-[var(--color-surface-0)] font-bold text-[10px] hover:bg-[var(--color-safe-hover)] transition-all"
                      >
                        Approve Action
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Playbook Steps Modal */}
      {selectedPlaybook && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="glass rounded-2xl max-w-xl w-full p-6 border border-[var(--color-border)] space-y-4 max-h-[85vh] overflow-y-auto font-mono text-xs">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
              <div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)]">
                  {selectedPlaybook.category}
                </span>
                <h2 className="text-base font-bold text-[var(--color-text-primary)] mt-1">
                  {selectedPlaybook.name}
                </h2>
              </div>
              <button
                onClick={() => setSelectedPlaybook(null)}
                className="p-1 rounded-lg bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <p className="text-[11px] text-[var(--color-text-secondary)] font-sans">{selectedPlaybook.description}</p>

            <div className="space-y-2">
              <h3 className="font-bold text-[var(--color-text-primary)] uppercase tracking-wider">
                Sequential Playbook Response Steps ({selectedPlaybook.steps?.length || 0})
              </h3>

              <div className="space-y-2">
                {(selectedPlaybook.steps || []).map((step) => (
                  <div key={step.step_order} className="p-3 rounded-xl bg-[var(--color-surface-200)]/60 border border-[var(--color-border)] flex items-center justify-between">
                    <div>
                      <span className="font-bold text-[var(--color-primary-500)] mr-2">Step {step.step_order}:</span>
                      <span className="font-bold text-[var(--color-text-primary)]">{step.step_name}</span>
                      <p className="text-[10px] text-[var(--color-text-muted)] mt-0.5">
                        Action: <strong>{step.action_type}</strong> • Target: {step.target_type}
                      </p>
                    </div>
                    {step.requires_approval && (
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-[var(--color-medium)]/20 text-[var(--color-medium)]">
                        Approval Required
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedPlaybook(null)}
                className="px-5 py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold text-xs"
              >
                Close Window
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Execution Audit Modal */}
      {selectedExecution && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="glass rounded-2xl max-w-xl w-full p-6 border border-[var(--color-border)] space-y-4 max-h-[85vh] overflow-y-auto font-mono text-xs">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
              <div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(selectedExecution.status)}`}>
                  {selectedExecution.status}
                </span>
                <h2 className="text-sm font-bold text-[var(--color-text-primary)] mt-1">
                  Execution ID: {selectedExecution.id}
                </h2>
              </div>
              <button
                onClick={() => setSelectedExecution(null)}
                className="p-1 rounded-lg bg-[var(--color-surface-300)] text-[var(--color-text-secondary)]"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-2">
              <h3 className="font-bold text-[var(--color-text-primary)] uppercase">Step Audit Logs</h3>
              <div className="space-y-1.5 max-h-60 overflow-y-auto pr-2">
                {(selectedExecution.logs || []).map((log) => (
                  <div key={log.id} className="p-2.5 rounded bg-[var(--color-surface-300)] text-[11px] space-y-0.5 border border-[var(--color-border)]">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="font-bold text-[var(--color-primary-500)]">[{log.log_level}]</span>
                      <span className="text-[var(--color-text-muted)]">{new Date(log.created_at).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-[var(--color-text-primary)]">{log.message}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedExecution(null)}
                className="px-5 py-2 rounded-xl bg-[var(--color-surface-300)] text-[var(--color-text-primary)] font-bold text-xs"
              >
                Close Audit
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
