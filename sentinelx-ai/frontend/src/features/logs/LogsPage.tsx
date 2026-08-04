import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  MagnifyingGlassIcon,
  ArrowPathIcon,
  FunnelIcon,
  XMarkIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ArrowDownTrayIcon,
  CheckIcon,
  ClipboardDocumentIcon,
  ExclamationTriangleIcon,
  ViewColumnsIcon,
  ClockIcon,
  ServerIcon,
  UserIcon,
  ComputerDesktopIcon,
  TagIcon,
  KeyIcon,
  Bars3BottomLeftIcon,
  AdjustmentsHorizontalIcon,
} from "@heroicons/react/24/outline";

import {
  fetchLogEntries,
  fetchLogEntryById,
  fetchLogSources,
  fetchLogStats,
} from "../../services/logService";
import type { LogEntrySummary, LogQueryParams } from "../../types/log";

// ─────────────────────────────────────────────────────────────────────────────
// Level Styles & Color Tokens
// ─────────────────────────────────────────────────────────────────────────────

const LEVEL_STYLES: Record<string, string> = {
  CRITICAL: "bg-[var(--color-critical)]/15 text-[var(--color-critical)] border border-[var(--color-critical)]/40",
  ERROR: "bg-[var(--color-high)]/15 text-[var(--color-high)] border border-[var(--color-high)]/40",
  WARNING: "bg-[var(--color-medium)]/15 text-[var(--color-medium)] border border-[var(--color-medium)]/40",
  WARN: "bg-[var(--color-medium)]/15 text-[var(--color-medium)] border border-[var(--color-medium)]/40",
  INFO: "bg-[var(--color-info)]/15 text-[var(--color-info)] border border-[var(--color-info)]/40",
  DEBUG: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  TRACE: "bg-purple-500/15 text-purple-400 border border-purple-500/30",
};

const LEVEL_DOTS: Record<string, string> = {
  CRITICAL: "bg-[var(--color-critical)]",
  ERROR: "bg-[var(--color-high)]",
  WARNING: "bg-[var(--color-medium)]",
  WARN: "bg-[var(--color-medium)]",
  INFO: "bg-[var(--color-info)]",
  DEBUG: "bg-blue-400",
  TRACE: "bg-purple-400",
};

// Available columns for visibility toggle
interface ColumnDef {
  id: string;
  label: string;
  defaultVisible: boolean;
}

const ALL_COLUMNS: ColumnDef[] = [
  { id: "timestamp", label: "Timestamp", defaultVisible: true },
  { id: "level", label: "Level", defaultVisible: true },
  { id: "source", label: "Source", defaultVisible: true },
  { id: "event_type", label: "Event Type", defaultVisible: true },
  { id: "category", label: "Category", defaultVisible: true },
  { id: "ips", label: "Src / Dst IP", defaultVisible: true },
  { id: "username", label: "User", defaultVisible: true },
  { id: "message", label: "Message", defaultVisible: true },
  { id: "event_id", label: "Event ID", defaultVisible: false },
  { id: "asset_id", label: "Asset ID", defaultVisible: false },
];

export default function LogsPage() {
  // ── State ────────────────────────────────────────────────────────────────
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [searchKeyword, setSearchKeyword] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");

  // Filters
  const [levelFilter, setLevelFilter] = useState<string>("ALL");
  const [sourceFilter, setSourceFilter] = useState<string>("ALL");
  const [assetFilter, setAssetFilter] = useState<string>("");
  const [usernameFilter, setUsernameFilter] = useState<string>("");
  const [eventTypeFilter, setEventTypeFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [timeRangePreset, setTimeRangePreset] = useState<string>("ALL");
  const [customStartTime, setCustomStartTime] = useState<string>("");
  const [customEndTime, setCustomEndTime] = useState<string>("");

  // UI Controls
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(0); // 0 = off, else ms
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [selectedEntryId, setSelectedEntryId] = useState<string | null>(null);
  const [selectedRowIds, setSelectedRowIds] = useState<Set<string>>(new Set());
  const [columnVisibility, setColumnVisibility] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    ALL_COLUMNS.forEach((col) => {
      init[col.id] = col.defaultVisible;
    });
    return init;
  });
  const [showColumnToggle, setShowColumnToggle] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Sorting
  const [sortField, setSortField] = useState<string>("event_timestamp");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // ── Compute Time Range ───────────────────────────────────────────────────
  const { startTimeISO, endTimeISO } = useMemo(() => {
    if (timeRangePreset === "CUSTOM") {
      return {
        startTimeISO: customStartTime ? new Date(customStartTime).toISOString() : undefined,
        endTimeISO: customEndTime ? new Date(customEndTime).toISOString() : undefined,
      };
    }
    if (timeRangePreset === "15m") {
      return { startTimeISO: new Date(Date.now() - 15 * 60 * 1000).toISOString() };
    }
    if (timeRangePreset === "1h") {
      return { startTimeISO: new Date(Date.now() - 60 * 60 * 1000).toISOString() };
    }
    if (timeRangePreset === "24h") {
      return { startTimeISO: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() };
    }
    return {};
  }, [timeRangePreset, customStartTime, customEndTime]);

  // ── Query Parameters ─────────────────────────────────────────────────────
  const queryParams: LogQueryParams = useMemo(() => {
    const params: LogQueryParams = {
      page,
      page_size: pageSize,
    };
    if (appliedSearch) params.keyword = appliedSearch;
    if (levelFilter !== "ALL") params.level = levelFilter;
    if (sourceFilter !== "ALL") params.source_id = sourceFilter;
    if (assetFilter.trim()) params.asset_id = assetFilter.trim();
    if (usernameFilter.trim()) params.username = usernameFilter.trim();
    if (eventTypeFilter.trim()) params.event_type = eventTypeFilter.trim();
    if (categoryFilter.trim()) params.category = categoryFilter.trim();
    if (startTimeISO) params.start_time = startTimeISO;
    if (endTimeISO) params.end_time = endTimeISO;

    return params;
  }, [
    page,
    pageSize,
    appliedSearch,
    levelFilter,
    sourceFilter,
    assetFilter,
    usernameFilter,
    eventTypeFilter,
    categoryFilter,
    startTimeISO,
    endTimeISO,
  ]);

  // ── Data Queries ─────────────────────────────────────────────────────────
  const {
    data: logsData,
    isLoading: isLogsLoading,
    isError: isLogsError,
    error: logsError,
    refetch: refetchLogs,
    isFetching: isLogsFetching,
  } = useQuery({
    queryKey: ["logs", queryParams],
    queryFn: () => fetchLogEntries(queryParams),
    refetchInterval: autoRefreshInterval > 0 ? autoRefreshInterval : false,
  });

  const { data: sourcesData } = useQuery({
    queryKey: ["logSources"],
    queryFn: () => fetchLogSources({ page_size: 100 }),
  });

  const { data: statsData } = useQuery({
    queryKey: ["logStats"],
    queryFn: () => fetchLogStats(),
  });

  // Selected Log Detail Query
  const {
    data: selectedLogDetail,
    isLoading: isDetailLoading,
  } = useQuery({
    queryKey: ["logEntryDetail", selectedEntryId],
    queryFn: () => fetchLogEntryById(selectedEntryId!),
    enabled: !!selectedEntryId,
  });

  // Source Lookup Map
  const sourceMap = useMemo(() => {
    const map = new Map<string, string>();
    sourcesData?.items.forEach((s) => map.set(s.id, s.name));
    return map;
  }, [sourcesData]);

  // Handle Search Submission
  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setAppliedSearch(searchKeyword.trim());
    setPage(1);
  };

  // Sort logs locally if needed
  const sortedLogs = useMemo(() => {
    if (!logsData?.items) return [];
    const items = [...logsData.items];
    items.sort((a, b) => {
      let valA: any = a[sortField as keyof LogEntrySummary] || "";
      let valB: any = b[sortField as keyof LogEntrySummary] || "";
      if (sortField === "event_timestamp") {
        valA = new Date(valA).getTime();
        valB = new Date(valB).getTime();
      }
      if (valA < valB) return sortOrder === "asc" ? -1 : 1;
      if (valA > valB) return sortOrder === "asc" ? 1 : -1;
      return 0;
    });
    return items;
  }, [logsData?.items, sortField, sortOrder]);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortOrder("desc");
    }
  };

  // Selection handlers
  const toggleSelectAll = () => {
    if (!sortedLogs.length) return;
    if (selectedRowIds.size === sortedLogs.length) {
      setSelectedRowIds(new Set());
    } else {
      setSelectedRowIds(new Set(sortedLogs.map((l) => l.id)));
    }
  };

  const toggleSelectRow = (id: string) => {
    const next = new Set(selectedRowIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedRowIds(next);
  };

  // Export UI handler
  const handleExport = (format: "json" | "csv") => {
    const exportItems = sortedLogs.filter((l) =>
      selectedRowIds.size > 0 ? selectedRowIds.has(l.id) : true
    );

    if (!exportItems.length) return;

    let blob: Blob;
    let filename: string;

    if (format === "json") {
      blob = new Blob([JSON.stringify(exportItems, null, 2)], {
        type: "application/json",
      });
      filename = `sentinelx_logs_${Date.now()}.json`;
    } else {
      const headers = ["id", "event_timestamp", "log_level", "event_type", "category", "source_ip", "destination_ip", "username", "event_id"];
      const csvLines = [
        headers.join(","),
        ...exportItems.map((item) =>
          headers.map((h) => `"${(item[h as keyof LogEntrySummary] || "").toString().replace(/"/g, '""')}"`).join(",")
        ),
      ];
      blob = new Blob([csvLines.join("\n")], { type: "text/csv" });
      filename = `sentinelx_logs_${Date.now()}.csv`;
    }

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Copy to clipboard helper
  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(label);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Reset Filters
  const resetFilters = () => {
    setSearchKeyword("");
    setAppliedSearch("");
    setLevelFilter("ALL");
    setSourceFilter("ALL");
    setAssetFilter("");
    setUsernameFilter("");
    setEventTypeFilter("");
    setCategoryFilter("");
    setTimeRangePreset("ALL");
    setCustomStartTime("");
    setCustomEndTime("");
    setPage(1);
  };

  const totalPages = logsData ? Math.ceil(logsData.total / pageSize) : 1;

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* ── Page Header ───────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-[var(--color-text-primary)] tracking-tight">
              Log Collection & Telemetry
            </h1>
            {isLogsFetching && (
              <span className="flex items-center gap-1 text-[11px] font-mono text-[var(--color-primary-500)] bg-[var(--color-primary-500)]/10 px-2.5 py-0.5 rounded-full border border-[var(--color-primary-500)]/30 animate-pulse">
                <ArrowPathIcon className="w-3 h-3 animate-spin" />
                Syncing
              </span>
            )}
          </div>
          <p className="text-xs text-[var(--color-text-secondary)] mt-1">
            Enterprise SIEM & SOC log stream inspector, structured search, and correlation engine
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Refresh Button */}
          <button
            onClick={() => refetchLogs()}
            disabled={isLogsFetching}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-[var(--color-surface-200)] text-[var(--color-text-primary)] hover:bg-[var(--color-surface-300)] border border-[var(--color-border)] transition-all disabled:opacity-50"
            title="Force refresh log entries"
          >
            <ArrowPathIcon className={`w-3.5 h-3.5 ${isLogsFetching ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>

          {/* Auto-Refresh Selector */}
          <div className="flex items-center gap-1 bg-[var(--color-surface-200)] p-1 rounded-lg border border-[var(--color-border)] text-xs font-mono">
            <span className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] px-1.5">
              Live:
            </span>
            {[
              { label: "Off", value: 0 },
              { label: "5s", value: 5000 },
              { label: "10s", value: 10000 },
              { label: "30s", value: 30000 },
            ].map((option) => (
              <button
                key={option.label}
                onClick={() => setAutoRefreshInterval(option.value)}
                className={`px-2 py-1 rounded text-[11px] font-semibold transition-all ${
                  autoRefreshInterval === option.value
                    ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)]"
                    : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>

          {/* Export Button */}
          <div className="relative group">
            <button
              onClick={() => handleExport("csv")}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-[var(--color-primary-500)]/15 text-[var(--color-primary-500)] border border-[var(--color-primary-500)]/30 hover:bg-[var(--color-primary-500)]/25 transition-all"
            >
              <ArrowDownTrayIcon className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>
          </div>
        </div>
      </div>

      {/* ── Stats Summary Bar ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        <div className="glass rounded-xl p-3 border border-[var(--color-border)]">
          <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] block">
            Total Telemetry
          </span>
          <span className="text-lg font-bold font-mono text-[var(--color-text-primary)]">
            {statsData?.total_entries?.toLocaleString() ?? "—"}
          </span>
        </div>
        <div className="glass rounded-xl p-3 border border-[var(--color-border)]">
          <span className="text-[10px] font-bold uppercase text-[var(--color-critical)] block">
            Critical
          </span>
          <span className="text-lg font-bold font-mono text-[var(--color-critical)]">
            {statsData?.by_level?.CRITICAL?.toLocaleString() ?? 0}
          </span>
        </div>
        <div className="glass rounded-xl p-3 border border-[var(--color-border)]">
          <span className="text-[10px] font-bold uppercase text-[var(--color-high)] block">
            Errors
          </span>
          <span className="text-lg font-bold font-mono text-[var(--color-high)]">
            {statsData?.by_level?.ERROR?.toLocaleString() ?? 0}
          </span>
        </div>
        <div className="glass rounded-xl p-3 border border-[var(--color-border)]">
          <span className="text-[10px] font-bold uppercase text-[var(--color-medium)] block">
            Warnings
          </span>
          <span className="text-lg font-bold font-mono text-[var(--color-medium)]">
            {(statsData?.by_level?.WARNING || statsData?.by_level?.WARN || 0).toLocaleString()}
          </span>
        </div>
        <div className="glass rounded-xl p-3 border border-[var(--color-border)]">
          <span className="text-[10px] font-bold uppercase text-[var(--color-info)] block">
            Info / Debug
          </span>
          <span className="text-lg font-bold font-mono text-[var(--color-info)]">
            {((statsData?.by_level?.INFO || 0) + (statsData?.by_level?.DEBUG || 0)).toLocaleString()}
          </span>
        </div>
        <div className="glass rounded-xl p-3 border border-[var(--color-border)]">
          <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] block">
            Active Sources
          </span>
          <span className="text-lg font-bold font-mono text-[var(--color-text-primary)]">
            {sourcesData?.total ?? "—"}
          </span>
        </div>
      </div>

      {/* ── Main Filter Bar ───────────────────────────────────────────────── */}
      <div className="glass rounded-xl p-4 border border-[var(--color-border)] space-y-3">
        <div className="flex flex-col lg:flex-row gap-3 items-stretch lg:items-center justify-between">
          {/* Keyword Search Form */}
          <form onSubmit={handleSearchSubmit} className="relative flex-1">
            <MagnifyingGlassIcon className="w-4 h-4 text-[var(--color-text-muted)] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchKeyword}
              onChange={(e) => setSearchKeyword(e.target.value)}
              placeholder="Search log messages, usernames, event types, raw payload..."
              className="w-full bg-[var(--color-surface-200)] text-xs font-mono text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-lg pl-9 pr-20 py-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
            />
            <button
              type="submit"
              className="absolute right-1.5 top-1/2 -translate-y-1/2 px-2.5 py-1 rounded text-[11px] font-semibold bg-[var(--color-primary-500)] text-[var(--color-surface-0)] hover:bg-[var(--color-primary-600)] transition-all"
            >
              Search
            </button>
          </form>

          {/* Level Filter Tabs */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1 lg:pb-0">
            {["ALL", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"].map((lvl) => (
              <button
                key={lvl}
                onClick={() => {
                  setLevelFilter(lvl);
                  setPage(1);
                }}
                className={`px-2.5 py-1.5 rounded-lg text-[11px] font-bold font-mono transition-all whitespace-nowrap ${
                  levelFilter === lvl
                    ? "bg-[var(--color-primary-500)] text-[var(--color-surface-0)] shadow"
                    : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)]"
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          {/* Advanced Filter & Column Visibility Toggles */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border transition-all ${
                showAdvancedFilters || assetFilter || usernameFilter || eventTypeFilter || categoryFilter || timeRangePreset !== "ALL"
                  ? "bg-[var(--color-primary-500)]/15 text-[var(--color-primary-500)] border-[var(--color-primary-500)]/40"
                  : "bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] border-[var(--color-border)] hover:bg-[var(--color-surface-300)]"
              }`}
            >
              <FunnelIcon className="w-3.5 h-3.5" />
              <span>Filters</span>
            </button>

            <div className="relative">
              <button
                onClick={() => setShowColumnToggle(!showColumnToggle)}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-300)] border border-[var(--color-border)] transition-all"
                title="Toggle Columns"
              >
                <ViewColumnsIcon className="w-3.5 h-3.5" />
                <span>Columns</span>
              </button>

              {/* Column Visibility Popover */}
              {showColumnToggle && (
                <div className="absolute right-0 mt-2 w-48 glass rounded-xl border border-[var(--color-border)] p-3 shadow-2xl z-30 space-y-2 text-xs">
                  <div className="flex justify-between items-center pb-1.5 border-b border-[var(--color-border)] font-semibold text-[var(--color-text-primary)]">
                    <span>Visible Columns</span>
                    <button
                      onClick={() => setShowColumnToggle(false)}
                      className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
                    >
                      <XMarkIcon className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {ALL_COLUMNS.map((col) => (
                      <label
                        key={col.id}
                        className="flex items-center gap-2 cursor-pointer text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] select-none text-[11px]"
                      >
                        <input
                          type="checkbox"
                          checked={columnVisibility[col.id]}
                          onChange={(e) =>
                            setColumnVisibility((prev) => ({
                              ...prev,
                              [col.id]: e.target.checked,
                            }))
                          }
                          className="rounded border-[var(--color-border)] bg-[var(--color-surface-200)] text-[var(--color-primary-500)] focus:ring-0"
                        />
                        <span>{col.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {(appliedSearch || levelFilter !== "ALL" || sourceFilter !== "ALL" || assetFilter || usernameFilter || eventTypeFilter || categoryFilter || timeRangePreset !== "ALL") && (
              <button
                onClick={resetFilters}
                className="p-2 rounded-lg text-xs text-[var(--color-critical)] hover:bg-[var(--color-critical)]/10 border border-transparent hover:border-[var(--color-critical)]/30 transition-all"
                title="Reset all filters"
              >
                <XMarkIcon className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* ── Advanced Filters Drawer ──────────────────────────────────────── */}
        {showAdvancedFilters && (
          <div className="pt-3 border-t border-[var(--color-border)] grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 animate-fade-in text-xs">
            {/* Source Dropdown */}
            <div>
              <label className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] mb-1 block">
                Log Source
              </label>
              <select
                value={sourceFilter}
                onChange={(e) => {
                  setSourceFilter(e.target.value);
                  setPage(1);
                }}
                className="w-full bg-[var(--color-surface-200)] text-[var(--color-text-primary)] text-xs rounded-lg p-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
              >
                <option value="ALL">All Sources</option>
                {sourcesData?.items.map((src) => (
                  <option key={src.id} value={src.id}>
                    {src.name} ({src.source_type})
                  </option>
                ))}
              </select>
            </div>

            {/* Time Range Preset */}
            <div>
              <label className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] mb-1 block">
                Time Window
              </label>
              <select
                value={timeRangePreset}
                onChange={(e) => {
                  setTimeRangePreset(e.target.value);
                  setPage(1);
                }}
                className="w-full bg-[var(--color-surface-200)] text-[var(--color-text-primary)] text-xs rounded-lg p-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
              >
                <option value="ALL">All Time</option>
                <option value="15m">Last 15 Minutes</option>
                <option value="1h">Last 1 Hour</option>
                <option value="24h">Last 24 Hours</option>
                <option value="CUSTOM">Custom Range</option>
              </select>
            </div>

            {/* User Filter */}
            <div>
              <label className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] mb-1 block">
                Username
              </label>
              <input
                type="text"
                value={usernameFilter}
                onChange={(e) => {
                  setUsernameFilter(e.target.value);
                  setPage(1);
                }}
                placeholder="e.g. admin, jdoe"
                className="w-full bg-[var(--color-surface-200)] font-mono text-[var(--color-text-primary)] text-xs rounded-lg p-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
              />
            </div>

            {/* Event Type Filter */}
            <div>
              <label className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] mb-1 block">
                Event Type
              </label>
              <input
                type="text"
                value={eventTypeFilter}
                onChange={(e) => {
                  setEventTypeFilter(e.target.value);
                  setPage(1);
                }}
                placeholder="e.g. UserLogin, FirewallDrop"
                className="w-full bg-[var(--color-surface-200)] font-mono text-[var(--color-text-primary)] text-xs rounded-lg p-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
              />
            </div>

            {/* Category Filter */}
            <div>
              <label className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] mb-1 block">
                Category
              </label>
              <input
                type="text"
                value={categoryFilter}
                onChange={(e) => {
                  setCategoryFilter(e.target.value);
                  setPage(1);
                }}
                placeholder="e.g. Authentication, Network"
                className="w-full bg-[var(--color-surface-200)] font-mono text-[var(--color-text-primary)] text-xs rounded-lg p-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
              />
            </div>

            {/* Asset Filter */}
            <div>
              <label className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] mb-1 block">
                Asset ID
              </label>
              <input
                type="text"
                value={assetFilter}
                onChange={(e) => {
                  setAssetFilter(e.target.value);
                  setPage(1);
                }}
                placeholder="UUID of target asset"
                className="w-full bg-[var(--color-surface-200)] font-mono text-[var(--color-text-primary)] text-xs rounded-lg p-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)]"
              />
            </div>

            {/* Custom Datetime Pickers if CUSTOM selected */}
            {timeRangePreset === "CUSTOM" && (
              <div className="col-span-full grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-[var(--color-border)]/50">
                <div>
                  <label className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] mb-1 block">
                    Start Time
                  </label>
                  <input
                    type="datetime-local"
                    value={customStartTime}
                    onChange={(e) => {
                      setCustomStartTime(e.target.value);
                      setPage(1);
                    }}
                    className="w-full bg-[var(--color-surface-200)] text-[var(--color-text-primary)] text-xs rounded-lg p-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)] font-mono"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] mb-1 block">
                    End Time
                  </label>
                  <input
                    type="datetime-local"
                    value={customEndTime}
                    onChange={(e) => {
                      setCustomEndTime(e.target.value);
                      setPage(1);
                    }}
                    className="w-full bg-[var(--color-surface-200)] text-[var(--color-text-primary)] text-xs rounded-lg p-2 border border-[var(--color-border)] focus:outline-none focus:border-[var(--color-primary-500)] font-mono"
                  />
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Selection Action Bar ──────────────────────────────────────────── */}
      {selectedRowIds.size > 0 && (
        <div className="glass rounded-xl p-3 border border-[var(--color-primary-500)]/40 bg-[var(--color-primary-500)]/10 flex items-center justify-between animate-fade-in text-xs">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[var(--color-primary-500)]" />
            <span className="font-semibold text-[var(--color-text-primary)]">
              {selectedRowIds.size} log entries selected
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExport("json")}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-[var(--color-primary-500)] text-[var(--color-surface-0)] hover:bg-[var(--color-primary-600)] transition-all"
            >
              Export Selected (JSON)
            </button>
            <button
              onClick={() => setSelectedRowIds(new Set())}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
            >
              Deselect All
            </button>
          </div>
        </div>
      )}

      {/* ── Log Table Container ───────────────────────────────────────────── */}
      <div className="glass rounded-xl border border-[var(--color-border)] overflow-hidden">
        {/* Table Controls Header */}
        <div className="p-3 bg-[var(--color-surface-200)]/80 border-b border-[var(--color-border)] flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase font-bold text-[var(--color-text-muted)] font-mono">
              Live Stream & Forensic Query Results
            </span>
            {logsData && (
              <span className="text-[11px] font-mono text-[var(--color-text-secondary)]">
                ({logsData.total.toLocaleString()} total entries)
              </span>
            )}
          </div>

          <div className="flex items-center gap-3">
            {/* Page Size Selector */}
            <div className="flex items-center gap-1.5 text-xs text-[var(--color-text-secondary)]">
              <span>Rows:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                className="bg-[var(--color-surface-100)] text-[var(--color-text-primary)] font-mono rounded px-2 py-0.5 border border-[var(--color-border)] focus:outline-none"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>
          </div>
        </div>

        {/* ── Table Content / States ─────────────────────────────────────── */}
        {isLogsLoading ? (
          <div className="p-12 text-center space-y-4">
            <ArrowPathIcon className="w-8 h-8 text-[var(--color-primary-500)] animate-spin mx-auto" />
            <p className="text-xs font-mono text-[var(--color-text-muted)]">
              Querying database log collection engine...
            </p>
          </div>
        ) : isLogsError ? (
          <div className="p-12 text-center space-y-4">
            <ExclamationTriangleIcon className="w-10 h-10 text-[var(--color-critical)] mx-auto" />
            <div>
              <h3 className="text-sm font-bold text-[var(--color-text-primary)]">
                Backend Connection / Query Error
              </h3>
              <p className="text-xs text-[var(--color-text-muted)] mt-1 max-w-md mx-auto">
                {(logsError as Error)?.message || "Failed to communicate with SentinelX AI API."}
              </p>
            </div>
            <button
              onClick={() => refetchLogs()}
              className="px-4 py-2 bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-semibold rounded-lg hover:bg-[var(--color-primary-600)] transition-all"
            >
              Retry Connection
            </button>
          </div>
        ) : !sortedLogs.length ? (
          <div className="p-16 text-center space-y-4">
            <Bars3BottomLeftIcon className="w-10 h-10 text-[var(--color-text-muted)] mx-auto" />
            <div>
              <h3 className="text-sm font-bold text-[var(--color-text-primary)]">
                No Log Entries Found
              </h3>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">
                {appliedSearch || levelFilter !== "ALL" || sourceFilter !== "ALL"
                  ? "No telemetry logs matched your filter criteria."
                  : "No log entries have been ingested into the platform yet."}
              </p>
            </div>
            {(appliedSearch || levelFilter !== "ALL" || sourceFilter !== "ALL") && (
              <button
                onClick={resetFilters}
                className="px-3 py-1.5 bg-[var(--color-surface-200)] text-[var(--color-text-primary)] text-xs font-semibold rounded-lg hover:bg-[var(--color-surface-300)] border border-[var(--color-border)] transition-all"
              >
                Clear Filters
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-[var(--color-surface-200)]/60 border-b border-[var(--color-border)] text-[10px] uppercase font-mono font-bold text-[var(--color-text-muted)] select-none">
                  <th className="p-3 w-8">
                    <input
                      type="checkbox"
                      checked={
                        sortedLogs.length > 0 &&
                        selectedRowIds.size === sortedLogs.length
                      }
                      onChange={toggleSelectAll}
                      className="rounded border-[var(--color-border)] bg-[var(--color-surface-200)] text-[var(--color-primary-500)] focus:ring-0 cursor-pointer"
                    />
                  </th>
                  {columnVisibility.timestamp && (
                    <th
                      onClick={() => handleSort("event_timestamp")}
                      className="p-3 cursor-pointer hover:text-[var(--color-text-primary)] transition-all"
                    >
                      <div className="flex items-center gap-1">
                        <span>Timestamp</span>
                        {sortField === "event_timestamp" && (
                          <span>{sortOrder === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {columnVisibility.level && (
                    <th
                      onClick={() => handleSort("log_level")}
                      className="p-3 cursor-pointer hover:text-[var(--color-text-primary)] transition-all"
                    >
                      <div className="flex items-center gap-1">
                        <span>Level</span>
                        {sortField === "log_level" && (
                          <span>{sortOrder === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {columnVisibility.source && <th className="p-3">Source</th>}
                  {columnVisibility.event_type && (
                    <th
                      onClick={() => handleSort("event_type")}
                      className="p-3 cursor-pointer hover:text-[var(--color-text-primary)] transition-all"
                    >
                      <div className="flex items-center gap-1">
                        <span>Event Type</span>
                        {sortField === "event_type" && (
                          <span>{sortOrder === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                  )}
                  {columnVisibility.category && <th className="p-3">Category</th>}
                  {columnVisibility.ips && <th className="p-3">Src / Dst IP</th>}
                  {columnVisibility.username && <th className="p-3">User</th>}
                  {columnVisibility.event_id && <th className="p-3">Event ID</th>}
                  {columnVisibility.asset_id && <th className="p-3">Asset ID</th>}
                  {columnVisibility.message && <th className="p-3">Message Snippet</th>}
                  <th className="p-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]/50 font-mono text-xs">
                {sortedLogs.map((log) => {
                  const isSelected = selectedRowIds.has(log.id);
                  const isDetailOpen = selectedEntryId === log.id;
                  const sourceName = sourceMap.get(log.source_id) || log.source_id.slice(0, 8);

                  return (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedEntryId(log.id)}
                      className={`cursor-pointer transition-all ${
                        isDetailOpen
                          ? "bg-[var(--color-primary-500)]/10 text-[var(--color-text-primary)]"
                          : isSelected
                          ? "bg-[var(--color-primary-500)]/5"
                          : "hover:bg-[var(--color-surface-200)]/60 text-[var(--color-text-secondary)]"
                      }`}
                    >
                      <td className="p-3" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => toggleSelectRow(log.id)}
                          className="rounded border-[var(--color-border)] bg-[var(--color-surface-200)] text-[var(--color-primary-500)] focus:ring-0 cursor-pointer"
                        />
                      </td>

                      {columnVisibility.timestamp && (
                        <td className="p-3 whitespace-nowrap text-[11px] text-[var(--color-text-muted)]">
                          {new Date(log.event_timestamp).toLocaleString()}
                        </td>
                      )}

                      {columnVisibility.level && (
                        <td className="p-3 whitespace-nowrap">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold ${
                              LEVEL_STYLES[log.log_level] || LEVEL_STYLES.INFO
                            }`}
                          >
                            <span
                              className={`w-1.5 h-1.5 rounded-full ${
                                LEVEL_DOTS[log.log_level] || "bg-gray-400"
                              }`}
                            />
                            {log.log_level}
                          </span>
                        </td>
                      )}

                      {columnVisibility.source && (
                        <td className="p-3 whitespace-nowrap text-[var(--color-primary-500)] font-semibold">
                          {sourceName}
                        </td>
                      )}

                      {columnVisibility.event_type && (
                        <td className="p-3 whitespace-nowrap font-semibold text-[var(--color-text-primary)]">
                          {log.event_type}
                        </td>
                      )}

                      {columnVisibility.category && (
                        <td className="p-3 whitespace-nowrap text-[var(--color-text-muted)]">
                          {log.category || "—"}
                        </td>
                      )}

                      {columnVisibility.ips && (
                        <td className="p-3 whitespace-nowrap text-[11px] text-[var(--color-text-muted)]">
                          {log.source_ip || log.destination_ip ? (
                            <span>
                              {log.source_ip || "—"} → {log.destination_ip || "—"}
                            </span>
                          ) : (
                            "—"
                          )}
                        </td>
                      )}

                      {columnVisibility.username && (
                        <td className="p-3 whitespace-nowrap text-[var(--color-text-primary)]">
                          {log.username ? `@${log.username}` : "—"}
                        </td>
                      )}

                      {columnVisibility.event_id && (
                        <td className="p-3 whitespace-nowrap text-[11px] text-[var(--color-text-muted)]">
                          {log.event_id || "—"}
                        </td>
                      )}

                      {columnVisibility.asset_id && (
                        <td className="p-3 whitespace-nowrap text-[11px] text-[var(--color-text-muted)]">
                          {log.asset_id ? log.asset_id.slice(0, 8) : "—"}
                        </td>
                      )}

                      {columnVisibility.message && (
                        <td className="p-3 max-w-xs truncate font-sans text-xs text-[var(--color-text-secondary)]">
                          {log.message || "(No raw message payload)"}
                        </td>
                      )}

                      <td className="p-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEntryId(log.id);
                          }}
                          className="px-2 py-1 text-[11px] font-sans font-semibold rounded bg-[var(--color-surface-200)] hover:bg-[var(--color-surface-300)] text-[var(--color-primary-500)] border border-[var(--color-border)] transition-all"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Server-Side Pagination Footer ───────────────────────────────── */}
        {logsData && logsData.total > 0 && (
          <div className="p-3 bg-[var(--color-surface-200)]/80 border-t border-[var(--color-border)] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
            <div className="text-[var(--color-text-secondary)] font-mono">
              Showing{" "}
              <span className="font-bold text-[var(--color-text-primary)]">
                {(page - 1) * pageSize + 1}
              </span>{" "}
              to{" "}
              <span className="font-bold text-[var(--color-text-primary)]">
                {Math.min(page * pageSize, logsData.total)}
              </span>{" "}
              of{" "}
              <span className="font-bold text-[var(--color-text-primary)]">
                {logsData.total.toLocaleString()}
              </span>{" "}
              entries
            </div>

            <div className="flex items-center gap-1 font-mono">
              <button
                onClick={() => setPage(1)}
                disabled={page === 1}
                className="px-2 py-1 rounded bg-[var(--color-surface-100)] text-[var(--color-text-primary)] disabled:opacity-40 border border-[var(--color-border)] hover:bg-[var(--color-surface-300)] text-[11px]"
              >
                First
              </button>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-1 rounded bg-[var(--color-surface-100)] text-[var(--color-text-primary)] disabled:opacity-40 border border-[var(--color-border)] hover:bg-[var(--color-surface-300)]"
              >
                <ChevronLeftIcon className="w-4 h-4" />
              </button>

              <span className="px-3 py-1 font-bold text-[var(--color-primary-500)] text-xs">
                Page {page} of {totalPages}
              </span>

              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1 rounded bg-[var(--color-surface-100)] text-[var(--color-text-primary)] disabled:opacity-40 border border-[var(--color-border)] hover:bg-[var(--color-surface-300)]"
              >
                <ChevronRightIcon className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage(totalPages)}
                disabled={page >= totalPages}
                className="px-2 py-1 rounded bg-[var(--color-surface-100)] text-[var(--color-text-primary)] disabled:opacity-40 border border-[var(--color-border)] hover:bg-[var(--color-surface-300)] text-[11px]"
              >
                Last
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Log Detail Drawer / Slide-Over Inspector ───────────────────────── */}
      {selectedEntryId && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs animate-fade-in">
          {/* Backdrop click to close */}
          <div
            className="absolute inset-0"
            onClick={() => setSelectedEntryId(null)}
          />

          {/* Drawer Content */}
          <div className="relative w-full max-w-2xl bg-[var(--color-surface-100)] border-l border-[var(--color-border)] h-full flex flex-col shadow-2xl z-10 overflow-hidden">
            {/* Header */}
            <div className="p-4 bg-[var(--color-surface-200)] border-b border-[var(--color-border)] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[var(--color-primary-500)]/15 text-[var(--color-primary-500)] border border-[var(--color-primary-500)]/30">
                  <Bars3BottomLeftIcon className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-[var(--color-text-primary)]">
                    Log Entry Inspector
                  </h2>
                  <p className="text-[11px] font-mono text-[var(--color-text-muted)]">
                    ID: {selectedEntryId}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => copyToClipboard(selectedEntryId, "entry_id")}
                  className="p-1.5 rounded-lg text-xs bg-[var(--color-surface-300)] hover:bg-[var(--color-surface-400)] text-[var(--color-text-primary)] transition-all flex items-center gap-1"
                  title="Copy Log ID"
                >
                  {copiedId === "entry_id" ? (
                    <CheckIcon className="w-4 h-4 text-[var(--color-safe)]" />
                  ) : (
                    <ClipboardDocumentIcon className="w-4 h-4" />
                  )}
                </button>
                <button
                  onClick={() => setSelectedEntryId(null)}
                  className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-300)] transition-all"
                >
                  <XMarkIcon className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Body */}
            {isDetailLoading ? (
              <div className="flex-1 p-12 text-center space-y-3">
                <ArrowPathIcon className="w-8 h-8 text-[var(--color-primary-500)] animate-spin mx-auto" />
                <p className="text-xs font-mono text-[var(--color-text-muted)]">
                  Loading full raw event payload...
                </p>
              </div>
            ) : selectedLogDetail ? (
              <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs font-sans">
                {/* Status Badges Header */}
                <div className="flex flex-wrap items-center gap-2 pb-4 border-b border-[var(--color-border)]">
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-bold font-mono ${
                      LEVEL_STYLES[selectedLogDetail.log_level] || LEVEL_STYLES.INFO
                    }`}
                  >
                    {selectedLogDetail.log_level}
                  </span>
                  <span className="px-2.5 py-1 rounded text-xs font-semibold font-mono bg-[var(--color-surface-200)] text-[var(--color-primary-500)] border border-[var(--color-border)]">
                    {selectedLogDetail.event_type}
                  </span>
                  {selectedLogDetail.category && (
                    <span className="px-2.5 py-1 rounded text-xs font-mono bg-[var(--color-surface-200)] text-[var(--color-text-secondary)] border border-[var(--color-border)]">
                      {selectedLogDetail.category}
                    </span>
                  )}
                </div>

                {/* Main Message Block */}
                <div>
                  <label className="text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-muted)] mb-1.5 block">
                    Full Log Message
                  </label>
                  <div className="p-3 bg-[var(--color-surface-200)] rounded-xl border border-[var(--color-border)] font-mono text-xs text-[var(--color-text-primary)] leading-relaxed whitespace-pre-wrap break-all">
                    {selectedLogDetail.message || "(No parsed message content)"}
                  </div>
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="p-3 bg-[var(--color-surface-200)]/60 rounded-xl border border-[var(--color-border)] space-y-1">
                    <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] flex items-center gap-1">
                      <ClockIcon className="w-3.5 h-3.5" /> Event Timestamp
                    </span>
                    <p className="font-mono text-xs font-semibold text-[var(--color-text-primary)]">
                      {new Date(selectedLogDetail.event_timestamp).toUTCString()}
                    </p>
                  </div>

                  <div className="p-3 bg-[var(--color-surface-200)]/60 rounded-xl border border-[var(--color-border)] space-y-1">
                    <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] flex items-center gap-1">
                      <ServerIcon className="w-3.5 h-3.5" /> Log Source ID
                    </span>
                    <p className="font-mono text-xs text-[var(--color-primary-500)] truncate">
                      {sourceMap.get(selectedLogDetail.source_id) || selectedLogDetail.source_id}
                    </p>
                  </div>

                  <div className="p-3 bg-[var(--color-surface-200)]/60 rounded-xl border border-[var(--color-border)] space-y-1">
                    <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] flex items-center gap-1">
                      <UserIcon className="w-3.5 h-3.5" /> User Identity
                    </span>
                    <p className="font-mono text-xs text-[var(--color-text-primary)]">
                      {selectedLogDetail.username ? `@${selectedLogDetail.username}` : "—"}
                    </p>
                  </div>

                  <div className="p-3 bg-[var(--color-surface-200)]/60 rounded-xl border border-[var(--color-border)] space-y-1">
                    <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] flex items-center gap-1">
                      <ComputerDesktopIcon className="w-3.5 h-3.5" /> Process / Binary
                    </span>
                    <p className="font-mono text-xs text-[var(--color-text-primary)]">
                      {selectedLogDetail.process_name || "—"}
                    </p>
                  </div>

                  <div className="p-3 bg-[var(--color-surface-200)]/60 rounded-xl border border-[var(--color-border)] space-y-1">
                    <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] flex items-center gap-1">
                      <TagIcon className="w-3.5 h-3.5" /> Source IP
                    </span>
                    <p className="font-mono text-xs text-[var(--color-text-primary)]">
                      {selectedLogDetail.source_ip || "—"}
                    </p>
                  </div>

                  <div className="p-3 bg-[var(--color-surface-200)]/60 rounded-xl border border-[var(--color-border)] space-y-1">
                    <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] flex items-center gap-1">
                      <TagIcon className="w-3.5 h-3.5" /> Destination IP
                    </span>
                    <p className="font-mono text-xs text-[var(--color-text-primary)]">
                      {selectedLogDetail.destination_ip || "—"}
                    </p>
                  </div>

                  <div className="p-3 bg-[var(--color-surface-200)]/60 rounded-xl border border-[var(--color-border)] space-y-1">
                    <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] flex items-center gap-1">
                      <KeyIcon className="w-3.5 h-3.5" /> Correlation ID
                    </span>
                    <p className="font-mono text-[11px] text-[var(--color-text-secondary)] truncate">
                      {selectedLogDetail.correlation_id || "—"}
                    </p>
                  </div>

                  <div className="p-3 bg-[var(--color-surface-200)]/60 rounded-xl border border-[var(--color-border)] space-y-1">
                    <span className="text-[10px] font-bold uppercase text-[var(--color-text-muted)] flex items-center gap-1">
                      <AdjustmentsHorizontalIcon className="w-3.5 h-3.5" /> Event ID
                    </span>
                    <p className="font-mono text-xs text-[var(--color-text-primary)]">
                      {selectedLogDetail.event_id || "—"}
                    </p>
                  </div>
                </div>

                {/* Formatted JSON Payload Inspector */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-muted)]">
                      Raw JSON Envelope (`raw_log`)
                    </label>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          JSON.stringify(selectedLogDetail.raw_log, null, 2),
                          "raw_json"
                        )
                      }
                      className="text-[11px] font-semibold text-[var(--color-primary-500)] hover:underline flex items-center gap-1"
                    >
                      {copiedId === "raw_json" ? (
                        <>
                          <CheckIcon className="w-3.5 h-3.5 text-[var(--color-safe)]" /> Copied
                        </>
                      ) : (
                        <>
                          <ClipboardDocumentIcon className="w-3.5 h-3.5" /> Copy JSON
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-4 bg-[var(--color-surface-200)] rounded-xl border border-[var(--color-border)] font-mono text-[11px] text-[var(--color-primary-500)] overflow-x-auto max-h-80 select-text">
                    {JSON.stringify(selectedLogDetail.raw_log, null, 2)}
                  </pre>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
