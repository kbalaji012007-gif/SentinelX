import { NavLink } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldCheckIcon,
  HomeIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ServerIcon,
  DocumentTextIcon,
  CpuChipIcon,
  LinkIcon,
  BugAntIcon,
  ChartBarIcon,
  DocumentChartBarIcon,
  SparklesIcon,
  UsersIcon,
  Cog6ToothIcon,
} from "@heroicons/react/24/outline";

import { fetchThreats } from "../../services/threatService";
import { fetchIncidents } from "../../services/incidentService";
import { fetchDashboardSummary } from "../../services/dashboardService";
import { fetchLogEntries } from "../../services/logService";

export default function Sidebar() {
  // Query live threat count
  const { data: threatsData } = useQuery({
    queryKey: ["threats", { page: 1, page_size: 1 }],
    queryFn: () => fetchThreats({ page: 1, page_size: 1 }),
    refetchInterval: 30000,
  });

  // Query live incident count
  const { data: incidentsData } = useQuery({
    queryKey: ["incidents", { page: 1, page_size: 1 }],
    queryFn: () => fetchIncidents({ page: 1, page_size: 1 }),
    refetchInterval: 30000,
  });

  // Query dashboard summary for assets & vulnerabilities count
  const { data: summaryData } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: fetchDashboardSummary,
    refetchInterval: 30000,
  });

  // Query live log entries count
  const { data: logsData } = useQuery({
    queryKey: ["logs", { page: 1, page_size: 1 }],
    queryFn: () => fetchLogEntries({ page_size: 1 }),
    refetchInterval: 30000,
  });

  const threatsCount = threatsData?.total ?? 0;
  const incidentsCount = incidentsData?.total ?? 0;
  const vulnerabilitiesCount = summaryData?.vulnerability_count ?? 0;
  const assetsCount = summaryData?.asset_count ?? 0;
  const logsCount = logsData?.total ?? 0;

  const navigation = [
    { name: "Dashboard", href: "/", icon: HomeIcon },
    { name: "Threats", href: "/threats", icon: ExclamationTriangleIcon, badge: threatsCount },
    { name: "Incidents", href: "/incidents", icon: ShieldExclamationIcon, badge: incidentsCount },
    { name: "Assets", href: "/assets", icon: ServerIcon, badge: assetsCount },
    { name: "Logs", href: "/logs", icon: DocumentTextIcon, badge: logsCount },
    { name: "Threat Intelligence", href: "/intelligence", icon: CpuChipIcon },
    { name: "Threat Correlation", href: "/correlation", icon: LinkIcon },
    { name: "Vulnerabilities", href: "/vulnerabilities", icon: BugAntIcon, badge: vulnerabilitiesCount },
    { name: "Analytics", href: "/analytics", icon: ChartBarIcon },
    { name: "Reports", href: "/reports", icon: DocumentChartBarIcon },
    { name: "AI Assistant", href: "/ai-assistant", icon: SparklesIcon, highlight: true },
    { name: "Users", href: "/users", icon: UsersIcon },
    { name: "Settings", href: "/settings", icon: Cog6ToothIcon },
  ];

  return (
    <aside className="w-64 bg-[var(--color-surface-100)] border-r border-[var(--color-border)] flex flex-col h-screen sticky top-0 z-30 select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-[var(--color-border)] flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[var(--color-primary-500)]/20 to-[var(--color-secondary-500)]/20 border border-[var(--color-primary-500)]/30 flex items-center justify-center shadow-[0_0_15px_rgba(0,229,255,0.15)]">
          <ShieldCheckIcon className="w-6 h-6 text-[var(--color-primary-500)]" />
        </div>
        <div>
          <h1 className="text-base font-bold tracking-tight text-[var(--color-text-primary)]">
            SentinelX AI
          </h1>
          <p className="text-[10px] font-semibold text-[var(--color-primary-500)] uppercase tracking-widest">
            Autonomous SOC
          </p>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-1">
        <p className="px-3 text-[10px] text-[var(--color-text-muted)] font-bold uppercase tracking-widest mb-2 mt-1">
          Command Center
        </p>
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            end={item.href === "/"}
            className={({ isActive }) =>
              `flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-150 ${
                isActive
                  ? "bg-gradient-to-r from-[var(--color-primary-500)]/15 to-transparent text-[var(--color-primary-500)] font-semibold border-l-2 border-[var(--color-primary-500)] shadow-[0_0_12px_rgba(0,229,255,0.1)]"
                  : item.highlight
                  ? "text-[var(--color-secondary-500)] hover:bg-[var(--color-secondary-500)]/10"
                  : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-200)] hover:text-[var(--color-text-primary)]"
              }`
            }
          >
            <div className="flex items-center gap-3">
              <item.icon className={`w-4 h-4 shrink-0 ${item.highlight ? "text-[var(--color-secondary-500)] animate-pulse" : ""}`} />
              <span>{item.name}</span>
            </div>

            {item.badge !== undefined && (
              <span
                className={`px-2 py-0.5 text-[10px] font-bold rounded-full font-mono ${
                  item.name === "Threats" && Number(item.badge) > 0
                    ? "bg-[var(--color-critical)]/20 text-[var(--color-critical)] border border-[var(--color-critical)]/30"
                    : item.name === "Incidents" && Number(item.badge) > 0
                    ? "bg-[var(--color-high)]/20 text-[var(--color-high)] border border-[var(--color-high)]/30"
                    : item.name === "Logs" && Number(item.badge) > 0
                    ? "bg-[var(--color-primary-500)]/20 text-[var(--color-primary-500)] border border-[var(--color-primary-500)]/30"
                    : "bg-[var(--color-surface-300)] text-[var(--color-text-muted)]"
                }`}
              >
                {item.badge}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer Status */}
      <div className="p-4 border-t border-[var(--color-border)] bg-[var(--color-surface-50)]/50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[var(--color-safe)] animate-pulse" />
            <span className="text-[11px] font-medium text-[var(--color-text-secondary)]">SOC Active</span>
          </div>
          <span className="text-[10px] font-mono text-[var(--color-text-muted)]">v2.0-PRO</span>
        </div>
      </div>
    </aside>
  );
}
