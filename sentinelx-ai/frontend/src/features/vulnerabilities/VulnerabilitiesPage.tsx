import { useQuery } from "@tanstack/react-query";
import { BugAntIcon, ShieldExclamationIcon, WrenchScrewdriverIcon, CheckCircleIcon } from "@heroicons/react/24/outline";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { fetchDashboardSummary } from "../../services/dashboardService";
import { mockCves } from "../../utils/mockData";

export default function VulnerabilitiesPage() {
  const { data: summaryData } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: fetchDashboardSummary,
    refetchInterval: 30000,
  });

  const totalVulnerabilities = summaryData?.vulnerability_count ?? 0;

  const cvssBreakdown = [
    { name: "Critical (9.0-10.0)", value: 0, color: "#ff1744" },
    { name: "High (7.0-8.9)", value: 0, color: "#ff6d00" },
    { name: "Medium (4.0-6.9)", value: 0, color: "#ffd600" },
    { name: "Low (0.1-3.9)", value: 0, color: "#448aff" },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Vulnerability Management & CVE Exposure</h1>
          <p className="text-xs text-[var(--color-text-secondary)]">CVSS scoring, patch prioritization, and automated vulnerability tracking</p>
        </div>
        <button className="px-4 py-2 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold shadow-lg shadow-[var(--color-primary-500)]/20 hover:opacity-90">
          Trigger Vulnerability Scan
        </button>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Vulnerabilities", value: totalVulnerabilities, icon: BugAntIcon, color: "var(--color-primary-500)" },
          { label: "Critical CVEs", value: 0, icon: ShieldExclamationIcon, color: "var(--color-critical)" },
          { label: "Pending Patch", value: 0, icon: WrenchScrewdriverIcon, color: "var(--color-high)" },
          { label: "Patched (30 Days)", value: 0, icon: CheckCircleIcon, color: "var(--color-safe)" },
        ].map((kpi) => (
          <div key={kpi.label} className="glass rounded-xl p-4 border border-[var(--color-border)] flex items-center justify-between">
            <div>
              <p className="text-[10px] text-[var(--color-text-muted)] uppercase font-bold">{kpi.label}</p>
              <p className="text-2xl font-mono font-bold text-[var(--color-text-primary)] mt-1">{kpi.value}</p>
            </div>
            <kpi.icon className="w-6 h-6" style={{ color: kpi.color }} />
          </div>
        ))}
      </div>

      {/* CVSS Distribution & Risk Chart */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold text-[var(--color-text-primary)]">CVSS Score Distribution</h2>
            <p className="text-[11px] text-[var(--color-text-muted)]">Severity score breakdown across infrastructure</p>
          </div>
          <div className="h-48 w-full my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={cvssBreakdown} innerRadius={45} outerRadius={70} paddingAngle={4} dataKey="value">
                  {cvssBreakdown.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: "#0f1520", borderColor: "#1c2638", borderRadius: "8px", fontSize: "11px" }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-1">
            {cvssBreakdown.map((item) => (
              <div key={item.name} className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  <span>{item.name}</span>
                </div>
                <span className="font-mono font-bold text-[var(--color-text-primary)]">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability List Table */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] md:col-span-2 space-y-4">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Top Critical Vulnerabilities</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider">
                  <th className="pb-3">CVE ID</th>
                  <th className="pb-3">Vulnerability Title</th>
                  <th className="pb-3">CVSS</th>
                  <th className="pb-3">Affected</th>
                  <th className="pb-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
                {mockCves.map((cve) => (
                  <tr key={cve.id} className="hover:bg-[var(--color-surface-200)]/50 transition-colors">
                    <td className="py-3 font-mono font-bold text-[var(--color-critical)]">{cve.cveId}</td>
                    <td className="py-3 font-semibold text-[var(--color-text-primary)]">{cve.title}</td>
                    <td className="py-3 font-mono font-extrabold text-[var(--color-critical)]">{cve.cvssScore}</td>
                    <td className="py-3 font-mono text-center">{cve.affectedCount}</td>
                    <td className="py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--color-surface-300)] text-[var(--color-text-primary)]">
                        {cve.patchStatus}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
