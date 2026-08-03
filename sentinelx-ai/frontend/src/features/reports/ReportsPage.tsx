import { useState } from "react";
import { DocumentArrowDownIcon, SparklesIcon } from "@heroicons/react/24/outline";
import { mockReports } from "../../utils/mockData";

export default function ReportsPage() {
  const [downloadNotification, setDownloadNotification] = useState<string | null>(null);

  const handleDownload = (title: string) => {
    setDownloadNotification(`Preparing download for "${title}"...`);
    setTimeout(() => {
      setDownloadNotification(null);
    }, 3000);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Compliance & Executive Reports</h1>
          <p className="text-xs text-[var(--color-text-secondary)]">Automated report generation for SOC 2 Type II, ISO 27001, and CISO Executive briefings</p>
        </div>
        <button className="px-4 py-2 rounded-lg bg-[var(--color-primary-500)] text-[var(--color-surface-0)] text-xs font-bold shadow-lg shadow-[var(--color-primary-500)]/20 hover:opacity-90 flex items-center gap-2">
          <SparklesIcon className="w-4 h-4" />
          <span>Generate New Report</span>
        </button>
      </div>

      {/* Download Alert Toast */}
      {downloadNotification && (
        <div className="p-3 rounded-lg bg-[var(--color-primary-500)]/15 border border-[var(--color-primary-500)]/40 text-[var(--color-primary-500)] text-xs font-bold font-mono animate-fade-in flex items-center justify-between">
          <span>{downloadNotification}</span>
          <span className="text-[10px] animate-pulse">EXPORTING...</span>
        </div>
      )}

      {/* Report Template Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {mockReports.map((report) => (
          <div key={report.id} className="glass rounded-xl p-5 border border-[var(--color-border)] flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between text-[10px] font-mono text-[var(--color-text-muted)] mb-2">
                <span>{report.id}</span>
                <span className="px-2 py-0.5 rounded bg-[var(--color-surface-300)] text-[var(--color-primary-500)] font-bold">{report.format}</span>
              </div>
              <h2 className="text-xs font-bold text-[var(--color-text-primary)] leading-snug">{report.title}</h2>
              <p className="text-[10px] text-[var(--color-text-muted)] mt-1 font-semibold">{report.type}</p>
            </div>

            <div className="pt-3 border-t border-[var(--color-border)] flex items-center justify-between text-xs">
              <span className="text-[10px] text-[var(--color-text-muted)] font-mono">{report.size}</span>
              <button
                onClick={() => handleDownload(report.title)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--color-surface-200)] hover:bg-[var(--color-primary-500)] hover:text-[var(--color-surface-0)] text-[11px] font-bold transition-all text-[var(--color-text-primary)]"
              >
                <DocumentArrowDownIcon className="w-4 h-4" />
                <span>Export</span>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Report History Table */}
      <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4">
        <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Report Export History</h2>
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider">
              <th className="pb-3">Report Title</th>
              <th className="pb-3">Type</th>
              <th className="pb-3">Generated Date</th>
              <th className="pb-3">Author</th>
              <th className="pb-3 text-right">Download</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
            {mockReports.map((r) => (
              <tr key={r.id} className="hover:bg-[var(--color-surface-200)]/50 transition-colors">
                <td className="py-3 font-semibold text-[var(--color-text-primary)]">{r.title}</td>
                <td className="py-3 text-[11px]">{r.type}</td>
                <td className="py-3 font-mono text-[11px] text-[var(--color-text-muted)]">{r.generatedDate}</td>
                <td className="py-3 text-[11px] font-bold text-[var(--color-secondary-500)]">{r.author}</td>
                <td className="py-3 text-right">
                  <button
                    onClick={() => handleDownload(r.title)}
                    className="px-2.5 py-1 text-[10px] font-bold rounded bg-[var(--color-surface-300)] text-[var(--color-text-primary)] hover:bg-[var(--color-primary-500)] hover:text-black"
                  >
                    Download ({r.format})
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
