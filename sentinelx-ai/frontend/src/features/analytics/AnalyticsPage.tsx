import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
} from "recharts";

export default function AnalyticsPage() {
  const trendData = [
    { day: "Mon", threats: 42, mttrMinutes: 24, incidents: 8 },
    { day: "Tue", threats: 65, mttrMinutes: 18, incidents: 12 },
    { day: "Wed", threats: 38, mttrMinutes: 15, incidents: 6 },
    { day: "Thu", threats: 89, mttrMinutes: 22, incidents: 14 },
    { day: "Fri", threats: 54, mttrMinutes: 14, incidents: 9 },
    { day: "Sat", threats: 28, mttrMinutes: 10, incidents: 3 },
    { day: "Sun", threats: 31, mttrMinutes: 12, incidents: 4 },
  ];

  const attackVectors = [
    { vector: "SSH Brute Force", count: 1420 },
    { vector: "Web Application SQLi", count: 850 },
    { vector: "Phishing Links", count: 640 },
    { vector: "DNS Tunneling", count: 310 },
    { vector: "Ransomware Canary", count: 85 },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Security Analytics & Performance KPIs</h1>
        <p className="text-xs text-[var(--color-text-secondary)]">Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), and attack vector analytics</p>
      </div>

      {/* KPI Highlights */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Average MTTD", value: "2.4 mins", sub: "-18% vs last week" },
          { label: "Average MTTR", value: "14.2 mins", sub: "-32% with SOAR playbooks" },
          { label: "False Positive Rate", value: "4.1%", sub: "AI filter accuracy" },
          { label: "SOC Automation Rate", value: "76%", sub: "Playbook auto-mitigation" },
        ].map((item) => (
          <div key={item.label} className="glass rounded-xl p-4 border border-[var(--color-border)]">
            <p className="text-[10px] uppercase font-bold text-[var(--color-text-muted)]">{item.label}</p>
            <p className="text-2xl font-mono font-bold text-[var(--color-primary-500)] mt-1">{item.value}</p>
            <p className="text-[10px] text-[var(--color-safe)] mt-0.5">{item.sub}</p>
          </div>
        ))}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Weekly Threat vs MTTR Trend */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Weekly Threat Volume vs MTTR</h2>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1c2638" />
                <XAxis dataKey="day" stroke="#546b8a" tick={{ fontSize: 11 }} />
                <YAxis stroke="#546b8a" tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ backgroundColor: "#0f1520", borderColor: "#1c2638", borderRadius: "8px", fontSize: "12px" }} />
                <Line type="monotone" dataKey="threats" stroke="#ff1744" strokeWidth={2} name="Threats Count" />
                <Line type="monotone" dataKey="mttrMinutes" stroke="#00e5ff" strokeWidth={2} name="MTTR (Mins)" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Vector Frequency */}
        <div className="glass rounded-xl p-5 border border-[var(--color-border)] space-y-4">
          <h2 className="text-sm font-bold text-[var(--color-text-primary)]">Top Attack Vector Frequency</h2>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attackVectors} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1c2638" />
                <XAxis type="number" stroke="#546b8a" tick={{ fontSize: 11 }} />
                <YAxis dataKey="vector" type="category" stroke="#546b8a" tick={{ fontSize: 10 }} width={130} />
                <Tooltip contentStyle={{ backgroundColor: "#0f1520", borderColor: "#1c2638", borderRadius: "8px", fontSize: "12px" }} />
                <Bar dataKey="count" fill="#7c4dff" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
