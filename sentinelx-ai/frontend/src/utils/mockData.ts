/**
 * SentinelX AI – Data Models & Report/CVE Mock Schemas
 */

export interface ThreatMock {
  id: string;
  name: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  category: string;
  sourceIp: string;
  targetAsset: string;
  mitreId: string;
  status: "Active" | "Investigating" | "Mitigated" | "False Positive";
  detectedAt: string;
  score: number;
}

export interface IncidentMock {
  id: string;
  title: string;
  priority: "P0 - Critical" | "P1 - High" | "P2 - Medium" | "P3 - Low";
  status: "New" | "In Progress" | "Pending Action" | "Resolved";
  assignee: string;
  affectedAsset: string;
  slaMinutesRemaining: number;
  createdAt: string;
  description: string;
  timeline: { time: string; event: string; author: string }[];
}

export interface AssetMock {
  id: string;
  hostname: string;
  assetName: string;
  assetType: "Server" | "Workstation" | "Cloud Resource" | "Router" | "Switch" | "Firewall";
  operatingSystem: string;
  ipAddress: string;
  macAddress: string;
  department: string;
  criticality: "Critical" | "High" | "Medium" | "Low";
  status: "Active" | "Inactive" | "Maintenance";
  lastSeen: string;
}

export interface LogMock {
  id: string;
  timestamp: string;
  level: "INFO" | "WARN" | "ERROR" | "CRITICAL";
  source: string;
  eventCode: string;
  message: string;
  rawJson: string;
}

export interface IocMock {
  id: string;
  type: "IP" | "Domain" | "Hash" | "URL";
  value: string;
  threatActor: string;
  confidence: number;
  firstSeen: string;
  tags: string[];
}

export interface CveMock {
  id: string;
  cveId: string;
  title: string;
  cvssScore: number;
  severity: "Critical" | "High" | "Medium" | "Low";
  patchStatus: "Patched" | "Pending Patch" | "Workaround Applied" | "Unpatched";
  affectedCount: number;
  publishedDate: string;
}

export interface ReportMock {
  id: string;
  title: string;
  type: "Executive Summary" | "Compliance (SOC 2)" | "Incident Post-Mortem" | "Vulnerability Assessment";
  generatedDate: string;
  format: "PDF" | "CSV" | "JSON";
  size: string;
  author: string;
}

export interface UserMock {
  id: string;
  name: string;
  email: string;
  role: "Super Administrator" | "Admin" | "Senior SOC Analyst" | "SOC Manager" | "Incident Responder" | "Auditor";
  department: string;
  status: "Active" | "Inactive";
  mfaEnabled: boolean;
  lastLogin: string;
}

// ── Production Real-Time Mode (Mock datasets purged) ──────────────────────────

export const mockThreats: ThreatMock[] = [];
export const mockIncidents: IncidentMock[] = [];
export const mockAssets: AssetMock[] = [];
export const mockLogs: LogMock[] = [];
export const mockIocs: IocMock[] = [];
export const mockUsers: UserMock[] = [];
export const mockTopAttackerIps: { ip: string; country: string; attempts: number; threatScore: number }[] = [];

// Static templates for CVEs & Reports (used by respective preview screens)
export const mockCves: CveMock[] = [
  {
    id: "CVE-2026-2144",
    cveId: "CVE-2026-2144",
    title: "OpenSSH Remote Pre-Auth Code Execution Vulnerability",
    cvssScore: 9.8,
    severity: "Critical",
    patchStatus: "Pending Patch",
    affectedCount: 14,
    publishedDate: "2026-07-15",
  },
  {
    id: "CVE-2026-3021",
    cveId: "CVE-2026-3021",
    title: "PostgreSQL Asyncpg Privilege Escalation in Authentication Handshake",
    cvssScore: 8.8,
    severity: "High",
    patchStatus: "Patched",
    affectedCount: 3,
    publishedDate: "2026-07-20",
  },
  {
    id: "CVE-2026-1189",
    cveId: "CVE-2026-1189",
    title: "Linux Kernel eBPF Subsystem Integer Overflow",
    cvssScore: 7.5,
    severity: "High",
    patchStatus: "Workaround Applied",
    affectedCount: 22,
    publishedDate: "2026-06-28",
  },
  {
    id: "CVE-2026-0944",
    cveId: "CVE-2026-0944",
    title: "Nginx HTTP/3 QUIC Buffer Overread Denial of Service",
    cvssScore: 6.5,
    severity: "Medium",
    patchStatus: "Patched",
    affectedCount: 8,
    publishedDate: "2026-06-11",
  },
];

export const mockReports: ReportMock[] = [
  {
    id: "REP-101",
    title: "SOC 2 Type II Annual Security Audit Report",
    type: "Compliance (SOC 2)",
    generatedDate: "2026-08-01",
    format: "PDF",
    size: "4.2 MB",
    author: "Automated Compliance Engine",
  },
  {
    id: "REP-102",
    title: "Monthly Executive Cyber Risk & Threat Summary",
    type: "Executive Summary",
    generatedDate: "2026-08-01",
    format: "PDF",
    size: "2.8 MB",
    author: "SentinelX AI",
  },
  {
    id: "REP-103",
    title: "Incident Post-Mortem & Remediation Summary",
    type: "Incident Post-Mortem",
    generatedDate: "2026-08-03",
    format: "PDF",
    size: "1.1 MB",
    author: "Incident Response Lead",
  },
  {
    id: "REP-104",
    title: "Q3 Vulnerability Exposure & Patch Prioritization Assessment",
    type: "Vulnerability Assessment",
    generatedDate: "2026-07-25",
    format: "CSV",
    size: "850 KB",
    author: "Security Architecture Team",
  },
];
