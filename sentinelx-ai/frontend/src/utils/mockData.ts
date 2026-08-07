/**
 * SentinelX AI – Realistic SOC Mock Data
 * Complete mock data suite for prototype pages.
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

// ── Mock Datasets ──────────────────────────────────────────

export const mockThreats: ThreatMock[] = [
  {
    id: "THR-9021",
    name: "Brute Force SSH Attack Flooding",
    severity: "Critical",
    category: "Credential Access",
    sourceIp: "185.220.101.5",
    targetAsset: "prod-db-master-01.sentinelx.internal",
    mitreId: "T1110.001",
    status: "Active",
    detectedAt: "2 minutes ago",
    score: 94,
  },
  {
    id: "THR-9020",
    name: "Possible Cobalt Strike C2 Beaconing",
    severity: "Critical",
    category: "Command and Control",
    sourceIp: "194.26.29.112",
    targetAsset: "corp-wkstn-882.sentinelx.internal",
    mitreId: "T1071.001",
    status: "Investigating",
    detectedAt: "14 minutes ago",
    score: 98,
  },
  {
    id: "THR-9019",
    name: "Anomalous Outbound Data Transfer",
    severity: "High",
    category: "Exfiltration",
    sourceIp: "10.0.4.155",
    targetAsset: "cloud-s3-analytics-bucket",
    mitreId: "T1048",
    status: "Active",
    detectedAt: "32 minutes ago",
    score: 85,
  },
  {
    id: "THR-9018",
    name: "Suspicious PowerShell Execution (Encoded Command)",
    severity: "High",
    category: "Execution",
    sourceIp: "10.0.2.44",
    targetAsset: "fin-ad-controller-01.sentinelx.internal",
    mitreId: "T1059.001",
    status: "Mitigated",
    detectedAt: "1 hour ago",
    score: 79,
  },
  {
    id: "THR-9017",
    name: "LSASS Memory Dump Attempt",
    severity: "High",
    category: "Credential Access",
    sourceIp: "10.0.3.91",
    targetAsset: "hr-payroll-server.sentinelx.internal",
    mitreId: "T1003.001",
    status: "Investigating",
    detectedAt: "2 hours ago",
    score: 88,
  },
  {
    id: "THR-9016",
    name: "Port Scanning Activity Detected",
    severity: "Medium",
    category: "Reconnaissance",
    sourceIp: "45.142.214.20",
    targetAsset: "edge-fw-external-01",
    mitreId: "T1595.001",
    status: "Mitigated",
    detectedAt: "3 hours ago",
    score: 62,
  },
  {
    id: "THR-9015",
    name: "Spear Phishing Link Clicked",
    severity: "Medium",
    category: "Initial Access",
    sourceIp: "10.0.12.33",
    targetAsset: "dev-laptop-jdoe.sentinelx.internal",
    mitreId: "T1566.002",
    status: "False Positive",
    detectedAt: "5 hours ago",
    score: 45,
  },
];

export const mockIncidents: IncidentMock[] = [
  {
    id: "INC-4081",
    title: "Unauthorized Root Access Attempt on Production Database",
    priority: "P0 - Critical",
    status: "In Progress",
    assignee: "Alex Rivera (Lead Analyst)",
    affectedAsset: "prod-db-master-01",
    slaMinutesRemaining: 18,
    createdAt: "2026-08-03T14:30:00Z",
    description: "Multiple failed SSH root logins followed by an elevated privilege shell session from an external IP.",
    timeline: [
      { time: "14:30:05", event: "Automated alert generated: High velocity login failure", author: "Detection Engine" },
      { time: "14:32:10", event: "Incident created and assigned to Alex Rivera", author: "SOAR Dispatch" },
      { time: "14:35:44", event: "Host network isolated via Automated Response Playbook", author: "Alex Rivera" },
    ],
  },
  {
    id: "INC-4080",
    title: "Potential Ransomware Canary File Access Triggered",
    priority: "P0 - Critical",
    status: "New",
    assignee: "Unassigned",
    affectedAsset: "corp-fs-shares-02",
    slaMinutesRemaining: 5,
    createdAt: "2026-08-03T15:10:00Z",
    description: "Decoy honeyfile modified in public file share. Rapid encryption activity suspected.",
    timeline: [
      { time: "15:10:01", event: "Canary file trigger: C:\\Shares\\Finance\\Budget_2026.docx.crypto", author: "Canary Sensor" },
    ],
  },
  {
    id: "INC-4079",
    title: "Suspicious OAuth App Authorization in Microsoft 365",
    priority: "P1 - High",
    status: "Pending Action",
    assignee: "Elena Rostova",
    affectedAsset: "m365-tenant-primary",
    slaMinutesRemaining: 120,
    createdAt: "2026-08-03T12:00:00Z",
    description: "Third-party application requested Mail.ReadWrite and Contacts.Read full domain permissions.",
    timeline: [
      { time: "12:00:00", event: "OAuth Audit Log alert triggered", author: "Cloud Monitor" },
      { time: "12:15:30", event: "User confirmation requested regarding consent prompt", author: "Elena Rostova" },
    ],
  },
  {
    id: "INC-4078",
    title: "Malicious Attachment Execution - Emotet Variant",
    priority: "P2 - Medium",
    status: "Resolved",
    assignee: "Marcus Vance",
    affectedAsset: "sales-laptop-402",
    slaMinutesRemaining: 0,
    createdAt: "2026-08-03T09:15:00Z",
    description: "Phishing email contained weaponized macro document. AV blocked payload execution.",
    timeline: [
      { time: "09:15:00", event: "EDR telemetry captured payload kill", author: "CrowdStrike Connector" },
      { time: "09:45:00", event: "Host scanned, artifact purged, incident closed", author: "Marcus Vance" },
    ],
  },
];

export const mockAssets: AssetMock[] = [
  {
    id: "AST-1001",
    hostname: "prod-db-master-01.sentinelx.internal",
    assetName: "Production Primary PostgreSQL Cluster",
    assetType: "Server",
    operatingSystem: "Ubuntu 24.04 LTS",
    ipAddress: "10.0.1.10",
    macAddress: "00:50:56:9A:12:34",
    department: "Data Engineering",
    criticality: "Critical",
    status: "Active",
    lastSeen: "Just now",
  },
  {
    id: "AST-1002",
    hostname: "fin-ad-controller-01.sentinelx.internal",
    assetName: "Active Directory Domain Controller 01",
    assetType: "Server",
    operatingSystem: "Windows Server 2025",
    ipAddress: "10.0.1.5",
    macAddress: "00:50:56:9A:56:78",
    department: "IT Infrastructure",
    criticality: "Critical",
    status: "Active",
    lastSeen: "1 minute ago",
  },
  {
    id: "AST-1003",
    hostname: "edge-fw-external-01.sentinelx.internal",
    assetName: "Perimeter Next-Gen Firewall",
    assetType: "Firewall",
    operatingSystem: "Palo Alto PAN-OS 11.1",
    ipAddress: "198.51.100.1",
    macAddress: "00:1B:17:00:11:22",
    department: "Network Security",
    criticality: "Critical",
    status: "Active",
    lastSeen: "Just now",
  },
  {
    id: "AST-1004",
    hostname: "cloud-k8s-ingress-01.sentinelx.internal",
    assetName: "Kubernetes Ingress Gateway Node",
    assetType: "Cloud Resource",
    operatingSystem: "Flatcar Container Linux",
    ipAddress: "10.0.4.50",
    macAddress: "02:42:AC:11:00:02",
    department: "DevOps",
    criticality: "High",
    status: "Active",
    lastSeen: "2 minutes ago",
  },
  {
    id: "AST-1005",
    hostname: "corp-wkstn-882.sentinelx.internal",
    assetName: "Executive Assistant Workstation",
    assetType: "Workstation",
    operatingSystem: "Windows 11 Pro 24H2",
    ipAddress: "10.0.2.140",
    macAddress: "A4:83:E7:88:99:AA",
    department: "Executive Office",
    criticality: "Medium",
    status: "Active",
    lastSeen: "5 minutes ago",
  },
  {
    id: "AST-1006",
    hostname: "core-switch-floor3.sentinelx.internal",
    assetName: "Building 3 Floor 2 Core Switch",
    assetType: "Switch",
    operatingSystem: "Cisco NX-OS 10.4",
    ipAddress: "10.0.0.254",
    macAddress: "00:00:0C:07:AC:01",
    department: "IT Infrastructure",
    criticality: "High",
    status: "Maintenance",
    lastSeen: "12 minutes ago",
  },
];

export const mockLogs: LogMock[] = [
  {
    id: "LOG-99401",
    timestamp: "2026-08-03 16:04:12.883",
    level: "CRITICAL",
    source: "sshd",
    eventCode: "AUTH_FAIL_EXCEEDED",
    message: "Failed password for root from 185.220.101.5 port 54812 ssh2 (Attempt 52/100)",
    rawJson: JSON.stringify({ src_ip: "185.220.101.5", user: "root", port: 54812, method: "password" }, null, 2),
  },
  {
    id: "LOG-99402",
    timestamp: "2026-08-03 16:04:10.120",
    level: "ERROR",
    source: "CrowdStrike-Falcon",
    eventCode: "SUSPICIOUS_PROCESS",
    message: "Process C:\\Windows\\System32\\cmd.exe spawned powershell -EncodedCommand JABzAD0...",
    rawJson: JSON.stringify({ pid: 4821, ppid: 1042, cmdline: "powershell -enc ...", user: "SYSTEM" }, null, 2),
  },
  {
    id: "LOG-99403",
    timestamp: "2026-08-03 16:03:55.401",
    level: "WARN",
    source: "PaloAlto-FW",
    eventCode: "TRAFFIC_DENY",
    message: "Denied TCP traffic from 45.142.214.20:44301 to 10.0.1.10:22 (Rule: Default-Deny-External)",
    rawJson: JSON.stringify({ src: "45.142.214.20", dst: "10.0.1.10", proto: "TCP", dport: 22, action: "deny" }, null, 2),
  },
  {
    id: "LOG-99404",
    timestamp: "2026-08-03 16:03:42.009",
    level: "INFO",
    source: "SupabaseAuth",
    eventCode: "TOKEN_REFRESH",
    message: "User session refreshed token successfully for user_id=e48a-1294-bf01",
    rawJson: JSON.stringify({ user_id: "e48a-1294-bf01", client_ip: "10.0.12.33" }, null, 2),
  },
  {
    id: "LOG-99405",
    timestamp: "2026-08-03 16:03:30.550",
    level: "INFO",
    source: "NginxIngress",
    eventCode: "HTTP_200",
    message: 'GET /api/v1/health HTTP/1.1 200 48 "-" "Mozilla/5.0"',
    rawJson: JSON.stringify({ status: 200, bytes: 48, duration_ms: 1.2 }, null, 2),
  },
];

export const mockIocs: IocMock[] = [
  {
    id: "IOC-101",
    type: "IP",
    value: "185.220.101.5",
    threatActor: "APT29 (Cozy Bear)",
    confidence: 96,
    firstSeen: "2026-07-28",
    tags: ["Tor Exit Node", "Brute Force", "Active C2"],
  },
  {
    id: "IOC-102",
    type: "Hash",
    value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    threatActor: "Lazarus Group",
    confidence: 99,
    firstSeen: "2026-08-01",
    tags: ["Ransomware", "Wiper", "Executable"],
  },
  {
    id: "IOC-103",
    type: "Domain",
    value: "update-security-verify-auth.com",
    threatActor: "TA505",
    confidence: 88,
    firstSeen: "2026-08-02",
    tags: ["Phishing", "Credential Harvesting"],
  },
  {
    id: "IOC-104",
    type: "URL",
    value: "https://update-security-verify-auth.com/login/verify.php",
    threatActor: "TA505",
    confidence: 92,
    firstSeen: "2026-08-02",
    tags: ["Phishing URL", "Malicious Form"],
  },
];

export const mockCves: CveMock[] = [
  {
    id: "CVE-01",
    cveId: "CVE-2026-21048",
    title: "Linux Kernel eBPF Subsystem Arbitrary Memory Write",
    cvssScore: 9.8,
    severity: "Critical",
    patchStatus: "Pending Patch",
    affectedCount: 14,
    publishedDate: "2026-07-15",
  },
  {
    id: "CVE-02",
    cveId: "CVE-2026-19022",
    title: "Palo Alto PAN-OS Command Injection Vulnerability",
    cvssScore: 9.1,
    severity: "Critical",
    patchStatus: "Workaround Applied",
    affectedCount: 2,
    publishedDate: "2026-07-20",
  },
  {
    id: "CVE-03",
    cveId: "CVE-2026-0941",
    title: "OpenSSL Denial of Service via Malformed Certificate Handshake",
    cvssScore: 7.5,
    severity: "High",
    patchStatus: "Patched",
    affectedCount: 42,
    publishedDate: "2026-06-30",
  },
  {
    id: "CVE-04",
    cveId: "CVE-2025-4819",
    title: "Windows Remote Desktop Protocol Buffer Overflow",
    cvssScore: 8.4,
    severity: "High",
    patchStatus: "Unpatched",
    affectedCount: 8,
    publishedDate: "2025-11-12",
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
    title: "Monthly Executive Cyber Risk & Threat Summary (July 2026)",
    type: "Executive Summary",
    generatedDate: "2026-08-01",
    format: "PDF",
    size: "2.8 MB",
    author: "SentinelX AI",
  },
  {
    id: "REP-103",
    title: "Incident Post-Mortem: INC-4081 Root Compromise Attempt",
    type: "Incident Post-Mortem",
    generatedDate: "2026-08-03",
    format: "PDF",
    size: "1.1 MB",
    author: "Alex Rivera",
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

export const mockUsers: UserMock[] = [
  {
    id: "USR-001",
    name: "K Balaji",
    email: "kbalaji@sentinelx.ai",
    role: "Super Administrator",
    department: "Executive Security Operations",
    status: "Active",
    mfaEnabled: false,
    lastLogin: "Just now",
  },
  {
    id: "USR-002",
    name: "Elena Rostova",
    email: "elena.rostova@sentinelx.ai",
    role: "SOC Manager",
    department: "Security Leadership",
    status: "Active",
    mfaEnabled: true,
    lastLogin: "10 minutes ago",
  },
  {
    id: "USR-003",
    name: "Marcus Vance",
    email: "marcus.vance@sentinelx.ai",
    role: "Incident Responder",
    department: "Incident Response",
    status: "Active",
    mfaEnabled: true,
    lastLogin: "1 hour ago",
  },
  {
    id: "USR-004",
    name: "Sarah Chen",
    email: "sarah.chen@sentinelx.ai",
    role: "Admin",
    department: "SecOps Engineering",
    status: "Active",
    mfaEnabled: true,
    lastLogin: "3 hours ago",
  },
  {
    id: "USR-005",
    name: "David Miller",
    email: "david.miller@external-audit.com",
    role: "Auditor",
    department: "External Compliance",
    status: "Inactive",
    mfaEnabled: false,
    lastLogin: "5 days ago",
  },
];

// ── Chart Datasets ──────────────────────────────────────────

export const mockTimelineData = [
  { time: "00:00", threats: 12, alerts: 45, incidents: 2 },
  { time: "03:00", threats: 8, alerts: 28, incidents: 1 },
  { time: "06:00", threats: 15, alerts: 52, incidents: 3 },
  { time: "09:00", threats: 34, alerts: 110, incidents: 7 },
  { time: "12:00", threats: 48, alerts: 165, incidents: 9 },
  { time: "15:00", threats: 62, alerts: 198, incidents: 12 },
  { time: "18:00", threats: 41, alerts: 140, incidents: 8 },
  { time: "21:00", threats: 25, alerts: 88, incidents: 4 },
];

export const mockSeverityDistribution = [
  { name: "Critical", value: 18, color: "#ff1744" },
  { name: "High", value: 35, color: "#ff6d00" },
  { name: "Medium", value: 72, color: "#ffd600" },
  { name: "Low", value: 140, color: "#448aff" },
];

export const mockTopAttackerIps = [
  { ip: "185.220.101.5", country: "RU", attempts: 1420, threatScore: 98 },
  { ip: "194.26.29.112", country: "NL", attempts: 980, threatScore: 94 },
  { ip: "45.142.214.20", country: "DE", attempts: 750, threatScore: 82 },
  { ip: "103.152.220.18", country: "CN", attempts: 540, threatScore: 78 },
  { ip: "193.142.146.210", country: "UA", attempts: 320, threatScore: 71 },
];
