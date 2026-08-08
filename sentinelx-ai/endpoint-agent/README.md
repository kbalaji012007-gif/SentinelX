# SentinelX Endpoint Telemetry Agent

The **SentinelX Endpoint Telemetry Agent** is a lightweight, secure Windows telemetry collector designed to run as a background service on endpoint laptops and workstations. It captures security-relevant Windows event logs, process executions, network socket states, and system health metrics, forwarding them securely over HTTPS to the SentinelX AI backend.

---

## 1. Architecture

```
Windows Laptop / Workstation
      ↓
[ Endpoint Agent ]
   ├── Identity Manager (UUID & token storage)
   ├── Heartbeat Worker (Periodic status signals)
   ├── Security Collectors (Windows Events, Processes, Network, System)
   └── HTTPS Transport (Bearer Token Auth)
      ↓ HTTPS
[ SentinelX FastAPI Backend ]
      ↓
[ Supabase PostgreSQL ] (sentinelx.endpoint_agents & sentinelx.agent_telemetry)
      ↓
[ SentinelX SOC Pipeline ] (log_entries → Threat Detection → Correlation → SOAR → AI SOC)
```

---

## 2. Security Model & Privacy Guardrails

The SentinelX agent enforces strict privacy and security boundaries:

- **No Passwords**: Never captures user passwords or secrets.
- **No Keystrokes**: Keylogging mechanisms are explicitly omitted.
- **No Personal Documents**: No scanning or uploading of user documents.
- **No Browser History**: Browser history and cookie stores are never accessed.
- **No Screenshots**: No screen capture or media recording.
- **No Arbitrary File Uploads**: Does not upload executable files.
- **No Remote Shell**: Accepts **zero** remote execution commands from the server.
- **Agent Authentication**: Every agent request is authenticated via short-lived enrollment tokens and secure bearer credentials.

---

## 3. Collected Telemetry

The agent collects only explicit security telemetry:

1. **Windows Security Events**:
   - `4624`: Successful Logon
   - `4625`: Failed Logon
   - `4740`: Account Lockout
   - `4688`: Process Creation
   - `4672`: Special Privileges Assigned
   - `7045`: Service Installed
2. **Process Telemetry**:
   - PID, Parent PID, Executable Path, Process Name, Username, Start Time, optional SHA256 Hash.
3. **Network Telemetry**:
   - Local IP/Port, Remote IP/Port, Protocol, Associated PID, Connection State.
4. **System Health**:
   - Hostname, OS Version, Architecture, CPU Usage %, Memory Usage %, Disk Usage %, Uptime, Local IP.

---

## 4. Configuration

The agent reads configuration from environment variables or a `.env` file:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SENTINELX_API_URL` | `http://localhost:8000/api/v1` | SentinelX FastAPI backend base URL |
| `AGENT_ID` | Auto-generated UUID | Unique installation agent UUID |
| `AGENT_TOKEN` | Generated on enrollment | Bearer token for authenticating telemetry requests |
| `HEARTBEAT_INTERVAL` | `60` | Interval in seconds between heartbeat signals |
| `TELEMETRY_INTERVAL` | `30` | Interval in seconds between telemetry batch collection |
| `LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `TEST_MODE` | `false` | When true, marks all events explicitly as `is_simulated: True` |

---

## 5. Installation & Enrollment Instructions for Windows

### Step 1: Prerequisites
- Python 3.10+ installed on Windows.
- Administrator access (for reading Windows Security Event Log and full socket metadata).

### Step 2: Extract & Install Dependencies
Open PowerShell or Command Prompt as Administrator:

```powershell
cd C:\path\to\sentinelx-ai\endpoint-agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Step 3: Configure Environment
Copy `.env.example` to `.env` and set your backend URL:

```powershell
cp .env.example .env
```

Edit `.env`:
```env
SENTINELX_API_URL=http://<YOUR_SENTINELX_BACKEND_IP>:8000/api/v1
HEARTBEAT_INTERVAL=60
TELEMETRY_INTERVAL=30
```

### Step 4: Enroll & Run the Agent

#### Run in Local Test Mode (Development & Verification):
```powershell
python -m src.main --test-mode
```

#### Run in Production Mode:
```powershell
python -m src.main
```

#### Run a Single Test Collection Cycle:
```powershell
python -m src.main --test-mode --once
```

---

## 6. Running as a Windows Background Service (Opt-In)

To run the agent as a background Windows Service using NSSM (Non-Sucking Service Manager):

1. Download NSSM from `https://nssm.cc/download`.
2. Open PowerShell as Administrator and run:

```powershell
nssm install SentinelXAgent "C:\path\to\sentinelx-ai\endpoint-agent\.venv\Scripts\python.exe" "-m src.main"
nssm set SentinelXAgent AppDirectory "C:\path\to\sentinelx-ai\endpoint-agent"
nssm set SentinelXAgent Start SERVICE_AUTO_START
nssm start SentinelXAgent
```

To stop or remove the service:
```powershell
nssm stop SentinelXAgent
nssm remove SentinelXAgent confirm
```

---

## 7. Troubleshooting

- **401 Unauthorized / Enrollment Error**:
  Delete `.agent_identity.json` and restart the agent to force a fresh enrollment request.
- **Permission Denied reading Event Log**:
  Ensure PowerShell / Command Prompt is running **As Administrator**.
- **Agent Status Offline**:
  Verify network connectivity to the SentinelX backend URL (`/api/v1/health`) and check backend server logs.
