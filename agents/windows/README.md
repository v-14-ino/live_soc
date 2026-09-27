# LiveSOC Windows Agent

Lightweight PowerShell agent that collects Windows Security Event Log, Windows Defender, and Windows Firewall telemetry and sends it to the LiveSOC backend.

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ (built into Windows)
- No external dependencies
- **Run as Administrator** (required to read Security Event Log)
- Network access to the LiveSOC server

## Telemetry Sources

| Source | Event Log | Event IDs | Description |
|--------|-----------|-----------|-------------|
| Windows Security | Security | 4624, 4625, 4688 | Logon success/failure, process creation |
| Windows Defender | Microsoft-Windows-Windows Defender/Operational | 1116, 1117, 5007 | Threat detection, remediation, config changes |
| Windows Firewall | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | 5152, 5154, 5157, 2004 | Dropped packets, blocked connections, rule changes |

Sources that are not available on the system are silently skipped.

## Setup

### 1. Register the agent in LiveSOC

**Via the Web UI:**
1. Open the LiveSOC web UI in your browser
2. Go to **Settings** → **Agents**
3. Click **Register**
4. Fill in:
   - Agent ID: e.g. `agent-win-01`
   - Name: e.g. `Lab Windows Agent`
   - Hostname: e.g. `DESKTOP-LAB`
   - OS: `Windows`
5. Click **Register**
6. **Copy the API key** — it is shown only once
7. Store the API key securely

**Via API (PowerShell on the Windows machine):**
```powershell
$response = Invoke-RestMethod -Uri "http://YOUR_SERVER:3000/api/agents/register" `
    -Method POST -ContentType "application/json" `
    -Body '{"agentId":"agent-win-01","name":"Lab Windows Agent","hostname":"DESKTOP-LAB","os":"Windows"}'
$apiKey = $response.apiKey
Write-Host "API Key: $apiKey"
Write-Host "SAVE THIS KEY - it will not be shown again."
```

### 2. Configure the agent

```powershell
# Create a directory for the agent
mkdir C:\LiveSOC-Agent
cd C:\LiveSOC-Agent

# Copy agent files here (agent.ps1, config.example.ps1)

# Create config
Copy-Item config.example.ps1 config.ps1
notepad config.ps1
```

Edit `config.ps1` and set:
- `$ServerUrl` — your LiveSOC server URL (e.g. `http://192.168.1.100:3000`)
- `$AgentId` — the agent ID you registered (e.g. `agent-win-01`)
- `$ApiKey` — the API key from registration (starts with `lsk_`)

### 3. Start a monitoring session

In the LiveSOC web UI:
1. Go to **Live Monitor**
2. Enter the target IP/domain
3. Select **Live Mode**
4. Click **Start Monitoring**
5. Note the session ID (visible in the URL bar or API response)

### 4. Run the agent

Open PowerShell **as Administrator**:

```powershell
cd C:\LiveSOC-Agent
.\agent.ps1 -SessionId "YOUR_SESSION_ID"
```

Or with a custom config path:
```powershell
.\agent.ps1 -Config C:\LiveSOC-Agent\config.ps1 -SessionId "YOUR_SESSION_ID"
```

### 5. Verify connectivity

The agent should print:
```
[2026-01-01 10:00:00] [INFO] Starting LiveSOC Windows Agent (agent_id=agent-win-01)
[2026-01-01 10:00:00] [INFO] Server: http://192.168.1.100:3000
[2026-01-01 10:00:00] [INFO] Heartbeat job started (interval=30s)
[2026-01-01 10:00:00] [INFO] Event collection started (poll=5s)
[2026-01-01 10:00:00] [INFO] Session: YOUR_SESSION_ID
```

### 6. Check heartbeat

In the LiveSOC web UI:
1. Go to **Settings** → **Agents**
2. Your agent should show **ONLINE** status with a recent last heartbeat

### 7. Check LiveSOC dashboard

In the LiveSOC web UI:
1. Go to **Live Monitor**
2. Events should appear in the **Live Security Log** with a green **REAL** tag
3. If detection rules match, alerts appear in **Live Alerts**

### 8. Required Windows permissions

- **Administrator** — required to read the Security Event Log
- **Event Log Readers** group membership (optional, if not running as admin)

To run without full admin, add the user to the Event Log Readers group:
```powershell
net localgroup "Event Log Readers" "DOMAIN\username" /add
```

### 9. Testing

**Generate a test failed logon (Event ID 4625):**
```powershell
# This will generate a failed logon event
runas /user:fakeuser cmd
# Enter any password — it will fail and generate Event ID 4625
```

**Generate a process creation event (Event ID 4688):**
```powershell
# Any process creation generates 4688 (if Process Auditing is enabled)
notepad.exe
```

**Enable Process Auditing (required for Event ID 4688):**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

### 10. Troubleshooting

**"Authentication failed (401)"**
- Verify the API key is correct in `config.ps1`
- Verify the agent ID matches what was registered
- Try rotating the key in Settings → Agents → Rotate Key

**"No session ID provided"**
- Pass the session ID via `-SessionId` parameter
- Start a monitoring session in LiveSOC first

**No events appearing in LiveSOC**
- Verify the session is active (Live Monitor shows MONITORING)
- Check the agent console for error messages
- Verify Windows Security Audit is enabled:
  ```powershell
  auditpol /get /category:"Logon"
  # Should show "Success and Failure"
  ```
- Enable logon auditing:
  ```powershell
  auditpol /set /subcategory:"Logon" /success:enable /failure:enable
  ```

**Defender events not collected**
- Verify Windows Defender is running:
  ```powershell
  Get-MpComputerStatus
  ```
- The Defender event log may not exist on systems without Defender

**Firewall events not collected**
- Enable firewall logging:
  ```powershell
  Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
  ```
- Enable firewall audit events:
  ```powershell
  auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
  auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
  ```

**State file issues**
- Delete the state file to re-read from the beginning:
  ```powershell
  Remove-Item "$env:TEMP\livesoc-agent-state.json"
  ```

## Running as a Windows Service (optional)

For production deployment, run the agent as a scheduled task:

```powershell
# Create a scheduled task that runs at startup
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\LiveSOC-Agent\agent.ps1 -SessionId YOUR_SESSION_ID"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "LiveSOC-Agent" -Action $action -Trigger $trigger -Principal $principal

# Start it now
Start-ScheduledTask -TaskName "LiveSOC-Agent"
```

## Security

- API keys are **never** stored in plaintext server-side (SHA-256 hash only)
- The agent sends the API key via the `X-Agent-Key` header over HTTP
- For production, use HTTPS (configure via Caddy/reverse proxy)
- Do NOT commit `config.ps1` with real API keys to version control
- Run the agent with the minimum necessary privileges

## Event Data Fields

Each event sent to LiveSOC includes:

| Field | Description |
|-------|-------------|
| `agentId` | Agent identifier |
| `hostname` | Windows computer name |
| `os` | Always "Windows" |
| `sourceType` | `windows_event_log`, `windows_defender`, or `windows_firewall` |
| `eventCategory` | `authentication`, `process`, `endpoint_security`, or `firewall` |
| `timestamp` | Event time (UTC ISO) |
| `username` | Target/subject user (if available) |
| `sourceIp` | Source IP (if available) |
| `eventType` | Normalized event type |
| `action` | `success`, `failure`, `blocked`, `allowed`, `detected` |
| `severity` | `info`, `low`, `medium`, `high` |
| `rawEvent` | Original event log line (preserved) |
| `metadata` | Event ID, log name, record ID |
