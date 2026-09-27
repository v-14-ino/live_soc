# LiveSOC Windows Agent

Lightweight PowerShell agent that collects Windows Security Event Log telemetry and sends it to the LiveSOC backend.

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ (built into Windows)
- No external dependencies
- Run as Administrator (to read Security Event Log)

## Setup

### 1. Register the agent in LiveSOC

In the LiveSOC web UI:
1. Go to **Settings** → **Agents**
2. Click **Register Agent**
3. Fill in: Agent ID (e.g. `agent-windows-001`), Name, Hostname, OS = Windows
4. Copy the API key — **it is shown only once**

Or via API:
```powershell
$response = Invoke-RestMethod -Uri "http://YOUR_SERVER:3000/api/agents/register" `
    -Method POST -ContentType "application/json" `
    -Body '{"agentId":"agent-windows-001","name":"Lab Windows Agent","hostname":"DESKTOP-01","os":"Windows"}'
$apiKey = $response.apiKey
Write-Host "API Key: $apiKey"
```

### 2. Configure the agent

```powershell
Copy-Item config.example.ps1 config.ps1
notepad config.ps1
```

Set:
- `$ServerUrl` — your LiveSOC URL
- `$AgentId` — the agent ID you registered
- `$ApiKey` — the API key from registration
- `$SessionId` — the monitoring session ID (pass via command line)

### 3. Start a monitoring session

In the LiveSOC web UI:
1. Go to **Live Monitor**
2. Enter the target
3. Select **Live Mode**
4. Click **Start Monitoring**
5. Copy the session ID from the URL or API

### 4. Run the agent

```powershell
# Run as Administrator
.\agent.ps1 -SessionId "cmui..."
```

Or with a custom config:
```powershell
.\agent.ps1 -Config C:\livesoc\config.ps1 -SessionId "cmui..."
```

## Event IDs Collected

| Event ID | Description | EventType |
|----------|-------------|-----------|
| 4624 | Successful logon | authentication_success |
| 4625 | Failed logon | authentication_failure |
| 4688 | Process creation | process_created |

## What the agent does

1. Sends periodic heartbeats (default 30s) to `POST /api/agents/heartbeat`
2. Polls the Windows Security Event Log for new events (default 5s)
3. Parses Event IDs 4624, 4625, 4688 into normalized payloads
4. Sends events to `POST /api/ingest` with `X-Agent-ID` + `X-Agent-Key` auth
5. Tracks the last-read RecordId to prevent duplicate events
6. All events are labeled `dataSource: REAL` and `sourceType: windows_event_log`

## State file

The agent stores its bookmark (last-read RecordId) in `$env:TEMP\livesoc-agent-state.json`. Delete this file to re-read from the beginning of the log.

## Security

- API keys are **never** stored in plaintext server-side (SHA-256 hash only)
- The agent sends the API key via the `X-Agent-Key` header
- Do NOT commit `config.ps1` with real API keys to version control
- Run the agent with the minimum necessary privileges (Administrator is needed to read the Security Event Log)

## Testing

To generate a test failed logon event on Windows:
```powershell
# This will generate Event ID 4625 (failed logon)
cmdkey /list  # view stored credentials
runas /user:fakeuser cmd  # will fail, generating 4625
```
