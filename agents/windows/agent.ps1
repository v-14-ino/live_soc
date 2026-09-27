# ============================================================
# LiveSOC Windows Agent
#
# Collects Windows Security Event Log telemetry (Event IDs
# 4624, 4625, 4688) and sends it to the LiveSOC backend via
# POST /api/ingest. Sends periodic heartbeats via
# POST /api/agents/heartbeat.
#
# Authentication: X-Agent-ID + X-Agent-Key headers
# Normalization: minimal — the backend normalizer handles the rest
#
# Usage:
#   .\agent.ps1 -SessionId <session-id>
#   .\agent.ps1 -Config .\config.ps1 -SessionId <session-id>
#
# No external dependencies — uses only built-in PowerShell cmdlets.
# ============================================================

param(
    [string]$Config = ".\config.ps1",
    [string]$SessionId = ""
)

# ============================================================
# Configuration loading
# ============================================================

$ErrorActionPreference = "Stop"

# Load config file
if (Test-Path $Config) {
    . $Config
} else {
    Write-Host "[WARNING] Config file '$Config' not found. Using defaults."
    $ServerUrl = "http://localhost:3000"
    $AgentId = "agent-windows-001"
    $ApiKey = ""
    $AgentName = "Windows Agent"
    $AgentVersion = "1.0.0"
    $HeartbeatIntervalSec = 30
    $PollIntervalSec = 5
    $EventIds = @(4624, 4625, 4688)
    $StateFile = "$env:TEMP\livesoc-agent-state.json"
    $LogLevel = "INFO"
}

if ($ApiKey -eq "CHANGE_ME_TO_YOUR_API_KEY" -or [string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host "[ERROR] No API key configured. Edit config.ps1 and set `$ApiKey." -ForegroundColor Red
    exit 1
}

# ============================================================
# Logging
# ============================================================

function Log-Msg([string]$Level, [string]$Message) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] [$Level] $Message"
}

# ============================================================
# HTTP helpers
# ============================================================

function Send-Request([string]$Path, [hashtable]$Payload) {
    $url = "$ServerUrl$Path"
    $headers = @{
        "Content-Type" = "application/json"
        "X-Agent-ID" = $AgentId
        "X-Agent-Key" = $ApiKey
        "User-Agent" = "LiveSOC-Windows-Agent/$AgentVersion"
    }
    $body = $Payload | ConvertTo-Json -Depth 10 -Compress

    try {
        $response = Invoke-WebRequest -Uri $url -Method POST -Headers $headers -Body $body -TimeoutSec 10 -UseBasicParsing
        return $response.Content | ConvertFrom-Json
    } catch [System.Net.WebException] {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 401 -or $status -eq 403) {
            Log-Msg "ERROR" "Authentication failed ($status). Check X-Agent-ID and X-Agent-Key."
            return $null
        }
        Log-Msg "WARNING" "Request to $Path failed: $($_.Exception.Message)"
        return $null
    } catch {
        Log-Msg "WARNING" "Request to $Path failed: $($_.Exception.Message)"
        return $null
    }
}

function Send-Event([hashtable]$Event) {
    if ([string]::IsNullOrWhiteSpace($SessionId)) {
        Log-Msg "DEBUG" "No session — dropping event: $($Event.eventType)"
        return
    }
    $Event["sessionId"] = $SessionId
    $result = Send-Request "/api/ingest" $Event
    if ($result -and $result.ok) {
        Log-Msg "DEBUG" "Sent: $($Event.eventType) ($($result.eventId))"
    } else {
        Log-Msg "WARNING" "Failed to send event: $($Event.eventType)"
    }
}

function Send-Heartbeat {
    $hostname = $env:COMPUTERNAME
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*" } | Select-Object -First 1).IPAddress

    $payload = @{
        agentId = $AgentId
        hostname = $hostname
        os = "Windows"
        version = $AgentVersion
        ip = $ip
        status = "ONLINE"
    }

    $result = Send-Request "/api/agents/heartbeat" $payload
    if ($result -and $result.ok) {
        Log-Msg "DEBUG" "Heartbeat sent: $hostname ONLINE"
    } else {
        Log-Msg "WARNING" "Heartbeat failed"
    }
}

# ============================================================
# State management (file rotation / dedup)
# ============================================================

function Load-State {
    if (Test-Path $StateFile) {
        try {
            return Get-Content $StateFile -Raw | ConvertFrom-Json
        } catch {
            return @{}
        }
    }
    return @{}
}

function Save-State([hashtable]$State) {
    try {
        $State | ConvertTo-Json | Set-Content $StateFile -Force
    } catch {
        Log-Msg "WARNING" "Failed to save state: $($_.Exception.Message)"
    }
}

# ============================================================
# Windows Event Log collection
# ============================================================

function Get-IsoTimestamp {
    return (Get-Date).ToUniversalTime().ToString("o")
}

function Parse-Event([System.Diagnostics.EventLogRecord]$Record) {
    <#
        Converts a Windows Event Log record into an ingestion payload.
        Minimal parsing — the backend normalizer does the heavy lifting.
    #>
    $eventId = $Record.InstanceId
    $eventType = "windows_event"
    $eventCategory = "system"
    $severity = "info"
    $action = "info"
    $username = $null
    $sourceIp = $null
    $destPort = $null

    # Extract XML for structured properties
    $eventXml = $null
    try {
        $eventXml = [xml]$Record.ToXml()
    } catch {
        $eventXml = $null
    }

    # Parse EventData
    $eventData = @{}
    if ($eventXml) {
        $ns = New-Object System.Xml.XmlNamespaceManager($eventXml.NameTable)
        $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $dataNodes = $eventXml.SelectNodes("//e:Data", $ns)
        foreach ($node in $dataNodes) {
            $name = $node.GetAttribute("Name")
            if (-not $name) { $name = "Data$($eventData.Count)" }
            $eventData[$name] = $node.InnerText
        }
    }

    switch ($eventId) {
        4624 {
            # Successful logon
            $eventType = "authentication_success"
            $eventCategory = "authentication"
            $action = "success"
            $severity = "info"
            $username = if ($eventData.ContainsKey("TargetUserName")) { $eventData["TargetUserName"] } else { $null }
            $sourceIp = if ($eventData.ContainsKey("IpAddress")) { $eventData["IpAddress"] } else { $null }
            $destPort = if ($eventData.ContainsKey("LogonPort")) { [int]$eventData["LogonPort"] } else { $null }
        }
        4625 {
            # Failed logon
            $eventType = "authentication_failure"
            $eventCategory = "authentication"
            $action = "failure"
            $severity = "high"
            $username = if ($eventData.ContainsKey("TargetUserName")) { $eventData["TargetUserName"] } else { $null }
            $sourceIp = if ($eventData.ContainsKey("IpAddress")) { $eventData["IpAddress"] } else { $null }
        }
        4688 {
            # Process creation
            $eventType = "process_created"
            $eventCategory = "process"
            $action = "success"
            $severity = "info"
            $username = if ($eventData.ContainsKey("SubjectUserName")) { $eventData["SubjectUserName"] } else { $null }
        }
        default {
            $eventType = "windows_event_$eventId"
            $severity = "info"
        }
    }

    $rawEvent = "EventID=$eventId LogName=$($Record.LogName) Source=$($Record.Source) TimeCreated=$($Record.TimeCreated) Message=$($Record.Message)"

    return @{
        agentId = $AgentId
        hostname = $env:COMPUTERNAME
        os = "Windows"
        sourceType = "windows_event_log"
        eventCategory = $eventCategory
        timestamp = $Record.TimeCreated.ToUniversalTime().ToString("o")
        username = $username
        sourceIp = $sourceIp
        destinationIp = $null
        destinationPort = $destPort
        protocol = $null
        eventType = $eventType
        action = $action
        severity = $severity
        message = "Windows Event $eventId: $eventType for '$username'"
        rawEvent = $rawEvent
        metadata = @{
            eventId = $eventId
            logName = $Record.LogName
            source = $Record.Source
            recordId = $Record.RecordId
        }
    }
}

function Collect-Events {
    <#
        Reads new Windows Security Event Log entries since the last
        bookmark. Tracks RecordId for dedup/rotation.
    #>
    $state = Load-State
    $lastRecordId = if ($state.ContainsKey("lastSecurityRecordId")) { [long]$state["lastSecurityRecordId"] } else { 0 }

    try {
        # Query Security log for our target Event IDs
        $filterHash = @{
            LogName = "Security"
            Id = $EventIds
        }
        if ($lastRecordId -gt 0) {
            # Only get events newer than the last seen RecordId
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 100 -ErrorAction SilentlyContinue |
                      Where-Object { $_.RecordId -gt $lastRecordId } |
                      Sort-Object RecordId
        } else {
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 100 -ErrorAction SilentlyContinue |
                      Sort-Object RecordId
        }

        if (-not $events) { return }

        foreach ($event in $events) {
            $payload = Parse-Event $event
            Send-Event $payload

            # Update bookmark
            $state["lastSecurityRecordId"] = $event.RecordId
        }

        Save-State $state
    } catch {
        Log-Msg "WARNING" "Failed to read Security event log: $($_.Exception.Message)"
    }
}

# ============================================================
# Main loop
# ============================================================

$running = $true

function Handle-CtrlC {
    $script:running = $false
    Log-Msg "INFO" "Stopping agent..."
}
[Console]::TreatControlCAsInput = $false
Register-EngineEvent PowerShell.Exiting -Action { Handle-CtrlC }

Log-Msg "INFO" "Starting LiveSOC Windows Agent (agent_id=$AgentId)"

# Start heartbeat in a runspace (background)
$heartbeatJob = Start-Job -ScriptBlock {
    param($ServerUrl, $AgentId, $ApiKey, $AgentVersion, $HeartbeatIntervalSec)

    function Send-Heartbeat-Internal {
        $hostname = $env:COMPUTERNAME
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*" } | Select-Object -First 1).IPAddress

        $headers = @{
            "Content-Type" = "application/json"
            "X-Agent-ID" = $AgentId
            "X-Agent-Key" = $ApiKey
        }
        $body = @{
            agentId = $AgentId
            hostname = $hostname
            os = "Windows"
            version = $AgentVersion
            ip = $ip
            status = "ONLINE"
        } | ConvertTo-Json -Compress

        try {
            Invoke-WebRequest -Uri "$ServerUrl/api/agents/heartbeat" -Method POST -Headers $headers -Body $body -TimeoutSec 10 -UseBasicParsing | Out-Null
        } catch {
            # silent
        }
    }

    while ($true) {
        Send-Heartbeat-Internal
        Start-Sleep -Seconds $HeartbeatIntervalSec
    }
} -ArgumentList $ServerUrl, $AgentId, $ApiKey, $AgentVersion, $HeartbeatIntervalSec

Log-Msg "INFO" "Heartbeat job started (interval=${HeartbeatIntervalSec}s)"
Log-Msg "INFO" "Event collection started (poll=${PollIntervalSec}s, EventIDs=$($EventIds -join ','))"

if ($SessionId) {
    Log-Msg "INFO" "Session: $SessionId"
} else {
    Log-Msg "WARNING" "No session ID provided. Events will be dropped until a session is set."
}

# Main event collection loop
while ($running) {
    try {
        Collect-Events
    } catch {
        Log-Msg "ERROR" "Collection error: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $PollIntervalSec
}

# Cleanup
Stop-Job $heartbeatJob -ErrorAction SilentlyContinue
Remove-Job $heartbeatJob -Force -ErrorAction SilentlyContinue
Log-Msg "INFO" "Agent stopped."
