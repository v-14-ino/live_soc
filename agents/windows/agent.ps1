# ============================================================
# LiveSOC Windows Agent
#
# Collects Windows Security Event Log, Windows Defender, and
# Windows Firewall telemetry and sends it to the LiveSOC backend
# via POST /api/ingest. Sends periodic heartbeats via
# POST /api/agents/heartbeat.
#
# Authentication: X-Agent-ID + X-Agent-Key headers
# Normalization: minimal — the backend normalizer handles the rest
#
# Event Sources:
#   - Windows Security Event Log (4624, 4625, 4688)
#   - Windows Defender (1116, 1117, 5007)
#   - Windows Firewall (5152, 5154, 5157, 2004)
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
    $StateFile = "$env:TEMP\livesoc-agent-state.json"
    $LogLevel = "INFO"
}

if ($ApiKey -eq "CHANGE_ME_TO_YOUR_API_KEY" -or [string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host "[ERROR] No API key configured. Edit config.ps1 and set `$ApiKey." -ForegroundColor Red
    exit 1
}

# Event IDs to collect from each source
$SecurityEventIds = @(4624, 4625, 4688)
$DefenderEventIds = @(1116, 1117, 5007)
$FirewallEventIds = @(5152, 5154, 5157, 2004)

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
        $status = 0
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -eq 401 -or $status -eq 403) {
            Log-Msg "ERROR" "Authentication failed ($status). Check X-Agent-ID and X-Agent-Key."
            return $null
        }
        Log-Msg "WARNING" "Request to $Path failed (HTTP $status): $($_.Exception.Message)"
        return $null
    } catch {
        Log-Msg "WARNING" "Request to $Path failed: $($_.Exception.Message)"
        return $null
    }
}

function Send-Event([hashtable]$Event) {
    if ([string]::IsNullOrWhiteSpace($SessionId)) {
        Log-Msg "DEBUG" "No session - dropping event: $($Event.eventType)"
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

# ============================================================
# State management (dedup / rotation tracking)
# ============================================================

function Load-State {
    if (Test-Path $StateFile) {
        try {
            $raw = Get-Content $StateFile -Raw | ConvertFrom-Json
            # Convert PSCustomObject to Hashtable for easier mutation
            $ht = @{}
            if ($raw) {
                foreach ($prop in $raw.PSObject.Properties) {
                    $ht[$prop.Name] = $prop.Value
                }
            }
            return $ht
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

function Get-State-Val([hashtable]$State, [string]$Key, $Default = 0) {
    if ($State.ContainsKey($Key)) { return $State[$Key] }
    return $Default
}

# ============================================================
# Windows Security Event Log collection
# ============================================================

function Parse-Security-Event($Record) {
    $eventId = [long]$Record.InstanceId
    $eventType = "windows_event"
    $eventCategory = "system"
    $severity = "info"
    $action = "info"
    $username = $null
    $sourceIp = $null
    $destPort = $null

    # Extract XML for structured properties
    $eventData = @{}
    try {
        $eventXml = [xml]$Record.ToXml()
        $ns = New-Object System.Xml.XmlNamespaceManager($eventXml.NameTable)
        $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $dataNodes = $eventXml.SelectNodes("//e:Data", $ns)
        foreach ($node in $dataNodes) {
            $name = $node.GetAttribute("Name")
            if (-not $name) { $name = "Data$($eventData.Count)" }
            $eventData[$name] = $node.InnerText
        }
    } catch {
        # XML parse failed - continue with empty eventData
    }

    switch ($eventId) {
        4624 {
            $eventType = "authentication_success"
            $eventCategory = "authentication"
            $action = "success"
            $severity = "info"
            if ($eventData.ContainsKey("TargetUserName")) { $username = $eventData["TargetUserName"] }
            if ($eventData.ContainsKey("IpAddress")) { $sourceIp = $eventData["IpAddress"] }
            if ($eventData.ContainsKey("LogonPort")) { $destPort = [int]$eventData["LogonPort"] }
        }
        4625 {
            $eventType = "authentication_failure"
            $eventCategory = "authentication"
            $action = "failure"
            $severity = "high"
            if ($eventData.ContainsKey("TargetUserName")) { $username = $eventData["TargetUserName"] }
            if ($eventData.ContainsKey("IpAddress")) { $sourceIp = $eventData["IpAddress"] }
        }
        4688 {
            $eventType = "process_created"
            $eventCategory = "process"
            $action = "success"
            $severity = "info"
            if ($eventData.ContainsKey("SubjectUserName")) { $username = $eventData["SubjectUserName"] }
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
        message = "Windows Event $eventId - $eventType for '$username'"
        rawEvent = $rawEvent
        metadata = @{
            eventId = $eventId
            logName = $Record.LogName
            source = $Record.Source
            recordId = $Record.RecordId
        }
    }
}

function Collect-Security-Events {
    $state = Load-State
    $lastRecordId = [long](Get-State-Val $state "lastSecurityRecordId" 0)

    try {
        $filterHash = @{ LogName = "Security"; Id = $SecurityEventIds }
        if ($lastRecordId -gt 0) {
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 100 -ErrorAction SilentlyContinue |
                      Where-Object { $_.RecordId -gt $lastRecordId } |
                      Sort-Object RecordId
        } else {
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 100 -ErrorAction SilentlyContinue |
                      Sort-Object RecordId
        }

        if (-not $events) { return }

        foreach ($event in $events) {
            $payload = Parse-Security-Event $event
            Send-Event $payload
            $state["lastSecurityRecordId"] = $event.RecordId
        }
        Save-State $state
    } catch {
        Log-Msg "WARNING" "Failed to read Security event log: $($_.Exception.Message)"
    }
}

# ============================================================
# Windows Defender Event Log collection (Phase 6)
# ============================================================

function Parse-Defender-Event($Record) {
    $eventId = [long]$Record.InstanceId
    $eventType = "defender_event"
    $severity = "medium"
    $action = "detected"
    $message = "Windows Defender Event $eventId"

    switch ($eventId) {
        1116 { $eventType = "defender_detection"; $severity = "high"; $message = "Defender: Threat detected" }
        1117 { $eventType = "defender_remediation"; $severity = "medium"; $message = "Defender: Threat remediated" }
        5007 { $eventType = "defender_config_changed"; $severity = "low"; $message = "Defender: Configuration changed" }
        default { $eventType = "defender_event_$eventId" }
    }

    $rawEvent = "EventID=$eventId LogName=$($Record.LogName) Source=$($Record.Source) TimeCreated=$($Record.TimeCreated) Message=$($Record.Message)"

    return @{
        agentId = $AgentId
        hostname = $env:COMPUTERNAME
        os = "Windows"
        sourceType = "windows_defender"
        eventCategory = "endpoint_security"
        timestamp = $Record.TimeCreated.ToUniversalTime().ToString("o")
        eventType = $eventType
        action = $action
        severity = $severity
        message = $message
        rawEvent = $rawEvent
        metadata = @{ eventId = $eventId; logName = $Record.LogName; recordId = $Record.RecordId }
    }
}

function Collect-Defender-Events {
    $state = Load-State
    $lastRecordId = [long](Get-State-Val $state "lastDefenderRecordId" 0)

    try {
        # Defender events are in "Microsoft-Windows-Windows Defender/Operational"
        $filterHash = @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; Id = $DefenderEventIds }
        if ($lastRecordId -gt 0) {
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 50 -ErrorAction SilentlyContinue |
                      Where-Object { $_.RecordId -gt $lastRecordId } |
                      Sort-Object RecordId
        } else {
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 50 -ErrorAction SilentlyContinue |
                      Sort-Object RecordId
        }

        if (-not $events) { return }

        foreach ($event in $events) {
            $payload = Parse-Defender-Event $event
            Send-Event $payload
            $state["lastDefenderRecordId"] = $event.RecordId
        }
        Save-State $state
        Log-Msg "INFO" "Defender events collected: $($events.Count)"
    } catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        # Defender log not available - this is expected on some systems
        if (-not $script:defenderUnavailable) {
            $script:defenderUnavailable = $true
            Log-Msg "WARNING" "Windows Defender event log not available. Defender telemetry disabled."
        }
    } catch {
        # Other errors - log once and suppress
        if (-not $script:defenderUnavailable) {
            $script:defenderUnavailable = $true
            Log-Msg "WARNING" "Defender collection unavailable: $($_.Exception.Message)"
        }
    }
}

# ============================================================
# Windows Firewall Event Log collection (Phase 7)
# ============================================================

function Parse-Firewall-Event($Record) {
    $eventId = [long]$Record.InstanceId
    $eventType = "firewall_event"
    $severity = "medium"
    $action = "blocked"
    $sourceIp = $null
    $destPort = $null
    $protocol = $null

    $message = "Windows Firewall Event $eventId"

    switch ($eventId) {
        5152 { $eventType = "firewall_dropped_packet"; $severity = "medium"; $message = "Firewall: Dropped packet" }
        5154 { $eventType = "firewall_listen_allowed"; $severity = "info"; $action = "allowed"; $message = "Firewall: Listen allowed" }
        5157 { $eventType = "firewall_connection_blocked"; $severity = "medium"; $message = "Firewall: Connection blocked" }
        2004 { $eventType = "firewall_rule_added"; $severity = "low"; $action = "config"; $message = "Firewall: Rule added/modified" }
        default { $eventType = "firewall_event_$eventId" }
    }

    # Try to extract IP/port from event XML
    try {
        $eventXml = [xml]$Record.ToXml()
        $ns = New-Object System.Xml.XmlNamespaceManager($eventXml.NameTable)
        $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $dataNodes = $eventXml.SelectNodes("//e:Data", $ns)
        foreach ($node in $dataNodes) {
            $name = $node.GetAttribute("Name")
            $val = $node.InnerText
            if ($name -eq "SourceAddress" -or $name -eq "remoteAddress") { $sourceIp = $val }
            if ($name -eq "DestPort" -or $name -eq "remotePort") { $destPort = [int]$val }
            if ($name -eq "Protocol") { $protocol = $val }
        }
    } catch {
        # XML parse failed - continue without IP/port
    }

    $rawEvent = "EventID=$eventId LogName=$($Record.LogName) Source=$($Record.Source) TimeCreated=$($Record.TimeCreated) Message=$($Record.Message)"

    return @{
        agentId = $AgentId
        hostname = $env:COMPUTERNAME
        os = "Windows"
        sourceType = "windows_firewall"
        eventCategory = "firewall"
        timestamp = $Record.TimeCreated.ToUniversalTime().ToString("o")
        sourceIp = $sourceIp
        destinationPort = $destPort
        protocol = $protocol
        eventType = $eventType
        action = $action
        severity = $severity
        message = $message
        rawEvent = $rawEvent
        metadata = @{ eventId = $eventId; logName = $Record.LogName; recordId = $Record.RecordId }
    }
}

function Collect-Firewall-Events {
    $state = Load-State
    $lastRecordId = [long](Get-State-Val $state "lastFirewallRecordId" 0)

    try {
        # Firewall events are in "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
        $filterHash = @{ LogName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; Id = $FirewallEventIds }
        if ($lastRecordId -gt 0) {
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 50 -ErrorAction SilentlyContinue |
                      Where-Object { $_.RecordId -gt $lastRecordId } |
                      Sort-Object RecordId
        } else {
            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents 50 -ErrorAction SilentlyContinue |
                      Sort-Object RecordId
        }

        if (-not $events) { return }

        foreach ($event in $events) {
            $payload = Parse-Firewall-Event $event
            Send-Event $payload
            $state["lastFirewallRecordId"] = $event.RecordId
        }
        Save-State $state
        Log-Msg "INFO" "Firewall events collected: $($events.Count)"
    } catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        if (-not $script:firewallUnavailable) {
            $script:firewallUnavailable = $true
            Log-Msg "WARNING" "Windows Firewall event log not available. Firewall telemetry disabled. Enable firewall logging via Group Policy or Windows Defender Firewall settings."
        }
    } catch {
        if (-not $script:firewallUnavailable) {
            $script:firewallUnavailable = $true
            Log-Msg "WARNING" "Firewall collection unavailable: $($_.Exception.Message)"
        }
    }
}

# ============================================================
# Main loop
# ============================================================

$running = $true
$script:defenderUnavailable = $false
$script:firewallUnavailable = $false

function Handle-CtrlC {
    $script:running = $false
    Log-Msg "INFO" "Stopping agent..."
}
[Console]::TreatControlCAsInput = $false
Register-EngineEvent PowerShell.Exiting -Action { Handle-CtrlC }

Log-Msg "INFO" "Starting LiveSOC Windows Agent (agent_id=$AgentId, version=$AgentVersion)"
Log-Msg "INFO" "Server: $ServerUrl"
Log-Msg "INFO" "Security Event IDs: $($SecurityEventIds -join ', ')"
Log-Msg "INFO" "Defender Event IDs: $($DefenderEventIds -join ', ')"
Log-Msg "INFO" "Firewall Event IDs: $($FirewallEventIds -join ', ')"

# Start heartbeat in a background job
$heartbeatJob = Start-Job -ScriptBlock {
    param($ServerUrl, $AgentId, $ApiKey, $AgentVersion, $HeartbeatIntervalSec)

    while ($true) {
        $hostname = $env:COMPUTERNAME
        $ip = $null
        try {
            $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*" } |
                   Select-Object -First 1).IPAddress
        } catch { }

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
        } catch { }

        Start-Sleep -Seconds $HeartbeatIntervalSec
    }
} -ArgumentList $ServerUrl, $AgentId, $ApiKey, $AgentVersion, $HeartbeatIntervalSec

Log-Msg "INFO" "Heartbeat job started (interval=${HeartbeatIntervalSec}s)"
Log-Msg "INFO" "Event collection started (poll=${PollIntervalSec}s)"

if ($SessionId) {
    Log-Msg "INFO" "Session: $SessionId"
} else {
    Log-Msg "WARNING" "No session ID provided. Events will be dropped until a session is set."
}

# Main event collection loop
while ($running) {
    try {
        Collect-Security-Events
        Collect-Defender-Events
        Collect-Firewall-Events
    } catch {
        Log-Msg "ERROR" "Collection error: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $PollIntervalSec
}

# Cleanup
Stop-Job $heartbeatJob -ErrorAction SilentlyContinue
Remove-Job $heartbeatJob -Force -ErrorAction SilentlyContinue
Log-Msg "INFO" "Agent stopped."
