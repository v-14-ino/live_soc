# ============================================================
# LiveSOC Windows Agent Configuration
#
# Copy this file to config.ps1 and fill in your values.
# Never commit config.ps1 with real API keys.
# ============================================================

# LiveSOC backend URL
$ServerUrl = "http://localhost:3000"

# Agent identity (register in LiveSOC first via Settings > Agents > Register)
$AgentId = "agent-windows-001"
$ApiKey = "CHANGE_ME_TO_YOUR_API_KEY"

# Agent display info
$AgentName = "Lab Windows Agent"
$AgentVersion = "1.0.0"

# Heartbeat interval in seconds
$HeartbeatIntervalSec = 30

# Event log polling interval in seconds
$PollIntervalSec = 5

# Which event IDs to collect (Windows Security log)
# 4624 = successful logon, 4625 = failed logon, 4688 = process creation
$EventIds = @(4624, 4625, 4688)

# State file for tracking last-read event record (prevents duplicates)
$StateFile = "$env:TEMP\livesoc-agent-state.json"

# Log level: DEBUG, INFO, WARNING, ERROR
$LogLevel = "INFO"
