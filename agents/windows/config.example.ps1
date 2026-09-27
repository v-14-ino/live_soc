# ============================================================
# LiveSOC Windows Agent Configuration
#
# Copy this file to config.ps1 and fill in your values.
# Never commit config.ps1 with real API keys.
# ============================================================

# LiveSOC backend URL
$ServerUrl = "http://YOUR_LIVESOC_SERVER:3000"

# Agent identity (register in LiveSOC first via Settings > Agents > Register)
$AgentId = "agent-windows-001"
$ApiKey = "CHANGE_ME_TO_YOUR_API_KEY"

# Agent display info
$AgentName = "Lab Windows Agent"
$AgentVersion = "1.1.0"

# Heartbeat interval in seconds
$HeartbeatIntervalSec = 30

# Event log polling interval in seconds
$PollIntervalSec = 5

# State file for tracking last-read event record (prevents duplicates)
$StateFile = "$env:TEMP\livesoc-agent-state.json"

# Log level: DEBUG, INFO, WARNING, ERROR
$LogLevel = "INFO"

# ============================================================
# Telemetry sources (automatically detected at runtime)
#
# The agent collects from these sources if available:
#   - Windows Security Event Log (4624, 4625, 4688)
#   - Windows Defender (1116, 1117, 5007)
#   - Windows Firewall (5152, 5154, 5157, 2004)
#
# Sources that are not available are silently skipped.
# No configuration needed — the agent auto-detects availability.
# ============================================================
