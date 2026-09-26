// ============================================================
// LiveSOC - Core Type Definitions
// ============================================================

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type MonitorStatus =
  | "ready"
  | "initializing"
  | "scanning"
  | "monitoring"
  | "reconnecting"
  | "stopped"
  | "completed"
  | "error";

export type ScenarioStatus = "active" | "inactive" | "resolved";

export type TelemetrySource =
  | "network"
  | "system_logs"
  | "web_logs"
  | "firewall"
  | "ids"
  | "scanner";

export type ViewKey =
  | "monitor"
  | "offense"
  | "defense"
  | "history"
  | "reports"
  | "settings";

// ============================================================
// Target & Assessment
// ============================================================
export interface TargetInfo {
  id: string;
  address: string;
  hostname?: string | null;
  targetType: "ip" | "domain" | "localhost";
  isLab: boolean;
  authorized: boolean;
  createdAt: string;
}

export interface PortInfo {
  id: string;
  number: number;
  protocol: string;
  state: string;
  serviceName?: string;
}

export interface ServiceInfo {
  id: string;
  name: string;
  port: number;
  protocol: string;
  product?: string | null;
  version?: string | null;
  extrainfo?: string | null;
  method: string;
  confidence: number;
}

export interface AssessmentResult {
  id: string;
  targetId: string;
  status: string;
  reachability: string;
  latencyMs?: number | null;
  hostname?: string | null;
  osGuess?: string | null;
  startedAt: string;
  completedAt?: string | null;
  ports: PortInfo[];
  services: ServiceInfo[];
}

// ============================================================
// Events & Alerts
// ============================================================
export interface SecurityEvent {
  id: string;
  eventId: string;
  sessionId?: string | null;
  timestamp: string;
  source: TelemetrySource | string;
  sourceIp?: string | null;
  sourcePort?: number | null;
  destIp?: string | null;
  destPort?: number | null;
  protocol?: string | null;
  eventType: string;
  severity: Severity;
  status: string;
  message: string;
  isDemo: boolean;
  raw?: Record<string, unknown> | null;
}

export interface SecurityAlert {
  id: string;
  alertId: string;
  sessionId?: string | null;
  eventId?: string | null;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  confidence: number;
  message: string;
  recommendedAction?: string | null;
  status: string;
  timestamp: string;
}

// ============================================================
// Detection Rules
// ============================================================
export interface DetectionRule {
  ruleId: string;
  name: string;
  description: string;
  severity: Severity;
  conditions: string;
  confidence: number;
  recommendedAction: string;
  category: string;
}

// ============================================================
// Scenarios
// ============================================================
export interface OffenseScenario {
  id: string;
  scenarioId: string;
  sessionId?: string | null;
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  affectedTarget?: string | null;
  affectedService?: string | null;
  technique?: string | null;
  techniqueMitre?: string | null;
  attackPath?: string | null;
  potentialImpact?: string | null;
  relatedEventIds: string[];
  eventCount: number;
  sourceCount: number;
  status: ScenarioStatus;
  firstObserved: string;
  lastObserved: string;
}

export interface DefenseScenario {
  id: string;
  scenarioId: string;
  sessionId?: string | null;
  relatedOffenseId?: string | null;
  title: string;
  category: string;
  priority: Severity;
  affectedService?: string | null;
  detect?: string | null;
  monitor?: string | null;
  prevent?: string | null;
  respond?: string | null;
  recommendedAction?: string | null;
  relatedEventIds: string[];
  status: ScenarioStatus;
  firstObserved: string;
  lastObserved: string;
}

// ============================================================
// Monitoring Session
// ============================================================
export interface MonitoringSessionInfo {
  id: string;
  targetId: string;
  targetAddress: string;
  assessmentId?: string | null;
  status: MonitorStatus;
  mode: "demo" | "live";
  startedAt: string;
  endedAt?: string | null;
  durationSec: number;
  eventCount: number;
  alertCount: number;
  riskSummary?: string | null;
}

// ============================================================
// KPI / Stats
// ============================================================
export interface KpiStats {
  events: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  activeConnections: number;
  eventsPerSec: number;
  trafficRate: number; // KB/s
  openPorts: number;
}

export interface ProtocolDistribution {
  protocol: string;
  count: number;
}

export interface TopItem {
  key: string;
  count: number;
}

export interface NetworkActivityStats {
  connectionCount: number;
  connectionsPerSec: number;
  requestRate: number;
  trafficRate: number;
  protocolDistribution: ProtocolDistribution[];
  topSourceIps: TopItem[];
  topDestPorts: TopItem[];
  recentConnections: SecurityEvent[];
  eventsPerSecTimeline: { t: string; v: number }[];
  trafficTimeline: { t: string; v: number }[];
}

// ============================================================
// WebSocket Messages
// ============================================================
export type WSMessage =
  | { type: "hello"; sessionId: string; serverTime: string }
  | { type: "heartbeat"; serverTime: string }
  | { type: "session_status"; sessionId: string; status: MonitorStatus; target?: string; mode?: string }
  | { type: "event"; event: SecurityEvent }
  | { type: "alert"; alert: SecurityAlert }
  | { type: "kpi"; kpi: KpiStats }
  | { type: "network_activity"; stats: NetworkActivityStats }
  | { type: "offense_scenario"; scenario: OffenseScenario }
  | { type: "offense_scenario_update"; scenario: OffenseScenario }
  | { type: "defense_scenario"; scenario: DefenseScenario }
  | { type: "defense_scenario_update"; scenario: DefenseScenario }
  | { type: "assessment_update"; assessment: Partial<AssessmentResult> & { id: string } }
  | { type: "log"; message: string; level: string; timestamp: string }
  | { type: "error"; message: string; code?: string }
  | { type: "session_ended"; sessionId: string; reason: string };

export type WSClientCommand =
  | { type: "subscribe"; sessionId: string }
  | { type: "unsubscribe"; sessionId: string }
  | { type: "ping" }
  | { type: "pause_stream" }
  | { type: "resume_stream" };

// ============================================================
// Reports
// ============================================================
export interface ReportInfo {
  id: string;
  reportId: string;
  sessionId?: string | null;
  target: string;
  title: string;
  generatedAt: string;
  riskLevel: Severity;
  eventCount: number;
  alertCount: number;
  scenarioCount: number;
  pdfUrl?: string | null;
}

// ============================================================
// Settings
// ============================================================
export interface AppSettings {
  demoMode: boolean;
  telemetryIntervalMs: number;
  maxLiveEvents: number;
  enableNetworkCollector: boolean;
  enableSystemLogsCollector: boolean;
  enableWebLogsCollector: boolean;
  enableFirewallCollector: boolean;
  enableIdsCollector: boolean;
  scanTimeoutSec: number;
  scanTopPorts: number;
  authorizedScopeNote: string;
}
