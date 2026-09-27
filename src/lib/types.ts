// ============================================================
// LiveSOC - Core Type Definitions
// ============================================================

export type Severity = "critical" | "high" | "medium" | "low" | "info";

// ============================================================
// PHASE 2 — Data Source Model
//
// Every event is tagged with its origin so the UI and pipeline
// can distinguish real telemetry from demo/simulated data and
// from initial-assessment results. Never mix silently.
// ============================================================
export type DataSource = "REAL" | "DEMO" | "ASSESSMENT";

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
  // Phase A: real nmap assessment metadata
  scanner?: string | null;        // "nmap" | "mock" | null
  scannerVersion?: string | null; // e.g. "nmap 7.94"
  scanDurationMs?: number | null;
  scanError?: string | null;
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
  // ---- PHASE 2: real-telemetry data source model (additive, all optional) ----
  // dataSource: REAL | DEMO | ASSESSMENT. When null, inferred from isDemo
  // for backward compatibility (isDemo=true => DEMO, else REAL).
  dataSource?: DataSource | null;
  // When LiveSOC received the event (ingestion time). Distinct from `timestamp`.
  receivedAt?: string | null;
  // Host/agent identity for real telemetry.
  hostId?: string | null;
  hostname?: string | null;
  os?: string | null;
  username?: string | null;
  // Broader category: authentication | network | process | firewall | web | ...
  eventCategory?: string | null;
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
// Custom Detection Rules (user-defined)
// ============================================================
export type RuleField =
  | "sourceIp"
  | "destPort"
  | "protocol"
  | "eventType"
  | "severity"
  | "message"
  | "sourceCollector";

export type RuleOperator = "equals" | "contains" | "matches" | "greaterThan" | "lessThan" | "in";

export interface RuleCondition {
  field: RuleField;
  operator: RuleOperator;
  value: string | number | string[];
}

export interface CustomRule {
  id: string;
  ruleId: string; // CSTM-NNNN
  name: string;
  description: string;
  severity: Severity;
  enabled: boolean;
  conditions: RuleCondition[];
  threshold: number; // fire when N matching events within windowMs
  windowMs: number;
  confidence: number;
  recommendedAction: string;
  firedCount: number;
  lastFired?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CustomRuleInput {
  name: string;
  description?: string;
  severity?: Severity;
  enabled?: boolean;
  conditions: RuleCondition[];
  threshold?: number;
  windowMs?: number;
  confidence?: number;
  recommendedAction?: string;
}

// ============================================================
// Webhook Configuration (alert notifications)
// ============================================================
export interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  severities: string[]; // e.g. ["critical", "high"]
  secret?: string | null;
  cooldownSec: number;
  lastCalled?: string | null;
  callCount: number;
  failCount: number;
  lastError?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface WebhookInput {
  name: string;
  url: string;
  enabled?: boolean;
  severities?: string[];
  secret?: string;
  cooldownSec?: number;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  alertId?: string | null;
  eventType: string; // "alert" | "test"
  statusCode?: number | null;
  status: string; // "success" | "failed" | "timeout" | "error"
  responseExcerpt?: string | null;
  errorMessage?: string | null;
  latencyMs?: number | null;
  payload: string;
  calledAt: string;
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
  // Phase C: configurable heartbeat thresholds
  agentHeartbeatIntervalSec: number;
  agentDegradedAfterSec: number;
  agentOfflineAfterSec: number;
}
