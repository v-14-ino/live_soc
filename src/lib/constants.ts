// ============================================================
// LiveSOC - Constants: Detection Rules, Scenario Templates
// ============================================================
import type { DetectionRule, Severity } from "./types";

// ============================================================
// Detection Rules (rule-based engine, no random generation)
// ============================================================
export const DETECTION_RULES: DetectionRule[] = [
  {
    ruleId: "RULE-001",
    name: "Port Discovery Pattern",
    description:
      "Observed connections to multiple distinct ports on the same target within a short time window.",
    severity: "medium",
    conditions:
      ">=4 distinct destination ports from the same source IP within 60s",
    confidence: 78,
    recommendedAction:
      "Verify the source is an authorized scanner. Correlate with service inventory.",
    category: "discovery",
  },
  {
    ruleId: "RULE-002",
    name: "Repeated Connection Pattern",
    description:
      "Same source IP repeatedly connecting to the same destination port.",
    severity: "medium",
    conditions:
      ">=5 connections from same source to same dest:port within 60s",
    confidence: 72,
    recommendedAction:
      "Inspect source reputation and service access policy. Apply rate limiting if unauthorized.",
    category: "reconnaissance",
  },
  {
    ruleId: "RULE-003",
    name: "Authentication Failure Burst",
    description:
      "Multiple authentication failures observed from the same source.",
    severity: "high",
    conditions:
      ">=3 auth_failure events from same source IP within 90s",
    confidence: 85,
    recommendedAction:
      "Investigate source IP. Review account lockout policy. Verify authorized testing scope.",
    category: "credential_access",
  },
  {
    ruleId: "RULE-004",
    name: "HTTP Request Spike",
    description:
      "Sudden increase in HTTP request rate compared to baseline.",
    severity: "medium",
    conditions:
      "HTTP request rate > 2x rolling baseline over 30s",
    confidence: 68,
    recommendedAction:
      "Check for web enumeration or fuzzing activity. Review WAF logs if available.",
    category: "web_anomaly",
  },
  {
    ruleId: "RULE-005",
    name: "Unusual Connection Rate",
    description:
      "Overall connection rate exceeds expected baseline for the target.",
    severity: "high",
    conditions:
      "Connections/sec > 5 sustained over 15s",
    confidence: 74,
    recommendedAction:
      "Correlate with active assessment window. Confirm against authorized test schedule.",
    category: "volume_anomaly",
  },
  {
    ruleId: "RULE-006",
    name: "Repeated Access to Same Service",
    description:
      "High frequency access to a single service from multiple sources.",
    severity: "medium",
    conditions:
      ">=10 accesses to same dest:port from >=2 sources within 60s",
    confidence: 70,
    recommendedAction:
      "Confirm expected service usage. Review service exposure and access controls.",
    category: "service_anomaly",
  },
  {
    ruleId: "RULE-007",
    name: "New Source IP",
    description:
      "Connection observed from a source IP not seen in the current baseline.",
    severity: "low",
    conditions:
      "Source IP not present in baseline source set",
    confidence: 60,
    recommendedAction:
      "Log and monitor. If source persists, escalate to correlation engine.",
    category: "baseline_deviation",
  },
  {
    ruleId: "RULE-008",
    name: "Service Access Anomaly",
    description:
      "Access pattern to a service deviates from observed baseline protocol usage.",
    severity: "medium",
    conditions:
      "Protocol/port combination outside baseline service set",
    confidence: 66,
    recommendedAction:
      "Investigate the service and source. Verify legitimate change vs probing.",
    category: "service_anomaly",
  },
];

export const RULES_BY_ID: Record<string, DetectionRule> = Object.fromEntries(
  DETECTION_RULES.map((r) => [r.ruleId, r]),
);

// ============================================================
// Offense Scenario Templates
// Each template maps detection signals to a potential attack scenario.
// Note: these are POTENTIAL scenarios, not confirmed attacks.
// ============================================================
export interface OffenseTemplate {
  category: string;
  title: string;
  technique: string;
  techniqueMitre: string;
  attackPath: string[];
  potentialImpact: string;
  severity: Severity;
  confidence: number;
  defenseCategory: string; // corresponding defense scenario
}

export const OFFENSE_TEMPLATES: Record<string, OffenseTemplate> = {
  network_service_discovery: {
    category: "network_service_discovery",
    title: "Network Service Discovery",
    technique: "Network Service Discovery",
    techniqueMitre: "T1046",
    attackPath: [
      "Discovery",
      "Service Enumeration",
      "Potential Service Targeting",
    ],
    potentialImpact:
      "Exposure of additional network services may increase the target's attack surface.",
    severity: "medium",
    confidence: 80,
    defenseCategory: "network_scan_monitoring",
  },
  port_scanning_pattern: {
    category: "port_scanning_pattern",
    title: "Port Scanning Pattern",
    technique: "Network Service Scanning",
    techniqueMitre: "T1046",
    attackPath: [
      "Reconnaissance",
      "Port Scan",
      "Open Port Identification",
    ],
    potentialImpact:
      "Systematic port enumeration could reveal live services for later targeting.",
    severity: "medium",
    confidence: 82,
    defenseCategory: "network_scan_monitoring",
  },
  repeated_auth_attempts: {
    category: "repeated_auth_attempts",
    title: "Repeated SSH Authentication Attempts",
    technique: "Brute Force",
    techniqueMitre: "T1110",
    attackPath: [
      "Credential Access",
      "Authentication Attempts",
      "Potential Account Compromise",
    ],
    potentialImpact:
      "Repeated authentication failures could indicate an attempted credential attack. Success is NOT confirmed without verified evidence.",
    severity: "high",
    confidence: 86,
    defenseCategory: "ssh_auth_monitoring",
  },
  http_request_anomaly: {
    category: "http_request_anomaly",
    title: "HTTP Request Anomaly",
    technique: "Web Service Enumeration",
    techniqueMitre: "T1190",
    attackPath: [
      "Reconnaissance",
      "HTTP Enumeration",
      "Potential Web Vector Identification",
    ],
    potentialImpact:
      "Abnormal HTTP request volume may indicate web application probing or fuzzing.",
    severity: "medium",
    confidence: 72,
    defenseCategory: "http_anomaly_monitoring",
  },
  unusual_connection_rate: {
    category: "unusual_connection_rate",
    title: "Unusual Connection Rate",
    technique: "Active Scanning",
    techniqueMitre: "T1595",
    attackPath: [
      "Reconnaissance",
      "High-Rate Connections",
      "Potential Saturation / Enumeration",
    ],
    potentialImpact:
      "Sustained high-rate connections could degrade service responsiveness or indicate automated tooling.",
    severity: "high",
    confidence: 75,
    defenseCategory: "connection_rate_monitoring",
  },
  suspicious_service_access: {
    category: "suspicious_service_access",
    title: "Suspicious Service Access",
    technique: "System Information Discovery",
    techniqueMitre: "T1082",
    attackPath: [
      "Discovery",
      "Service Access",
      "Potential Information Disclosure",
    ],
    potentialImpact:
      "Access to services outside expected usage patterns could expose sensitive information.",
    severity: "medium",
    confidence: 70,
    defenseCategory: "exposed_service_monitoring",
  },
  new_source_activity: {
    category: "new_source_activity",
    title: "New Source IP Activity",
    technique: "Indicator of Activity",
    techniqueMitre: "T1592",
    attackPath: [
      "Observation",
      "New Source Detected",
      "Monitor for Escalation",
    ],
    potentialImpact:
      "A new source IP may represent a legitimate change or unauthorized access attempt. Continued monitoring required.",
    severity: "low",
    confidence: 60,
    defenseCategory: "suspicious_source_monitoring",
  },
};

// ============================================================
// Defense Scenario Templates
// ============================================================
export interface DefenseTemplate {
  category: string;
  title: string;
  detect: string;
  monitor: string;
  prevent: string;
  respond: string;
  recommendedAction: string;
  priority: Severity;
}

export const DEFENSE_TEMPLATES: Record<string, DefenseTemplate> = {
  network_scan_monitoring: {
    category: "network_scan_monitoring",
    title: "Network Scan Monitoring",
    detect:
      "Monitor repeated connections to multiple distinct ports from a single source within a short window.",
    monitor:
      "Network telemetry and firewall logs for multi-port connection patterns.",
    prevent:
      "Use network segmentation, firewall rules to restrict unauthorized sources, and IDS signatures for scan patterns.",
    respond:
      "Investigate the source IP, confirm authorization, and review exposed service inventory.",
    recommendedAction:
      "Verify the source is part of the authorized assessment scope. Otherwise block and document.",
    priority: "medium",
  },
  ssh_auth_monitoring: {
    category: "ssh_auth_monitoring",
    title: "SSH Authentication Monitoring",
    detect:
      "Monitor repeated authentication failures from the same source.",
    monitor:
      "SSH authentication logs, connection attempts, and failed login counters.",
    prevent:
      "Use authorized access controls, strong authentication, key-based auth, and appropriate rate limiting (e.g. fail2ban).",
    respond:
      "Investigate the source IP, review authentication events, and follow the organization's incident response procedure.",
    recommendedAction:
      "Confirm whether attempts originate from authorized testing. Block the source if unauthorized.",
    priority: "high",
  },
  http_anomaly_monitoring: {
    category: "http_anomaly_monitoring",
    title: "HTTP Anomaly Monitoring",
    detect:
      "Monitor request rate, request size, and unusual URI patterns against the baseline.",
    monitor:
      "Web server access logs and WAF telemetry for anomalous request patterns.",
    prevent:
      "Deploy WAF rules, request rate limiting, and input validation on web endpoints.",
    respond:
      "Analyze request samples, identify patterns, and apply targeted WAF rules if needed.",
    recommendedAction:
      "Compare current patterns to the assessment baseline. Escalate if patterns suggest exploitation attempts.",
    priority: "medium",
  },
  connection_rate_monitoring: {
    category: "connection_rate_monitoring",
    title: "Connection Rate Monitoring",
    detect:
      "Monitor overall connection rate against the established baseline.",
    monitor:
      "Network flow telemetry and connection counters on perimeter devices.",
    prevent:
      "Apply connection rate limits and connection tracking rules on the firewall.",
    respond:
      "Identify top source IPs and apply temporary rate limits while investigating.",
    recommendedAction:
      "Correlate with authorized test schedule. Apply rate limiting if rate exceeds acceptable threshold.",
    priority: "high",
  },
  exposed_service_monitoring: {
    category: "exposed_service_monitoring",
    title: "Exposed Service Monitoring",
    detect:
      "Monitor access to services identified during the initial assessment baseline.",
    monitor:
      "Service-level logs and IDS alerts for unexpected service interaction.",
    prevent:
      "Restrict service exposure to required sources only. Disable unused services.",
    respond:
      "Review service configuration and access logs. Patch or restrict services showing anomalous access.",
    recommendedAction:
      "Re-baseline the service inventory after changes. Confirm exposure matches policy.",
    priority: "medium",
  },
  suspicious_source_monitoring: {
    category: "suspicious_source_monitoring",
    title: "Suspicious Source Monitoring",
    detect:
      "Flag source IPs not present in the current baseline source set.",
    monitor:
      "All telemetry sources for repeat appearances of new source IPs.",
    prevent:
      "Maintain allow-lists for known authorized sources where applicable.",
    respond:
      "Log new sources, watch for escalation, and escalate if correlated with other detections.",
    recommendedAction:
      "Add to a watchlist. If activity persists or escalates, escalate to investigation.",
    priority: "low",
  },
};

// ============================================================
// Severity ordering & helpers
// ============================================================
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export function severityColor(s: Severity): string {
  switch (s) {
    case "critical":
      return "var(--soc-critical)";
    case "high":
      return "var(--soc-high)";
    case "medium":
      return "var(--soc-medium)";
    case "low":
      return "var(--soc-low)";
    default:
      return "var(--soc-info)";
  }
}

// ============================================================
// Authorized scope notice
// ============================================================
export const AUTHORIZED_SCOPE_NOTICE =
  "Only monitor systems you are authorized to assess.";

// Default settings
export const DEFAULT_SETTINGS = {
  demoMode: true,
  telemetryIntervalMs: 1500,
  maxLiveEvents: 500,
  enableNetworkCollector: true,
  enableSystemLogsCollector: true,
  enableWebLogsCollector: true,
  enableFirewallCollector: true,
  enableIdsCollector: false,
  scanTimeoutSec: 30,
  scanTopPorts: 100,
  authorizedScopeNote: AUTHORIZED_SCOPE_NOTICE,
};
