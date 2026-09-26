// ============================================================
// LiveSOC - Custom Rule Templates
//
// Pre-built detection rule templates that users can one-click
// create and customize. Each template provides sensible defaults
// that cover common security monitoring use cases.
// ============================================================

import type { CustomRuleInput, RuleCondition, Severity } from "@/lib/types";

export interface RuleTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  icon: string; // lucide icon name hint
  severity: Severity;
  conditions: RuleCondition[];
  threshold: number;
  windowMs: number;
  confidence: number;
  recommendedAction: string;
  tags: string[];
}

export const RULE_TEMPLATES: RuleTemplate[] = [
  {
    id: "tmpl-ssh-brute-force",
    name: "SSH Brute Force Detection",
    description:
      "Detects repeated SSH authentication failures from a single source IP within a short window. Common indicator of credential stuffing or brute-force attacks.",
    category: "Authentication",
    icon: "KeyRound",
    severity: "high",
    conditions: [
      { field: "eventType", operator: "equals", value: "auth_failure" },
    ],
    threshold: 5,
    windowMs: 60000,
    confidence: 85,
    recommendedAction:
      "Investigate the source IP, verify it's within authorized assessment scope, and review SSH access controls. Consider rate limiting or blocking the source if unauthorized.",
    tags: ["ssh", "authentication", "brute-force", "credential-access"],
  },
  {
    id: "tmpl-port-scan",
    name: "Port Scan Detection",
    description:
      "Detects port probing activity from a single source IP. Multiple port probes in a short window indicate network service discovery / scanning.",
    category: "Reconnaissance",
    icon: "ScanLine",
    severity: "medium",
    conditions: [
      { field: "eventType", operator: "equals", value: "port_probe" },
    ],
    threshold: 4,
    windowMs: 60000,
    confidence: 78,
    recommendedAction:
      "Verify the source is an authorized scanner. If not, investigate the source IP and review firewall rules to restrict unauthorized scanning.",
    tags: ["port-scan", "reconnaissance", "discovery"],
  },
  {
    id: "tmpl-http-fuzzing",
    name: "HTTP Request Fuzzing",
    description:
      "Detects high-volume HTTP requests that may indicate web application fuzzing, directory brute-forcing, or vulnerability scanning.",
    category: "Web Activity",
    icon: "Globe",
    severity: "medium",
    conditions: [
      { field: "eventType", operator: "equals", value: "http_request" },
    ],
    threshold: 20,
    windowMs: 30000,
    confidence: 72,
    recommendedAction:
      "Analyze HTTP request patterns (URIs, methods, user agents). Review WAF logs if available. Apply rate limiting if the source appears unauthorized.",
    tags: ["http", "web", "fuzzing", "reconnaissance"],
  },
  {
    id: "tmpl-specific-source-ip",
    name: "Monitor Specific Source IP",
    description:
      "Alert on ANY activity from a specific source IP address. Useful for watching known suspicious or authorized testing sources.",
    category: "Source Monitoring",
    icon: "Eye",
    severity: "low",
    conditions: [
      { field: "sourceIp", operator: "equals", value: "192.168.1.50" },
    ],
    threshold: 1,
    windowMs: 60000,
    confidence: 60,
    recommendedAction:
      "Review all activity from this source. Update the IP address in the rule conditions to match your target source.",
    tags: ["source-ip", "monitoring", "watchlist"],
  },
  {
    id: "tmpl-firewall-deny-burst",
    name: "Firewall Deny Burst",
    description:
      "Detects a burst of firewall deny events, indicating repeated blocked connection attempts that may indicate an attack pattern.",
    category: "Network",
    icon: "ShieldAlert",
    severity: "medium",
    conditions: [
      { field: "eventType", operator: "equals", value: "firewall_deny" },
    ],
    threshold: 10,
    windowMs: 30000,
    confidence: 70,
    recommendedAction:
      "Review the firewall logs for the denied sources. If the pattern persists, consider escalating the source IPs to a blocklist.",
    tags: ["firewall", "network", "denied-connections"],
  },
  {
    id: "tmpl-critical-severity-watch",
    name: "Critical Severity Event Watch",
    description:
      "Alert immediately on any critical-severity event. Use as a catch-all for the most serious observed activity.",
    category: "Severity Watch",
    icon: "AlertOctagon",
    severity: "critical",
    conditions: [
      { field: "severity", operator: "equals", value: "critical" },
    ],
    threshold: 1,
    windowMs: 60000,
    confidence: 90,
    recommendedAction:
      "Immediately investigate the critical event. Verify the source and target, check authorized scope, and follow incident response procedures.",
    tags: ["critical", "severity", "incident-response"],
  },
  {
    id: "tmpl-external-scanner",
    name: "External Scanner Activity",
    description:
      "Detects activity from a known external scanner IP range. Customize the IP list in the 'in' condition to match your threat intel.",
    category: "Threat Intelligence",
    icon: "Radar",
    severity: "high",
    conditions: [
      {
        field: "sourceIp",
        operator: "in",
        value: ["10.0.0.99", "172.16.5.99", "192.168.1.99"],
      },
    ],
    threshold: 1,
    windowMs: 300000,
    confidence: 75,
    recommendedAction:
      "Investigate the source IP immediately. If unauthorized, block at the firewall and document for incident response.",
    tags: ["threat-intel", "scanner", "external"],
  },
  {
    id: "tmpl-database-port-access",
    name: "Database Port Access",
    description:
      "Detects connections to database ports (MySQL 3306, PostgreSQL 5432, Redis 6379). Useful for monitoring unauthorized database access attempts.",
    category: "Service Monitoring",
    icon: "Database",
    severity: "high",
    conditions: [
      {
        field: "destPort",
        operator: "in",
        value: ["3306", "5432", "6379", "1433", "1521", "27017"],
      },
    ],
    threshold: 1,
    windowMs: 60000,
    confidence: 80,
    recommendedAction:
      "Verify the database access is from an authorized source. Review database authentication logs and access controls if unauthorized.",
    tags: ["database", "ports", "service-access"],
  },
];
