// ============================================================
// LiveSOC - Event Normalizer (Phase 3 + Phase 6)
//
// Converts raw ingestion payloads (POST /api/ingest) into
// normalized SecurityEvent objects. Preserves the raw payload
// in RawLog (done by the caller) BEFORE normalization.
//
// Pipeline:
//   RAW LOG  →  normalize()  →  SecurityEvent  →  processEvent()
//
// The normalizer is source-type-aware: each sourceType
// (linux_auth, windows_event_log, firewall, network, web_log,
// process, ...) has its own parser. All parsers are pure
// functions: (raw) → SecurityEvent. They never throw on
// malformed input — they produce an info-severity "parse_error"
// event so the raw evidence is still visible + traceable.
// ============================================================

import type { SecurityEvent, Severity, DataSource } from "@/lib/types";

// ============================================================
// Ingestion payload schema (Phase 6)
//
// POST /api/ingest body. All fields optional except sourceType
// + eventType so agents can send minimal payloads. The
// normalizer fills in defaults.
// ============================================================
export interface IngestPayload {
  // Agent identity (optional — anonymous ingestion allowed)
  agentId?: string;
  hostname?: string;
  os?: string;
  // Telemetry source type: linux_auth | syslog | journald |
  // windows_event_log | firewall | network | web_log | process | demo
  sourceType: string;
  // Broader category: authentication | network | process | firewall | web
  eventCategory?: string;
  // When the source observed the event (ISO string). Defaults to now.
  timestamp?: string;
  // Core event fields
  username?: string;
  sourceIp?: string;
  sourcePort?: number;
  destinationIp?: string;
  destinationPort?: number;
  protocol?: string;
  eventType: string;
  action?: string;
  severity?: Severity;
  message?: string;
  // The ORIGINAL raw log line/payload (preserved verbatim in RawLog).
  rawEvent?: string;
  // Extra structured metadata
  metadata?: Record<string, unknown>;
}

export interface NormalizeResult {
  event: SecurityEvent;
  parser: string;
  warnings: string[];
}

// ---- helpers

function toSeverity(s: string | undefined): Severity {
  if (!s) return "info";
  const lower = s.toLowerCase();
  if (lower === "critical" || lower === "high" || lower === "medium" || lower === "low" || lower === "info") {
    return lower;
  }
  // Numeric PRIORITY (syslog-style 0-7): 0-2=critical, 3-4=high, 5-6=medium, 7=low
  const n = Number(s);
  if (!isNaN(n)) {
    if (n <= 2) return "critical";
    if (n <= 4) return "high";
    if (n <= 6) return "medium";
    return "low";
  }
  return "info";
}

function deriveEventCategory(sourceType: string, eventType: string): string {
  if (sourceType.startsWith("linux_auth") || sourceType === "journald" || eventType.includes("auth") || eventType.includes("login")) {
    return "authentication";
  }
  if (sourceType === "firewall" || eventType.includes("firewall")) return "firewall";
  if (sourceType === "web_log" || eventType.includes("http")) return "web";
  if (sourceType === "process" || eventType.includes("process")) return "process";
  if (sourceType === "network" || eventType.includes("connection") || eventType.includes("port")) return "network";
  return "other";
}

function inferSeverityFromEventType(eventType: string): Severity {
  const t = eventType.toLowerCase();
  if (t.includes("critical") || t.includes("exploit") || t.includes("malware")) return "critical";
  if (t.includes("failure") || t.includes("failed") || t.includes("brute") || t.includes("denied") || t.includes("block")) return "high";
  if (t.includes("scan") || t.includes("probe") || t.includes("anomal") || t.includes("suspicious")) return "medium";
  if (t.includes("connection") || t.includes("request") || t.includes("access")) return "low";
  return "info";
}

// ---- per-source-type parsers

function parseLinuxAuth(p: IngestPayload, warnings: string[]): SecurityEvent {
  const eventType = p.eventType || "authentication_failure";
  const severity = p.severity ?? (eventType.includes("success") ? "info" : "high");
  const message = p.message || (p.rawEvent ? p.rawEvent.slice(0, 200) : `${eventType} for ${p.username ?? "unknown"}`);

  return {
    id: "", // filled by caller
    eventId: "", // filled by caller
    sessionId: null,
    timestamp: p.timestamp || new Date().toISOString(),
    source: "system_logs",
    sourceIp: p.sourceIp ?? null,
    sourcePort: p.sourcePort ?? null,
    destIp: p.destinationIp ?? null,
    destPort: p.destinationPort ?? null,
    protocol: p.protocol ?? "tcp",
    eventType,
    severity,
    status: "new",
    message,
    isDemo: false,
    dataSource: "REAL",
    receivedAt: new Date().toISOString(),
    hostId: null,
    hostname: p.hostname ?? null,
    os: p.os ?? null,
    username: p.username ?? null,
    eventCategory: p.eventCategory ?? "authentication",
    raw: p.metadata ?? null,
  };
}

function parseWindowsEventLog(p: IngestPayload, warnings: string[]): SecurityEvent {
  const eventType = p.eventType || "windows_event";
  const severity = p.severity ?? inferSeverityFromEventType(eventType);
  const message = p.message || (p.rawEvent ? p.rawEvent.slice(0, 200) : `Windows event: ${eventType}`);

  return {
    id: "",
    eventId: "",
    sessionId: null,
    timestamp: p.timestamp || new Date().toISOString(),
    source: "system_logs",
    sourceIp: p.sourceIp ?? null,
    sourcePort: p.sourcePort ?? null,
    destIp: p.destinationIp ?? null,
    destPort: p.destinationPort ?? null,
    protocol: p.protocol ?? null,
    eventType,
    severity,
    status: "new",
    message,
    isDemo: false,
    dataSource: "REAL",
    receivedAt: new Date().toISOString(),
    hostId: null,
    hostname: p.hostname ?? null,
    os: p.os ?? "Windows",
    username: p.username ?? null,
    eventCategory: p.eventCategory ?? "system",
    raw: p.metadata ?? null,
  };
}

function parseFirewall(p: IngestPayload, warnings: string[]): SecurityEvent {
  const eventType = p.eventType || (p.action === "allow" ? "firewall_allow" : "firewall_deny");
  const severity = p.severity ?? (p.action === "allow" ? "info" : "medium");
  const message = p.message || `Firewall ${p.action ?? "deny"}: ${p.sourceIp ?? "?"} → ${p.destinationIp ?? "?"}:${p.destinationPort ?? "?"}`;

  return {
    id: "",
    eventId: "",
    sessionId: null,
    timestamp: p.timestamp || new Date().toISOString(),
    source: "firewall",
    sourceIp: p.sourceIp ?? null,
    sourcePort: p.sourcePort ?? null,
    destIp: p.destinationIp ?? null,
    destPort: p.destinationPort ?? null,
    protocol: p.protocol ?? "tcp",
    eventType,
    severity,
    status: "new",
    message,
    isDemo: false,
    dataSource: "REAL",
    receivedAt: new Date().toISOString(),
    hostId: null,
    hostname: p.hostname ?? null,
    os: p.os ?? null,
    username: null,
    eventCategory: "firewall",
    raw: p.metadata ?? null,
  };
}

function parseNetwork(p: IngestPayload, warnings: string[]): SecurityEvent {
  const eventType = p.eventType || "connection";
  const severity = p.severity ?? "info";
  const message = p.message || `Network ${eventType}: ${p.sourceIp ?? "?"}:${p.sourcePort ?? "?"} → ${p.destinationIp ?? "?"}:${p.destinationPort ?? "?"}`;

  return {
    id: "",
    eventId: "",
    sessionId: null,
    timestamp: p.timestamp || new Date().toISOString(),
    source: "network",
    sourceIp: p.sourceIp ?? null,
    sourcePort: p.sourcePort ?? null,
    destIp: p.destinationIp ?? null,
    destPort: p.destinationPort ?? null,
    protocol: p.protocol ?? "tcp",
    eventType,
    severity,
    status: "new",
    message,
    isDemo: false,
    dataSource: "REAL",
    receivedAt: new Date().toISOString(),
    hostId: null,
    hostname: p.hostname ?? null,
    os: p.os ?? null,
    username: null,
    eventCategory: "network",
    raw: p.metadata ?? null,
  };
}

function parseWebLog(p: IngestPayload, warnings: string[]): SecurityEvent {
  const eventType = p.eventType || "http_request";
  const severity = p.severity ?? "info";
  const message = p.message || `HTTP request to :${p.destinationPort ?? 80}`;

  return {
    id: "",
    eventId: "",
    sessionId: null,
    timestamp: p.timestamp || new Date().toISOString(),
    source: "web_logs",
    sourceIp: p.sourceIp ?? null,
    sourcePort: p.sourcePort ?? null,
    destIp: p.destinationIp ?? null,
    destPort: p.destinationPort ?? 80,
    protocol: p.protocol ?? "tcp",
    eventType,
    severity,
    status: "new",
    message,
    isDemo: false,
    dataSource: "REAL",
    receivedAt: new Date().toISOString(),
    hostId: null,
    hostname: p.hostname ?? null,
    os: p.os ?? null,
    username: null,
    eventCategory: "web",
    raw: p.metadata ?? null,
  };
}

function parseProcess(p: IngestPayload, warnings: string[]): SecurityEvent {
  const eventType = p.eventType || "process_created";
  const severity = p.severity ?? "info";
  const message = p.message || `Process: ${p.username ?? "?"} ${p.rawEvent?.slice(0, 100) ?? ""}`;

  return {
    id: "",
    eventId: "",
    sessionId: null,
    timestamp: p.timestamp || new Date().toISOString(),
    source: "system_logs",
    sourceIp: p.sourceIp ?? null,
    sourcePort: null,
    destIp: null,
    destPort: null,
    protocol: null,
    eventType,
    severity,
    status: "new",
    message,
    isDemo: false,
    dataSource: "REAL",
    receivedAt: new Date().toISOString(),
    hostId: null,
    hostname: p.hostname ?? null,
    os: p.os ?? null,
    username: p.username ?? null,
    eventCategory: "process",
    raw: p.metadata ?? null,
  };
}

function parseGeneric(p: IngestPayload, warnings: string[]): SecurityEvent {
  warnings.push(`Unknown sourceType "${p.sourceType}" — using generic parser`);
  const eventType = p.eventType || "unknown";
  const severity = p.severity ?? inferSeverityFromEventType(eventType);
  const message = p.message || (p.rawEvent ? p.rawEvent.slice(0, 200) : `Event: ${eventType}`);

  return {
    id: "",
    eventId: "",
    sessionId: null,
    timestamp: p.timestamp || new Date().toISOString(),
    source: p.sourceType,
    sourceIp: p.sourceIp ?? null,
    sourcePort: p.sourcePort ?? null,
    destIp: p.destinationIp ?? null,
    destPort: p.destinationPort ?? null,
    protocol: p.protocol ?? null,
    eventType,
    severity,
    status: "new",
    message,
    isDemo: false,
    dataSource: "REAL",
    receivedAt: new Date().toISOString(),
    hostId: null,
    hostname: p.hostname ?? null,
    os: p.os ?? null,
    username: p.username ?? null,
    eventCategory: p.eventCategory ?? deriveEventCategory(p.sourceType, eventType),
    raw: p.metadata ?? null,
  };
}

// ---- main entry point

/**
 * Normalize a raw ingestion payload into a SecurityEvent.
 * Never throws — on malformed input, produces a parse_error event.
 */
export function normalizePayload(payload: IngestPayload): NormalizeResult {
  const warnings: string[] = [];

  if (!payload.sourceType) {
    warnings.push("Missing sourceType — defaulting to 'unknown'");
    payload.sourceType = "unknown";
  }
  if (!payload.eventType) {
    warnings.push("Missing eventType — defaulting to 'unknown'");
    payload.eventType = "unknown";
  }

  let event: SecurityEvent;
  let parser: string;

  try {
    switch (payload.sourceType) {
      case "linux_auth":
      case "syslog":
      case "journald":
        parser = `${payload.sourceType}_v1`;
        event = parseLinuxAuth(payload, warnings);
        break;
      case "windows_event_log":
        parser = "windows_event_log_v1";
        event = parseWindowsEventLog(payload, warnings);
        break;
      case "windows_defender":
        parser = "windows_defender_v1";
        event = {
          id: "", eventId: "", sessionId: null,
          timestamp: payload.timestamp || new Date().toISOString(),
          source: "system_logs",
          sourceIp: payload.sourceIp ?? null,
          sourcePort: null,
          destIp: payload.destinationIp ?? null,
          destPort: payload.destinationPort ?? null,
          protocol: null,
          eventType: payload.eventType || "defender_event",
          severity: payload.severity ?? "medium",
          status: "new",
          message: payload.message || `Windows Defender: ${payload.eventType}`,
          isDemo: false,
          dataSource: "REAL",
          receivedAt: new Date().toISOString(),
          hostId: null,
          hostname: payload.hostname ?? null,
          os: "Windows",
          username: null,
          eventCategory: "endpoint_security",
          raw: payload.metadata ?? null,
        };
        break;
      case "windows_firewall":
        parser = "windows_firewall_v1";
        event = {
          id: "", eventId: "", sessionId: null,
          timestamp: payload.timestamp || new Date().toISOString(),
          source: "firewall",
          sourceIp: payload.sourceIp ?? null,
          sourcePort: payload.sourcePort ?? null,
          destIp: payload.destinationIp ?? null,
          destPort: payload.destinationPort ?? null,
          protocol: payload.protocol ?? null,
          eventType: payload.eventType || "firewall_event",
          severity: payload.severity ?? "medium",
          status: "new",
          message: payload.message || `Windows Firewall: ${payload.eventType}`,
          isDemo: false,
          dataSource: "REAL",
          receivedAt: new Date().toISOString(),
          hostId: null,
          hostname: payload.hostname ?? null,
          os: "Windows",
          username: null,
          eventCategory: "firewall",
          raw: payload.metadata ?? null,
        };
        break;
      case "firewall":
      case "iptables":
        parser = "firewall_v1";
        event = parseFirewall(payload, warnings);
        break;
      case "network":
        parser = "network_v1";
        event = parseNetwork(payload, warnings);
        break;
      case "web_log":
      case "nginx":
      case "apache":
        parser = "web_log_v1";
        event = parseWebLog(payload, warnings);
        break;
      case "process":
      case "sysmon":
        parser = "process_v1";
        event = parseProcess(payload, warnings);
        break;
      default:
        parser = "generic_v1";
        event = parseGeneric(payload, warnings);
    }
  } catch (err) {
    warnings.push(`Normalizer threw: ${err instanceof Error ? err.message : "unknown"}`);
    parser = "error_v1";
    event = {
      id: "",
      eventId: "",
      sessionId: null,
      timestamp: payload.timestamp || new Date().toISOString(),
      source: payload.sourceType || "unknown",
      sourceIp: payload.sourceIp ?? null,
      sourcePort: payload.sourcePort ?? null,
      destIp: payload.destinationIp ?? null,
      destPort: payload.destinationPort ?? null,
      protocol: payload.protocol ?? null,
      eventType: "parse_error",
      severity: "medium",
      status: "new",
      message: `Failed to normalize ${payload.sourceType} event: ${payload.eventType}`,
      isDemo: false,
      dataSource: "REAL",
      receivedAt: new Date().toISOString(),
      hostId: null,
      hostname: payload.hostname ?? null,
      os: payload.os ?? null,
      username: null,
      eventCategory: "other",
      raw: { originalPayload: payload, error: String(err) },
    };
  }

  return { event, parser, warnings };
}

/**
 * Validate an ingestion payload. Returns a list of human-readable
 * errors (empty = valid).
 */
export function validateIngestPayload(payload: unknown): string[] {
  const errors: string[] = [];
  if (!payload || typeof payload !== "object") {
    errors.push("Body must be a JSON object");
    return errors;
  }
  const p = payload as Partial<IngestPayload>;
  if (!p.sourceType || typeof p.sourceType !== "string") {
    errors.push("sourceType is required (string)");
  }
  if (!p.eventType || typeof p.eventType !== "string") {
    errors.push("eventType is required (string)");
  }
  if (p.timestamp && isNaN(Date.parse(p.timestamp))) {
    errors.push("timestamp must be a valid ISO date string");
  }
  if (p.severity && !["critical", "high", "medium", "low", "info"].includes(p.severity)) {
    errors.push("severity must be one of: critical, high, medium, low, info");
  }
  return errors;
}
