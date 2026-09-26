// ============================================================
// LiveSOC - Demo Telemetry Generator (TelemetryCollector w/ adapters)
//
// All emitted events are clearly labeled isDemo=true. The
// generator drives a deterministic 5-phase narrative that
// exercises every detection rule and spawns offense/defense
// scenarios over ~2-3 minutes.
//
// No real network traffic is generated. This is a pure in-process
// event emitter.
// ============================================================

import type { SecurityEvent, ServiceInfo, Severity, TelemetrySource } from "@/lib/types";

export interface TelemetryCollectorConfig {
  targetAddress: string;
  services: ServiceInfo[];
  intervalMs: number;
  enabledCollectors: {
    network: boolean;
    systemLogs: boolean;
    webLogs: boolean;
    firewall: boolean;
    ids: boolean;
  };
  /**
   * Optional session identifier used to derive a globally-unique event ID
   * prefix. Without this, event IDs are `EVT-NNNNN` (only unique within a
   * single generator run). With this, event IDs become
   * `EVT-{sessionIdShort}-NNNNN`, which guarantees global uniqueness across
   * sessions (required by the DB's unique constraint on Event.eventId).
   */
  sessionId?: string;
}

export interface TelemetryGenerator {
  start(): void;
  stop(): void;
  onEvent(cb: (e: SecurityEvent) => void): void;
}

export function nextEventId(counter: number): string {
  return `EVT-${String(counter).padStart(5, "0")}`;
}

// ---- fake source IP pool (RFC1918 / lab-only)
const SOURCE_IPS = {
  normal: ["192.168.1.50", "192.168.1.51", "10.0.0.5", "172.16.5.8"],
  scanner: "192.168.10.20",
  bruteForcer: "192.168.10.20",
  webSpammer: "10.0.0.5",
  highVolume: "172.16.99.50",
};

function pickEphemeralPort(rand: () => number): number {
  return 32768 + Math.floor(rand() * 28000);
}

function pick<T>(arr: T[], rand: () => number): T {
  return arr[Math.floor(rand() * arr.length)];
}

// ---- phase definition
type Phase = 1 | 2 | 3 | 4 | 5;

function phaseFor(elapsedMs: number): Phase {
  const s = elapsedMs / 1000;
  if (s < 20) return 1;
  if (s < 40) return 2;
  if (s < 70) return 3;
  if (s < 100) return 4;
  return 5;
}

// ---- event factory
interface EventDraft {
  source: TelemetrySource | string;
  sourceIp: string;
  destPort: number;
  protocol: string;
  eventType: string;
  severity: Severity;
  message: string;
  sourcePort?: number;
  raw?: Record<string, unknown>;
}

function makeEvent(
  counter: number,
  cfg: TelemetryCollectorConfig,
  draft: EventDraft,
): SecurityEvent {
  // Base event ID per the spec helper. If a sessionId is provided we prefix
  // it with the short session id to guarantee global uniqueness across
  // sessions (DB enforces UNIQUE on Event.eventId).
  const base = nextEventId(counter);
  const sessionIdShort = cfg.sessionId ? cfg.sessionId.replace(/[^a-z0-9]/gi, "").slice(0, 8).toLowerCase() : "";
  const eventId = sessionIdShort
    ? `EVT-${sessionIdShort}-${String(counter).padStart(5, "0")}`
    : base;
  return {
    id: eventId,
    eventId,
    sessionId: null,
    timestamp: new Date().toISOString(),
    source: draft.source,
    sourceIp: draft.sourceIp,
    sourcePort: draft.sourcePort ?? null,
    destIp: cfg.targetAddress,
    destPort: draft.destPort,
    protocol: draft.protocol,
    eventType: draft.eventType,
    severity: draft.severity,
    status: "new",
    message: draft.message,
    isDemo: true,
    raw: draft.raw ?? null,
  };
}

// ---- phase-specific event generators
function genPhase1(cfg: TelemetryCollectorConfig, rand: () => number, counter: { value: number }): SecurityEvent[] {
  // Normal low-rate: 1 event/tick from random normal source to a baseline service
  const out: SecurityEvent[] = [];
  const srcIp = pick(SOURCE_IPS.normal, rand);
  const fallbackSvc: ServiceInfo = {
    id: "fallback-http",
    name: "http",
    port: 80,
    protocol: "tcp",
    product: null,
    version: null,
    extrainfo: null,
    method: "table",
    confidence: 50,
  };
  const svc: ServiceInfo = cfg.services.length ? pick(cfg.services, rand) : fallbackSvc;
  const eventType = rand() < 0.5 ? "connection" : "service_access";
  out.push(
    makeEvent(++counter.value, cfg, {
      source: "network",
      sourceIp: srcIp,
      sourcePort: pickEphemeralPort(rand),
      destPort: svc.port,
      protocol: svc.protocol || "tcp",
      eventType,
      severity: "info",
      message: `Normal ${svc.name} access from ${srcIp}`,
      raw: { service: svc.name },
    }),
  );
  // Occasionally a firewall allow log
  if (rand() < 0.3) {
    out.push(
      makeEvent(++counter.value, cfg, {
        source: "firewall",
        sourceIp: pick(SOURCE_IPS.normal, rand),
        destPort: svc.port,
        protocol: svc.protocol || "tcp",
        eventType: "log_entry",
        severity: "info",
        message: `Firewall ALLOW rule matched for ${svc.name} (port ${svc.port})`,
      }),
    );
  }
  return out;
}

function genPhase2(cfg: TelemetryCollectorConfig, rand: () => number, counter: { value: number }): SecurityEvent[] {
  // Scanner source hits multiple distinct ports per tick (RULE-001)
  const out: SecurityEvent[] = [];
  const count = 4 + Math.floor(rand() * 3); // 4-6
  const availablePorts = cfg.services.length
    ? cfg.services.map((s) => s.port)
    : [22, 80, 443, 3306, 8080, 53];
  // Shuffle ports so each tick explores different ports
  const shuffled = [...availablePorts].sort(() => rand() - 0.5);
  for (let i = 0; i < count; i++) {
    const port = shuffled[i % shuffled.length];
    const svc = cfg.services.find((s) => s.port === port);
    out.push(
      makeEvent(++counter.value, cfg, {
        source: "network",
        sourceIp: SOURCE_IPS.scanner,
        sourcePort: pickEphemeralPort(rand),
        destPort: port,
        protocol: svc?.protocol || "tcp",
        eventType: "port_probe",
        severity: "medium",
        message: `Port probe from ${SOURCE_IPS.scanner} to port ${port} (${svc?.name || "unknown"})`,
        raw: { service: svc?.name },
      }),
    );
  }
  return out;
}

function genPhase3(cfg: TelemetryCollectorConfig, rand: () => number, counter: { value: number }): SecurityEvent[] {
  // Repeated SSH auth failures from one source (RULE-003)
  const out: SecurityEvent[] = [];
  const authCount = 3 + Math.floor(rand() * 3); // 3-5
  const sshSvc = cfg.services.find((s) => s.port === 22) || { name: "ssh", port: 22, protocol: "tcp" };
  for (let i = 0; i < authCount; i++) {
    const usernames = ["root", "admin", "ubuntu", "user", "test", "postgres"];
    out.push(
      makeEvent(++counter.value, cfg, {
        source: "system_logs",
        sourceIp: SOURCE_IPS.bruteForcer,
        sourcePort: pickEphemeralPort(rand),
        destPort: 22,
        protocol: "tcp",
        eventType: "auth_failure",
        severity: "medium",
        message: `Failed SSH password for '${pick(usernames, rand)}' from ${SOURCE_IPS.bruteForcer} port ${pickEphemeralPort(rand)} ssh2`,
        raw: { service: sshSvc.name, username: pick(usernames, rand) },
      }),
    );
  }
  return out;
}

function genPhase4(cfg: TelemetryCollectorConfig, rand: () => number, counter: { value: number }): SecurityEvent[] {
  // HTTP request spike on port 80/8080 (RULE-004)
  const out: SecurityEvent[] = [];
  const count = 8 + Math.floor(rand() * 5); // 8-12
  const httpSvc = cfg.services.find((s) => s.port === 80 || s.port === 8080) || { port: 80, name: "http", protocol: "tcp" };
  const httpPort = (httpSvc.port === 80 || httpSvc.port === 8080) ? httpSvc.port : 80;
  const uris = ["/", "/admin", "/login", "/api/users", "/.env", "/wp-login.php", "/api/v1/health", "/index.html"];
  for (let i = 0; i < count; i++) {
    const srcIp = rand() < 0.85 ? SOURCE_IPS.webSpammer : pick(SOURCE_IPS.normal, rand);
    out.push(
      makeEvent(++counter.value, cfg, {
        source: "web_logs",
        sourceIp: srcIp,
        sourcePort: pickEphemeralPort(rand),
        destPort: httpPort,
        protocol: "tcp",
        eventType: "http_request",
        severity: "info",
        message: `GET ${pick(uris, rand)} from ${srcIp} (port ${httpPort})`,
        raw: { method: "GET", uri: pick(uris, rand), status: rand() < 0.7 ? 200 : 404 },
      }),
    );
  }
  return out;
}

function genPhase5(cfg: TelemetryCollectorConfig, rand: () => number, counter: { value: number }): SecurityEvent[] {
  // Sustained high connection rate (RULE-005)
  const out: SecurityEvent[] = [];
  const count = 10 + Math.floor(rand() * 6); // 10-15
  const availablePorts = cfg.services.length
    ? cfg.services.map((s) => s.port)
    : [22, 80, 443, 3306, 8080];
  for (let i = 0; i < count; i++) {
    const srcIp = pick([SOURCE_IPS.highVolume, SOURCE_IPS.scanner, ...SOURCE_IPS.normal], rand);
    const port = pick(availablePorts, rand);
    const svc = cfg.services.find((s) => s.port === port);
    out.push(
      makeEvent(++counter.value, cfg, {
        source: "network",
        sourceIp: srcIp,
        sourcePort: pickEphemeralPort(rand),
        destPort: port,
        protocol: svc?.protocol || "tcp",
        eventType: "connection",
        severity: "low",
        message: `High-rate connection from ${srcIp} to port ${port}`,
        raw: { service: svc?.name },
      }),
    );
  }
  // Occasionally a firewall deny
  if (rand() < 0.5) {
    out.push(
      makeEvent(++counter.value, cfg, {
        source: "firewall",
        sourceIp: SOURCE_IPS.highVolume,
        destPort: pick(availablePorts, rand),
        protocol: "tcp",
        eventType: "firewall_deny",
        severity: "medium",
        message: `Firewall DENY: suspicious source ${SOURCE_IPS.highVolume} rate-limited`,
      }),
    );
  }
  return out;
}

// ---- main generator factory
export function createTelemetryGenerator(config: TelemetryCollectorConfig): TelemetryGenerator {
  const callbacks = new Set<(e: SecurityEvent) => void>();
  let timer: ReturnType<typeof setInterval> | null = null;
  let startTime = 0;
  let stopped = true;
  const counter = { value: 0 };

  // Seeded PRNG so the same target produces the same narrative shape
  let seed = 2166136261;
  for (let i = 0; i < config.targetAddress.length; i++) {
    seed ^= config.targetAddress.charCodeAt(i);
    seed = Math.imul(seed, 16777619);
  }
  seed >>>= 0;
  const rand = () => {
    seed = (seed + 0x6d2b79f5) >>> 0;
    let t = seed;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  function tick(): void {
    if (stopped) return;
    const elapsed = Date.now() - startTime;
    const phase = phaseFor(elapsed);
    let events: SecurityEvent[] = [];
    switch (phase) {
      case 1:
        events = genPhase1(config, rand, counter);
        break;
      case 2:
        events = genPhase2(config, rand, counter);
        break;
      case 3:
        events = genPhase3(config, rand, counter);
        break;
      case 4:
        events = genPhase4(config, rand, counter);
        break;
      case 5:
        events = genPhase5(config, rand, counter);
        break;
    }
    for (const e of events) {
      for (const cb of callbacks) {
        try {
          cb(e);
        } catch (err) {
           
          console.error("[telemetry] onEvent callback error:", err);
        }
      }
    }
  }

  return {
    start() {
      if (!stopped) return;
      startTime = Date.now();
      stopped = false;
      counter.value = 0;
      // emit an initial tick immediately for responsiveness
      tick();
      timer = setInterval(tick, Math.max(250, config.intervalMs));
    },
    stop() {
      stopped = true;
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
    onEvent(cb) {
      callbacks.add(cb);
    },
  };
}
