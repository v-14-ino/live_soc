// ============================================================
// LiveSOC - Telemetry Adapter Abstraction
//
// A "TelemetryAdapter" is a pluggable collector that produces
// SecurityEvent objects from a REAL telemetry source (nmap scan,
// journald tail, nginx access log tail, iptables LOG target tail,
// Suricata/Zeek EVE.json tail). Each adapter is self-contained:
//   * checkAvailability() probes the environment WITHOUT throwing.
//   * start() begins producing events and returns a stop handle.
//   * validateConfig() returns a list of human-readable issues.
//
// The existing demo generator (`src/lib/monitoring/telemetry.ts`)
// remains the default event source for monitoring sessions. The
// adapters are additive — they provide a production path for real
// telemetry when the underlying tools/files are available.
//
// SAFETY CONTRACT (every adapter MUST honour):
//   * Never use `exec` or `shell: true`. Always `execFile` or
//     `spawn` with an explicit argument array.
//   * Never execute user input as a shell command.
//   * `checkAvailability()` MUST NOT throw — wrap everything in
//     try/catch and return `{ available: false, reason }`.
//   * `start()` MUST validate `config.targetAddress` via
//     `validateTarget()` from `@/lib/monitoring/scanner` BEFORE
//     touching any system resource.
//   * Adapters MUST degrade gracefully when the underlying tool or
//     file does not exist (sandbox-friendly).
// ============================================================

import type { SecurityEvent, TelemetrySource } from "@/lib/types";

/** Canonical adapter names. */
export type AdapterName = "nmap" | "journald" | "nginx" | "iptables" | "suricata";

/** Result of probing an adapter's environment. */
export interface AdapterStatus {
  available: boolean;
  /** Why the adapter is unavailable (only set when available=false). */
  reason?: string;
  /** Detected tool version or readable path (only when available=true). */
  version?: string;
  /** ISO timestamp of when the check was performed. */
  checkedAt: string;
}

/** Adapter configuration. The `options` bag is adapter-specific. */
export interface AdapterConfig {
  /** Authorized lab target address (validated by `validateTarget`). */
  targetAddress: string;
  /** Adapter-specific options as a JSON object. */
  options?: Record<string, unknown>;
  /** Default polling / scan interval in ms (adapters may ignore). */
  intervalMs?: number;
}

/** Handle returned by `start()` — used to stop the adapter and inspect its state. */
export interface AdapterHandle {
  /** Stop the adapter (idempotent). */
  stop(): void;
  /** True while the adapter is still producing events. */
  isRunning: boolean;
  /** Number of events emitted since start(). */
  eventsEmitted: number;
  /** ISO timestamp of the last emitted event (if any). */
  lastEventAt?: string;
  /** Last error encountered by the adapter (if any). */
  lastError?: string;
}

/** The adapter contract. */
export interface TelemetryAdapter {
  readonly name: AdapterName;
  readonly displayName: string;
  readonly description: string;
  readonly sourceType: TelemetrySource;
  /** True if the adapter needs non-default config (e.g. a log path). */
  readonly requiresConfig: boolean;

  /**
   * Probe the environment (binary exists, log file readable, etc.).
   * MUST NOT throw. Returns a fresh AdapterStatus.
   */
  checkAvailability(): Promise<AdapterStatus>;

  /**
   * Start collecting events. Calls `onEvent` for each new event.
   * Returns a handle whose `stop()` halts the adapter.
   */
  start(
    config: AdapterConfig,
    onEvent: (e: SecurityEvent) => void,
  ): Promise<AdapterHandle>;

  /**
   * Validate the adapter's configuration. Returns a list of
   * human-readable issues; an empty list means OK.
   */
  validateConfig(config: AdapterConfig): string[];
}

/** Metadata describing an adapter (subset of TelemetryAdapter, safe for JSON). */
export interface AdapterMetadata {
  name: AdapterName;
  displayName: string;
  description: string;
  sourceType: TelemetrySource;
  requiresConfig: boolean;
}

/** Adapter metadata + a (possibly cached) status snapshot. */
export interface AdapterInfo extends AdapterMetadata {
  status: AdapterStatus;
}

/** Extract the metadata subset from a full adapter. */
export function adapterMetadata(a: TelemetryAdapter): AdapterMetadata {
  return {
    name: a.name,
    displayName: a.displayName,
    description: a.description,
    sourceType: a.sourceType,
    requiresConfig: a.requiresConfig,
  };
}
