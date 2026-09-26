// ============================================================
// LiveSOC - Adapter shared utilities
//
// Helpers used by every adapter implementation:
//   * `execFileP` — promise-wrapped child_process.execFile with a
//     hard timeout. Never throws `shell` injection (no shell used).
//   * `isFileReadable` — fs.accessSync-based readable probe.
//   * `mapPriorityToSeverity` — syslog PRIORITY → Severity.
//   * `mapHttpStatusToSeverity` — HTTP status → Severity.
//   * `extractIpFromMessage` — best-effort IPv4 extraction from a
//     free-form log line.
//   * `makeAdapterEvent` — builds a SecurityEvent with the adapter
//     convention (eventId prefixed with the adapter name + counter,
//     isDemo=false because these are REAL telemetry events).
// ============================================================

import { execFile } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { randomUUID } from "node:crypto";
import type { SecurityEvent, Severity, TelemetrySource } from "@/lib/types";

/**
 * Promise-wrapped execFile. Resolves with { stdout, stderr } on
 * success, rejects on error or non-zero exit. Never uses a shell.
 *
 * `timeoutMs` aborts the child after the given delay; the resulting
 * Error will have `killed: true` and `signal: "SIGTERM"`.
 */
export function execFileP(
  file: string,
  args: string[],
  options: { timeoutMs?: number; maxBufferMb?: number } = {},
): Promise<{ stdout: string; stderr: string }> {
  const { timeoutMs = 5_000, maxBufferMb = 4 } = options;
  return new Promise((resolve, reject) => {
    execFile(
      file,
      args,
      {
        timeout: timeoutMs,
        maxBuffer: Math.max(1, maxBufferMb) * 1024 * 1024,
        windowsHide: true,
        shell: false, // never use a shell
      },
      (err, stdout, stderr) => {
        if (err) {
          reject(err);
          return;
        }
        resolve({ stdout: String(stdout ?? ""), stderr: String(stderr ?? "") });
      },
    );
  });
}

/** Non-throwing readable probe for a file path. */
export function isFileReadable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/** Map a syslog PRIORITY (0-7) to LiveSOC severity. */
export function mapPriorityToSeverity(priority: number | string | undefined): Severity {
  const p = typeof priority === "string" ? parseInt(priority, 10) : priority;
  if (!Number.isFinite(p)) return "info";
  if (p <= 1) return "critical"; // 0=emerg, 1=alert
  if (p === 2) return "critical"; // 2=crit
  if (p <= 4) return "high"; // 3=err, 4=warning
  if (p <= 6) return "medium"; // 5=notice, 6=info
  return "low"; // 7=debug
}

/** Map an HTTP status code to LiveSOC severity. */
export function mapHttpStatusToSeverity(status: number): Severity {
  if (status >= 500) return "high";
  if (status >= 400) return "medium";
  if (status >= 200 && status < 400) return "info";
  return "info";
}

const IPV4_RE = /\b((?:\d{1,3}\.){3}\d{1,3})\b/;

/** Best-effort IPv4 extraction from a free-form log message. */
export function extractIpFromMessage(message: string): string | null {
  const m = IPV4_RE.exec(message ?? "");
  if (!m) return null;
  const octets = m[1].split(".").map((o) => parseInt(o, 10));
  if (octets.some((o) => o > 255)) return null;
  return m[1];
}

/** Build a SecurityEvent from adapter-emitted pieces. */
export interface MakeAdapterEventInput {
  source: TelemetrySource | string;
  eventType: string;
  severity: Severity;
  message: string;
  destIp?: string | null;
  destPort?: number | null;
  sourceIp?: string | null;
  sourcePort?: number | null;
  protocol?: string | null;
  timestamp?: string;
  raw?: Record<string, unknown> | null;
}

/**
 * Construct a SecurityEvent with adapter conventions:
 *   * `eventId` = `EVT-ADAPT-{adapterName}-{uuid8}` (globally unique)
 *   * `id` = same as `eventId` (the DB will replace this on persist)
 *   * `isDemo` = false (these are REAL telemetry events)
 *   * `status` = "new"
 *   * `sessionId` = null (the session manager stamps this on ingest)
 */
export function makeAdapterEvent(
  adapterName: string,
  input: MakeAdapterEventInput,
): SecurityEvent {
  const shortUuid = randomUUID().replace(/-/g, "").slice(0, 12);
  const eventId = `EVT-ADAPT-${adapterName}-${shortUuid}`;
  return {
    id: eventId,
    eventId,
    sessionId: null,
    timestamp: input.timestamp ?? new Date().toISOString(),
    source: input.source,
    sourceIp: input.sourceIp ?? null,
    sourcePort: input.sourcePort ?? null,
    destIp: input.destIp ?? null,
    destPort: input.destPort ?? null,
    protocol: input.protocol ?? null,
    eventType: input.eventType,
    severity: input.severity,
    status: "new",
    message: input.message,
    isDemo: false,
    raw: input.raw ?? null,
  };
}

/**
 * Read a numeric option from an AdapterConfig.options bag, with
 * bounds validation. Returns the clamped value or the default.
 */
export function readNumberOption(
  options: Record<string, unknown> | undefined,
  key: string,
  def: number,
  min: number,
  max: number,
): number {
  const raw = options?.[key];
  const n = typeof raw === "number" ? raw : typeof raw === "string" ? parseFloat(raw) : NaN;
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

/** Read a string option from an AdapterConfig.options bag, with a default. */
export function readStringOption(
  options: Record<string, unknown> | undefined,
  key: string,
  def: string,
): string {
  const raw = options?.[key];
  return typeof raw === "string" && raw.length > 0 ? raw : def;
}
