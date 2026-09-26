// ============================================================
// LiveSOC - Journald (System Logs) Adapter
//
// Tails the Linux journald log stream via `journalctl -f -o json
// --no-pager`. Each JSON line is mapped to a SecurityEvent.
//
// Common log patterns are mapped to typed eventTypes:
//   * "Failed password" → auth_failure (severity high)
//   * "Accepted password" / "Accepted publickey" → auth_success (info)
//   * "session opened" / "session closed" → log_entry (info)
//   * message contains "error" → log_entry (medium)
//   * anything else → log_entry (severity from PRIORITY)
//
// SAFETY:
//   * Uses `spawn` (never `exec`, never `shell: true`).
//   * Argument list is a hard-coded whitelist; the only user-
//     influenced argument is an optional `units` filter array,
//     which is sanitised to `-u <name>` entries (validated as
//     `[a-zA-Z0-9_.@-]+`).
//   * stop() kills the spawned child + removes listeners.
//
// The adapter degrades gracefully when journalctl is not installed.
// ============================================================

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import type { SecurityEvent, Severity, TelemetrySource } from "@/lib/types";
import { validateTarget } from "@/lib/monitoring/scanner";
import type { AdapterConfig, AdapterHandle, AdapterStatus, TelemetryAdapter } from "./base";
import { execFileP, extractIpFromMessage, makeAdapterEvent, mapPriorityToSeverity } from "./util";

const ADAPTER_NAME = "journald" as const;
const SOURCE_TYPE: TelemetrySource = "system_logs";

const JOURNAL_DIRS = ["/var/log/journal", "/run/log/journal"];
const UNIT_NAME_RE = /^[a-zA-Z0-9_.@-]{1,128}$/;

interface JournaldEntry {
  __REALTIME_TIMESTAMP?: string;
  _SYSTEMD_UNIT?: string;
  SYSLOG_IDENTIFIER?: string;
  MESSAGE?: string;
  PRIORITY?: string | number;
  _HOSTNAME?: string;
  _PID?: string;
  [k: string]: unknown;
}

export class JournaldAdapter implements TelemetryAdapter {
  readonly name = ADAPTER_NAME;
  readonly displayName = "System Logs (journald)";
  readonly description =
    "Tails `journalctl -f -o json --no-pager` and maps entries (auth, service, error) to security events.";
  readonly sourceType = SOURCE_TYPE;
  readonly requiresConfig = false;

  async checkAvailability(): Promise<AdapterStatus> {
    const checkedAt = new Date().toISOString();
    // Step 1: binary check.
    try {
      const { stdout } = await execFileP("journalctl", ["--version"], { timeoutMs: 3_000 });
      const m = /systemd\s+(\d+)/i.exec(stdout);
      const version = m ? `systemd ${m[1]}` : "journalctl (version unknown)";
      // Step 2: persistent or volatile journal dir present?
      const journalDir = JOURNAL_DIRS.find((d) => existsSync(d));
      if (!journalDir) {
        return {
          available: false,
          reason: "journalctl installed but no /var/log/journal or /run/log/journal directory exists",
          version,
          checkedAt,
        };
      }
      return { available: true, version, checkedAt };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const reason = /ENOENT/i.test(msg)
        ? "journalctl binary not found"
        : `journalctl not usable: ${msg.split("\n")[0] ?? "unknown error"}`;
      return { available: false, reason, checkedAt };
    }
  }

  validateConfig(config: AdapterConfig): string[] {
    const issues: string[] = [];

    // journald is a host-local log stream. We don't enforce localhost
    // here because logs may be forwarded via journald-remote; we only
    // validate that a targetAddress was supplied (used as destIp).
    const v = validateTarget(config.targetAddress ?? "");
    if (!v.ok) {
      issues.push(`Invalid target: ${v.reason ?? "validation failed"}`);
    }

    // Optional `units` filter must be a list of valid unit names.
    const units = config.options?.units;
    if (units !== undefined) {
      if (!Array.isArray(units) || units.some((u) => typeof u !== "string" || !UNIT_NAME_RE.test(u))) {
        issues.push("options.units must be an array of systemd unit name strings");
      }
    }

    return issues;
  }

  async start(
    config: AdapterConfig,
    onEvent: (e: SecurityEvent) => void,
  ): Promise<AdapterHandle> {
    const issues = this.validateConfig(config);
    if (issues.length > 0) {
      throw new Error(`Invalid journald adapter config: ${issues.join("; ")}`);
    }

    const targetAddress = config.targetAddress;
    const unitsRaw = config.options?.units;
    const units: string[] =
      Array.isArray(unitsRaw) && unitsRaw.every((u) => typeof u === "string" && UNIT_NAME_RE.test(u))
        ? (unitsRaw as string[])
        : [];

    // Build the argument whitelist. Only `-u <name>` entries are
    // data-influenced and they are strictly validated above.
    const args: string[] = ["-f", "-o", "json", "--no-pager"];
    for (const u of units) {
      args.push("-u", u);
    }

    let child: ChildProcessWithoutNullStreams | null = null;
    let stopped = false;
    let buffer = "";

    const handle: AdapterHandle = {
      isRunning: true,
      eventsEmitted: 0,
      stop: () => {
        if (stopped) return;
        stopped = true;
        handle.isRunning = false;
        if (child && !child.killed) {
          try {
            child.kill("SIGTERM");
          } catch {
            /* ignore */
          }
        }
      },
    };

    try {
      child = spawn("journalctl", args, {
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
        shell: false,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      handle.lastError = msg;
      handle.isRunning = false;
      // Emit a single error event so the operator sees the failure.
      onEvent(
        makeAdapterEvent(ADAPTER_NAME, {
          source: SOURCE_TYPE,
          eventType: "log_error",
          severity: "high",
          message: `journald adapter failed to spawn journalctl: ${msg.split("\n")[0] ?? "unknown error"}`,
          destIp: targetAddress,
          raw: { error: msg },
        }),
      );
      handle.eventsEmitted = 1;
      handle.lastEventAt = new Date().toISOString();
      return handle;
    }

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      if (stopped) return;
      buffer += chunk;
      let nl = buffer.indexOf("\n");
      while (nl >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        nl = buffer.indexOf("\n");
        if (line) {
          const ev = parseJournaldLine(line, targetAddress);
          if (ev) {
            try {
              onEvent(ev);
              handle.eventsEmitted += 1;
              handle.lastEventAt = new Date().toISOString();
            } catch (cbErr) {
              // never let a downstream callback error kill the stream
              handle.lastError = cbErr instanceof Error ? cbErr.message : String(cbErr);
            }
          }
        }
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8").trim();
      if (text) {
        handle.lastError = text.split("\n")[0];
      }
    });

    child.on("error", (err) => {
      handle.lastError = err.message;
    });
    child.on("close", () => {
      handle.isRunning = false;
    });

    return handle;
  }
}

/**
 * Parse a single `journalctl -o json` line into a SecurityEvent.
 * Returns null if the line is malformed or has no MESSAGE.
 */
function parseJournaldLine(line: string, destIp: string): SecurityEvent | null {
  let entry: JournaldEntry;
  try {
    entry = JSON.parse(line) as JournaldEntry;
  } catch {
    return null;
  }
  const message = typeof entry.MESSAGE === "string" ? entry.MESSAGE : "";
  if (!message) return null;

  const unit = entry._SYSTEMD_UNIT ?? entry.SYSLOG_IDENTIFIER ?? "journald";
  const priority = entry.PRIORITY;
  const lower = message.toLowerCase();

  // Classify by common log patterns.
  let eventType = "log_entry";
  let severity: Severity = mapPriorityToSeverity(priority);
  if (lower.includes("failed password") || lower.includes("authentication failure")) {
    eventType = "auth_failure";
    severity = "high";
  } else if (lower.includes("accepted password") || lower.includes("accepted publickey")) {
    eventType = "auth_success";
    severity = "info";
  } else if (lower.includes("session opened") || lower.includes("session closed")) {
    eventType = "log_entry";
    severity = "info";
  } else if (lower.includes("error") || lower.includes("failed")) {
    eventType = "log_entry";
    severity = "medium";
  }

  const sourceIp = extractIpFromMessage(message);

  // journald timestamps are microseconds since epoch.
  let timestamp: string | undefined;
  if (entry.__REALTIME_TIMESTAMP) {
    const us = parseInt(entry.__REALTIME_TIMESTAMP, 10);
    if (Number.isFinite(us)) {
      timestamp = new Date(us / 1000).toISOString();
    }
  }

  return makeAdapterEvent(ADAPTER_NAME, {
    source: SOURCE_TYPE,
    eventType,
    severity,
    message: `[${unit}] ${message}`,
    sourceIp,
    destIp,
    destPort: null,
    protocol: null,
    timestamp,
    raw: {
      unit,
      priority: priority ?? null,
      hostname: entry._HOSTNAME ?? null,
      pid: entry._PID ?? null,
      syslogIdentifier: entry.SYSLOG_IDENTIFIER ?? null,
    },
  });
}
