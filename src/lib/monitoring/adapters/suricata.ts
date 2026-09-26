// ============================================================
// LiveSOC - Suricata / Zeek IDS Adapter
//
// Tails the Suricata EVE.json log (one JSON object per line) and
// emits a SecurityEvent for every `event_type: "alert"` entry.
//
// Example EVE.json alert line:
// {
//   "timestamp": "2023-10-10T13:55:36.123456+0000",
//   "event_type": "alert",
//   "src_ip": "192.168.1.50",
//   "src_port": 54321,
//   "dest_ip": "192.168.1.100",
//   "dest_port": 22,
//   "proto": "TCP",
//   "alert": {
//     "severity": 1,                    // 1=high, 2=medium, 3=low
//     "signature": "ET POLICY Suspicious SSH connection",
//     "signature_id": 2000001,
//     "category": "Attempted Information Leak"
//   }
// }
//
// SAFETY:
//   * No shell. Pure `fs` + `fs.watch`.
//   * The eveJsonPath is validated to be a non-empty string.
//
// The adapter degrades gracefully when no EVE.json is readable.
// ============================================================

import { createReadStream, promises as fs } from "node:fs";
import type { SecurityEvent, Severity, TelemetrySource } from "@/lib/types";
import { validateTarget } from "@/lib/monitoring/scanner";
import type { AdapterConfig, AdapterHandle, AdapterStatus, TelemetryAdapter } from "./base";
import { execFileP, isFileReadable, makeAdapterEvent, readStringOption } from "./util";

const ADAPTER_NAME = "suricata" as const;
const SOURCE_TYPE: TelemetrySource = "ids";

const DEFAULT_EVE_PATHS = [
  "/var/log/suricata/eve.json",
  "/var/log/suricata/eve",
  "/var/log/zeek/current/notice.log",
];

interface EveAlert {
  severity?: number;
  signature?: string;
  signature_id?: number;
  category?: string;
  action?: string;
}

interface EveEntry {
  timestamp?: string;
  event_type?: string;
  src_ip?: string;
  src_port?: number;
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  alert?: EveAlert;
}

export class SuricataAdapter implements TelemetryAdapter {
  readonly name = ADAPTER_NAME;
  readonly displayName = "IDS (Suricata/Zeek)";
  readonly description =
    "Tails Suricata eve.json (or Zeek notice.log) and emits IDS alert events for every alert entry.";
  readonly sourceType = SOURCE_TYPE;
  readonly requiresConfig = true;

  async checkAvailability(): Promise<AdapterStatus> {
    const checkedAt = new Date().toISOString();
    const path = DEFAULT_EVE_PATHS.find((p) => isFileReadable(p));
    if (path) {
      return { available: true, version: path, checkedAt };
    }
    // Fallback: suricata binary present?
    try {
      const { stdout } = await execFileP("suricata", ["--version"], { timeoutMs: 2_000 });
      const m = /suricata\s+(\S+)/i.exec(stdout);
      return {
        available: false,
        reason: "suricata binary installed but no readable eve.json found at default paths",
        version: m ? `suricata ${m[1]}` : "suricata (version unknown)",
        checkedAt,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const reason = /ENOENT/i.test(msg)
        ? "No readable eve.json and suricata binary not found"
        : `IDS log not available: ${msg.split("\n")[0] ?? "unknown error"}`;
      return { available: false, reason, checkedAt };
    }
  }

  validateConfig(config: AdapterConfig): string[] {
    const issues: string[] = [];

    const v = validateTarget(config.targetAddress ?? "");
    if (!v.ok) {
      issues.push(`Invalid target: ${v.reason ?? "validation failed"}`);
    }

    const eveJsonPath = readStringOption(config.options, "eveJsonPath", "");
    if (!eveJsonPath) {
      issues.push("options.eveJsonPath is required (e.g. /var/log/suricata/eve.json)");
    }

    return issues;
  }

  async start(
    config: AdapterConfig,
    onEvent: (e: SecurityEvent) => void,
  ): Promise<AdapterHandle> {
    const issues = this.validateConfig(config);
    if (issues.length > 0) {
      throw new Error(`Invalid suricata adapter config: ${issues.join("; ")}`);
    }

    const targetAddress = config.targetAddress;
    const eveJsonPath = readStringOption(config.options, "eveJsonPath", "");

    const handle: AdapterHandle = {
      isRunning: true,
      eventsEmitted: 0,
      stop: () => {
        if (stopped) return;
        stopped = true;
        handle.isRunning = false;
        if (watcher) {
          try {
            watcher.close();
          } catch {
            /* ignore */
          }
        }
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      },
    };

    let stopped = false;
    let watcher: ReturnType<typeof import("node:fs").watch> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let lastSize = 0;
    let buffer = "";

    try {
      const stat = await fs.stat(eveJsonPath);
      lastSize = stat.size;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      handle.lastError = msg;
      handle.isRunning = false;
      onEvent(
        makeAdapterEvent(ADAPTER_NAME, {
          source: SOURCE_TYPE,
          eventType: "log_error",
          severity: "high",
          message: `IDS adapter cannot stat ${eveJsonPath}: ${msg.split("\n")[0] ?? "unknown error"}`,
          destIp: targetAddress,
          raw: { eveJsonPath, error: msg },
        }),
      );
      handle.eventsEmitted = 1;
      handle.lastEventAt = new Date().toISOString();
      return handle;
    }

    const emitLine = (line: string): void => {
      if (stopped) return;
      const ev = parseEveLine(line, targetAddress);
      if (ev) {
        try {
          onEvent(ev);
          handle.eventsEmitted += 1;
          handle.lastEventAt = new Date().toISOString();
        } catch (cbErr) {
          handle.lastError = cbErr instanceof Error ? cbErr.message : String(cbErr);
        }
      }
    };

    const readNew = async (): Promise<void> => {
      if (stopped) return;
      let stat: Awaited<ReturnType<typeof fs.stat>>;
      try {
        stat = await fs.stat(eveJsonPath);
      } catch {
        return;
      }
      if (stat.size <= lastSize) {
        if (stat.size < lastSize) lastSize = 0;
        return;
      }
      const start = lastSize;
      lastSize = stat.size;
      try {
        const stream = createReadStream(eveJsonPath, { start, end: stat.size - 1, encoding: "utf8" });
        let data = "";
        for await (const chunk of stream) {
          data += chunk as string;
        }
        data = buffer + data;
        const lines = data.split(/\r?\n/);
        buffer = lines.pop() ?? "";
        for (const ln of lines) {
          const line = ln.trim();
          if (line) emitLine(line);
        }
      } catch (err) {
        handle.lastError = err instanceof Error ? err.message : String(err);
      }
    };

    try {
      const fsSync = await import("node:fs");
      watcher = fsSync.watch(eveJsonPath, { persistent: false }, () => {
        void readNew();
      });
      watcher.on("error", () => {
        /* swallow — poll fallback covers us */
      });
    } catch {
      // No inotify available; rely on polling.
    }

    pollTimer = setInterval(() => {
      void readNew();
    }, 2_000);

    void readNew();

    return handle;
  }
}

/** Map a Suricata severity (1=high, 2=medium, 3=low) to LiveSOC severity. */
function mapSuricataSeverity(s: number | undefined): Severity {
  if (s === undefined || !Number.isFinite(s)) return "medium";
  if (s <= 1) return "high";
  if (s === 2) return "medium";
  return "low";
}

/** Parse a single eve.json line. Returns null if not an alert or malformed. */
function parseEveLine(line: string, fallbackDestIp: string): SecurityEvent | null {
  let entry: EveEntry;
  try {
    entry = JSON.parse(line) as EveEntry;
  } catch {
    return null;
  }
  if (entry.event_type !== "alert" || !entry.alert) return null;

  const alert = entry.alert;
  const severity = mapSuricataSeverity(alert.severity);
  const signature = alert.signature ?? "Unknown signature";
  const sid = alert.signature_id ?? 0;
  const category = alert.category ?? null;
  const proto = (entry.proto ?? "TCP").toLowerCase();

  // Parse the Suricata timestamp: "2023-10-10T13:55:36.123456+0000"
  let timestamp: string | undefined;
  if (entry.timestamp) {
    // Suricata uses "+0000" not "+00:00"; normalise for Date.
    const normalised = entry.timestamp.replace(/([+-])(\d{2})(\d{2})$/, "$1$2:$3");
    const d = new Date(normalised);
    if (!Number.isNaN(d.getTime())) timestamp = d.toISOString();
  }

  return makeAdapterEvent(ADAPTER_NAME, {
    source: SOURCE_TYPE,
    eventType: "ids_alert",
    severity,
    message: `${signature} [SID:${sid}]`,
    sourceIp: entry.src_ip ?? null,
    destIp: entry.dest_ip ?? fallbackDestIp,
    destPort: entry.dest_port ?? null,
    sourcePort: entry.src_port ?? null,
    protocol: proto,
    timestamp,
    raw: {
      signature,
      signatureId: sid,
      category,
      severity: alert.severity ?? null,
      action: alert.action ?? null,
      srcIp: entry.src_ip ?? null,
      destIp: entry.dest_ip ?? null,
      srcPort: entry.src_port ?? null,
      destPort: entry.dest_port ?? null,
      proto,
    },
  });
}
