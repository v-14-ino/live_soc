// ============================================================
// LiveSOC - Nginx / Apache Web Logs Adapter
//
// Tails a web server access log and parses each new line into a
// SecurityEvent. Supports two log formats:
//   * "combined" (nginx default): $remote_addr - $remote_user
//     [$time_local] "$request" $status $body_bytes_sent
//     "$http_referer" "$http_user_agent"
//   * "common": $remote_addr - $remote_user [$time_local]
//     "$request" $status $body_bytes_sent
//
// The tail uses `fs.watch` plus a small polling fallback so it
// works on filesystems where inotify is unavailable. Lines are
// only parsed AFTER the file size grows past our last read offset.
//
// SAFETY:
//   * No shell, no exec. Pure `fs` + `fs.watch`.
//   * The log path is validated to be a non-empty string. The
//     adapter will refuse to start if the path is not readable.
//
// The adapter degrades gracefully when no log file is readable.
// ============================================================

import { createReadStream, promises as fs } from "node:fs";
import type { SecurityEvent, TelemetrySource } from "@/lib/types";
import { validateTarget } from "@/lib/monitoring/scanner";
import type { AdapterConfig, AdapterHandle, AdapterStatus, TelemetryAdapter } from "./base";
import { isFileReadable, makeAdapterEvent, mapHttpStatusToSeverity, readStringOption } from "./util";

const ADAPTER_NAME = "nginx" as const;
const SOURCE_TYPE: TelemetrySource = "web_logs";

const DEFAULT_LOG_PATHS = [
  "/var/log/nginx/access.log",
  "/var/log/apache2/access.log",
  "/var/log/httpd/access_log",
];

// Regexes capture named groups for the standard log formats.
// Combined: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
const COMBINED_RE =
  /^(?<ip>\S+)\s+\S+\s+(?<user>\S+)\s+\[(?<time>[^\]]+)\]\s+"(?<request>[^"]*)"\s+(?<status>\d{3})\s+(?<bytes>\S+)\s+"(?<referer>[^"]*)"\s+"(?<ua>[^"]*)"\s*$/;

// Common: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
const COMMON_RE =
  /^(?<ip>\S+)\s+\S+\s+(?<user>\S+)\s+\[(?<time>[^\]]+)\]\s+"(?<request>[^"]*)"\s+(?<status>\d{3})\s+(?<bytes>\S+)\s*$/;

interface ParsedLine {
  ip: string;
  user: string;
  time: string;
  request: string;
  status: number;
  bytes: string;
  referer?: string;
  ua?: string;
}

export class NginxAdapter implements TelemetryAdapter {
  readonly name = ADAPTER_NAME;
  readonly displayName = "Web Logs (nginx/apache)";
  readonly description =
    "Tails nginx/apache access logs and parses combined or common format lines into HTTP request events.";
  readonly sourceType = SOURCE_TYPE;
  readonly requiresConfig = true;

  async checkAvailability(): Promise<AdapterStatus> {
    const checkedAt = new Date().toISOString();
    // If the user has supplied a logPath in config, prefer it; otherwise
    // probe the default locations.
    const path = DEFAULT_LOG_PATHS.find((p) => isFileReadable(p));
    if (!path) {
      return {
        available: false,
        reason: "No readable access log found at default paths (nginx/apache2/httpd). Configure options.logPath to point at your access log.",
        checkedAt,
      };
    }
    return {
      available: true,
      version: path,
      checkedAt,
    };
  }

  validateConfig(config: AdapterConfig): string[] {
    const issues: string[] = [];

    const v = validateTarget(config.targetAddress ?? "");
    if (!v.ok) {
      issues.push(`Invalid target: ${v.reason ?? "validation failed"}`);
    }

    const logPath = readStringOption(config.options, "logPath", "");
    if (!logPath) {
      issues.push("options.logPath is required (e.g. /var/log/nginx/access.log)");
    }

    const parser = readStringOption(config.options, "parser", "combined");
    if (parser !== "combined" && parser !== "common") {
      issues.push('options.parser must be "combined" or "common"');
    }

    return issues;
  }

  async start(
    config: AdapterConfig,
    onEvent: (e: SecurityEvent) => void,
  ): Promise<AdapterHandle> {
    const issues = this.validateConfig(config);
    if (issues.length > 0) {
      throw new Error(`Invalid nginx adapter config: ${issues.join("; ")}`);
    }

    const targetAddress = config.targetAddress;
    const logPath = readStringOption(config.options, "logPath", "");
    const parser = readStringOption(config.options, "parser", "combined");
    const tls = config.options?.tls === true || config.options?.port === 443;

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

    try {
      const stat = await fs.stat(logPath);
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
          message: `Web log adapter cannot stat ${logPath}: ${msg.split("\n")[0] ?? "unknown error"}`,
          destIp: targetAddress,
          raw: { logPath, error: msg },
        }),
      );
      handle.eventsEmitted = 1;
      handle.lastEventAt = new Date().toISOString();
      return handle;
    }

    // Tail new content. We use fs.watch for low-latency change
    // notification, plus a 2s poll fallback for filesystems without
    // inotify (or where fs.watch is unreliable).
    const readNew = async (): Promise<void> => {
      if (stopped) return;
      let stat: Awaited<ReturnType<typeof fs.stat>>;
      try {
        stat = await fs.stat(logPath);
      } catch {
        return; // file vanished; will retry on next poll
      }
      if (stat.size <= lastSize) {
        // truncated? reset to 0 so we read from the top after rotation
        if (stat.size < lastSize) lastSize = 0;
        return;
      }
      const start = lastSize;
      const length = stat.size - lastSize;
      lastSize = stat.size;

      try {
        const stream = createReadStream(logPath, { start, end: stat.size - 1, encoding: "utf8" });
        let data = "";
        for await (const chunk of stream) {
          data += chunk as string;
        }
        const lines = data.split(/\r?\n/);
        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line) continue;
          const ev = parseLine(line, parser, targetAddress, tls);
          if (ev) {
            try {
              onEvent(ev);
              handle.eventsEmitted += 1;
              handle.lastEventAt = new Date().toISOString();
            } catch (cbErr) {
              handle.lastError = cbErr instanceof Error ? cbErr.message : String(cbErr);
            }
          }
        }
      } catch (err) {
        handle.lastError = err instanceof Error ? err.message : String(err);
      }
    };

    try {
      // The dynamic import keeps this from breaking in environments
      // that statically analyse node:fs at build time.
      const fsSync = await import("node:fs");
      watcher = fsSync.watch(logPath, { persistent: false }, () => {
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

    // Initial drain (in case the file already has new content since stat).
    void readNew();

    return handle;
  }
}

/** Parse a single access-log line into a SecurityEvent, or null if it doesn't match. */
function parseLine(
  line: string,
  parser: "combined" | "common",
  destIp: string,
  tls: boolean,
): SecurityEvent | null {
  const re = parser === "combined" ? COMBINED_RE : COMMON_RE;
  const m = re.exec(line);
  if (!m || !m.groups) return null;
  const g = m.groups as ParsedLine;
  const status = parseInt(g.status, 10);
  if (!Number.isFinite(status)) return null;

  // Decompose the request line into method + path.
  const reqParts = g.request.split(/\s+/);
  const method = reqParts[0] ?? "GET";
  const path = reqParts[1] ?? "/";
  const proto = reqParts[2] ?? "HTTP/1.1";

  // Map common attack paths to higher severity.
  let severity = mapHttpStatusToSeverity(status);
  if (/\/\.env|\/wp-login\.php|\/admin\/?(\?|$)/i.test(path) && status >= 400) {
    severity = "high";
  }

  // Parse the time_local format: "10/Oct/2023:13:55:36 +0000"
  let timestamp: string | undefined;
  const timeMatch = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/.exec(g.time);
  if (timeMatch) {
    const [_, dd, mon, yyyy, hh, mm, ss, tz] = timeMatch;
    void _;
    const months: Record<string, string> = {
      Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
      Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
    };
    const mo = months[mon] ?? "01";
    const tzSign = tz.slice(0, 1);
    const tzH = tz.slice(1, 3);
    const tzM = tz.slice(3, 5);
    const isoTz = `${tzSign}${tzH}:${tzM}`;
    const iso = `${yyyy}-${mo}-${dd}T${hh}:${mm}:${ss}${isoTz}`;
    const d = new Date(iso);
    if (!Number.isNaN(d.getTime())) timestamp = d.toISOString();
  }

  return makeAdapterEvent(ADAPTER_NAME, {
    source: SOURCE_TYPE,
    eventType: "http_request",
    severity,
    message: `${method} ${path} → ${status}`,
    sourceIp: g.ip,
    destIp,
    destPort: tls ? 443 : 80,
    protocol: "tcp",
    timestamp,
    raw: {
      method,
      path,
      protocol: proto,
      status,
      bytes: g.bytes === "-" ? 0 : parseInt(g.bytes, 10) || 0,
      user: g.user === "-" ? null : g.user,
      referer: g.referer && g.referer !== "-" ? g.referer : null,
      userAgent: g.ua && g.ua !== "-" ? g.ua : null,
    },
  });
}
