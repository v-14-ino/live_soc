// ============================================================
// LiveSOC - iptables / Firewall Logs Adapter
//
// Tails the kernel log (kern.log, messages, or `dmesg --follow`)
// and parses lines emitted by iptables `-j LOG` rules:
//
//   ... IN=<iface> OUT= ... MAC=... SRC=<ip> DST=<ip> LEN=...
//   TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=<port> DPT=<port>
//   WINDOW=65535 RES=0x00 SYN URGP=0
//
// Each matching line becomes a SecurityEvent with eventType
// `firewall_deny` (DROP/REJECT) or `firewall_allow` (ACCEPT).
//
// SAFETY:
//   * No shell. Tail uses `fs` + `fs.watch` for files, and
//     `spawn('dmesg', ['--follow'])` for the kernel ring buffer.
//     The dmesg argument list is a hard-coded whitelist.
//   * The log path is validated to be a non-empty string.
//
// The adapter degrades gracefully when no kernel log is available.
// ============================================================

import { createReadStream, promises as fs } from "node:fs";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import type { SecurityEvent, Severity, TelemetrySource } from "@/lib/types";
import { validateTarget } from "@/lib/monitoring/scanner";
import type { AdapterConfig, AdapterHandle, AdapterStatus, TelemetryAdapter } from "./base";
import { execFileP, isFileReadable, makeAdapterEvent, readStringOption } from "./util";

const ADAPTER_NAME = "iptables" as const;
const SOURCE_TYPE: TelemetrySource = "firewall";

const DEFAULT_LOG_PATHS = [
  "/var/log/kern.log",
  "/var/log/messages",
  "/var/log/syslog",
];

// iptables LOG target line. We only require the IN=, SRC=, DST=, DPT= groups.
const IPTABLES_RE =
  /IN=(\S*)\s+OUT=(\S*).*?SRC=(\S+).*?DST=(\S+).*?(?:PROTO=(\S+))?.*?(?:SPT=(\d+))?.*?DPT=(\d+)/;

export class IptablesAdapter implements TelemetryAdapter {
  readonly name = ADAPTER_NAME;
  readonly displayName = "Firewall Logs (iptables)";
  readonly description =
    "Tails kernel logs (kern.log / messages / dmesg) for iptables LOG target entries and emits firewall allow/deny events.";
  readonly sourceType = SOURCE_TYPE;
  readonly requiresConfig = true;

  async checkAvailability(): Promise<AdapterStatus> {
    const checkedAt = new Date().toISOString();
    const path = DEFAULT_LOG_PATHS.find((p) => isFileReadable(p));
    if (path) {
      return { available: true, version: path, checkedAt };
    }
    // Fallback: dmesg binary usable? (used for `dmesg --follow`)
    try {
      await execFileP("dmesg", ["--version"], { timeoutMs: 2_000 });
      return { available: true, version: "dmesg --follow", checkedAt };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const reason = /ENOENT/i.test(msg)
        ? "No readable kern.log/messages/syslog and dmesg binary not found"
        : `Firewall log not available: ${msg.split("\n")[0] ?? "unknown error"}`;
      return { available: false, reason, checkedAt };
    }
  }

  validateConfig(config: AdapterConfig): string[] {
    const issues: string[] = [];

    const v = validateTarget(config.targetAddress ?? "");
    if (!v.ok) {
      issues.push(`Invalid target: ${v.reason ?? "validation failed"}`);
    }

    const logPath = readStringOption(config.options, "logPath", "");
    const source = readStringOption(config.options, "source", "auto");
    if (source !== "auto" && source !== "file" && source !== "dmesg") {
      issues.push('options.source must be "auto", "file", or "dmesg"');
    }
    if (source === "file" && !logPath) {
      issues.push("options.logPath is required when source=file");
    }

    return issues;
  }

  async start(
    config: AdapterConfig,
    onEvent: (e: SecurityEvent) => void,
  ): Promise<AdapterHandle> {
    const issues = this.validateConfig(config);
    if (issues.length > 0) {
      throw new Error(`Invalid iptables adapter config: ${issues.join("; ")}`);
    }

    const targetAddress = config.targetAddress;
    const logPath = readStringOption(config.options, "logPath", "");
    const source = readStringOption(config.options, "source", "auto");

    // Resolve the effective source: file > dmesg > auto-detect.
    let effectiveSource: "file" | "dmesg" = "dmesg";
    let effectivePath: string | null = logPath || DEFAULT_LOG_PATHS.find((p) => isFileReadable(p)) || null;
    if (source === "file") {
      if (!effectivePath) {
        throw new Error("iptables adapter: source=file but no readable log path");
      }
      effectiveSource = "file";
    } else if (source === "dmesg") {
      effectiveSource = "dmesg";
      effectivePath = null;
    } else {
      // auto
      if (effectivePath) {
        effectiveSource = "file";
      } else {
        effectiveSource = "dmesg";
      }
    }

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
        if (child && !child.killed) {
          try {
            child.kill("SIGTERM");
          } catch {
            /* ignore */
          }
        }
      },
    };

    let stopped = false;
    let watcher: ReturnType<typeof import("node:fs").watch> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let child: ChildProcessWithoutNullStreams | null = null;
    let buffer = "";

    const emitLine = (line: string): void => {
      if (stopped) return;
      const ev = parseIptablesLine(line, targetAddress);
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

    if (effectiveSource === "file" && effectivePath) {
      // File tail mode.
      let lastSize = 0;
      try {
        const stat = await fs.stat(effectivePath);
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
            message: `Firewall log adapter cannot stat ${effectivePath}: ${msg.split("\n")[0] ?? "unknown error"}`,
            destIp: targetAddress,
            raw: { logPath: effectivePath, error: msg },
          }),
        );
        handle.eventsEmitted = 1;
        handle.lastEventAt = new Date().toISOString();
        return handle;
      }

      const readNew = async (): Promise<void> => {
        if (stopped) return;
        let stat: Awaited<ReturnType<typeof fs.stat>>;
        try {
          stat = await fs.stat(effectivePath!);
        } catch {
          return;
        }
        if (stat.size <= lastSize) {
          if (stat.size < lastSize) lastSize = 0;
          return;
        }
        const start = lastSize;
        const length = stat.size - lastSize;
        lastSize = stat.size;
        void length;
        try {
          const stream = createReadStream(effectivePath!, { start, end: stat.size - 1, encoding: "utf8" });
          let data = "";
          for await (const chunk of stream) {
            data += chunk as string;
          }
          // Prepend any leftover buffer from a previous partial line.
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
        watcher = fsSync.watch(effectivePath, { persistent: false }, () => {
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
    } else {
      // dmesg --follow mode.
      try {
        child = spawn("dmesg", ["--follow", "--time-format", "iso"], {
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
          shell: false,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        handle.lastError = msg;
        handle.isRunning = false;
        onEvent(
          makeAdapterEvent(ADAPTER_NAME, {
            source: SOURCE_TYPE,
            eventType: "log_error",
            severity: "high",
            message: `Firewall log adapter failed to spawn dmesg: ${msg.split("\n")[0] ?? "unknown error"}`,
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
          if (line) emitLine(line);
        }
      });
      child.stderr.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8").trim();
        if (text) handle.lastError = text.split("\n")[0];
      });
      child.on("error", (err) => {
        handle.lastError = err.message;
      });
      child.on("close", () => {
        handle.isRunning = false;
      });
    }

    return handle;
  }
}

/** Parse an iptables LOG target line. Returns null if no match. */
function parseIptablesLine(line: string, destIp: string): SecurityEvent | null {
  const m = IPTABLES_RE.exec(line);
  if (!m) return null;
  const [, _inIface, _outIface, src, dst, proto, spt, dpt] = m;
  void _inIface;
  void _outIface;
  if (!src || !dst || !dpt) return null;

  // Heuristic: if the surrounding line mentions DROP/REJECT → deny,
  // ACCEPT → allow; default to deny for LOG targets (most LOG rules
  // are placed on DROP/REJECT chains).
  const lower = line.toLowerCase();
  let eventType = "firewall_deny";
  let severity: Severity = "medium";
  if (lower.includes("accept")) {
    eventType = "firewall_allow";
    severity = "info";
  } else if (lower.includes("drop") || lower.includes("reject")) {
    eventType = "firewall_deny";
    severity = "medium";
  }

  const destPort = parseInt(dpt, 10);
  const sourcePort = spt ? parseInt(spt, 10) : null;

  return makeAdapterEvent(ADAPTER_NAME, {
    source: SOURCE_TYPE,
    eventType,
    severity,
    message: `Firewall ${eventType === "firewall_deny" ? "DENY" : "ALLOW"} ${proto ?? "tcp"} ${src}:${spt ?? "*"} → ${dst}:${dpt}`,
    sourceIp: src,
    destIp: dst,
    destPort: Number.isFinite(destPort) ? destPort : null,
    sourcePort: sourcePort && Number.isFinite(sourcePort) ? sourcePort : null,
    protocol: proto ?? "tcp",
    raw: {
      inInterface: _inIface || null,
      outInterface: _outIface || null,
      src,
      dst,
      proto: proto ?? "tcp",
      spt: spt ?? null,
      dpt,
      rawLine: line.slice(0, 1024),
    },
  });
}
