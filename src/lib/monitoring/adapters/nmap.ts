// ============================================================
// LiveSOC - Nmap Scanner Adapter
//
// Wraps the `nmap` binary for REAL port/service discovery on
// authorized lab targets. This is a ONE-SHOT scan: it runs once,
// emits a single `scan_complete` SecurityEvent with the discovered
// ports in `raw`, then the handle's `isRunning` becomes false.
//
// SAFETY:
//   * Uses `execFile` (never `exec`, never `shell: true`).
//   * Validates the target via `validateTarget()` BEFORE invoking
//     nmap — only lab ranges (RFC1918 / loopback / lab TLDs) are
//     accepted. Public IPs are rejected.
//   * Argument list is a hard-coded whitelist. The only user-
//     influenced argument is the target address (validated) and the
//     top-ports integer (bounds-checked).
//   * The scan runs with a hard timeout (default 30s, max 300s).
//   * No `-O`, no `--script`, no `--traceroute`, no NSE — pure
//     service/version discovery.
//
// The adapter degrades gracefully when nmap is not installed.
// ============================================================

import type { SecurityEvent, TelemetrySource } from "@/lib/types";
import { validateTarget } from "@/lib/monitoring/scanner";
import type { AdapterConfig, AdapterHandle, AdapterStatus, TelemetryAdapter } from "./base";
import { execFileP, makeAdapterEvent, readNumberOption } from "./util";

const ADAPTER_NAME = "nmap" as const;
const SOURCE_TYPE: TelemetrySource = "scanner";

interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  product?: string | null;
  version?: string | null;
  extrainfo?: string | null;
}

export class NmapAdapter implements TelemetryAdapter {
  readonly name = ADAPTER_NAME;
  readonly displayName = "Nmap Scanner";
  readonly description =
    "Runs `nmap -sV --top-ports <N> -Pn <target>` for real port/service discovery. One-shot scan per start().";
  readonly sourceType = SOURCE_TYPE;
  readonly requiresConfig = false;

  async checkAvailability(): Promise<AdapterStatus> {
    const checkedAt = new Date().toISOString();
    try {
      const { stdout } = await execFileP("nmap", ["--version"], { timeoutMs: 3_000 });
      // Output looks like:
      //   Nmap version 7.94 ( https://nmap.org )
      //   Nmap --version ...
      const m = /Nmap version\s+(\S+)/.exec(stdout);
      return {
        available: true,
        version: m ? `nmap ${m[1]}` : "nmap (version unknown)",
        checkedAt,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // ENOENT means binary not found; anything else (timeout, non-zero exit)
      // is still "unavailable" for our purposes.
      const reason = /ENOENT/i.test(msg)
        ? "nmap binary not found"
        : `nmap not usable: ${msg.split("\n")[0] ?? "unknown error"}`;
      return { available: false, reason, checkedAt };
    }
  }

  validateConfig(config: AdapterConfig): string[] {
    const issues: string[] = [];

    const v = validateTarget(config.targetAddress ?? "");
    if (!v.ok) {
      issues.push(`Invalid target: ${v.reason ?? "validation failed"}`);
    }

    const topPorts = readNumberOption(config.options, "topPorts", 100, 1, 65535);
    if (topPorts < 1 || topPorts > 65535) {
      issues.push("topPorts must be an integer between 1 and 65535");
    }

    const timeoutSec = readNumberOption(config.options, "timeoutSec", 30, 5, 300);
    if (timeoutSec < 5 || timeoutSec > 300) {
      issues.push("timeoutSec must be between 5 and 300 seconds");
    }

    return issues;
  }

  async start(
    config: AdapterConfig,
    onEvent: (e: SecurityEvent) => void,
  ): Promise<AdapterHandle> {
    // Validate config (fail fast).
    const issues = this.validateConfig(config);
    if (issues.length > 0) {
      throw new Error(`Invalid nmap adapter config: ${issues.join("; ")}`);
    }

    const topPorts = readNumberOption(config.options, "topPorts", 100, 1, 65535);
    const timeoutSec = readNumberOption(config.options, "timeoutSec", 30, 5, 300);
    const targetAddress = config.targetAddress;

    const handle: AdapterHandle = {
      isRunning: true,
      eventsEmitted: 0,
      stop: () => {
        // No long-lived process to kill (execFileP already resolved or
        // will resolve shortly). Mark as not running for caller UX.
        handle.isRunning = false;
      },
    };

    // Build the nmap argument list — STRICT whitelist. No user input
    // reaches a shell. The target address is validated above.
    const args: string[] = [
      "-sV", // service/version detection
      "-T3", // timing template: normal
      "--top-ports",
      String(topPorts),
      "-Pn", // skip host discovery (we already know the target is up)
      "-oG",
      "-", // grepable output to stdout
      targetAddress,
    ];

    try {
      const { stdout } = await execFileP("nmap", args, {
        timeoutMs: timeoutSec * 1000,
        maxBufferMb: 8,
      });
      const ports = parseGrepable(stdout);
      const event: SecurityEvent = makeAdapterEvent(ADAPTER_NAME, {
        source: SOURCE_TYPE,
        eventType: "scan_complete",
        severity: "info",
        message: `nmap scan of ${targetAddress} completed: ${ports.length} open port(s) discovered`,
        destIp: targetAddress,
        protocol: null,
        raw: {
          target: targetAddress,
          topPorts,
          openPorts: ports.length,
          ports,
        },
      });
      onEvent(event);
      handle.eventsEmitted = 1;
      handle.lastEventAt = new Date().toISOString();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // Emit a single error event so the operator UI surfaces the failure.
      const errorEvent: SecurityEvent = makeAdapterEvent(ADAPTER_NAME, {
        source: SOURCE_TYPE,
        eventType: "scan_error",
        severity: "medium",
        message: `nmap scan of ${targetAddress} failed: ${msg.split("\n")[0] ?? "unknown error"}`,
        destIp: targetAddress,
        raw: { target: targetAddress, error: msg },
      });
      onEvent(errorEvent);
      handle.eventsEmitted = 1;
      handle.lastEventAt = new Date().toISOString();
      handle.lastError = msg;
    } finally {
      handle.isRunning = false;
    }

    return handle;
  }
}

/**
 * Parse nmap grepable output (`-oG -`) into a list of discovered
 * ports. Grepable lines look like:
 *
 *   Host: 192.168.1.100 (lab-01)	Status: Up
 *   Host: 192.168.1.100 (lab-01)	Ports: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu 4ubuntu0.1; protocol 2.0/, 80/open/tcp//http//nginx 1.18.0///
 *
 * Only ports whose state is "open" are returned.
 */
function parseGrepable(stdout: string): NmapPort[] {
  const ports: NmapPort[] = [];
  const lines = stdout.split(/\r?\n/);
  for (const line of lines) {
    if (!line.startsWith("Host:")) continue;
    const portsIdx = line.indexOf("Ports:");
    if (portsIdx < 0) continue;
    const portsBlob = line.slice(portsIdx + "Ports:".length).trim();
    // Each port entry is comma-separated, fields are slash-separated:
    //   port/state/proto//owner//service//sunrpc_info//version//
    const entries = portsBlob.split(/,\s*/);
    for (const entry of entries) {
      const parts = entry.split("/");
      if (parts.length < 3) continue;
      const portNum = parseInt(parts[0], 10);
      const state = parts[1];
      const proto = parts[2];
      const service = parts[3] ?? "";
      // version blob = parts[6] in older grepable, parts[7] in newer
      const versionStr = parts.slice(4).join("/").trim();
      if (!Number.isFinite(portNum) || portNum <= 0) continue;
      if (state !== "open") continue;
      let product: string | null = null;
      let version: string | null = null;
      let extrainfo: string | null = null;
      if (versionStr) {
        // Heuristic: "nginx 1.18.0" or "OpenSSH 8.9p1 Ubuntu 4ubuntu0.1; protocol 2.0"
        const semi = versionStr.indexOf(";");
        const main = semi >= 0 ? versionStr.slice(0, semi).trim() : versionStr;
        const extra = semi >= 0 ? versionStr.slice(semi + 1).trim() : null;
        const sp = main.indexOf(" ");
        if (sp > 0) {
          product = main.slice(0, sp);
          version = main.slice(sp + 1).trim() || null;
        } else {
          product = main || null;
        }
        extrainfo = extra;
      }
      ports.push({
        port: portNum,
        protocol: proto || "tcp",
        state,
        service: service || "unknown",
        product,
        version,
        extrainfo,
      });
    }
  }
  return ports;
}
