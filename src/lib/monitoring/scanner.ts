// ============================================================
// LiveSOC - Initial Assessment Scanner
//
// Authorized defensive monitoring ONLY.
//
// PHASE A: Now attempts a REAL nmap scan first (via safe
// execFile with a strict argument whitelist). Falls back to
// the deterministic mock when nmap is not installed or the
// scan fails. The scanner field in the result indicates
// which path was used ("nmap" vs "mock").
//
// Safety:
//   * No shell execution. Uses execFile with explicit args.
//   * Target is validated via validateTarget() BEFORE nmap.
//   * Argument list is a hard-coded whitelist.
//   * No -O, no --script, no NSE — pure service/version discovery.
// ============================================================

import type { AssessmentResult, PortInfo, ServiceInfo } from "@/lib/types";
import { execFile } from "child_process";

// Realistic authorized-assessment service catalog. Discovery only.
interface CatalogEntry {
  port: number;
  name: string;
  product: string;
  version: string;
  extrainfo?: string;
  protocol: "tcp" | "udp";
  osHint?: "linux" | "windows" | "mixed";
}

const PORT_CATALOG: CatalogEntry[] = [
  { port: 22, name: "ssh", product: "OpenSSH", version: "8.9p1", extrainfo: "Ubuntu 4ubuntu0.1; protocol 2.0", protocol: "tcp", osHint: "linux" },
  { port: 80, name: "http", product: "nginx", version: "1.18.0", protocol: "tcp", osHint: "linux" },
  { port: 443, name: "https", product: "nginx", version: "1.18.0", extrainfo: "TLS 1.3", protocol: "tcp", osHint: "linux" },
  { port: 3306, name: "mysql", product: "MySQL", version: "8.0.34", extrainfo: "protocol 10", protocol: "tcp", osHint: "linux" },
  { port: 5432, name: "postgresql", product: "PostgreSQL DB", version: "14.9", protocol: "tcp", osHint: "linux" },
  { port: 6379, name: "redis", product: "Redis key-value store", version: "7.0.11", protocol: "tcp", osHint: "linux" },
  { port: 8080, name: "http-proxy", product: "Apache Tomcat", version: "9.0.71", protocol: "tcp", osHint: "mixed" },
  { port: 8443, name: "https-alt", product: "Apache Tomcat", version: "9.0.71", extrainfo: "TLS 1.2", protocol: "tcp", osHint: "mixed" },
  { port: 21, name: "ftp", product: "vsftpd", version: "3.0.5", protocol: "tcp", osHint: "linux" },
  { port: 25, name: "smtp", product: "Postfix smtpd", version: "3.6.4", protocol: "tcp", osHint: "linux" },
  { port: 53, name: "domain", product: "dnsmasq", version: "2.86", protocol: "udp", osHint: "linux" },
  { port: 111, name: "rpcbind", product: "rpcbind", version: "2-4", extrainfo: "rpc 100000", protocol: "tcp", osHint: "linux" },
  { port: 139, name: "netbios-ssn", product: "Samba smbd", version: "4.6.2", extrainfo: "workgroup: WORKGROUP", protocol: "tcp", osHint: "mixed" },
  { port: 445, name: "microsoft-ds", product: "Samba smbd", version: "4.6.2", extrainfo: "workgroup: WORKGROUP", protocol: "tcp", osHint: "mixed" },
  { port: 3389, name: "ms-wbt-server", product: "Microsoft Terminal Service", version: "", protocol: "tcp", osHint: "windows" },
  { port: 5900, name: "vnc", product: "VNC", version: "", extrainfo: "protocol 3.8", protocol: "tcp", osHint: "mixed" },
];

const OS_GUESSES = [
  "Linux 5.x (Ubuntu 22.04)",
  "Linux 5.x (Debian 11)",
  "Linux 4.x (CentOS 7)",
  "Windows Server 2019",
  "Windows 10",
  "FreeBSD 13.1",
  "Generic Linux 3.x",
];

const HOSTNAME_PREFIXES = ["lab", "srv", "app", "db", "web", "infra", "edge"];

// ---- deterministic hashing & PRNG (no real randomness; reproducible baselines)

function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function mulberry32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function stableId(prefix: string, ...parts: (string | number)[]): string {
  const base = parts.join("|");
  return `${prefix}-${hashString(base).toString(36)}`;
}

// ---- target validation

export interface ValidateTargetResult {
  ok: boolean;
  reason?: string;
  targetType: "ip" | "domain" | "localhost";
  isLab: boolean;
}

const LAB_TLDS = [".lab", ".local", ".internal", ".test", ".example", ".invalid", ".home", ".lan", ".corp"];

export function validateTarget(address: string): ValidateTargetResult {
  const addr = (address || "").trim().toLowerCase();
  if (!addr) {
    return { ok: false, reason: "Empty target address", targetType: "ip", isLab: false };
  }

  // localhost keyword
  if (addr === "localhost") {
    return { ok: true, targetType: "localhost", isLab: true };
  }

  // IPv4 form
  const ipMatch = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (ipMatch) {
    const oct = [parseInt(ipMatch[1], 10), parseInt(ipMatch[2], 10), parseInt(ipMatch[3], 10), parseInt(ipMatch[4], 10)];
    if (oct.some((v) => v > 255)) {
      return { ok: false, reason: "Invalid IP octet range", targetType: "ip", isLab: false };
    }
    const [a, b] = oct;
    // loopback (treat as localhost-equivalent for authorized lab)
    if (a === 127) {
      return { ok: true, targetType: "localhost", isLab: true };
    }
    // unspecified / loopback-abuse
    if (a === 0) {
      return { ok: false, reason: "Unspecified address (0.0.0.0) is not allowed", targetType: "ip", isLab: false };
    }
    // link-local
    if (a === 169 && b === 254) {
      return { ok: false, reason: "Link-local addresses are not supported", targetType: "ip", isLab: false };
    }
    // private ranges
    if (a === 10) return { ok: true, targetType: "ip", isLab: true };
    if (a === 192 && b === 168) return { ok: true, targetType: "ip", isLab: true };
    if (a === 172 && b >= 16 && b <= 31) return { ok: true, targetType: "ip", isLab: true };
    return {
      ok: false,
      reason: "Public IP addresses are outside the authorized lab scope",
      targetType: "ip",
      isLab: false,
    };
  }

  // domain form
  const domainRegex = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
  if (!domainRegex.test(addr)) {
    return {
      ok: false,
      reason: "Invalid domain format",
      targetType: "domain",
      isLab: false,
    };
  }
  const isLab = LAB_TLDS.some((tld) => addr.endsWith(tld));
  if (!isLab) {
    return {
      ok: false,
      reason: "Domain does not look like a lab host. Use a TLD like .lab, .local, .internal, .test, or .example.",
      targetType: "domain",
      isLab: false,
    };
  }
  return { ok: true, targetType: "domain", isLab: true };
}

// ---- assessment runner

export interface RunAssessmentOptions {
  timeoutSec: number;
  topPorts: number;
  isDemo: boolean;
}

// ============================================================
// PHASE A — Real nmap execution
//
// Runs `nmap -sV -T3 --top-ports N -Pn -oX - <target>` (XML to stdout).
// Uses execFile (never shell). Returns null if nmap is not installed
// or the scan fails — the caller falls back to the mock.
// ============================================================

interface NmapResult {
  ports: PortInfo[];
  services: ServiceInfo[];
  hostname: string | null;
  osGuess: string | null;
  scannerVersion: string | null;
  latencyMs: number | null;
  durationMs: number;
  error?: string;
}

function execFilePAsync(cmd: string, args: string[], opts: { timeout: number; maxBuffer: number }): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, opts, (err, stdout, stderr) => {
      if (err) reject(err);
      else resolve({ stdout, stderr });
    });
  });
}

async function runRealNmap(
  targetAddress: string,
  options: RunAssessmentOptions,
): Promise<NmapResult | null> {
  const startedAt = Date.now();
  try {
    // First check nmap version
    let versionStr: string | null = null;
    try {
      const { stdout: versionOut } = await execFilePAsync("nmap", ["--version"], {
        timeout: 3000,
        maxBuffer: 1024 * 1024,
      });
      const m = /Nmap version\s+(\S+)/.exec(versionOut);
      versionStr = m ? `nmap ${m[1]}` : "nmap (version unknown)";
    } catch {
      return null; // nmap not installed
    }

    // Run the scan with XML output
    const args = [
      "-sV",           // service/version detection
      "-T3",           // timing template: normal
      "--top-ports",
      String(Math.min(65535, Math.max(1, options.topPorts))),
      "-Pn",           // skip host discovery
      "-oX",           // XML output
      "-",             // to stdout
      targetAddress,   // validated target
    ];

    const { stdout } = await execFilePAsync("nmap", args, {
      timeout: options.timeoutSec * 1000,
      maxBuffer: 16 * 1024 * 1024,
    });

    const durationMs = Date.now() - startedAt;
    const parsed = parseNmapXml(stdout);
    return {
      ...parsed,
      scannerVersion: versionStr,
      latencyMs: null,
      durationMs,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ports: [],
      services: [],
      hostname: null,
      osGuess: null,
      scannerVersion: null,
      latencyMs: null,
      durationMs: Date.now() - startedAt,
      error: msg,
    };
  }
}

/**
 * Parse nmap XML output into ports + services.
 * Uses regex-based parsing (no DOM dependency) for robustness.
 */
function parseNmapXml(xml: string): {
  ports: PortInfo[];
  services: ServiceInfo[];
  hostname: string | null;
  osGuess: string | null;
} {
  const ports: PortInfo[] = [];
  const services: ServiceInfo[] = [];

  // Extract hostname from <hostname name="..." type="..."/>
  let hostname: string | null = null;
  const hostMatch = /<hostname\s+name="([^"]+)"/.exec(xml);
  if (hostMatch) hostname = hostMatch[1];

  // Extract OS guess from <osmatch name="..." />
  let osGuess: string | null = null;
  const osMatch = /<osmatch\s+name="([^"]+)"/.exec(xml);
  if (osMatch) osGuess = osMatch[1];

  // Extract ports from <port protocol="tcp" portid="22">...<state state="open"/>...<service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="..."/></port>
  const portRegex = /<port\s+protocol="([^"]+)"\s+portid="(\d+)">[\s\S]*?<state\s+state="([^"]+)"[\s\S]*?(?:<service\s+([^/]*?)\/>)?/g;
  let match: RegExpExecArray | null;
  while ((match = portRegex.exec(xml)) !== null) {
    const protocol = match[1];
    const portNum = parseInt(match[2], 10);
    const state = match[3];
    const serviceAttrs = match[4] || "";

    if (state !== "open") continue;
    if (!Number.isFinite(portNum) || portNum <= 0) continue;

    // Parse service attributes: name="ssh" product="OpenSSH" version="8.9p1" extrainfo="..."
    const nameMatch = /name="([^"]+)"/.exec(serviceAttrs);
    const productMatch = /product="([^"]+)"/.exec(serviceAttrs);
    const versionMatch = /version="([^"]+)"/.exec(serviceAttrs);
    const extrainfoMatch = /extrainfo="([^"]+)"/.exec(serviceAttrs);

    const serviceName = nameMatch ? nameMatch[1] : "unknown";
    const product = productMatch ? productMatch[1] : null;
    const version = versionMatch ? versionMatch[1] : null;
    const extrainfo = extrainfoMatch ? extrainfoMatch[1] : null;

    ports.push({
      id: `port-${portNum}-${protocol}`,
      number: portNum,
      protocol,
      state,
      serviceName,
    });

    services.push({
      id: `svc-${portNum}-${serviceName}`,
      name: serviceName,
      port: portNum,
      protocol,
      product,
      version,
      extrainfo,
      method: "probe",
      confidence: 80,
    });
  }

  return { ports, services, hostname, osGuess };
}

export async function runAssessment(
  targetAddress: string,
  options: RunAssessmentOptions,
): Promise<AssessmentResult> {
  const now = new Date();
  const startedAt = new Date();

  // ============================================================
  // PHASE A: Try real nmap first
  // ============================================================
  const nmapResult = await runRealNmap(targetAddress, options);
  if (nmapResult && nmapResult.ports.length > 0 && !nmapResult.error) {
    return {
      id: `asm-${hashString(targetAddress).toString(36)}`,
      targetId: `tgt-${hashString(targetAddress).toString(36)}`,
      status: "completed",
      reachability: "reachable",
      latencyMs: nmapResult.latencyMs,
      hostname: nmapResult.hostname,
      osGuess: nmapResult.osGuess,
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      ports: nmapResult.ports,
      services: nmapResult.services,
      scanner: "nmap",
      scannerVersion: nmapResult.scannerVersion,
      scanDurationMs: nmapResult.durationMs,
      scanError: null,
    };
  }

  // ============================================================
  // FALLBACK: Deterministic mock (nmap not installed or scan failed)
  // ============================================================
  const seed = hashString(targetAddress);
  const rand = mulberry32(seed);

  const latencyMs = Math.floor(1 + rand() * 25);
  const portCount = Math.max(3, Math.min(8, 3 + Math.floor(rand() * 6)));

  const catalog = [...PORT_CATALOG];
  for (let i = catalog.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [catalog[i], catalog[j]] = [catalog[j], catalog[i]];
  }
  const chosen = catalog.slice(0, portCount);

  const ports: PortInfo[] = chosen.map((p) => ({
    id: stableId("port", targetAddress, p.port, p.protocol),
    number: p.port,
    protocol: p.protocol,
    state: "open",
    serviceName: p.name,
  }));

  const services: ServiceInfo[] = chosen.map((p) => ({
    id: stableId("svc", targetAddress, p.port, p.name),
    name: p.name,
    port: p.port,
    protocol: p.protocol,
    product: p.product,
    version: p.version || null,
    extrainfo: p.extrainfo || null,
    method: "probe",
    confidence: 75 + Math.floor(rand() * 20),
  }));

  const prefix = HOSTNAME_PREFIXES[seed % HOSTNAME_PREFIXES.length];
  const hostnameNum = (seed % 100).toString().padStart(2, "0");
  const hostname = `${prefix}-${hostnameNum}`;

  const osHints = chosen.map((c) => c.osHint ?? "linux");
  const linuxCount = osHints.filter((h) => h === "linux").length;
  const windowsCount = osHints.filter((h) => h === "windows").length;
  let osGuess: string;
  if (windowsCount > linuxCount) {
    osGuess = "Windows Server 2019";
  } else if (linuxCount > 0 && windowsCount === 0) {
    osGuess = rand() > 0.5 ? "Linux 5.x (Ubuntu 22.04)" : "Linux 5.x (Debian 11)";
  } else {
    osGuess = OS_GUESSES[seed % OS_GUESSES.length];
  }

  const mockStartedAt = new Date(now.getTime() - Math.min(options.timeoutSec, 5) * 1000);

  return {
    id: stableId("asm", targetAddress),
    targetId: stableId("tgt", targetAddress),
    status: "completed",
    reachability: "reachable",
    latencyMs,
    hostname,
    osGuess,
    startedAt: mockStartedAt.toISOString(),
    completedAt: now.toISOString(),
    ports,
    services,
    scanner: "mock",
    scannerVersion: null,
    scanDurationMs: Date.now() - startedAt.getTime(),
    scanError: nmapResult?.error ?? (nmapResult ? "nmap scan returned no open ports" : "nmap not installed — using mock"),
  };
}
