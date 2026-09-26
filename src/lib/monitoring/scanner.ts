// ============================================================
// LiveSOC - Initial Assessment Scanner (safe deterministic mock)
//
// Authorized defensive monitoring ONLY. No real network calls,
// no shell execution. Produces reproducible, clearly-labeled
// assessment output derived from a stable hash of the target
// address so the same target always yields the same baseline.
// ============================================================

import type { AssessmentResult, PortInfo, ServiceInfo } from "@/lib/types";

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

export async function runAssessment(
  targetAddress: string,
  options: RunAssessmentOptions,
): Promise<AssessmentResult> {
  const seed = hashString(targetAddress);
  const rand = mulberry32(seed);

  // latency 1-25 ms
  const latencyMs = Math.floor(1 + rand() * 25);

  // 3-8 open ports
  const portCount = Math.max(3, Math.min(8, 3 + Math.floor(rand() * 6)));

  // deterministic shuffle of catalog (Fisher-Yates with seeded rand)
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

  // hostname derived from address hash
  const prefix = HOSTNAME_PREFIXES[seed % HOSTNAME_PREFIXES.length];
  const hostnameNum = (seed % 100).toString().padStart(2, "0");
  const hostname = `${prefix}-${hostnameNum}`;

  // OS guess influenced by which OS hints appeared most often
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

  const now = new Date();
  const startedAt = new Date(now.getTime() - Math.min(options.timeoutSec, 5) * 1000);

  return {
    id: stableId("asm", targetAddress),
    targetId: stableId("tgt", targetAddress),
    status: "completed",
    reachability: "reachable",
    latencyMs,
    hostname,
    osGuess,
    startedAt: startedAt.toISOString(),
    completedAt: now.toISOString(),
    ports,
    services,
  };
}
