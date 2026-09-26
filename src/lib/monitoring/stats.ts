// ============================================================
// LiveSOC - KPI & Network Activity Stats
//
// Pure functions over a slice of recent events. O(n) over the
// windowed slice.
// ============================================================

import type {
  KpiStats,
  NetworkActivityStats,
  ProtocolDistribution,
  SecurityEvent,
  TopItem,
} from "@/lib/types";

const SEVERITY_KEYS = ["critical", "high", "medium", "low"] as const;

export function computeKpi(
  events: SecurityEvent[],
  openPorts: number,
  activeConnections: number,
): KpiStats {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let info = 0;
  const nowMs = Date.now();
  let eventsInLast1s = 0;
  let trafficBytes = 0;

  for (const e of events) {
    switch (e.severity) {
      case "critical":
        critical++;
        break;
      case "high":
        high++;
        break;
      case "medium":
        medium++;
        break;
      case "low":
        low++;
        break;
      default:
        info++;
        break;
    }
    const t = Date.parse(e.timestamp);
    if (nowMs - t <= 1000) eventsInLast1s++;
    // Estimate per-event traffic: HTTP ~2KB, connection ~1KB, log ~256B
    if (e.eventType === "http_request") trafficBytes += 2048;
    else if (e.eventType === "connection" || e.eventType === "port_probe" || e.eventType === "service_access") trafficBytes += 1024;
    else trafficBytes += 256;
  }

  // Compute traffic rate over the window covered by events (max 60s)
  const windowSec = Math.min(60, events.length > 0 ? 60 : 1);
  const trafficRate = +(trafficBytes / 1024 / windowSec).toFixed(2);

  return {
    events: events.length,
    critical,
    high,
    medium,
    low,
    info,
    activeConnections,
    eventsPerSec: +eventsInLast1s.toFixed(2),
    trafficRate,
    openPorts,
  };
}

function topN(items: Map<string, number>, n: number): TopItem[] {
  return Array.from(items.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

export function computeNetworkActivity(
  events: SecurityEvent[],
  windowMs = 60_000,
): NetworkActivityStats {
  const nowMs = Date.now();
  const cutoff = nowMs - windowMs;
  // Filter to window
  const windowed: SecurityEvent[] = [];
  for (const e of events) {
    const t = Date.parse(e.timestamp);
    if (t >= cutoff) windowed.push(e);
  }

  const protocolMap = new Map<string, number>();
  const srcIpMap = new Map<string, number>();
  const destPortMap = new Map<string, number>();
  let connectionCount = 0;
  let requestCount = 0;
  let trafficBytes = 0;

  for (const e of windowed) {
    const proto = e.protocol ?? "tcp";
    protocolMap.set(proto, (protocolMap.get(proto) ?? 0) + 1);
    if (e.sourceIp) srcIpMap.set(e.sourceIp, (srcIpMap.get(e.sourceIp) ?? 0) + 1);
    const dp = String(e.destPort ?? 0);
    destPortMap.set(dp, (destPortMap.get(dp) ?? 0) + 1);
    if (e.eventType === "connection" || e.eventType === "port_probe" || e.eventType === "service_access") {
      connectionCount++;
      trafficBytes += 1024;
    }
    if (e.eventType === "http_request") {
      requestCount++;
      trafficBytes += 2048;
    }
  }

  // Recent connections (last 20), newest first
  const recentConnections = windowed.slice(-20).reverse();

  // Events-per-sec timeline: last 30 buckets of 2s
  const bucketMs = 2000;
  const bucketCount = 30;
  const eventsPerSecTimeline: { t: string; v: number }[] = [];
  const trafficTimeline: { t: string; v: number }[] = [];
  for (let i = bucketCount - 1; i >= 0; i--) {
    const bucketStart = nowMs - (i + 1) * bucketMs;
    const bucketEnd = nowMs - i * bucketMs;
    let count = 0;
    let bytes = 0;
    for (const e of windowed) {
      const t = Date.parse(e.timestamp);
      if (t >= bucketStart && t < bucketEnd) {
        count++;
        if (e.eventType === "http_request") bytes += 2048;
        else if (e.eventType === "connection" || e.eventType === "port_probe" || e.eventType === "service_access") bytes += 1024;
        else bytes += 256;
      }
    }
    eventsPerSecTimeline.push({ t: new Date(bucketEnd).toISOString(), v: count });
    trafficTimeline.push({ t: new Date(bucketEnd).toISOString(), v: +(bytes / 1024).toFixed(2) });
  }

  const windowSec = windowMs / 1000;
  const protocolDistribution: ProtocolDistribution[] = Array.from(protocolMap.entries())
    .map(([protocol, count]) => ({ protocol, count }))
    .sort((a, b) => b.count - a.count);

  return {
    connectionCount,
    connectionsPerSec: +(connectionCount / windowSec).toFixed(2),
    requestRate: +(requestCount / windowSec).toFixed(2),
    trafficRate: +(trafficBytes / 1024 / windowSec).toFixed(2),
    protocolDistribution,
    topSourceIps: topN(srcIpMap, 5),
    topDestPorts: topN(destPortMap, 5),
    recentConnections,
    eventsPerSecTimeline,
    trafficTimeline,
  };
}

// Re-export severity keys for callers that want them
export { SEVERITY_KEYS };
