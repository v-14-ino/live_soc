// ============================================================
// LiveSOC - Rule-based Detection Engine
//
// Evaluates SecurityEvents against the 8 rules defined in
// src/lib/constants.ts (DETECTION_RULES). Maintains a rolling
// DetectionContext with timestamps and counters.
// ============================================================

import type { SecurityEvent, Severity } from "@/lib/types";
import { RULES_BY_ID } from "@/lib/constants";

export interface DetectionResult {
  ruleId: string;
  severity: Severity;
  confidence: number;
  message: string;
  recommendedAction: string;
}

const WINDOW_PORT_DISCOVERY_MS = 60_000; // RULE-001
const WINDOW_REPEATED_CONN_MS = 60_000; // RULE-002
const WINDOW_AUTH_FAILURE_MS = 90_000; // RULE-003
const WINDOW_HTTP_SPIKE_RECENT_MS = 30_000; // RULE-004
const WINDOW_HTTP_SPIKE_BASELINE_MS = 60_000; // RULE-004 (prior 30s window)
const WINDOW_CONN_RATE_MS = 15_000; // RULE-005
const WINDOW_SERVICE_ACCESS_MS = 60_000; // RULE-006
const PRUNE_MS = 90_000; // global prune horizon

const RULE_COOLDOWN_MS = 30_000; // per-key rule cooldown to avoid alert floods

export interface DetectionContext {
  // Rolling-window counts (kept in sync by updateContext / pruneContext)
  sourcePortCounts: Map<string, Map<number, number>>;
  sourceDestPortCounts: Map<string, Map<string, number>>;
  authFailuresBySource: Map<string, number>;
  httpRequestTimeline: number[]; // timestamps (ms) of HTTP requests in window
  connectionTimeline: number[]; // timestamps (ms) of connection events in window
  baselineSourceIps: Set<string>;
  baselineServices: Set<string>;
  totalConnections: number;

  // Timestamp tracking (helpers for pruning & rule evaluation)
  sourcePortTimestamps: Map<string, Map<number, number[]>>;
  sourceDestPortTimestamps: Map<string, Map<string, number[]>>;
  authFailureTimestamps: Map<string, number[]>;
  serviceAccessTimestamps: Map<string, Map<string, number[]>>; // destPort:protocol -> sourceIp -> ts[]
  lastFired: Map<string, number>; // rule-key -> last fired ms (cooldown)
  lastPruneMs: number;
}

export function createDetectionContext(): DetectionContext {
  return {
    sourcePortCounts: new Map(),
    sourceDestPortCounts: new Map(),
    authFailuresBySource: new Map(),
    httpRequestTimeline: [],
    connectionTimeline: [],
    baselineSourceIps: new Set(),
    baselineServices: new Set(),
    totalConnections: 0,
    sourcePortTimestamps: new Map(),
    sourceDestPortTimestamps: new Map(),
    authFailureTimestamps: new Map(),
    serviceAccessTimestamps: new Map(),
    lastFired: new Map(),
    lastPruneMs: Date.now(),
  };
}

// ---- context maintenance

function bumpCounter(
  countMap: Map<string, Map<number, number>>,
  tsMap: Map<string, Map<number, number[]>>,
  outerKey: string,
  innerKey: number,
  nowMs: number,
): void {
  if (!countMap.has(outerKey)) countMap.set(outerKey, new Map());
  if (!tsMap.has(outerKey)) tsMap.set(outerKey, new Map());
  const innerCount = countMap.get(outerKey)!;
  const innerTs = tsMap.get(outerKey)!;
  innerCount.set(innerKey, (innerCount.get(innerKey) ?? 0) + 1);
  if (!innerTs.has(innerKey)) innerTs.set(innerKey, []);
  innerTs.get(innerKey)!.push(nowMs);
}

function bumpStringCounter(
  countMap: Map<string, Map<string, number>>,
  tsMap: Map<string, Map<string, number[]>>,
  outerKey: string,
  innerKey: string,
  nowMs: number,
): void {
  if (!countMap.has(outerKey)) countMap.set(outerKey, new Map());
  if (!tsMap.has(outerKey)) tsMap.set(outerKey, new Map());
  const innerCount = countMap.get(outerKey)!;
  const innerTs = tsMap.get(outerKey)!;
  innerCount.set(innerKey, (innerCount.get(innerKey) ?? 0) + 1);
  if (!innerTs.has(innerKey)) innerTs.set(innerKey, []);
  innerTs.get(innerKey)!.push(nowMs);
}

export function updateContext(event: SecurityEvent, ctx: DetectionContext): void {
  const nowMs = Date.parse(event.timestamp) || Date.now();
  const srcIp = event.sourceIp ?? "unknown";
  const destPort = event.destPort ?? 0;
  const proto = event.protocol ?? "tcp";
  const eventType = event.eventType;

  // port + dest:port counters (for connection / port_probe / service_access / http_request)
  if (
    eventType === "connection" ||
    eventType === "port_probe" ||
    eventType === "service_access" ||
    eventType === "http_request"
  ) {
    bumpCounter(ctx.sourcePortCounts, ctx.sourcePortTimestamps, srcIp, destPort, nowMs);
    // sourceDestPortCounts: outer=srcIp, inner=`destIp:destPort`
    bumpStringCounter(
      ctx.sourceDestPortCounts,
      ctx.sourceDestPortTimestamps,
      srcIp,
      `${event.destIp ?? "unknown"}:${destPort}`,
      nowMs,
    );
    // service access (for RULE-006: destPort:protocol -> sourceIp -> timestamps)
    const svcKey = `${destPort}:${proto}`;
    if (!ctx.serviceAccessTimestamps.has(svcKey)) ctx.serviceAccessTimestamps.set(svcKey, new Map());
    const inner = ctx.serviceAccessTimestamps.get(svcKey)!;
    if (!inner.has(srcIp)) inner.set(srcIp, []);
    inner.get(srcIp)!.push(nowMs);
  }

  // auth failure tracking
  if (eventType === "auth_failure") {
    ctx.authFailuresBySource.set(srcIp, (ctx.authFailuresBySource.get(srcIp) ?? 0) + 1);
    if (!ctx.authFailureTimestamps.has(srcIp)) ctx.authFailureTimestamps.set(srcIp, []);
    ctx.authFailureTimestamps.get(srcIp)!.push(nowMs);
  }

  // http request timeline
  if (eventType === "http_request") {
    ctx.httpRequestTimeline.push(nowMs);
  }

  // connection timeline (only true `connection` events; http_request and
  // port_probe have their own timelines and rules)
  if (eventType === "connection") {
    ctx.connectionTimeline.push(nowMs);
    ctx.totalConnections += 1;
  }

  // periodic prune
  if (nowMs - ctx.lastPruneMs > 10_000) {
    pruneContext(ctx, nowMs);
  }
}

export function pruneContext(ctx: DetectionContext, nowMs: number): void {
  ctx.lastPruneMs = nowMs;
  const cutoff = nowMs - PRUNE_MS;

  // helper to prune a number[] timeline
  const pruneTimeline = (tl: number[]) => {
    while (tl.length > 0 && tl[0] < cutoff) tl.shift();
  };

  pruneTimeline(ctx.httpRequestTimeline);
  pruneTimeline(ctx.connectionTimeline);

  // source port timestamps -> recompute counts
  for (const [srcIp, innerMap] of ctx.sourcePortTimestamps) {
    const countInner = ctx.sourcePortCounts.get(srcIp) ?? new Map<number, number>();
    for (const [port, tsArr] of innerMap) {
      while (tsArr.length > 0 && tsArr[0] < cutoff) tsArr.shift();
      if (tsArr.length === 0) {
        innerMap.delete(port);
        countInner.delete(port);
      } else {
        countInner.set(port, tsArr.length);
      }
    }
    if (innerMap.size === 0) {
      ctx.sourcePortTimestamps.delete(srcIp);
      ctx.sourcePortCounts.delete(srcIp);
    } else {
      ctx.sourcePortCounts.set(srcIp, countInner);
    }
  }

  // source dest:port timestamps -> recompute counts
  for (const [srcIp, innerMap] of ctx.sourceDestPortTimestamps) {
    const countInner = ctx.sourceDestPortCounts.get(srcIp) ?? new Map<string, number>();
    for (const [destKey, tsArr] of innerMap) {
      while (tsArr.length > 0 && tsArr[0] < cutoff) tsArr.shift();
      if (tsArr.length === 0) {
        innerMap.delete(destKey);
        countInner.delete(destKey);
      } else {
        countInner.set(destKey, tsArr.length);
      }
    }
    if (innerMap.size === 0) {
      ctx.sourceDestPortTimestamps.delete(srcIp);
      ctx.sourceDestPortCounts.delete(srcIp);
    } else {
      ctx.sourceDestPortCounts.set(srcIp, countInner);
    }
  }

  // auth failures
  for (const [srcIp, tsArr] of ctx.authFailureTimestamps) {
    while (tsArr.length > 0 && tsArr[0] < cutoff) tsArr.shift();
    if (tsArr.length === 0) {
      ctx.authFailureTimestamps.delete(srcIp);
      ctx.authFailuresBySource.delete(srcIp);
    } else {
      ctx.authFailuresBySource.set(srcIp, tsArr.length);
    }
  }

  // service access timestamps (for RULE-006)
  for (const [, innerMap] of ctx.serviceAccessTimestamps) {
    for (const [srcIp, tsArr] of innerMap) {
      while (tsArr.length > 0 && tsArr[0] < cutoff) tsArr.shift();
      if (tsArr.length === 0) innerMap.delete(srcIp);
    }
  }

  // prune cooldown map of stale entries
  for (const [key, ts] of ctx.lastFired) {
    if (ts < cutoff) ctx.lastFired.delete(key);
  }
}

// ---- cooldown helper
function checkCooldown(ctx: DetectionContext, key: string, nowMs: number): boolean {
  const last = ctx.lastFired.get(key);
  if (last !== undefined && nowMs - last < RULE_COOLDOWN_MS) return false;
  ctx.lastFired.set(key, nowMs);
  return true;
}

// ---- rules

function rule001(ctx: DetectionContext, event: SecurityEvent, nowMs: number): DetectionResult | null {
  const srcIp = event.sourceIp ?? "unknown";
  const portMap = ctx.sourcePortCounts.get(srcIp);
  if (!portMap || portMap.size < 4) return null;
  // ensure timestamps within window
  const tsMap = ctx.sourcePortTimestamps.get(srcIp);
  let distinctInWindow = 0;
  const cutoff = nowMs - WINDOW_PORT_DISCOVERY_MS;
  if (tsMap) {
    for (const [port, tsArr] of tsMap) {
      if (tsArr.some((t) => t >= cutoff)) distinctInWindow++;
    }
  }
  if (distinctInWindow < 4) return null;
  if (!checkCooldown(ctx, `RULE-001:${srcIp}`, nowMs)) return null;
  const r = RULES_BY_ID["RULE-001"];
  return {
    ruleId: r.ruleId,
    severity: r.severity,
    confidence: r.confidence,
    message: `Observed connections to ${distinctInWindow} distinct ports from source ${srcIp} within ${WINDOW_PORT_DISCOVERY_MS / 1000}s. Possible service discovery activity.`,
    recommendedAction: r.recommendedAction,
  };
}

function rule002(ctx: DetectionContext, event: SecurityEvent, nowMs: number): DetectionResult | null {
  const srcIp = event.sourceIp ?? "unknown";
  const destKey = `${event.destIp ?? "unknown"}:${event.destPort ?? 0}`;
  const tsMap = ctx.sourceDestPortTimestamps.get(srcIp);
  if (!tsMap) return null;
  const tsArr = tsMap.get(destKey);
  if (!tsArr) return null;
  const cutoff = nowMs - WINDOW_REPEATED_CONN_MS;
  const count = tsArr.filter((t) => t >= cutoff).length;
  if (count < 5) return null;
  if (!checkCooldown(ctx, `RULE-002:${srcIp}:${destKey}`, nowMs)) return null;
  const r = RULES_BY_ID["RULE-002"];
  return {
    ruleId: r.ruleId,
    severity: r.severity,
    confidence: r.confidence,
    message: `${count} connections from ${srcIp} to ${destKey} within ${WINDOW_REPEATED_CONN_MS / 1000}s. Repeated access pattern observed.`,
    recommendedAction: r.recommendedAction,
  };
}

function rule003(ctx: DetectionContext, event: SecurityEvent, nowMs: number): DetectionResult | null {
  if (event.eventType !== "auth_failure") return null;
  const srcIp = event.sourceIp ?? "unknown";
  const tsArr = ctx.authFailureTimestamps.get(srcIp);
  if (!tsArr) return null;
  const cutoff = nowMs - WINDOW_AUTH_FAILURE_MS;
  const count = tsArr.filter((t) => t >= cutoff).length;
  if (count < 3) return null;
  if (!checkCooldown(ctx, `RULE-003:${srcIp}`, nowMs)) return null;
  const r = RULES_BY_ID["RULE-003"];
  return {
    ruleId: r.ruleId,
    severity: r.severity,
    confidence: r.confidence,
    message: `${count} authentication failures from ${srcIp} within ${WINDOW_AUTH_FAILURE_MS / 1000}s. Possible credential access attempt — success NOT confirmed.`,
    recommendedAction: r.recommendedAction,
  };
}

function rule004(ctx: DetectionContext, event: SecurityEvent, nowMs: number): DetectionResult | null {
  if (event.eventType !== "http_request") return null;
  const recentCutoff = nowMs - WINDOW_HTTP_SPIKE_RECENT_MS;
  const baselineCutoff = nowMs - WINDOW_HTTP_SPIKE_BASELINE_MS;
  let recent = 0;
  let baseline = 0;
  for (const t of ctx.httpRequestTimeline) {
    if (t >= recentCutoff) recent++;
    else if (t >= baselineCutoff) baseline++;
  }
  const effectiveBaseline = Math.max(baseline, 1);
  const recentPerSec = recent / (WINDOW_HTTP_SPIKE_RECENT_MS / 1000);
  if (recent < 5 || recent <= effectiveBaseline * 2) return null;
  if (!checkCooldown(ctx, `RULE-004`, nowMs)) return null;
  const r = RULES_BY_ID["RULE-004"];
  return {
    ruleId: r.ruleId,
    severity: r.severity,
    confidence: r.confidence,
    message: `HTTP request rate ~${recentPerSec.toFixed(1)}/s over last ${WINDOW_HTTP_SPIKE_RECENT_MS / 1000}s (${recent} requests), exceeds 2x baseline (${effectiveBaseline}). Possible web enumeration.`,
    recommendedAction: r.recommendedAction,
  };
}

function rule005(ctx: DetectionContext, event: SecurityEvent, nowMs: number): DetectionResult | null {
  if (event.eventType !== "connection") return null;
  const cutoff = nowMs - WINDOW_CONN_RATE_MS;
  const count = ctx.connectionTimeline.filter((t) => t >= cutoff).length;
  const threshold = 5 * (WINDOW_CONN_RATE_MS / 1000); // 5/s sustained
  if (count < threshold) return null;
  if (!checkCooldown(ctx, `RULE-005`, nowMs)) return null;
  const r = RULES_BY_ID["RULE-005"];
  return {
    ruleId: r.ruleId,
    severity: r.severity,
    confidence: r.confidence,
    message: `Connection rate ${count} over last ${WINDOW_CONN_RATE_MS / 1000}s (~${(count / (WINDOW_CONN_RATE_MS / 1000)).toFixed(1)}/s) exceeds sustained threshold. Possible volume anomaly.`,
    recommendedAction: r.recommendedAction,
  };
}

function rule006(ctx: DetectionContext, event: SecurityEvent, nowMs: number): DetectionResult | null {
  const destPort = event.destPort ?? 0;
  const proto = event.protocol ?? "tcp";
  const svcKey = `${destPort}:${proto}`;
  const inner = ctx.serviceAccessTimestamps.get(svcKey);
  if (!inner) return null;
  const cutoff = nowMs - WINDOW_SERVICE_ACCESS_MS;
  let total = 0;
  let sources = 0;
  for (const [, tsArr] of inner) {
    const c = tsArr.filter((t) => t >= cutoff).length;
    if (c > 0) {
      total += c;
      sources++;
    }
  }
  if (total < 10 || sources < 2) return null;
  if (!checkCooldown(ctx, `RULE-006:${svcKey}`, nowMs)) return null;
  const r = RULES_BY_ID["RULE-006"];
  return {
    ruleId: r.ruleId,
    severity: r.severity,
    confidence: r.confidence,
    message: `${total} accesses to ${svcKey} from ${sources} sources within ${WINDOW_SERVICE_ACCESS_MS / 1000}s. Repeated service access observed.`,
    recommendedAction: r.recommendedAction,
  };
}

function rule007(ctx: DetectionContext, event: SecurityEvent, _nowMs: number): DetectionResult | null {
  const srcIp = event.sourceIp ?? "unknown";
  if (ctx.baselineSourceIps.has(srcIp)) return null;
  // fire then add to baseline so it only fires once per source
  ctx.baselineSourceIps.add(srcIp);
  const r = RULES_BY_ID["RULE-007"];
  return {
    ruleId: r.ruleId,
    severity: r.severity,
    confidence: r.confidence,
    message: `New source IP observed: ${srcIp}. Not present in current baseline.`,
    recommendedAction: r.recommendedAction,
  };
}

function rule008(ctx: DetectionContext, event: SecurityEvent, _nowMs: number): DetectionResult | null {
  const destPort = event.destPort ?? 0;
  const proto = event.protocol ?? "tcp";
  const svcKey = `${destPort}:${proto}`;
  if (ctx.baselineServices.has(svcKey)) return null;
  ctx.baselineServices.add(svcKey);
  const r = RULES_BY_ID["RULE-008"];
  return {
    ruleId: r.ruleId,
    severity: r.severity,
    confidence: r.confidence,
    message: `First observation of service ${svcKey}. Protocol/port combination outside current baseline.`,
    recommendedAction: r.recommendedAction,
  };
}

export function evaluateEvent(event: SecurityEvent, ctx: DetectionContext): DetectionResult[] {
  const nowMs = Date.parse(event.timestamp) || Date.now();
  // ensure counters are current before evaluating
  updateContext(event, ctx);
  // periodic prune happened in updateContext if needed
  const results: DetectionResult[] = [];
  // RULE-001: port discovery
  const r1 = rule001(ctx, event, nowMs);
  if (r1) results.push(r1);
  // RULE-002: repeated connection
  const r2 = rule002(ctx, event, nowMs);
  if (r2) results.push(r2);
  // RULE-003: auth failure burst
  const r3 = rule003(ctx, event, nowMs);
  if (r3) results.push(r3);
  // RULE-004: HTTP request spike
  const r4 = rule004(ctx, event, nowMs);
  if (r4) results.push(r4);
  // RULE-005: unusual connection rate
  const r5 = rule005(ctx, event, nowMs);
  if (r5) results.push(r5);
  // RULE-006: repeated access to same service
  const r6 = rule006(ctx, event, nowMs);
  if (r6) results.push(r6);
  // RULE-007: new source IP
  const r7 = rule007(ctx, event, nowMs);
  if (r7) results.push(r7);
  // RULE-008: service access anomaly
  const r8 = rule008(ctx, event, nowMs);
  if (r8) results.push(r8);
  return results;
}
