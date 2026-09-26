// ============================================================
// LiveSOC - Report Data Assembly
//
// Fetches session + assessment + events + alerts + scenarios
// from DB and returns a structured object ready for PDF rendering.
// ============================================================

import { db } from "@/lib/db";
import type {
  AssessmentResult,
  DefenseScenario,
  OffenseScenario,
  PortInfo,
  SecurityAlert,
  Severity,
  ServiceInfo,
  TopItem,
} from "@/lib/types";
import { SEVERITY_ORDER } from "@/lib/constants";

export interface ReportData {
  session: {
    id: string;
    targetAddress: string;
    mode: string;
    status: string;
    startedAt: string;
    endedAt: string | null;
    durationSec: number;
    eventCount: number;
    alertCount: number;
    riskSummary: string | null;
  };
  target: {
    address: string;
    targetType: string;
    isLab: boolean;
    hostname: string | null;
  };
  assessment: AssessmentResult;
  eventsSummary: {
    total: number;
    bySeverity: Record<Severity, number>;
  };
  alerts: SecurityAlert[];
  offenseScenarios: OffenseScenario[];
  defenseScenarios: DefenseScenario[];
  timeline: { time: string; count: number }[];
  topSourceIps: TopItem[];
  topDestPorts: TopItem[];
  riskSummary: string;
  recommendations: string[];
  generatedAt: string;
}

export function computeRiskLevel(
  alerts: SecurityAlert[],
  scenarios: OffenseScenario[],
): Severity {
  let max: Severity = "info";
  for (const a of alerts) {
    if (SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[max]) max = a.severity;
  }
  for (const s of scenarios) {
    if (SEVERITY_ORDER[s.severity] > SEVERITY_ORDER[max]) max = s.severity;
  }
  return max;
}

export async function assembleReportData(sessionId: string): Promise<ReportData> {
  const session = await db.monitoringSession.findUnique({
    where: { id: sessionId },
    include: { target: true, assessment: { include: { ports: true, services: true } } },
  });
  if (!session) {
    throw new Error(`Session not found: ${sessionId}`);
  }

  const [events, alerts, offenseRows, defenseRows] = await Promise.all([
    db.event.findMany({
      where: { sessionId },
      orderBy: { timestamp: "asc" },
    }),
    db.alert.findMany({
      where: { sessionId },
      orderBy: { timestamp: "asc" },
    }),
    db.scenarioOffense.findMany({
      where: { sessionId },
      orderBy: { firstObserved: "asc" },
    }),
    db.scenarioDefense.findMany({
      where: { sessionId },
      orderBy: { firstObserved: "asc" },
    }),
  ]);

  // events summary
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const e of events) {
    const sev = e.severity as Severity;
    if (sev in bySeverity) bySeverity[sev]++;
  }

  // timeline: bucket events into 5s buckets
  const bucketMs = 5000;
  const bucketMap = new Map<number, number>();
  for (const e of events) {
    const t = e.timestamp instanceof Date ? e.timestamp.getTime() : Date.parse(String(e.timestamp));
    const bucket = Math.floor(t / bucketMs) * bucketMs;
    bucketMap.set(bucket, (bucketMap.get(bucket) ?? 0) + 1);
  }
  const timeline = Array.from(bucketMap.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([ms, count]) => ({ time: new Date(ms).toISOString(), count }));

  // top source IPs and dest ports
  const srcIpMap = new Map<string, number>();
  const destPortMap = new Map<string, number>();
  for (const e of events) {
    if (e.sourceIp) srcIpMap.set(e.sourceIp, (srcIpMap.get(e.sourceIp) ?? 0) + 1);
    if (e.destPort != null) {
      const key = String(e.destPort);
      destPortMap.set(key, (destPortMap.get(key) ?? 0) + 1);
    }
  }
  const topSourceIps: TopItem[] = Array.from(srcIpMap.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  const topDestPorts: TopItem[] = Array.from(destPortMap.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // map DB rows to platform types
  const assessment: AssessmentResult = session.assessment
    ? (() => {
        // Build a serviceId → name lookup so port rows (which store a foreign
        // key in `serviceId`) can be resolved to a human-readable service name.
        const serviceNameById = new Map<string, string>();
        for (const s of session.assessment.services) {
          if (s.id && s.name) serviceNameById.set(s.id, s.name);
        }
        return {
          id: session.assessment.id,
          targetId: session.targetId,
          status: session.assessment.status,
          reachability: session.assessment.reachability,
          latencyMs: session.assessment.latencyMs,
          hostname: session.assessment.hostname,
          osGuess: session.assessment.osGuess,
          startedAt: session.assessment.startedAt.toISOString(),
          completedAt: session.assessment.completedAt?.toISOString() ?? null,
          ports: session.assessment.ports.map((p): PortInfo => ({
            id: p.id,
            number: p.number,
            protocol: p.protocol,
            state: p.state,
            serviceName: p.serviceId
              ? (serviceNameById.get(p.serviceId) ?? undefined)
              : undefined,
          })),
          services: session.assessment.services.map((s): ServiceInfo => ({
            id: s.id,
            name: s.name,
            port: s.port,
            protocol: s.protocol,
            product: s.product,
            version: s.version,
            extrainfo: s.extrainfo,
            method: s.method,
            confidence: s.confidence,
          })),
        };
      })()
    : {
        id: "",
        targetId: session.targetId,
        status: "missing",
        reachability: "unknown",
        latencyMs: null,
        hostname: null,
        osGuess: null,
        startedAt: session.startedAt.toISOString(),
        completedAt: null,
        ports: [],
        services: [],
      };

  const offenseScenarios: OffenseScenario[] = offenseRows.map((r) => ({
    id: r.id,
    scenarioId: r.scenarioId,
    sessionId: r.sessionId,
    title: r.title,
    category: r.category,
    severity: r.severity as Severity,
    confidence: r.confidence,
    affectedTarget: r.affectedTarget,
    affectedService: r.affectedService,
    technique: r.technique,
    techniqueMitre: r.techniqueMitre,
    attackPath: r.attackPath,
    potentialImpact: r.potentialImpact,
    relatedEventIds: r.relatedEventIds ? r.relatedEventIds.split(",").filter(Boolean) : [],
    eventCount: r.eventCount,
    sourceCount: r.sourceCount,
    status: r.status as OffenseScenario["status"],
    firstObserved: r.firstObserved.toISOString(),
    lastObserved: r.lastObserved.toISOString(),
  }));

  const defenseScenarios: DefenseScenario[] = defenseRows.map((r) => ({
    id: r.id,
    scenarioId: r.scenarioId,
    sessionId: r.sessionId,
    relatedOffenseId: r.relatedOffenseId,
    title: r.title,
    category: r.category,
    priority: r.priority as Severity,
    affectedService: r.affectedService,
    detect: r.detect,
    monitor: r.monitor,
    prevent: r.prevent,
    respond: r.respond,
    recommendedAction: r.recommendedAction,
    relatedEventIds: r.relatedEventIds ? r.relatedEventIds.split(",").filter(Boolean) : [],
    status: r.status as DefenseScenario["status"],
    firstObserved: r.firstObserved.toISOString(),
    lastObserved: r.lastObserved.toISOString(),
  }));

  const alertDtos: SecurityAlert[] = alerts.map((a) => ({
    id: a.id,
    alertId: a.alertId,
    sessionId: a.sessionId,
    eventId: a.eventId,
    ruleId: a.ruleId,
    ruleName: a.ruleName,
    severity: a.severity as Severity,
    confidence: a.confidence,
    message: a.message,
    recommendedAction: a.recommendedAction,
    status: a.status,
    timestamp: a.timestamp.toISOString(),
  }));

  // dedupe recommendations across defense scenarios
  const recSet = new Set<string>();
  for (const d of defenseScenarios) {
    if (d.recommendedAction) recSet.add(d.recommendedAction);
  }
  const recommendations = Array.from(recSet);

  const riskSummary =
    session.riskSummary ??
    `${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.low} low alerts over ${session.durationSec}s`;

  return {
    session: {
      id: session.id,
      targetAddress: session.target.address,
      mode: session.mode,
      status: session.status,
      startedAt: session.startedAt.toISOString(),
      endedAt: session.endedAt?.toISOString() ?? null,
      durationSec: session.durationSec,
      eventCount: session.eventCount,
      alertCount: session.alertCount,
      riskSummary: session.riskSummary,
    },
    target: {
      address: session.target.address,
      targetType: session.target.targetType,
      isLab: session.target.isLab,
      hostname: session.target.hostname,
    },
    assessment,
    eventsSummary: {
      total: events.length,
      bySeverity,
    },
    alerts: alertDtos,
    offenseScenarios,
    defenseScenarios,
    timeline,
    topSourceIps,
    topDestPorts,
    riskSummary,
    recommendations,
    generatedAt: new Date().toISOString(),
  };
}
