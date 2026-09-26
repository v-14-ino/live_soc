// ============================================================
// LiveSOC - In-memory Session Manager
//
// Owns the lifecycle of monitoring sessions: target validation,
// initial assessment, telemetry generator wiring, detection +
// correlation pipelines, DB persistence, and WebSocket message
// broadcasting.
//
// Pure TypeScript (no Next.js imports). Imported by both Next.js
// API routes (node runtime) and the standalone socket.io
// mini-service.
// ============================================================

import { db } from "@/lib/db";
import type {
  AssessmentResult,
  CustomRule,
  KpiStats,
  NetworkActivityStats,
  SecurityAlert,
  SecurityEvent,
  WSMessage,
} from "@/lib/types";
import { RULES_BY_ID } from "@/lib/constants";
import type { MonitoringSession } from "@prisma/client";

import { runAssessment, validateTarget } from "./scanner";
import { createTelemetryGenerator, type TelemetryGenerator } from "./telemetry";
import {
  createDetectionContext,
  evaluateEvent,
  type DetectionContext,
} from "./detection";
import {
  createCorrelationState,
  processDetection,
  type CorrelationState,
} from "./correlation";
import { computeKpi, computeNetworkActivity } from "./stats";
import { auditLog } from "./audit";
import { evaluateCustomRules } from "./custom-rules";
import {
  createCustomRuleContext,
  checkCustomRuleFiring,
  type CustomRuleContext,
} from "./custom-rule-context";
import { loadEnabledWebhooks, notifyWebhooks } from "./webhook-notifier";

const RECENT_EVENTS_CAP = 500;
const RECENT_ALERTS_CAP = 200;
const SESSION_COUNTER_FLUSH_EVERY = 10;

// ============================================================
// PHASE 9 — Telemetry source status (for live-mode source reporting)
// ============================================================
export interface TelemetrySourceStatus {
  name: string;
  displayName: string;
  sourceType: string;
  status: "CONNECTED" | "DISCONNECTED" | "UNAVAILABLE" | "ERROR" | "NOT_CONFIGURED";
  reason?: string;
}

export interface ActiveSession {
  session: MonitoringSession;
  assessment: AssessmentResult;
  detectionCtx: DetectionContext;
  correlationState: CorrelationState;
  telemetry: TelemetryGenerator;
  customRules: CustomRule[];
  customRuleCtx: CustomRuleContext;
  webhooks: import("@/lib/types").WebhookConfig[];
  telemetrySources: TelemetrySourceStatus[];
  subscribers: Set<(msg: WSMessage) => void>;
  eventCounter: { value: number };
  alertCounter: { value: number };
  offenseCounter: { value: number };
  defenseCounter: { value: number };
  recentEvents: SecurityEvent[];
  recentAlerts: SecurityAlert[];
  kpi: KpiStats;
  networkActivity: NetworkActivityStats;
  startedAt: number;
  processingChain: Promise<void>;
  /**
   * Short prefix derived from the session id, used to guarantee global
   * uniqueness of eventId / alertId / scenarioId values across sessions
   * (the DB enforces UNIQUE constraints on these columns).
   */
  idPrefix: string;
}

const activeSessions = new Map<string, ActiveSession>();

function broadcastLocal(active: ActiveSession, msg: WSMessage): void {
  for (const cb of active.subscribers) {
    try {
      cb(msg);
    } catch (err) {
       
      console.error("[session] subscriber callback error:", err);
    }
  }
}

// ---- DB upsert helpers for scenarios

async function upsertOffenseScenario(s: import("@/lib/types").OffenseScenario, sessionId: string): Promise<void> {
  await db.scenarioOffense.upsert({
    where: { scenarioId: s.scenarioId },
    create: {
      scenarioId: s.scenarioId,
      sessionId,
      title: s.title,
      category: s.category,
      severity: s.severity,
      confidence: s.confidence,
      affectedTarget: s.affectedTarget ?? null,
      affectedService: s.affectedService ?? null,
      technique: s.technique ?? null,
      techniqueMitre: s.techniqueMitre ?? null,
      attackPath: s.attackPath ?? null,
      potentialImpact: s.potentialImpact ?? null,
      relatedEventIds: s.relatedEventIds.join(","),
      eventCount: s.eventCount,
      sourceCount: s.sourceCount,
      status: s.status,
      firstObserved: new Date(s.firstObserved),
      lastObserved: new Date(s.lastObserved),
    },
    update: {
      severity: s.severity,
      confidence: s.confidence,
      relatedEventIds: s.relatedEventIds.join(","),
      eventCount: s.eventCount,
      sourceCount: s.sourceCount,
      status: s.status,
      lastObserved: new Date(s.lastObserved),
    },
  });
}

async function upsertDefenseScenario(s: import("@/lib/types").DefenseScenario, sessionId: string): Promise<void> {
  await db.scenarioDefense.upsert({
    where: { scenarioId: s.scenarioId },
    create: {
      scenarioId: s.scenarioId,
      sessionId,
      relatedOffenseId: s.relatedOffenseId ?? null,
      title: s.title,
      category: s.category,
      priority: s.priority,
      affectedService: s.affectedService ?? null,
      detect: s.detect ?? null,
      monitor: s.monitor ?? null,
      prevent: s.prevent ?? null,
      respond: s.respond ?? null,
      recommendedAction: s.recommendedAction ?? null,
      relatedEventIds: s.relatedEventIds.join(","),
      status: s.status,
      firstObserved: new Date(s.firstObserved),
      lastObserved: new Date(s.lastObserved),
    },
    update: {
      relatedEventIds: s.relatedEventIds.join(","),
      status: s.status,
      lastObserved: new Date(s.lastObserved),
    },
  });
}

// ---- per-event processing

async function processEvent(active: ActiveSession, event: SecurityEvent): Promise<void> {
  // stamp session id
  event.sessionId = active.session.id;

  // persist event
  let dbEventId: string | undefined;
  try {
    const dbEvent = await db.event.create({
      data: {
        eventId: event.eventId,
        sessionId: active.session.id,
        assessmentId: active.assessment.id,
        timestamp: new Date(event.timestamp),
        source: String(event.source),
        sourceIp: event.sourceIp ?? null,
        sourcePort: event.sourcePort ?? null,
        destIp: event.destIp ?? null,
        destPort: event.destPort ?? null,
        protocol: event.protocol ?? null,
        eventType: event.eventType,
        severity: event.severity,
        status: event.status,
        message: event.message,
        isDemo: event.isDemo,
        rawJson: event.raw ? JSON.stringify(event.raw) : null,
        // Phase 2: real-telemetry data source fields (all nullable)
        dataSource: event.dataSource ?? (event.isDemo ? "DEMO" : "REAL"),
        receivedAt: event.receivedAt ? new Date(event.receivedAt) : new Date(),
        hostId: event.hostId ?? null,
        hostname: event.hostname ?? null,
        os: event.os ?? null,
        username: event.username ?? null,
        eventCategory: event.eventCategory ?? null,
      },
    });
    dbEventId = dbEvent.id;
    event.id = dbEvent.id;
  } catch (err) {

    console.error("[session] event persist failed:", err);
  }

  // push to recent events (cap)
  active.recentEvents.push(event);
  if (active.recentEvents.length > RECENT_EVENTS_CAP) {
    active.recentEvents.splice(0, active.recentEvents.length - RECENT_EVENTS_CAP);
  }

  // broadcast event
  broadcastLocal(active, { type: "event", event });

  // run detection
  const detections = evaluateEvent(event, active.detectionCtx);

  // process each detection -> alert + scenario updates
  for (const det of detections) {
    active.alertCounter.value += 1;
    const seq = String(active.alertCounter.value).padStart(5, "0");
    // Prefix alertId with short session id to guarantee global uniqueness
    // (DB enforces UNIQUE on Alert.alertId).
    const alertId = active.idPrefix
      ? `ALR-${active.idPrefix}-${seq}`
      : `ALR-${seq}`;
    const alert: SecurityAlert = {
      id: alertId,
      alertId,
      sessionId: active.session.id,
      eventId: event.eventId,
      ruleId: det.ruleId,
      ruleName: RULES_BY_ID[det.ruleId]?.name ?? det.ruleId,
      severity: det.severity,
      confidence: det.confidence,
      message: det.message,
      recommendedAction: det.recommendedAction,
      status: "active",
      timestamp: new Date().toISOString(),
    };

    // persist alert
    try {
      const dbAlert = await db.alert.create({
        data: {
          alertId: alert.alertId,
          sessionId: active.session.id,
          eventId: dbEventId ?? null,
          ruleId: alert.ruleId,
          ruleName: alert.ruleName,
          severity: alert.severity,
          confidence: alert.confidence,
          message: alert.message,
          recommendedAction: alert.recommendedAction,
          status: alert.status,
          timestamp: new Date(alert.timestamp),
        },
      });
      alert.id = dbAlert.id;
    } catch (err) {
       
      console.error("[session] alert persist failed:", err);
    }

    active.recentAlerts.push(alert);
    if (active.recentAlerts.length > RECENT_ALERTS_CAP) {
      active.recentAlerts.splice(0, active.recentAlerts.length - RECENT_ALERTS_CAP);
    }
    broadcastLocal(active, { type: "alert", alert });

    // fire webhooks (non-blocking, respects severity filter + cooldown)
    if (active.webhooks.length > 0) {
      notifyWebhooks(alert, active.webhooks).catch((err) => {
        console.error("[session] webhook notify failed:", err);
      });
    }

    // correlation
    const result = processDetection(active.correlationState, det, event);
    if (result.offenseScenario) {
      try {
        await upsertOffenseScenario(result.offenseScenario, active.session.id);
      } catch (err) {
         
        console.error("[session] offense upsert failed:", err);
      }
      broadcastLocal(active, {
        type: result.offenseUpdated ? "offense_scenario_update" : "offense_scenario",
        scenario: result.offenseScenario,
      });
    }
    if (result.defenseScenario) {
      try {
        await upsertDefenseScenario(result.defenseScenario, active.session.id);
      } catch (err) {
         
        console.error("[session] defense upsert failed:", err);
      }
      broadcastLocal(active, {
        type: result.defenseUpdated ? "defense_scenario_update" : "defense_scenario",
        scenario: result.defenseScenario,
      });
    }
  }

  // ---- custom rules evaluation (runs alongside built-in rules) ----
  if (active.customRules.length > 0) {
    const customMatches = evaluateCustomRules(event, active.customRules);
    const nowMs = Date.parse(event.timestamp) || Date.now();
    for (const match of customMatches) {
      // Check threshold + window + cooldown
      const shouldFire = checkCustomRuleFiring(
        active.customRuleCtx,
        match.rule,
        nowMs,
      );
      if (!shouldFire) continue;

      active.alertCounter.value += 1;
      const seq = String(active.alertCounter.value).padStart(5, "0");
      const alertId = active.idPrefix
        ? `ALR-${active.idPrefix}-${seq}`
        : `ALR-${seq}`;
      const alert: SecurityAlert = {
        id: alertId,
        alertId,
        sessionId: active.session.id,
        eventId: event.eventId,
        ruleId: match.rule.ruleId,
        ruleName: `[Custom] ${match.rule.name}`,
        severity: match.severity,
        confidence: match.confidence,
        message: match.message,
        recommendedAction: match.recommendedAction,
        status: "active",
        timestamp: new Date().toISOString(),
      };

      // persist custom alert
      try {
        const dbAlert = await db.alert.create({
          data: {
            alertId: alert.alertId,
            sessionId: active.session.id,
            eventId: dbEventId ?? null,
            ruleId: alert.ruleId,
            ruleName: alert.ruleName,
            severity: alert.severity,
            confidence: alert.confidence,
            message: alert.message,
            recommendedAction: alert.recommendedAction,
            status: alert.status,
            timestamp: new Date(alert.timestamp),
          },
        });
        alert.id = dbAlert.id;
      } catch (err) {
        console.error("[session] custom alert persist failed:", err);
      }

      // increment fired count on the custom rule
      try {
        await db.customRule.update({
          where: { ruleId: match.rule.ruleId },
          data: {
            firedCount: { increment: 1 },
            lastFired: new Date(),
          },
        });
      } catch (err) {
        console.error("[session] custom rule firedCount update failed:", err);
      }

      active.recentAlerts.push(alert);
      if (active.recentAlerts.length > RECENT_ALERTS_CAP) {
        active.recentAlerts.splice(0, active.recentAlerts.length - RECENT_ALERTS_CAP);
      }
      broadcastLocal(active, { type: "alert", alert });

      // fire webhooks for custom rule alerts too
      if (active.webhooks.length > 0) {
        notifyWebhooks(alert, active.webhooks).catch((err) => {
          console.error("[session] webhook notify (custom) failed:", err);
        });
      }

      await auditLog("info", "session", `Custom rule fired: ${match.rule.ruleId}`, {
        sessionId: active.session.id,
        ruleId: match.rule.ruleId,
        ruleName: match.rule.name,
        eventId: event.eventId,
      });
    }
  }

  // recompute KPI + network activity
  active.kpi = computeKpi(
    active.recentEvents,
    active.assessment.ports.length,
    active.recentEvents.length,
  );
  active.networkActivity = computeNetworkActivity(active.recentEvents);
  broadcastLocal(active, { type: "kpi", kpi: active.kpi });
  broadcastLocal(active, { type: "network_activity", stats: active.networkActivity });

  // counters
  active.eventCounter.value += 1;
  if (active.eventCounter.value % SESSION_COUNTER_FLUSH_EVERY === 0) {
    try {
      await db.monitoringSession.update({
        where: { id: active.session.id },
        data: {
          eventCount: active.eventCounter.value,
          alertCount: active.alertCounter.value,
        },
      });
    } catch (err) {
       
      console.error("[session] session counter update failed:", err);
    }
  }
}

// ---- session manager

export const sessionManager = {
  async startSession(
    targetAddress: string,
    mode: "demo" | "live",
  ): Promise<{ session: MonitoringSession; assessment: AssessmentResult }> {
    // 1. validate target
    const validation = validateTarget(targetAddress);
    if (!validation.ok) {
      throw new Error(`Invalid target: ${validation.reason ?? "validation failed"}`);
    }

    await auditLog("info", "session", `Starting monitoring session for ${targetAddress}`, {
      targetAddress,
      mode,
      targetType: validation.targetType,
    });

    // 2. upsert target
    const dbTarget = await db.target.upsert({
      where: { address: targetAddress },
      create: {
        address: targetAddress,
        targetType: validation.targetType,
        isLab: validation.isLab,
        authorized: true,
      },
      update: {
        targetType: validation.targetType,
        isLab: validation.isLab,
      },
    });

    // 3. run mock assessment
    const assessmentData = await runAssessment(targetAddress, {
      timeoutSec: 30,
      topPorts: 100,
      isDemo: mode === "demo",
    });

    // 4. create assessment row
    const dbAssessment = await db.assessment.create({
      data: {
        targetId: dbTarget.id,
        status: assessmentData.status,
        reachability: assessmentData.reachability,
        latencyMs: assessmentData.latencyMs ?? null,
        hostname: assessmentData.hostname ?? null,
        osGuess: assessmentData.osGuess ?? null,
        startedAt: new Date(assessmentData.startedAt),
        completedAt: assessmentData.completedAt ? new Date(assessmentData.completedAt) : null,
      },
    });

    // 5. create services (ports reference them)
    const serviceDbIdMap = new Map<string, string>();
    for (const svc of assessmentData.services) {
      const dbSvc = await db.service.create({
        data: {
          assessmentId: dbAssessment.id,
          name: svc.name,
          port: svc.port,
          protocol: svc.protocol,
          product: svc.product ?? null,
          version: svc.version ?? null,
          extrainfo: svc.extrainfo ?? null,
          method: svc.method,
          confidence: svc.confidence,
        },
      });
      serviceDbIdMap.set(svc.id, dbSvc.id);
    }

    // 6. create ports
    for (const p of assessmentData.ports) {
      const svc = assessmentData.services.find(
        (s) => s.port === p.number && s.protocol === p.protocol,
      );
      const svcDbId = svc ? serviceDbIdMap.get(svc.id) ?? null : null;
      try {
        await db.port.create({
          data: {
            assessmentId: dbAssessment.id,
            number: p.number,
            protocol: p.protocol,
            state: p.state,
            serviceId: svcDbId,
          },
        });
      } catch (err) {
        // port unique constraint may collide if assessment runs twice; ignore
         
        console.error("[session] port create failed:", err);
      }
    }

    // 7. create monitoring session row
    const dbSession = await db.monitoringSession.create({
      data: {
        targetId: dbTarget.id,
        assessmentId: dbAssessment.id,
        status: "monitoring",
        mode,
      },
    });

    // 8. assemble full AssessmentResult with DB ids
    const assessment: AssessmentResult = {
      ...assessmentData,
      id: dbAssessment.id,
      targetId: dbTarget.id,
    };

    // 8a. derive a short prefix from the session id for globally-unique
    // eventId / alertId / scenarioId values (DB enforces UNIQUE).
    const idPrefix = dbSession.id.replace(/[^a-z0-9]/gi, "").slice(0, 8).toLowerCase();

    // 9. detection context + correlation state
    const detectionCtx = createDetectionContext();
    const correlationState = createCorrelationState(idPrefix);

    // 9a. load enabled custom rules from DB
    let customRules: CustomRule[] = [];
    try {
      const ruleRows = await db.customRule.findMany({
        where: { enabled: true },
        orderBy: { createdAt: "desc" },
      });
      customRules = ruleRows.map((r) => {
        let conditions: import("@/lib/types").RuleCondition[] = [];
        try {
          conditions = JSON.parse(r.conditions) as import("@/lib/types").RuleCondition[];
        } catch {
          conditions = [];
        }
        return {
          id: r.id,
          ruleId: r.ruleId,
          name: r.name,
          description: r.description,
          severity: r.severity as import("@/lib/types").Severity,
          enabled: r.enabled,
          conditions,
          threshold: r.threshold,
          windowMs: r.windowMs,
          confidence: r.confidence,
          recommendedAction: r.recommendedAction,
          firedCount: r.firedCount,
          lastFired: r.lastFired?.toISOString() ?? null,
          createdAt: r.createdAt.toISOString(),
          updatedAt: r.updatedAt.toISOString(),
        };
      });
      if (customRules.length > 0) {
        await auditLog("info", "session", `Loaded ${customRules.length} custom rule(s) for session`, {
          sessionId: dbSession.id,
          ruleIds: customRules.map((r) => r.ruleId),
        });
      }
    } catch (err) {
      console.error("[session] failed to load custom rules:", err);
    }
    const customRuleCtx = createCustomRuleContext();

    // 9b. load enabled webhooks for alert notifications
    let webhooks: import("@/lib/types").WebhookConfig[] = [];
    try {
      webhooks = await loadEnabledWebhooks();
      if (webhooks.length > 0) {
        await auditLog("info", "session", `Loaded ${webhooks.length} webhook(s) for session`, {
          sessionId: dbSession.id,
          webhookIds: webhooks.map((w) => w.id),
        });
      }
    } catch (err) {
      console.error("[session] failed to load webhooks:", err);
    }

    // 10. telemetry generator — mode-aware (Phase 8)
    //    DEMO mode: use the existing demo generator (unchanged behavior).
    //    LIVE mode: do NOT use the demo generator. Instead, start available
    //    real telemetry adapters. If no adapters are available, the session
    //    starts but shows "NO TELEMETRY" — events can still arrive via
    //    POST /api/ingest. Never silently fall back to demo in live mode.
    const telemetrySources: TelemetrySourceStatus[] = [];
    let telemetry: TelemetryGenerator;
    const adapterHandles: import("@/lib/monitoring/adapters/base").AdapterHandle[] = [];

    if (mode === "live") {
      // LIVE mode: attempt to start real adapters
      const { ADAPTER_LIST } = await import("@/lib/monitoring/adapters");
      for (const adapter of ADAPTER_LIST) {
        try {
          const status = await adapter.checkAvailability();
          if (status.available) {
            const handle = await adapter.start(
              { targetAddress, intervalMs: 2000 },
              (e: SecurityEvent) => {
                // Tag real-adapter events with dataSource=REAL
                e.dataSource = "REAL";
                e.isDemo = false;
                e.receivedAt = new Date().toISOString();
                active.processingChain = active.processingChain
                  .then(() => processEvent(active, e))
                  .catch((err) => {
                    console.error("[session] adapter processEvent error:", err);
                  });
              },
            );
            adapterHandles.push(handle);
            telemetrySources.push({
              name: adapter.name,
              displayName: adapter.displayName,
              sourceType: String(adapter.sourceType),
              status: "CONNECTED",
            });
            await auditLog("info", "session", `Started real adapter: ${adapter.name}`, {
              sessionId: dbSession.id,
              version: status.version,
            });
          } else {
            telemetrySources.push({
              name: adapter.name,
              displayName: adapter.displayName,
              sourceType: String(adapter.sourceType),
              status: "UNAVAILABLE",
              reason: status.reason,
            });
          }
        } catch (err) {
          telemetrySources.push({
            name: adapter.name,
            displayName: adapter.displayName,
            sourceType: String(adapter.sourceType),
            status: "ERROR",
            reason: err instanceof Error ? err.message : "Unknown error",
          });
        }
      }

      // Create a no-op telemetry generator for live mode (adapters feed directly)
      telemetry = {
        start: () => { /* adapters already started above */ },
        stop: () => {
          for (const h of adapterHandles) {
            try { h.stop(); } catch { /* ignore */ }
          }
        },
        onEvent: () => { /* adapters call processEvent directly */ },
      };

      const connectedCount = telemetrySources.filter((s) => s.status === "CONNECTED").length;
      await auditLog("info", "session", `Live mode: ${connectedCount}/${telemetrySources.length} adapters connected`, {
        sessionId: dbSession.id,
        sources: telemetrySources.map((s) => ({ name: s.name, status: s.status })),
      });
    } else {
      // DEMO mode: use the existing demo generator (unchanged)
      telemetry = createTelemetryGenerator({
        targetAddress,
        services: assessment.services,
        intervalMs: 1500,
        enabledCollectors: {
          network: true,
          systemLogs: true,
          webLogs: true,
          firewall: true,
          ids: false,
        },
        sessionId: dbSession.id,
      });
      telemetrySources.push({
        name: "demo",
        displayName: "Demo Telemetry Generator",
        sourceType: "demo",
        status: "CONNECTED",
      });
    }

    // 11. build active session
    const active: ActiveSession = {
      session: dbSession,
      assessment,
      detectionCtx,
      correlationState,
      telemetry,
      customRules,
      customRuleCtx,
      webhooks,
      telemetrySources,
      subscribers: new Set(),
      eventCounter: { value: 0 },
      alertCounter: { value: 0 },
      offenseCounter: correlationState.offenseCounter,
      defenseCounter: correlationState.defenseCounter,
      recentEvents: [],
      recentAlerts: [],
      kpi: computeKpi([], assessment.ports.length, 0),
      networkActivity: computeNetworkActivity([]),
      startedAt: Date.now(),
      processingChain: Promise.resolve(),
      idPrefix,
    };

    // 12. wire telemetry onEvent (serialized via processing chain)
    //     (Only used in DEMO mode; live-mode adapters feed directly above)
    telemetry.onEvent((event) => {
      active.processingChain = active.processingChain
        .then(() => processEvent(active, event))
        .catch((err) => {

          console.error("[session] processEvent error:", err);
        });
    });

    // 13. store + start
    activeSessions.set(dbSession.id, active);
    telemetry.start();

    await auditLog("info", "session", `Monitoring session ${dbSession.id} active (${mode} mode)`, {
      sessionId: dbSession.id,
      target: targetAddress,
      openPorts: assessment.ports.length,
      mode,
      telemetrySources: telemetrySources.map((s) => ({ name: s.name, status: s.status })),
    });

    return { session: dbSession, assessment };
  },

  async stopSession(sessionId: string): Promise<void> {
    const active = activeSessions.get(sessionId);
    if (!active) return;

    active.telemetry.stop();

    // flush pending processing
    try {
      await active.processingChain;
    } catch {
      // ignore
    }

    // compute duration + risk summary
    const durationSec = Math.max(1, Math.floor((Date.now() - active.startedAt) / 1000));
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of active.recentAlerts) {
      if (a.severity === "critical") severityCounts.critical++;
      else if (a.severity === "high") severityCounts.high++;
      else if (a.severity === "medium") severityCounts.medium++;
      else if (a.severity === "low") severityCounts.low++;
    }
    const riskSummary = `${severityCounts.critical} critical, ${severityCounts.high} high, ${severityCounts.medium} medium, ${severityCounts.low} low alerts over ${durationSec}s`;

    try {
      await db.monitoringSession.update({
        where: { id: sessionId },
        data: {
          status: "completed",
          endedAt: new Date(),
          durationSec,
          eventCount: active.eventCounter.value,
          alertCount: active.alertCounter.value,
          riskSummary,
        },
      });
    } catch (err) {
       
      console.error("[session] session stop update failed:", err);
    }

    activeSessions.delete(sessionId);

    // notify subscribers
    broadcastLocal(active, {
      type: "session_ended",
      sessionId,
      reason: "Stopped by user",
    });

    await auditLog("info", "session", `Monitoring session ${sessionId} stopped`, {
      sessionId,
      durationSec,
      eventCount: active.eventCounter.value,
      alertCount: active.alertCounter.value,
    });
  },

  getActive(sessionId: string): ActiveSession | undefined {
    return activeSessions.get(sessionId);
  },

  /**
   * Update the status of an alert in an active session.
   *
   * - Updates the in-memory `recentAlerts` list.
   * - Persists the change to the DB via `db.alert.update`.
   * - Broadcasts an `alert` WS message with the updated alert so all
   *   connected clients see the status change immediately.
   *
   * Returns the updated alert on success, or `null` if the session or
   * alert could not be found (or if the DB update failed).
   */
  async updateAlertStatus(
    sessionId: string,
    alertId: string,
    status: "acknowledged" | "resolved" | "active",
  ): Promise<SecurityAlert | null> {
    const active = activeSessions.get(sessionId);
    if (!active) return null;

    const idx = active.recentAlerts.findIndex((a) => a.alertId === alertId);
    if (idx < 0) return null;

    const updated: SecurityAlert = {
      ...active.recentAlerts[idx],
      status,
    };
    active.recentAlerts[idx] = updated;

    try {
      await db.alert.update({
        where: { alertId },
        data: { status },
      });
    } catch (err) {
      await auditLog(
        "error",
        "session",
        `Failed to persist alert status update for ${alertId}`,
        {
          sessionId,
          alertId,
          status,
          error: (err as Error).message,
          stack: (err as Error).stack,
        },
      );
      // We still broadcast the in-memory change so the operator UI is
      // responsive; the DB will be retried implicitly on next start.
    }

    await auditLog("info", "alert", `Alert ${alertId} status → ${status}`, {
      sessionId,
      alertId,
      status,
      ruleId: updated.ruleId,
      severity: updated.severity,
    });

    broadcastLocal(active, { type: "alert", alert: updated });

    return updated;
  },

  getActiveAll(): ActiveSession[] {
    return Array.from(activeSessions.values());
  },

  // PHASE 9 — telemetry source status for a session
  getTelemetrySources(sessionId: string): TelemetrySourceStatus[] {
    const active = activeSessions.get(sessionId);
    if (!active) return [];
    return active.telemetrySources;
  },

  broadcast(sessionId: string, msg: WSMessage): void {
    const active = activeSessions.get(sessionId);
    if (active) broadcastLocal(active, msg);
  },

  subscribe(sessionId: string, cb: (msg: WSMessage) => void): boolean {
    const active = activeSessions.get(sessionId);
    if (!active) return false;
    active.subscribers.add(cb);
    return true;
  },

  unsubscribe(sessionId: string, cb: (msg: WSMessage) => void): void {
    const active = activeSessions.get(sessionId);
    if (!active) return;
    active.subscribers.delete(cb);
  },

  // ============================================================
  // PHASE 5/7 — External ingestion entry point
  //
  // Accepts a normalized SecurityEvent (from POST /api/ingest via
  // the normalizer), persists a RawLog, stamps it with dataSource=REAL
  // + receivedAt, and feeds it into the EXISTING processEvent()
  // pipeline. This is the ONLY way external real telemetry enters
  // the system. It reuses the same detection/correlation/broadcast
  // logic as demo events — no second pipeline.
  // ============================================================
  async ingestEvent(
    sessionId: string,
    event: SecurityEvent,
    rawLog: {
      sourceType: string;
      rawPayload: string;
      parser?: string;
      agentId?: string;
      hostId?: string;
      hostname?: string;
      metadata?: string;
    },
  ): Promise<{ ok: boolean; eventId?: string; error?: string }> {
    const active = activeSessions.get(sessionId);
    if (!active) {
      return { ok: false, error: "Session not active" };
    }

    // Generate a globally-unique eventId for the ingested event
    active.eventCounter.value += 1;
    const seq = String(active.eventCounter.value).padStart(5, "0");
    const eventId = active.idPrefix
      ? `EVT-${active.idPrefix}-${seq}`
      : `EVT-${seq}`;
    event.eventId = eventId;
    event.id = eventId;
    event.sessionId = active.session.id;
    // Force REAL data source for ingested events
    event.dataSource = "REAL";
    event.isDemo = false;
    if (!event.receivedAt) {
      event.receivedAt = new Date().toISOString();
    }

    // Persist RawLog (preserve original evidence BEFORE normalization)
    let rawLogId: string | undefined;
    try {
      const rl = await db.rawLog.create({
        data: {
          timestamp: new Date(event.timestamp),
          receivedAt: new Date(event.receivedAt),
          sourceType: rawLog.sourceType,
          dataSource: "REAL",
          agentId: rawLog.agentId ?? null,
          hostId: rawLog.hostId ?? null,
          hostname: rawLog.hostname ?? null,
          rawPayload: rawLog.rawPayload.slice(0, 65536),
          parser: rawLog.parser ?? null,
          metadata: rawLog.metadata ?? null,
        },
      });
      rawLogId = rl.id;
    } catch (err) {
      console.error("[session] rawlog persist failed:", err);
    }

    // Feed into the EXISTING processEvent pipeline (serialized via processingChain)
    active.processingChain = active.processingChain
      .then(async () => {
        await processEvent(active, event);
        // Link RawLog → normalized Event after processEvent persists the event
        if (rawLogId && event.id) {
          try {
            await db.rawLog.update({
              where: { id: rawLogId },
              data: { normalizedEventId: event.id },
            });
          } catch {
            // non-fatal
          }
        }
      })
      .catch((err) => {
        console.error("[session] ingestEvent processEvent error:", err);
      });

    return { ok: true, eventId };
  },

  // ============================================================
  // PHASE 4 — Agent heartbeat
  //
  // Upserts an Agent row + creates a Heartbeat row. Called by
  // POST /api/ingest when an agentId is present, or by a dedicated
  // heartbeat endpoint. Updates agent status to ONLINE.
  // ============================================================
  async recordHeartbeat(agentId: string, info: {
    hostname?: string;
    os?: string;
    version?: string;
    ip?: string;
    status?: string;
    metadata?: string;
  }): Promise<void> {
    try {
      const agent = await db.agent.upsert({
        where: { agentId },
        create: {
          agentId,
          hostname: info.hostname ?? null,
          os: info.os ?? null,
          version: info.version ?? null,
          ip: info.ip ?? null,
          status: info.status ?? "ONLINE",
          lastHeartbeat: new Date(),
        },
        update: {
          hostname: info.hostname ?? undefined,
          os: info.os ?? undefined,
          version: info.version ?? undefined,
          ip: info.ip ?? undefined,
          status: info.status ?? "ONLINE",
          lastHeartbeat: new Date(),
        },
      });

      await db.heartbeat.create({
        data: {
          agentId: agent.id,
          status: info.status ?? "ONLINE",
          metadata: info.metadata ?? null,
        },
      });

      // Upsert Host
      if (info.hostname) {
        await db.host.upsert({
          where: { hostname_ip: { hostname: info.hostname, ip: info.ip ?? "" } },
          create: {
            hostname: info.hostname,
            os: info.os ?? null,
            ip: info.ip ?? null,
            status: "ONLINE",
            lastSeen: new Date(),
          },
          update: {
            os: info.os ?? undefined,
            status: "ONLINE",
            lastSeen: new Date(),
          },
        }).catch(() => { /* unique constraint may not match — ignore */ });
      }
    } catch (err) {
      console.error("[session] heartbeat record failed:", err);
    }
  },
};
