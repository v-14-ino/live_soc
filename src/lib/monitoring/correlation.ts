// ============================================================
// LiveSOC - Correlation Engine
//
// Turns DetectionResults into offense/defense scenarios with
// deduplication. Each detection rule maps to an offense category
// (and a paired defense category). Repeated detections of the
// same category UPDATE the existing scenario rather than
// creating new ones.
// ============================================================

import type {
  DefenseScenario,
  OffenseScenario,
  ScenarioStatus,
  SecurityEvent,
  Severity,
} from "@/lib/types";
import { DEFENSE_TEMPLATES, OFFENSE_TEMPLATES, SEVERITY_ORDER } from "@/lib/constants";
import type { DetectionResult } from "./detection";

const MAX_RELATED_EVENT_IDS = 50;

// ruleId -> offense category
const RULE_TO_OFFENSE: Record<string, string> = {
  "RULE-001": "network_service_discovery",
  "RULE-002": "suspicious_service_access",
  "RULE-003": "repeated_auth_attempts",
  "RULE-004": "http_request_anomaly",
  "RULE-005": "unusual_connection_rate",
  "RULE-006": "suspicious_service_access",
  "RULE-007": "new_source_activity",
  "RULE-008": "network_service_discovery",
};

export interface CorrelationState {
  offenseScenarios: Map<string, OffenseScenario>; // category -> scenario
  defenseScenarios: Map<string, DefenseScenario>; // defense category -> scenario
  offenseByCategory: Map<string, string>; // offense category -> scenarioId (for linking defense)
  offenseCounter: { value: number };
  defenseCounter: { value: number };
  /**
   * Optional short prefix (typically derived from the session id) used to
   * guarantee global uniqueness of scenario IDs across sessions, since the
   * DB enforces UNIQUE on ScenarioOffense.scenarioId and
   * ScenarioDefense.scenarioId. When omitted, IDs are SCN-O-NNNNN /
   * SCN-D-NNNNN (unique only within a single session).
   */
  idPrefix?: string;
}

export function createCorrelationState(idPrefix?: string): CorrelationState {
  return {
    offenseScenarios: new Map(),
    defenseScenarios: new Map(),
    offenseByCategory: new Map(),
    offenseCounter: { value: 0 },
    defenseCounter: { value: 0 },
    idPrefix,
  };
}

export interface ProcessDetectionResult {
  offenseScenario?: OffenseScenario;
  defenseScenario?: DefenseScenario;
  offenseUpdated?: boolean;
  defenseUpdated?: boolean;
}

function severityMax(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

// Escalate severity based on event count for high-volume scenarios.
function escalateSeverity(category: string, eventCount: number, base: Severity): Severity {
  if (
    category === "repeated_auth_attempts" ||
    category === "unusual_connection_rate" ||
    category === "http_request_anomaly"
  ) {
    if (eventCount > 50) return "critical";
    if (eventCount > 20) return severityMax(base, "high");
  }
  if (category === "network_service_discovery" || category === "suspicious_service_access") {
    if (eventCount > 40) return severityMax(base, "high");
  }
  return base;
}

// Increase confidence with more evidence, cap at 95.
function adjustConfidence(base: number, eventCount: number): number {
  const bonus = Math.min(15, Math.floor(eventCount / 5));
  return Math.min(95, base + bonus);
}

function nowIso(): string {
  return new Date().toISOString();
}

function relatedEventIdsWith(existing: string[], newId: string): string[] {
  // Cap at MAX_RELATED_EVENT_IDS, keep most recent.
  const next = [newId, ...existing.filter((id) => id !== newId)];
  return next.slice(0, MAX_RELATED_EVENT_IDS);
}

function buildOffense(
  state: CorrelationState,
  category: string,
  event: SecurityEvent,
  detection: DetectionResult,
): OffenseScenario {
  const tpl = OFFENSE_TEMPLATES[category];
  state.offenseCounter.value += 1;
  const seq = String(state.offenseCounter.value).padStart(5, "0");
  const scenarioId = state.idPrefix ? `SCN-O-${state.idPrefix}-${seq}` : `SCN-O-${seq}`;
  state.offenseByCategory.set(category, scenarioId);
  const targetRef = event.destIp ?? "unknown";
  const svcRef = event.destPort ? `${event.destPort}/${event.protocol ?? "tcp"}` : "unknown";
  return {
    id: scenarioId,
    scenarioId,
    sessionId: event.sessionId ?? null,
    title: tpl.title,
    category,
    severity: tpl.severity,
    confidence: tpl.confidence,
    affectedTarget: targetRef,
    affectedService: svcRef,
    technique: tpl.technique,
    techniqueMitre: tpl.techniqueMitre,
    attackPath: tpl.attackPath.join(" -> "),
    potentialImpact: tpl.potentialImpact,
    relatedEventIds: [event.eventId],
    eventCount: 1,
    sourceCount: 1,
    status: "active",
    firstObserved: event.timestamp,
    lastObserved: event.timestamp,
  };
}

function buildDefense(
  state: CorrelationState,
  offenseScenario: OffenseScenario,
  event: SecurityEvent,
): DefenseScenario {
  const tpl = DEFENSE_TEMPLATES[OFFENSE_TEMPLATES[offenseScenario.category].defenseCategory];
  if (!tpl) {
    // Defensive fallback — should never happen, but keep types honest.
    state.defenseCounter.value += 1;
    const scenarioId = `SCN-D-${String(state.defenseCounter.value).padStart(5, "0")}`;
    return {
      id: scenarioId,
      scenarioId,
      sessionId: event.sessionId ?? null,
      relatedOffenseId: offenseScenario.scenarioId,
      title: `Defense: ${offenseScenario.title}`,
      category: "unknown",
      priority: "medium",
      affectedService: offenseScenario.affectedService,
      detect: "",
      monitor: "",
      prevent: "",
      respond: "",
      recommendedAction: "",
      relatedEventIds: [event.eventId],
      status: "active",
      firstObserved: event.timestamp,
      lastObserved: event.timestamp,
    };
  }
  state.defenseCounter.value += 1;
  const seq = String(state.defenseCounter.value).padStart(5, "0");
  const scenarioId = state.idPrefix ? `SCN-D-${state.idPrefix}-${seq}` : `SCN-D-${seq}`;
  return {
    id: scenarioId,
    scenarioId,
    sessionId: event.sessionId ?? null,
    relatedOffenseId: offenseScenario.scenarioId,
    title: tpl.title,
    category: tpl.category,
    priority: tpl.priority,
    affectedService: offenseScenario.affectedService,
    detect: tpl.detect,
    monitor: tpl.monitor,
    prevent: tpl.prevent,
    respond: tpl.respond,
    recommendedAction: tpl.recommendedAction,
    relatedEventIds: [event.eventId],
    status: "active",
    firstObserved: event.timestamp,
    lastObserved: event.timestamp,
  };
}

function updateOffense(existing: OffenseScenario, event: SecurityEvent, _detection: DetectionResult): OffenseScenario {
  const eventCount = existing.eventCount + 1;
  const relatedEventIds = relatedEventIdsWith(existing.relatedEventIds, event.eventId);
  const sourceSet = new Set<string>(relatedEventIds.length ? [event.sourceIp ?? "unknown"] : []);
  // Estimate source count from event IDs (each unique source adds). We don't
  // store source IPs in the scenario directly; approximate from related events.
  // For accuracy, sourceCount is incremented when a new sourceIp is observed.
  // Since we don't track that explicitly, keep conservative: at least 1.
  void sourceSet;
  const tpl = OFFENSE_TEMPLATES[existing.category];
  const base = tpl?.severity ?? existing.severity;
  return {
    ...existing,
    relatedEventIds,
    eventCount,
    sourceCount: Math.max(existing.sourceCount, 1),
    severity: escalateSeverity(existing.category, eventCount, base),
    confidence: adjustConfidence(existing.confidence, eventCount),
    lastObserved: event.timestamp,
    status: "active",
  };
}

function updateDefense(existing: DefenseScenario, event: SecurityEvent): DefenseScenario {
  const relatedEventIds = relatedEventIdsWith(existing.relatedEventIds, event.eventId);
  return {
    ...existing,
    relatedEventIds,
    lastObserved: event.timestamp,
    status: "active",
  };
}

export function processDetection(
  state: CorrelationState,
  detection: DetectionResult,
  event: SecurityEvent,
): ProcessDetectionResult {
  const category = RULE_TO_OFFENSE[detection.ruleId];
  if (!category) return {};
  const offenseTpl = OFFENSE_TEMPLATES[category];
  if (!offenseTpl) return {};

  const existing = state.offenseScenarios.get(category);
  let offenseScenario: OffenseScenario;
  let offenseUpdated: boolean;
  if (existing) {
    offenseScenario = updateOffense(existing, event, detection);
    state.offenseScenarios.set(category, offenseScenario);
    offenseUpdated = true;
  } else {
    offenseScenario = buildOffense(state, category, event, detection);
    state.offenseScenarios.set(category, offenseScenario);
    offenseUpdated = false;
  }

  // Find/build the matching defense scenario (keyed by defense category).
  const defenseCat = offenseTpl.defenseCategory;
  const existingDefense = state.defenseScenarios.get(defenseCat);
  let defenseScenario: DefenseScenario | undefined;
  let defenseUpdated: boolean | undefined;
  if (existingDefense) {
    defenseScenario = updateDefense(existingDefense, event);
    state.defenseScenarios.set(defenseCat, defenseScenario);
    defenseUpdated = true;
  } else {
    defenseScenario = buildDefense(state, offenseScenario, event);
    state.defenseScenarios.set(defenseCat, defenseScenario);
    defenseUpdated = false;
  }

  return {
    offenseScenario,
    defenseScenario,
    offenseUpdated,
    defenseUpdated,
  };
}

export function markInactive(state: CorrelationState, inactiveAfterMs = 30_000): void {
  const nowMs = Date.now();
  for (const [, sc] of state.offenseScenarios) {
    if (sc.status !== "active") continue;
    const lastMs = Date.parse(sc.lastObserved);
    if (nowMs - lastMs > inactiveAfterMs) {
      state.offenseScenarios.set(sc.category, { ...sc, status: "inactive" as ScenarioStatus });
    }
  }
  for (const [cat, sc] of state.defenseScenarios) {
    if (sc.status !== "active") continue;
    const lastMs = Date.parse(sc.lastObserved);
    if (nowMs - lastMs > inactiveAfterMs) {
      state.defenseScenarios.set(cat, { ...sc, status: "inactive" as ScenarioStatus });
    }
  }
}

export function resolveScenario(state: CorrelationState, scenarioId: string): boolean {
  for (const [cat, sc] of state.offenseScenarios) {
    if (sc.scenarioId === scenarioId) {
      state.offenseScenarios.set(cat, { ...sc, status: "resolved" as ScenarioStatus });
      return true;
    }
  }
  for (const [cat, sc] of state.defenseScenarios) {
    if (sc.scenarioId === scenarioId) {
      state.defenseScenarios.set(cat, { ...sc, status: "resolved" as ScenarioStatus });
      return true;
    }
  }
  return false;
}

export function getStateSnapshot(state: CorrelationState): {
  offense: OffenseScenario[];
  defense: DefenseScenario[];
} {
  return {
    offense: Array.from(state.offenseScenarios.values()),
    defense: Array.from(state.defenseScenarios.values()),
  };
}
