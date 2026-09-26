// ============================================================
// LiveSOC - Custom Rules Engine
//
// Evaluates SecurityEvents against user-defined custom rules.
// Runs alongside the built-in detection engine (detection.ts).
// Custom rules use a simple condition-matching model:
//   - Each rule has an array of conditions (AND logic)
//   - Each condition matches a field with an operator
//   - A rule fires when >= threshold matching events occur within windowMs
// ============================================================

import type { SecurityEvent, CustomRule, RuleCondition, Severity } from "@/lib/types";

/**
 * Check if a single event matches a single condition.
 */
function matchesCondition(event: SecurityEvent, cond: RuleCondition): boolean {
  let fieldValue: unknown;
  switch (cond.field) {
    case "sourceIp":
      fieldValue = event.sourceIp ?? "";
      break;
    case "destPort":
      fieldValue = event.destPort ?? 0;
      break;
    case "protocol":
      fieldValue = (event.protocol ?? "").toLowerCase();
      break;
    case "eventType":
      fieldValue = event.eventType;
      break;
    case "severity":
      fieldValue = event.severity;
      break;
    case "message":
      fieldValue = event.message ?? "";
      break;
    case "sourceCollector":
      fieldValue = event.source ?? "";
      break;
    default:
      return false;
  }

  const target = cond.value;

  switch (cond.operator) {
    case "equals":
      if (typeof fieldValue === "number") {
        return Number(target) === fieldValue;
      }
      return String(target).toLowerCase() === String(fieldValue).toLowerCase();

    case "contains":
      return String(fieldValue)
        .toLowerCase()
        .includes(String(target).toLowerCase());

    case "matches": {
      try {
        const re = new RegExp(String(target), "i");
        return re.test(String(fieldValue));
      } catch {
        return false;
      }
    }

    case "greaterThan":
      return Number(fieldValue) > Number(target);

    case "lessThan":
      return Number(fieldValue) < Number(target);

    case "in":
      if (Array.isArray(target)) {
        const lowerTarget = target.map((t) => String(t).toLowerCase());
        return lowerTarget.includes(String(fieldValue).toLowerCase());
      }
      return false;

    default:
      return false;
  }
}

/**
 * Check if an event matches ALL conditions of a rule (AND logic).
 */
export function eventMatchesRule(event: SecurityEvent, rule: CustomRule): boolean {
  if (!rule.enabled) return false;
  if (rule.conditions.length === 0) return false;
  return rule.conditions.every((cond) => matchesCondition(event, cond));
}

export interface CustomRuleMatch {
  rule: CustomRule;
  event: SecurityEvent;
  message: string;
  severity: Severity;
  confidence: number;
  recommendedAction: string;
}

/**
 * Evaluate an event against all custom rules.
 * Returns matches for rules where the event matches conditions.
 * The caller is responsible for threshold/window tracking.
 */
export function evaluateCustomRules(
  event: SecurityEvent,
  rules: CustomRule[],
): CustomRuleMatch[] {
  const matches: CustomRuleMatch[] = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (eventMatchesRule(event, rule)) {
      matches.push({
        rule,
        event,
        message: `Custom rule "${rule.name}" matched: ${rule.conditions
          .map((c) => `${c.field} ${c.operator} ${Array.isArray(c.value) ? c.value.join(",") : c.value}`)
          .join(" AND ")}`,
        severity: rule.severity,
        confidence: rule.confidence,
        recommendedAction: rule.recommendedAction || "Investigate the matched event within authorized scope.",
      });
    }
  }
  return matches;
}

/**
 * Validate a custom rule's conditions.
 * Returns an array of human-readable error messages (empty = valid).
 */
export function validateConditions(conditions: RuleCondition[]): string[] {
  const errors: string[] = [];
  if (conditions.length === 0) {
    errors.push("At least one condition is required");
    return errors;
  }
  for (let i = 0; i < conditions.length; i++) {
    const c = conditions[i];
    if (!c.field) errors.push(`Condition ${i + 1}: field is required`);
    if (!c.operator) errors.push(`Condition ${i + 1}: operator is required`);
    if (c.value === undefined || c.value === null || c.value === "") {
      errors.push(`Condition ${i + 1}: value is required`);
    }
    if (c.operator === "in" && !Array.isArray(c.value)) {
      errors.push(`Condition ${i + 1}: "in" operator requires an array value`);
    }
    if (c.operator === "matches") {
      try {
        new RegExp(String(c.value));
      } catch {
        errors.push(`Condition ${i + 1}: invalid regex pattern`);
      }
    }
    if ((c.operator === "greaterThan" || c.operator === "lessThan") && isNaN(Number(c.value))) {
      errors.push(`Condition ${i + 1}: "${c.operator}" requires a numeric value`);
    }
  }
  return errors;
}

/**
 * Get a human-readable description of a condition.
 */
export function describeCondition(cond: RuleCondition): string {
  const val = Array.isArray(cond.value) ? `[${cond.value.join(", ")}]` : cond.value;
  return `${cond.field} ${cond.operator} ${val}`;
}

/**
 * Get a human-readable summary of all conditions in a rule.
 */
export function describeRule(rule: CustomRule): string {
  if (rule.conditions.length === 0) return "No conditions";
  return rule.conditions.map(describeCondition).join(" AND ");
}
