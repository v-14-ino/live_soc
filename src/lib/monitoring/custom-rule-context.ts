// ============================================================
// LiveSOC - Custom Rule Context (threshold + window tracking)
//
// Tracks match timestamps per custom rule so a rule only fires
// when >= threshold matching events occur within windowMs.
// ============================================================

import type { CustomRule } from "@/lib/types";

export interface CustomRuleContext {
  // ruleId -> array of timestamps (ms) when the rule matched
  matchTimestamps: Map<string, number[]>;
  // ruleId -> last fired timestamp (ms) for cooldown
  lastFired: Map<string, number>;
}

export function createCustomRuleContext(): CustomRuleContext {
  return {
    matchTimestamps: new Map(),
    lastFired: new Map(),
  };
}

const COOLDOWN_MS = 5000; // min 5s between fires of the same rule

/**
 * Record a match for a custom rule and check if the threshold is met
 * within the window. Returns true if the rule should fire (threshold met
 * and cooldown elapsed), false otherwise.
 */
export function checkCustomRuleFiring(
  ctx: CustomRuleContext,
  rule: CustomRule,
  nowMs: number,
): boolean {
  // Get or init timestamps for this rule
  let timestamps = ctx.matchTimestamps.get(rule.ruleId);
  if (!timestamps) {
    timestamps = [];
    ctx.matchTimestamps.set(rule.ruleId, timestamps);
  }

  // Add current match
  timestamps.push(nowMs);

  // Prune timestamps outside the window
  const cutoff = nowMs - rule.windowMs;
  while (timestamps.length > 0 && timestamps[0] < cutoff) {
    timestamps.shift();
  }

  // Check cooldown
  const lastFired = ctx.lastFired.get(rule.ruleId) ?? 0;
  if (nowMs - lastFired < COOLDOWN_MS) {
    return false; // still in cooldown
  }

  // Check threshold
  if (timestamps.length >= rule.threshold) {
    ctx.lastFired.set(rule.ruleId, nowMs);
    // Reset timestamps after firing to avoid immediate re-fire
    timestamps.length = 0;
    return true;
  }

  return false;
}
