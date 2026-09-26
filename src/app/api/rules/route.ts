// ============================================================
// LiveSOC - /api/rules
//
// GET  → list all custom rules
// POST → create a new custom rule
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";
import { validateConditions } from "@/lib/monitoring/custom-rules";
import type { CustomRule, CustomRuleInput, RuleCondition, Severity } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function generateRuleId(): string {
  const rand = Math.random().toString(36).substring(2, 8);
  return `CSTM-${rand}`;
}

function serializeRule(row: {
  id: string;
  ruleId: string;
  name: string;
  description: string;
  severity: string;
  enabled: boolean;
  conditions: string;
  threshold: number;
  windowMs: number;
  confidence: number;
  recommendedAction: string;
  firedCount: number;
  lastFired: Date | null;
  createdAt: Date;
  updatedAt: Date;
}): CustomRule {
  let conditions: RuleCondition[] = [];
  try {
    conditions = JSON.parse(row.conditions) as RuleCondition[];
  } catch {
    conditions = [];
  }
  return {
    id: row.id,
    ruleId: row.ruleId,
    name: row.name,
    description: row.description,
    severity: row.severity as Severity,
    enabled: row.enabled,
    conditions,
    threshold: row.threshold,
    windowMs: row.windowMs,
    confidence: row.confidence,
    recommendedAction: row.recommendedAction,
    firedCount: row.firedCount,
    lastFired: row.lastFired?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export const GET = withApiHandler(async () => {
  const rows = await db.customRule.findMany({
    orderBy: { createdAt: "desc" },
  });
  const rules = rows.map(serializeRule);
  return NextResponse.json({ rules, total: rules.length });
}, { module: "api.rules" });

export const POST = withApiHandler(async (req: NextRequest) => {
  const body = (await req.json()) as CustomRuleInput;

  // Validate
  if (!body.name || body.name.trim().length === 0) {
    return NextResponse.json({ error: "Rule name is required" }, { status: 400 });
  }
  if (!body.conditions || body.conditions.length === 0) {
    return NextResponse.json({ error: "At least one condition is required" }, { status: 400 });
  }
  const condErrors = validateConditions(body.conditions);
  if (condErrors.length > 0) {
    return NextResponse.json({ error: "Invalid conditions", details: condErrors }, { status: 400 });
  }

  const ruleId = generateRuleId();
  const row = await db.customRule.create({
    data: {
      ruleId,
      name: body.name.trim(),
      description: body.description ?? "",
      severity: body.severity ?? "medium",
      enabled: body.enabled ?? true,
      conditions: JSON.stringify(body.conditions),
      threshold: body.threshold ?? 1,
      windowMs: body.windowMs ?? 60000,
      confidence: body.confidence ?? 60,
      recommendedAction: body.recommendedAction ?? "",
    },
  });

  await auditLog("info", "api.rules", `Custom rule created: ${ruleId} (${body.name})`);

  return NextResponse.json({ rule: serializeRule(row) }, { status: 201 });
}, { module: "api.rules" });
