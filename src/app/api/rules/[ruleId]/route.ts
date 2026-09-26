// ============================================================
// LiveSOC - /api/rules/[ruleId]
//
// GET    → get a single custom rule
// PATCH  → update a custom rule (partial update)
// DELETE → delete a custom rule
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";
import { validateConditions } from "@/lib/monitoring/custom-rules";
import type { CustomRuleInput, RuleCondition, Severity } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

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
}) {
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

export const GET = withApiHandler(
  async (_req: NextRequest, ctx: { params: Promise<{ ruleId: string }> }) => {
    const { ruleId } = await ctx.params;
    const row = await db.customRule.findUnique({ where: { ruleId } });
    if (!row) {
      return NextResponse.json({ error: "Rule not found" }, { status: 404 });
    }
    return NextResponse.json({ rule: serializeRule(row) });
  },
  { module: "api.rules" },
);

export const PATCH = withApiHandler(
  async (req: NextRequest, ctx: { params: Promise<{ ruleId: string }> }) => {
    const { ruleId } = await ctx.params;
    const body = (await req.json()) as Partial<CustomRuleInput>;

    const existing = await db.customRule.findUnique({ where: { ruleId } });
    if (!existing) {
      return NextResponse.json({ error: "Rule not found" }, { status: 404 });
    }

    // Validate conditions if provided
    if (body.conditions !== undefined) {
      if (body.conditions.length === 0) {
        return NextResponse.json({ error: "At least one condition is required" }, { status: 400 });
      }
      const condErrors = validateConditions(body.conditions);
      if (condErrors.length > 0) {
        return NextResponse.json({ error: "Invalid conditions", details: condErrors }, { status: 400 });
      }
    }

    const data: Record<string, unknown> = {};
    if (body.name !== undefined) data.name = body.name.trim();
    if (body.description !== undefined) data.description = body.description;
    if (body.severity !== undefined) data.severity = body.severity;
    if (body.enabled !== undefined) data.enabled = body.enabled;
    if (body.conditions !== undefined) data.conditions = JSON.stringify(body.conditions);
    if (body.threshold !== undefined) data.threshold = body.threshold;
    if (body.windowMs !== undefined) data.windowMs = body.windowMs;
    if (body.confidence !== undefined) data.confidence = body.confidence;
    if (body.recommendedAction !== undefined) data.recommendedAction = body.recommendedAction;

    const row = await db.customRule.update({
      where: { ruleId },
      data,
    });

    await auditLog("info", "api.rules", `Custom rule updated: ${ruleId}`);

    return NextResponse.json({ rule: serializeRule(row) });
  },
  { module: "api.rules" },
);

export const DELETE = withApiHandler(
  async (_req: NextRequest, ctx: { params: Promise<{ ruleId: string }> }) => {
    const { ruleId } = await ctx.params;
    const existing = await db.customRule.findUnique({ where: { ruleId } });
    if (!existing) {
      return NextResponse.json({ error: "Rule not found" }, { status: 404 });
    }
    await db.customRule.delete({ where: { ruleId } });
    await auditLog("warning", "api.rules", `Custom rule deleted: ${ruleId} (${existing.name})`);
    return NextResponse.json({ ok: true, ruleId });
  },
  { module: "api.rules" },
);
