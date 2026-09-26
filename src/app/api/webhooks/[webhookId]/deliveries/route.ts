// ============================================================
// LiveSOC - /api/webhooks/[webhookId]/deliveries
//
// GET    → delivery history for a webhook (paginated, newest first)
// DELETE → clear all deliveries for a webhook (or older than ?olderThanDays=N)
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function parseLimit(value: string | null): number {
  const n = value == null ? NaN : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 50;
  return Math.min(200, Math.floor(n));
}

export const GET = withApiHandler(
  async (req: NextRequest, ctx: { params: Promise<{ webhookId: string }> }) => {
    const { webhookId } = await ctx.params;
    const limit = parseLimit(req.nextUrl.searchParams.get("limit"));

    const [deliveries, total] = await Promise.all([
      db.webhookDelivery.findMany({
        where: { webhookId },
        orderBy: { calledAt: "desc" },
        take: limit,
      }),
      db.webhookDelivery.count({ where: { webhookId } }),
    ]);

    return NextResponse.json({
      webhookId,
      deliveries: deliveries.map((d) => ({
        id: d.id,
        webhookId: d.webhookId,
        alertId: d.alertId,
        eventType: d.eventType,
        statusCode: d.statusCode,
        status: d.status,
        responseExcerpt: d.responseExcerpt,
        errorMessage: d.errorMessage,
        latencyMs: d.latencyMs,
        payload: d.payload,
        calledAt: d.calledAt.toISOString(),
      })),
      total,
    });
  },
  { module: "api.webhooks.deliveries" },
);

export const DELETE = withApiHandler(
  async (req: NextRequest, ctx: { params: Promise<{ webhookId: string }> }) => {
    const { webhookId } = await ctx.params;
    const olderThanDaysStr = req.nextUrl.searchParams.get("olderThanDays");
    const olderThanDays = olderThanDaysStr ? Number(olderThanDaysStr) : NaN;

    let deleted: { count: number };
    if (Number.isFinite(olderThanDays) && olderThanDays > 0) {
      // Delete deliveries older than N days
      const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);
      deleted = await db.webhookDelivery.deleteMany({
        where: { webhookId, calledAt: { lt: cutoff } },
      });
      await auditLog("info", "api.webhooks.deliveries", `Cleared ${deleted.count} deliveries older than ${olderThanDays}d for webhook`, { webhookId });
    } else {
      // Delete ALL deliveries for this webhook
      deleted = await db.webhookDelivery.deleteMany({ where: { webhookId } });
      await auditLog("warning", "api.webhooks.deliveries", `Cleared ALL ${deleted.count} deliveries for webhook`, { webhookId });
    }

    return NextResponse.json({ ok: true, webhookId, deleted: deleted.count });
  },
  { module: "api.webhooks.deliveries" },
);
