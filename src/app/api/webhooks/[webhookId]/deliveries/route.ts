// ============================================================
// LiveSOC - /api/webhooks/[webhookId]/deliveries
//
// GET → delivery history for a webhook (paginated, newest first)
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";

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
