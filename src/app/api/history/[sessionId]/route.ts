// ============================================================
// LiveSOC - /api/history/[sessionId]
//
// GET → full historical session detail: session row + assessment +
//       ports + services + events (paginated, newest first, default 200)
//       + alerts + offense scenarios + defense scenarios. Joins from DB.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function parsePositiveInt(value: string | null, def: number, max: number): number {
  const n = value == null ? NaN : Number(value);
  if (!Number.isFinite(n) || n < 1) return def;
  return Math.min(max, Math.floor(n));
}

export const GET = withApiHandler(async (
  req: NextRequest,
  ctx: { params: Promise<{ sessionId: string }> },
) => {
  const { sessionId } = await ctx.params;
  const sp = req.nextUrl.searchParams;
  const eventLimit = parsePositiveInt(sp.get("limit"), 200, 5_000);
  const eventOffset = parsePositiveInt(sp.get("offset"), 0, 1_000_000) - 1;

  const session = await db.monitoringSession.findUnique({
    where: { id: sessionId },
    include: {
      target: true,
      assessment: {
        include: { ports: true, services: true },
      },
    },
  });

  if (!session) {
    await auditLog("info", "api.history", "Session not found", { sessionId });
    return NextResponse.json(
      { error: "Session not found." },
      { status: 404 },
    );
  }

  const [events, eventsTotal, alerts, offense, defense] = await Promise.all([
    db.event.findMany({
      where: { sessionId },
      orderBy: { timestamp: "desc" },
      take: eventLimit,
      skip: Math.max(0, eventOffset),
    }),
    db.event.count({ where: { sessionId } }),
    db.alert.findMany({
      where: { sessionId },
      orderBy: { timestamp: "desc" },
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

  return NextResponse.json({
    session,
    events,
    eventsTotal,
    alerts,
    offenseScenarios: offense,
    defenseScenarios: defense,
  });
}, { module: "api.history" });
