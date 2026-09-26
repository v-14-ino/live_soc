// ============================================================
// LiveSOC - /api/history
//
// GET    → paginated list of monitoring sessions from the DB.
//          Query params: ?page=1&pageSize=20&status=...&target=...
//          Ordered by startedAt desc. Includes `target`.
// DELETE → wipe ALL monitoring history (sessions + events + alerts +
//          scenarios). Use with caution — irreversible. Audit-logged.
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

export const GET = withApiHandler(async (req: NextRequest) => {
  const sp = req.nextUrl.searchParams;
  const page = parsePositiveInt(sp.get("page"), 1, 10_000);
  const pageSize = parsePositiveInt(sp.get("pageSize"), 20, 100);
  const status = sp.get("status")?.trim() || undefined;
  const target = sp.get("target")?.trim() || undefined;

  const where: { status?: string; target?: { address: { contains: string } } } = {};
  if (status) where.status = status;
  if (target) {
    where.target = { address: { contains: target } };
  }

  const [sessions, total] = await Promise.all([
    db.monitoringSession.findMany({
      where,
      include: { target: true },
      orderBy: { startedAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
    db.monitoringSession.count({ where }),
  ]);

  return NextResponse.json({ sessions, total, page, pageSize });
}, { module: "api.history" });

export const DELETE = withApiHandler(async () => {
  // Delete in dependency order to honor FK constraints.
  // Prisma cascades most relations, but we delete the leaf tables first
  // for clarity and to avoid surprises if cascade rules change.
  const result = await db.$transaction([
    db.alert.deleteMany({}),
    db.event.deleteMany({}),
    db.scenarioDefense.deleteMany({}),
    db.scenarioOffense.deleteMany({}),
    db.report.deleteMany({}),
    db.monitoringSession.deleteMany({}),
  ]);

  const counts = {
    alerts: result[0].count,
    events: result[1].count,
    defenseScenarios: result[2].count,
    offenseScenarios: result[3].count,
    reports: result[4].count,
    sessions: result[5].count,
  };

  await auditLog("warning", "api.history", "All monitoring history cleared", counts);

  return NextResponse.json({ ok: true, deleted: counts });
}, { module: "api.history" });
