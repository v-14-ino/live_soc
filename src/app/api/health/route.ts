// ============================================================
// LiveSOC - /api/health
//
// GET → { status: 'ok', monitorService: 'up'|'down', db: 'up', time }
//       Pings monitor-service /internal/active with a 2s timeout.
// ============================================================

import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { pingMonitorService, withApiHandler } from "@/lib/server/monitor-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withApiHandler(async () => {
  const time = new Date().toISOString();

  // Ping monitor-service (2s timeout).
  const monitorService = (await pingMonitorService(2_000)) ? "up" : "down";

  // Ping DB with a trivial query.
  let dbStatus: "up" | "down" = "down";
  try {
    await db.appSetting.count();
    dbStatus = "up";
  } catch {
    dbStatus = "down";
  }

  const ok = monitorService === "up" && dbStatus === "up";

  return NextResponse.json({
    status: ok ? "ok" : "degraded",
    monitorService,
    db: dbStatus,
    time,
  });
}, { module: "api.health" });
