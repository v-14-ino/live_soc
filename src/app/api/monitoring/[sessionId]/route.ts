// ============================================================
// LiveSOC - /api/monitoring/[sessionId]
//
// GET    → status snapshot (proxied to monitor-service).
// DELETE → stop monitoring (proxied to monitor-service).
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import {
  monitorFetch,
  withApiHandler,
} from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface MonitorStatusResponse {
  sessionId: string;
  session: unknown;
  assessment: unknown;
  kpi: unknown;
  networkActivity: unknown;
  eventCount: number;
  alertCount: number;
  offenseScenarios: unknown[];
  defenseScenarios: unknown[];
}

export const GET = withApiHandler(async (
  _req: NextRequest,
  ctx: { params: Promise<{ sessionId: string }> },
) => {
  const { sessionId } = await ctx.params;
  const result = await monitorFetch<MonitorStatusResponse>(
    `/internal/status/${encodeURIComponent(sessionId)}`,
  );
  return NextResponse.json(result);
}, { module: "api.monitoring" });

export const DELETE = withApiHandler(async (
  _req: NextRequest,
  ctx: { params: Promise<{ sessionId: string }> },
) => {
  const { sessionId } = await ctx.params;

  const result = await monitorFetch<{ ok: boolean; sessionId: string }>(
    "/internal/stop",
    {
      method: "POST",
      body: JSON.stringify({ sessionId }),
    },
  );

  await auditLog("info", "api.monitoring", "Monitoring session stopped", {
    sessionId,
  });

  return NextResponse.json(result);
}, { module: "api.monitoring" });
