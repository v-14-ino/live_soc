// ============================================================
// LiveSOC - /api/monitoring/[sessionId]/scenarios
//
// GET → { offense: [], defense: [] } (proxied).
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import {
  monitorFetch,
  withApiHandler,
} from "@/lib/server/monitor-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface MonitorScenariosResponse {
  sessionId: string;
  offense: unknown[];
  defense: unknown[];
}

export const GET = withApiHandler(async (
  _req: NextRequest,
  ctx: { params: Promise<{ sessionId: string }> },
) => {
  const { sessionId } = await ctx.params;
  const result = await monitorFetch<MonitorScenariosResponse>(
    `/internal/scenarios/${encodeURIComponent(sessionId)}`,
  );
  return NextResponse.json(result);
}, { module: "api.monitoring" });
