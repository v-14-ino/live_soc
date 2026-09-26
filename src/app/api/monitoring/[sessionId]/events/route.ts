// ============================================================
// LiveSOC - /api/monitoring/[sessionId]/events
//
// GET → recent events for the session (proxied; limit default 100, cap 500).
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import {
  monitorFetch,
  withApiHandler,
} from "@/lib/server/monitor-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface MonitorEventsResponse {
  sessionId: string;
  events: unknown[];
}

function parseLimit(value: string | null): number {
  const n = value == null ? NaN : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 100;
  return Math.min(500, Math.floor(n));
}

export const GET = withApiHandler(async (
  req: NextRequest,
  ctx: { params: Promise<{ sessionId: string }> },
) => {
  const { sessionId } = await ctx.params;
  const limit = parseLimit(req.nextUrl.searchParams.get("limit"));

  const result = await monitorFetch<MonitorEventsResponse>(
    `/internal/events/${encodeURIComponent(sessionId)}?limit=${limit}`,
  );
  return NextResponse.json(result);
}, { module: "api.monitoring" });
