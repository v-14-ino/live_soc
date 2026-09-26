// ============================================================
// LiveSOC - /api/monitoring/[sessionId]/telemetry-sources
//
// GET → telemetry source status for a session (Phase 9)
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { monitorFetch, withApiHandler } from "@/lib/server/monitor-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withApiHandler(
  async (_req: NextRequest, ctx: { params: Promise<{ sessionId: string }> }) => {
    const { sessionId } = await ctx.params;
    const result = await monitorFetch<{
      sessionId: string;
      sources: Array<{
        name: string;
        displayName: string;
        sourceType: string;
        status: string;
        reason?: string;
      }>;
    }>(`/internal/telemetry-sources/${encodeURIComponent(sessionId)}`);
    return NextResponse.json(result);
  },
  { module: "api.monitoring.telemetry-sources" },
);
