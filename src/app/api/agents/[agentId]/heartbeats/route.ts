// ============================================================
// LiveSOC - /api/agents/[agentId]/heartbeats
//
// GET → heartbeat history for an agent (paginated, newest first)
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withApiHandler(
  async (req: NextRequest, ctx: { params: Promise<{ agentId: string }> }) => {
    const { agentId } = await ctx.params;
    const limit = Math.min(100, Math.max(1, Number(req.nextUrl.searchParams.get("limit") ?? 50)));

    // Find the agent DB record by agentId
    const agent = await db.agent.findUnique({ where: { agentId } });
    if (!agent) {
      return NextResponse.json({ error: "Agent not found" }, { status: 404 });
    }

    const [heartbeats, total] = await Promise.all([
      db.heartbeat.findMany({
        where: { agentId: agent.id },
        orderBy: { timestamp: "desc" },
        take: limit,
      }),
      db.heartbeat.count({ where: { agentId: agent.id } }),
    ]);

    return NextResponse.json({
      agentId,
      heartbeats: heartbeats.map((h) => ({
        id: h.id,
        timestamp: h.timestamp.toISOString(),
        status: h.status,
        metadata: h.metadata,
      })),
      total,
    });
  },
  { module: "api.agents.heartbeats" },
);
