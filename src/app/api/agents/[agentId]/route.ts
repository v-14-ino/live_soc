// ============================================================
// LiveSOC - /api/agents/[agentId]
//
// GET    → get a single agent (without API key hash)
// PATCH  → update agent (enable/disable, name)
// POST   → rotate API key (generates new key, invalidates old)
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { generateApiKey } from "@/lib/monitoring/agent-auth";
import { auditLog } from "@/lib/monitoring/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function serializeAgent(a: {
  id: string;
  agentId: string;
  name: string;
  hostname: string | null;
  os: string | null;
  version: string | null;
  ip: string | null;
  status: string;
  enabled: boolean;
  lastHeartbeat: Date | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: a.id,
    agentId: a.agentId,
    name: a.name,
    hostname: a.hostname,
    os: a.os,
    version: a.version,
    ip: a.ip,
    status: a.status,
    enabled: a.enabled,
    lastHeartbeat: a.lastHeartbeat?.toISOString() ?? null,
    createdAt: a.createdAt.toISOString(),
    updatedAt: a.updatedAt.toISOString(),
    hasApiKey: true, // indicate a key is set, without exposing it
  };
}

export const GET = withApiHandler(
  async (_req: NextRequest, ctx: { params: Promise<{ agentId: string }> }) => {
    const { agentId } = await ctx.params;
    const agent = await db.agent.findUnique({ where: { agentId } });
    if (!agent) {
      return NextResponse.json({ error: "Agent not found" }, { status: 404 });
    }
    return NextResponse.json({ agent: serializeAgent(agent) });
  },
  { module: "api.agents.detail" },
);

export const PATCH = withApiHandler(
  async (req: NextRequest, ctx: { params: Promise<{ agentId: string }> }) => {
    const { agentId } = await ctx.params;
    const body = (await req.json()) as {
      enabled?: boolean;
      name?: string;
    };

    const existing = await db.agent.findUnique({ where: { agentId } });
    if (!existing) {
      return NextResponse.json({ error: "Agent not found" }, { status: 404 });
    }

    const data: Record<string, unknown> = {};
    if (body.enabled !== undefined) data.enabled = body.enabled;
    if (body.name !== undefined) data.name = body.name;

    const agent = await db.agent.update({ where: { agentId }, data });

    await auditLog("info", "api.agents", `Agent updated: ${agentId}`, {
      enabled: body.enabled,
      name: body.name,
    });

    return NextResponse.json({ agent: serializeAgent(agent) });
  },
  { module: "api.agents.detail" },
);

// Rotate API key — generates a new key, invalidates the old one
export const POST = withApiHandler(
  async (_req: NextRequest, ctx: { params: Promise<{ agentId: string }> }) => {
    const { agentId } = await ctx.params;
    const existing = await db.agent.findUnique({ where: { agentId } });
    if (!existing) {
      return NextResponse.json({ error: "Agent not found" }, { status: 404 });
    }

    // Generate new key
    const { key, hash } = generateApiKey();

    // Invalidate old key by replacing the hash
    await db.agent.update({
      where: { agentId },
      data: { apiKeyHash: hash },
    });

    await auditLog("warning", "api.agents", `API key rotated for agent: ${agentId}`);

    // Return the new key ONCE
    return NextResponse.json({
      ok: true,
      agentId,
      apiKey: key,
      message: "New API key generated. Store this securely — it will not be shown again. The old key is now invalid.",
    });
  },
  { module: "api.agents.detail" },
);
