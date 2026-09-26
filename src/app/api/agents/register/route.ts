// ============================================================
// LiveSOC - POST /api/agents/register
//
// Registers a new agent and returns an API key.
// The API key is shown ONCE — only the hash is stored.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { generateApiKey } from "@/lib/monitoring/agent-auth";
import { auditLog } from "@/lib/monitoring/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = withApiHandler(async (req: NextRequest) => {
  const body = (await req.json()) as {
    agentId?: string;
    name?: string;
    hostname?: string;
    os?: string;
  };

  if (!body.agentId || body.agentId.trim().length === 0) {
    return NextResponse.json({ error: "agentId is required" }, { status: 400 });
  }

  // Check if agent already exists
  const existing = await db.agent.findUnique({ where: { agentId: body.agentId } });
  if (existing) {
    return NextResponse.json(
      { error: "Agent already registered. Use a unique agentId." },
      { status: 409 },
    );
  }

  // Generate API key
  const { key, hash } = generateApiKey();

  // Create agent
  const agent = await db.agent.create({
    data: {
      agentId: body.agentId.trim(),
      name: body.name ?? body.agentId,
      hostname: body.hostname ?? null,
      os: body.os ?? null,
      apiKeyHash: hash,
      enabled: true,
      status: "OFFLINE",
    },
  });

  await auditLog("info", "api.agents", `Agent registered: ${body.agentId}`, {
    agentId: body.agentId,
    name: body.name,
  });

  // Return the API key ONCE
  return NextResponse.json({
    ok: true,
    agentId: agent.agentId,
    apiKey: key,
    message: "Store this API key securely — it will not be shown again.",
  }, { status: 201 });
}, { module: "api.agents.register" });

// GET → list registered agents (without API keys)
export const GET = withApiHandler(async () => {
  const agents = await db.agent.findMany({
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      agentId: true,
      name: true,
      hostname: true,
      os: true,
      version: true,
      ip: true,
      status: true,
      enabled: true,
      lastHeartbeat: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  return NextResponse.json({ agents, total: agents.length });
}, { module: "api.agents.register" });
