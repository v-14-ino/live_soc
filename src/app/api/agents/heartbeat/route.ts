// ============================================================
// LiveSOC - POST /api/agents/heartbeat
//
// Receives agent heartbeats. Authenticates via X-Agent-ID/X-Agent-Key.
// Updates agent status to ONLINE + creates a Heartbeat row.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { authenticateAgent } from "@/lib/monitoring/agent-auth";
import { auditLog } from "@/lib/monitoring/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = withApiHandler(async (req: NextRequest) => {
  // Authenticate the agent
  const agent = await authenticateAgent(req);
  if (!agent) {
    return NextResponse.json(
      { error: "Authentication failed. Check X-Agent-ID and X-Agent-Key headers." },
      { status: 401 },
    );
  }

  const body = (await req.json()) as {
    hostname?: string;
    os?: string;
    version?: string;
    ip?: string;
    status?: string;
    metadata?: string;
  };

  // Update agent status
  await db.agent.update({
    where: { id: agent.id },
    data: {
      hostname: body.hostname ?? undefined,
      os: body.os ?? undefined,
      version: body.version ?? undefined,
      ip: body.ip ?? undefined,
      status: body.status ?? "ONLINE",
      lastHeartbeat: new Date(),
    },
  });

  // Create heartbeat record
  await db.heartbeat.create({
    data: {
      agentId: agent.id,
      status: body.status ?? "ONLINE",
      metadata: body.metadata ?? null,
    },
  });

  // Upsert host
  if (body.hostname) {
    await db.host.upsert({
      where: { hostname_ip: { hostname: body.hostname, ip: body.ip ?? "" } },
      create: {
        hostname: body.hostname,
        os: body.os ?? null,
        ip: body.ip ?? null,
        status: "ONLINE",
        lastSeen: new Date(),
      },
      update: {
        os: body.os ?? undefined,
        status: "ONLINE",
        lastSeen: new Date(),
      },
    }).catch(() => { /* unique constraint may not match */ });
  }

  return NextResponse.json({ ok: true, agentId: agent.agentId, status: body.status ?? "ONLINE" });
}, { module: "api.agents.heartbeat" });
