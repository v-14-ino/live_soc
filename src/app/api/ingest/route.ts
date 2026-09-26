// ============================================================
// LiveSOC - POST /api/ingest
//
// External real-telemetry ingestion endpoint (Phase 5).
//
// Flow:
//   1. Validate the incoming JSON payload (validateIngestPayload)
//   2. Authenticate the source where practical (agent API key — future)
//   3. Identify the agent/source (agentId → recordHeartbeat)
//   4. Store the ORIGINAL payload in RawLog (via sessionManager.ingestEvent)
//   5. Normalize the event (normalizePayload → SecurityEvent)
//   6. Add receivedAt + dataSource=REAL
//   7. Feed into the EXISTING processEvent() pipeline (no second pipeline)
//   8. → detection → correlation → alert → OFFENSE/DEFENSE → WebSocket
//
// The endpoint requires an active monitoring session (sessionId in the
// body or query). If no session is active, returns 409 Conflict with a
// helpful message.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { monitorFetch, withApiHandler } from "@/lib/server/monitor-proxy";
import {
  normalizePayload,
  validateIngestPayload,
  type IngestPayload,
} from "@/lib/monitoring/normalizer";
import { auditLog } from "@/lib/monitoring/audit";
import type { SecurityEvent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface IngestBody extends IngestPayload {
  // The monitoring session to ingest into. Required.
  sessionId?: string;
}

interface IngestInternalResponse {
  ok: boolean;
  eventId?: string;
  error?: string;
}

export const POST = withApiHandler(async (req: NextRequest) => {
  const body = (await req.json()) as IngestBody;

  // 1. Validate
  const errors = validateIngestPayload(body);
  if (errors.length > 0) {
    await auditLog("warning", "api.ingest", "Invalid ingestion payload", { errors });
    return NextResponse.json(
      { error: "Invalid payload", details: errors },
      { status: 400 },
    );
  }

  // 2. Identify session
  const sessionId = body.sessionId || req.nextUrl.searchParams.get("sessionId");
  if (!sessionId) {
    return NextResponse.json(
      { error: "sessionId is required (in body or query). Start a monitoring session first." },
      { status: 409 },
    );
  }

  // 3. Record agent heartbeat (if agentId present)
  if (body.agentId) {
    try {
      await monitorFetch("/internal/heartbeat", {
        method: "POST",
        body: JSON.stringify({
          agentId: body.agentId,
          hostname: body.hostname,
          os: body.os,
          ip: body.sourceIp,
          status: "ONLINE",
        }),
      });
    } catch {
      // non-fatal — heartbeat failure shouldn't block ingestion
    }
  }

  // 4. Normalize the payload into a SecurityEvent
  const { event, parser, warnings } = normalizePayload(body as IngestPayload);

  // 5. Build the raw log payload (original evidence)
  const rawPayload = JSON.stringify(body);
  const rawLogMeta = warnings.length > 0 ? JSON.stringify({ warnings }) : undefined;

  // 6. Feed into the EXISTING processEvent pipeline via monitor-service
  //    The monitor-service owns the sessionManager singleton, so we proxy
  //    the ingestEvent call to it.
  try {
    const result = await monitorFetch<IngestInternalResponse>("/internal/ingest", {
      method: "POST",
      body: JSON.stringify({
        sessionId,
        event,
        rawLog: {
          sourceType: body.sourceType,
          rawPayload,
          parser,
          agentId: body.agentId,
          hostname: body.hostname,
          metadata: rawLogMeta,
        },
      }),
    });

    if (!result.ok) {
      return NextResponse.json(
        { error: result.error || "Ingestion failed" },
        { status: 409 },
      );
    }

    await auditLog("info", "api.ingest", `Ingested REAL event ${result.eventId}`, {
      sessionId,
      sourceType: body.sourceType,
      eventType: body.eventType,
      agentId: body.agentId,
    });

    return NextResponse.json({
      ok: true,
      eventId: result.eventId,
      dataSource: "REAL",
      parser,
      warnings: warnings.length > 0 ? warnings : undefined,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Ingestion service unavailable";
    await auditLog("error", "api.ingest", `Ingestion failed: ${msg}`, {
      sessionId,
      sourceType: body.sourceType,
    });
    return NextResponse.json(
      { error: "Unable to connect to monitoring service." },
      { status: 503 },
    );
  }
}, { module: "api.ingest" });

// GET → endpoint documentation (helps agents discover the schema)
export const GET = withApiHandler(async () => {
  return NextResponse.json({
    endpoint: "POST /api/ingest",
    description: "External real-telemetry ingestion endpoint",
    schema: {
      sessionId: "string (required) — active monitoring session ID",
      agentId: "string (optional) — agent identifier",
      hostname: "string (optional)",
      os: "string (optional)",
      sourceType: "string (required) — linux_auth | syslog | journald | windows_event_log | firewall | network | web_log | process | demo",
      eventCategory: "string (optional) — authentication | network | process | firewall | web",
      timestamp: "string (optional, ISO) — when the source observed the event",
      username: "string (optional)",
      sourceIp: "string (optional)",
      sourcePort: "number (optional)",
      destinationIp: "string (optional)",
      destinationPort: "number (optional)",
      protocol: "string (optional)",
      eventType: "string (required) — e.g. authentication_failure, connection, firewall_deny",
      action: "string (optional) — allow | deny | success | failure",
      severity: "string (optional) — critical | high | medium | low | info",
      message: "string (optional)",
      rawEvent: "string (optional) — original raw log line",
      metadata: "object (optional)",
    },
    example: {
      sessionId: "cmui...",
      agentId: "agent-001",
      hostname: "lab-linux",
      os: "Linux",
      sourceType: "linux_auth",
      eventType: "authentication_failure",
      username: "root",
      sourceIp: "192.168.1.50",
      destinationIp: "192.168.1.100",
      destinationPort: 22,
      protocol: "TCP",
      timestamp: "2026-01-01T00:00:00Z",
      rawEvent: "Failed password for root from 192.168.1.50 port 49152 ssh2",
    },
  });
}, { module: "api.ingest" });
