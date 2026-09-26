// ============================================================
// LiveSOC - /api/monitoring
//
// POST  → start a monitoring session. Validates the target is in
//         authorized lab scope FIRST, then proxies to the
//         monitor-service `/internal/start`.
// GET   → list currently active sessions (proxied).
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import {
  monitorFetch,
  checkRateLimit,
  getClientIp,
  withApiHandler,
  MonitorServiceError,
} from "@/lib/server/monitor-proxy";
import { validateTarget } from "@/lib/monitoring/scanner";
import { auditLog } from "@/lib/monitoring/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const StartSchema = z.object({
  target: z.string().min(1).max(255),
  mode: z.enum(["demo", "live"]).optional().default("demo"),
});

interface MonitorStartResponse {
  sessionId: string;
  session: unknown;
  assessment: unknown;
}

export const POST = withApiHandler(async (req: NextRequest) => {
  const ip = getClientIp(req);

  // --- Per-IP rate-limit guard: max 10 starts / minute ---
  const rl = checkRateLimit(ip, 10, 60_000);
  if (!rl.ok) {
    await auditLog("warning", "api.monitoring", "Rate limit exceeded", {
      ip,
      resetInMs: rl.resetInMs,
    });
    return NextResponse.json(
      {
        error: "Too many start requests. Please try again later.",
        retryAfterMs: rl.resetInMs,
      },
      { status: 429 },
    );
  }

  // --- Parse body ---
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body." },
      { status: 400 },
    );
  }

  const parsed = StartSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request.", details: parsed.error.flatten() },
      { status: 400 },
    );
  }
  const { target, mode } = parsed.data;

  // --- Validate target against authorized-lab scope FIRST ---
  const v = validateTarget(target);
  if (!v.ok) {
    await auditLog("warning", "api.monitoring", "Target rejected", {
      target,
      reason: v.reason,
      ip,
    });
    return NextResponse.json(
      { error: v.reason ?? "Target is unreachable.", code: "INVALID_TARGET" },
      { status: 400 },
    );
  }

  // --- Proxy to monitor-service ---
  try {
    const result = await monitorFetch<MonitorStartResponse>(
      "/internal/start",
      {
        method: "POST",
        body: JSON.stringify({ target, mode }),
      },
    );

    await auditLog("info", "api.monitoring", "Monitoring session started", {
      sessionId: result.sessionId,
      target,
      mode,
      ip,
    });

    return NextResponse.json(result, { status: 200 });
  } catch (err) {
    if (err instanceof MonitorServiceError && err.code === "BAD_REQUEST") {
      // Monitor-service rejects with 400 if startSession fails (e.g.
      // assessment error). Translate to the user-friendly message.
      return NextResponse.json(
        { error: "Initial assessment failed.", code: "START_FAILED" },
        { status: 400 },
      );
    }
    throw err;
  }
}, { module: "api.monitoring" });

export const GET = withApiHandler(async () => {
  const result = await monitorFetch<{ sessions: unknown[] }>(
    "/internal/active",
  );
  return NextResponse.json(result);
}, { module: "api.monitoring" });
