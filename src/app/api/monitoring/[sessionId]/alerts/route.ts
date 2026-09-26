// ============================================================
// LiveSOC - /api/monitoring/[sessionId]/alerts
//
// GET   → recent alerts for the session (proxied; limit default 100, cap 200).
// PATCH → update the status of a single alert.
//         Body: { alertId, status: "acknowledged" | "resolved" | "active" }.
//         Proxied to monitor-service which handles both active and
//         historical (DB-only) sessions.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import {
  monitorFetch,
  withApiHandler,
  type MonitorServiceError,
} from "@/lib/server/monitor-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface MonitorAlertsResponse {
  sessionId: string;
  alerts: unknown[];
}

interface AlertStatusUpdateResponse {
  ok: boolean;
  alertId: string;
  status: string;
}

const VALID_ALERT_STATUSES = new Set(["acknowledged", "resolved", "active"]);

function parseLimit(value: string | null): number {
  const n = value == null ? NaN : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 100;
  // Monitor-service caps alerts at 200.
  return Math.min(200, Math.floor(n));
}

export const GET = withApiHandler(async (
  req: NextRequest,
  ctx: { params: Promise<{ sessionId: string }> },
) => {
  const { sessionId } = await ctx.params;
  const limit = parseLimit(req.nextUrl.searchParams.get("limit"));

  const result = await monitorFetch<MonitorAlertsResponse>(
    `/internal/alerts/${encodeURIComponent(sessionId)}?limit=${limit}`,
  );
  return NextResponse.json(result);
}, { module: "api.monitoring" });

export const PATCH = withApiHandler(async (
  req: NextRequest,
  ctx: { params: Promise<{ sessionId: string }> },
) => {
  const { sessionId } = await ctx.params;

  let body: { alertId?: unknown; status?: unknown };
  try {
    body = (await req.json()) as { alertId?: unknown; status?: unknown };
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body." },
      { status: 400 },
    );
  }

  const alertId = typeof body.alertId === "string" ? body.alertId.trim() : "";
  const status = typeof body.status === "string" ? body.status.trim() : "";

  if (!alertId) {
    return NextResponse.json(
      { error: "Missing 'alertId' in body." },
      { status: 400 },
    );
  }
  if (!VALID_ALERT_STATUSES.has(status)) {
    return NextResponse.json(
      {
        error:
          "Invalid 'status'. Must be one of: acknowledged, resolved, active.",
      },
      { status: 400 },
    );
  }

  try {
    const result = await monitorFetch<AlertStatusUpdateResponse>(
      `/internal/alerts/${encodeURIComponent(alertId)}`,
      {
        method: "PATCH",
        body: JSON.stringify({ sessionId, status }),
      },
    );
    return NextResponse.json(result);
  } catch (err) {
    const e = err as MonitorServiceError;
    // 404 from the monitor-service means the alert wasn't found (either
    // in the active session or in the DB for historical sessions).
    if (e.code === "NOT_FOUND") {
      return NextResponse.json(
        { error: "Alert not found." },
        { status: 404 },
      );
    }
    if (e.code === "UNREACHABLE") {
      return NextResponse.json(
        { error: "Unable to connect to monitoring service." },
        { status: 503 },
      );
    }
    if (e.code === "BAD_REQUEST") {
      return NextResponse.json(
        { error: "Invalid alert status request." },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Unable to update alert status." },
      { status: 502 },
    );
  }
}, { module: "api.monitoring" });
