// ============================================================
// LiveSOC - /api/reports
//
// GET  → paginated list of reports from the DB (newest first).
// POST → generate a new report. Body: { sessionId }.
//        Fetches session data via assembleReportData, creates a
//        Report DB row, returns { report, data }.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";
import {
  assembleReportData,
  computeRiskLevel,
  type ReportData,
} from "@/lib/monitoring/report";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function parsePositiveInt(value: string | null, def: number, max: number): number {
  const n = value == null ? NaN : Number(value);
  if (!Number.isFinite(n) || n < 1) return def;
  return Math.min(max, Math.floor(n));
}

export const GET = withApiHandler(async (req: NextRequest) => {
  const sp = req.nextUrl.searchParams;
  const page = parsePositiveInt(sp.get("page"), 1, 10_000);
  const pageSize = parsePositiveInt(sp.get("pageSize"), 20, 100);

  const [reports, total] = await Promise.all([
    db.report.findMany({
      orderBy: { generatedAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
    db.report.count(),
  ]);

  return NextResponse.json({ reports, total, page, pageSize });
}, { module: "api.reports" });

const GenerateSchema = z.object({
  sessionId: z.string().min(1).max(255),
});

export const POST = withApiHandler(async (req: NextRequest) => {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body." },
      { status: 400 },
    );
  }

  const parsed = GenerateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request.", details: parsed.error.flatten() },
      { status: 400 },
    );
  }
  const { sessionId } = parsed.data;

  // Verify the session exists.
  const session = await db.monitoringSession.findUnique({
    where: { id: sessionId },
    include: { target: true },
  });
  if (!session) {
    return NextResponse.json(
      { error: "Session not found." },
      { status: 404 },
    );
  }

  // Assemble full report data (events + alerts + scenarios + summary).
  let data: ReportData;
  try {
    data = await assembleReportData(sessionId);
  } catch (err) {
    await auditLog("error", "api.reports", "Failed to assemble report data", {
      sessionId,
      error: err instanceof Error ? err.message : String(err),
    });
    return NextResponse.json(
      { error: "Initial assessment failed." },
      { status: 500 },
    );
  }

  const riskLevel = computeRiskLevel(data.alerts, data.offenseScenarios);

  // Build a short human-readable summary for quick listing.
  const summary = {
    target: data.session.targetAddress,
    mode: data.session.mode,
    durationSec: data.session.durationSec,
    riskSummary: data.riskSummary,
    topSourceIps: data.topSourceIps,
    topDestPorts: data.topDestPorts,
    eventsBySeverity: data.eventsSummary.bySeverity,
    recommendations: data.recommendations,
  };

  // Generate a unique report id: RPT-<epoch base36>-<random base36>.
  const reportId = `RPT-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 8)}`;

  const report = await db.report.create({
    data: {
      reportId,
      sessionId,
      target: data.session.targetAddress,
      title: `LiveSOC Report — ${data.session.targetAddress} — ${data.session.startedAt}`,
      riskLevel,
      eventCount: data.session.eventCount,
      alertCount: data.session.alertCount,
      scenarioCount: data.offenseScenarios.length + data.defenseScenarios.length,
      jsonSummary: JSON.stringify(summary),
    },
  });

  await auditLog("info", "api.reports", "Report generated", {
    reportId: report.id,
    sessionId,
    target: data.session.targetAddress,
    riskLevel,
  });

  return NextResponse.json({ report, data }, { status: 201 });
}, { module: "api.reports" });
