// ============================================================
// LiveSOC - /api/reports/[reportId]
//
// GET → report detail: the stored Report row + its jsonSummary parsed
//       + the full `data: ReportData` re-assembled from the DB (so the
//       client can render a complete preview / generate a PDF without
//       needing to remember the POST-time payload).
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { assembleReportData, type ReportData } from "@/lib/monitoring/report";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withApiHandler(async (
  _req: NextRequest,
  ctx: { params: Promise<{ reportId: string }> },
) => {
  const { reportId } = await ctx.params;

  // Allow lookup by either the DB id (cuid) or the unique reportId.
  const report = await db.report.findFirst({
    where: {
      OR: [{ id: reportId }, { reportId: reportId }],
    },
  });

  if (!report) {
    return NextResponse.json(
      { error: "Report not found." },
      { status: 404 },
    );
  }

  let summary: unknown = null;
  if (report.jsonSummary) {
    try {
      summary = JSON.parse(report.jsonSummary);
    } catch {
      summary = null;
    }
  }

  // Re-assemble the full ReportData from the still-persisted session.
  // If the session row (or its children) was deleted, fall back to null.
  let data: ReportData | null = null;
  if (report.sessionId) {
    try {
      data = await assembleReportData(report.sessionId);
    } catch {
      data = null;
    }
  }

  return NextResponse.json({ report, summary, data });
}, { module: "api.reports" });
