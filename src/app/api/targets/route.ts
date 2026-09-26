// ============================================================
// LiveSOC - /api/targets
//
// GET → distinct targets from DB for quick reuse in the UI.
//       Returns { targets: [{ address, hostname, lastAssessedAt }] }.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface TargetRow {
  address: string;
  hostname: string | null;
  lastAssessedAt: Date | null;
}

export const GET = withApiHandler(async (_req: NextRequest) => {
  // Use groupBy to get distinct addresses, then look up hostname + the
  // most-recent assessment startedAt for each address.
  const distinct = await db.target.findMany({
    distinct: ["address"],
    select: {
      address: true,
      hostname: true,
      assessments: {
        orderBy: { startedAt: "desc" },
        take: 1,
        select: { startedAt: true },
      },
    },
    orderBy: { address: "asc" },
  });

  const targets: TargetRow[] = distinct.map((t) => ({
    address: t.address,
    hostname: t.hostname,
    lastAssessedAt: t.assessments[0]?.startedAt ?? null,
  }));

  return NextResponse.json({ targets });
}, { module: "api.targets" });
