// ============================================================
// LiveSOC - /api/adapters/[name]
//
// GET → returns a single adapter's metadata + cached/fresh status.
//       Query param `?force=1` bypasses the cache.
//
// Node.js runtime (adapters use child_process / fs).
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import {
  adapterMetadata,
  fetchAdapterStatus,
  getAdapter,
} from "@/lib/monitoring/adapters";
import type { AdapterInfo } from "@/lib/monitoring/adapters";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withApiHandler(async (
  req: NextRequest,
  ctx: { params: Promise<{ name: string }> },
) => {
  const { name } = await ctx.params;
  const force = req.nextUrl.searchParams.get("force") === "1";

  const adapter = getAdapter(name);
  if (!adapter) {
    return NextResponse.json(
      { error: `Unknown adapter: ${name}` },
      { status: 404 },
    );
  }

  const status = await fetchAdapterStatus(adapter, force);
  const info: AdapterInfo = { ...adapterMetadata(adapter), status };

  return NextResponse.json({ adapter: info });
}, { module: "api.adapters.detail" });
