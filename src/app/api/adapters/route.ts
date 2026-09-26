// ============================================================
// LiveSOC - /api/adapters
//
// GET  → list all telemetry adapters with their cached/fresh status.
//        Calls `checkAvailability()` on each adapter in parallel via
//        Promise.allSettled. Results are cached for 30s (process-wide).
//        Query param `?force=1` bypasses the cache.
//
// POST → validate a specific adapter's configuration without
//        starting it. Body: `{ name: string, config: AdapterConfig }`.
//        Returns `{ valid: boolean, issues: string[] }`.
//
// All adapters require Node.js (child_process / fs), so this route
// is pinned to `runtime = "nodejs"`.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";
import {
  ADAPTER_LIST,
  adapterMetadata,
  clearStatusCache,
  fetchAdapterStatus,
  getAdapter,
} from "@/lib/monitoring/adapters";
import type { AdapterInfo } from "@/lib/monitoring/adapters";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = withApiHandler(async (req: NextRequest) => {
  const force = req.nextUrl.searchParams.get("force") === "1";
  if (force) {
    clearStatusCache();
  }

  // Probe every adapter in parallel. Promise.allSettled so a single
  // adapter throwing (it shouldn't) doesn't break the whole response.
  const results = await Promise.allSettled(
    ADAPTER_LIST.map(async (a) => ({
      meta: adapterMetadata(a),
      status: await fetchAdapterStatus(a, force),
    })),
  );

  const adapters: AdapterInfo[] = results.map((r) =>
    r.status === "fulfilled"
      ? { ...r.value.meta, status: r.value.status }
      : {
          name: "nmap" as never, // placeholder; will be replaced below
          displayName: "Unknown",
          description: "Unknown",
          sourceType: "scanner" as const,
          requiresConfig: false,
          status: {
            available: false,
            reason: r.status === "rejected" ? String(r.reason) : "unknown error",
            checkedAt: new Date().toISOString(),
          },
        },
  );

  // The rejected branch above can't easily recover the metadata (we'd
  // need the index). Since the source list is small and known, just
  // re-map any "Unknown" entries by index using ADAPTER_LIST.
  for (let i = 0; i < adapters.length; i++) {
    if (adapters[i].displayName === "Unknown") {
      const meta = adapterMetadata(ADAPTER_LIST[i]);
      adapters[i] = { ...meta, status: adapters[i].status };
    }
  }

  const availableCount = adapters.filter((a) => a.status.available).length;

  await auditLog("info", "api.adapters", "Adapter status list queried", {
    force,
    available: availableCount,
    total: adapters.length,
  });

  return NextResponse.json({
    adapters,
    summary: { available: availableCount, total: adapters.length },
    cached: !force,
  });
}, { module: "api.adapters" });

// ---- POST: validate a config ----------------------------------

const PostSchema = z.object({
  name: z.string().min(1).max(64),
  config: z.object({
    targetAddress: z.string().min(1).max(255),
    options: z.record(z.string(), z.unknown()).optional(),
    intervalMs: z.number().int().min(100).max(3_600_000).optional(),
  }),
});

export const POST = withApiHandler(async (req: NextRequest) => {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const parsed = PostSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request body.", details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const { name, config } = parsed.data;
  const adapter = getAdapter(name);
  if (!adapter) {
    return NextResponse.json(
      { error: `Unknown adapter: ${name}`, valid: false, issues: [`Unknown adapter: ${name}`] },
      { status: 404 },
    );
  }

  const issues = adapter.validateConfig(config);

  await auditLog("info", "api.adapters", `Adapter config validated: ${name}`, {
    name,
    valid: issues.length === 0,
    issueCount: issues.length,
    targetAddress: config.targetAddress,
  });

  return NextResponse.json({
    valid: issues.length === 0,
    issues,
    name,
  });
}, { module: "api.adapters" });
