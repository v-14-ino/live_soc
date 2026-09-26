// ============================================================
// LiveSOC - /api/settings
//
// GET → current settings (read AppSetting rows; if empty, seed defaults).
// PUT → update settings (partial AppSettings). Upserts each key.
//       Returns the merged settings.
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { DEFAULT_SETTINGS } from "@/lib/constants";
import type { AppSettings } from "@/lib/types";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Coerce a stored string value back into its typed form based on the
 * default value's type. Booleans → "true"/"false", numbers → stringified
 * integer, everything else stays a string.
 */
function coerceValue(key: keyof AppSettings, raw: string): unknown {
  const def = DEFAULT_SETTINGS[key];
  if (typeof def === "boolean") return raw === "true";
  if (typeof def === "number") {
    const n = Number(raw);
    return Number.isFinite(n) ? n : def;
  }
  return raw;
}

/**
 * Read all AppSetting rows and merge with DEFAULT_SETTINGS. Stored values
 * take precedence. Missing rows default to DEFAULT_SETTINGS.
 */
export async function loadSettings(): Promise<AppSettings> {
  const rows = await db.appSetting.findMany();
  const map = new Map(rows.map((r) => [r.key, r.value]));
  const merged: Record<string, unknown> = {};
  for (const key of Object.keys(DEFAULT_SETTINGS) as (keyof AppSettings)[]) {
    const stored = map.get(key);
    merged[key] = stored == null ? DEFAULT_SETTINGS[key] : coerceValue(key, stored);
  }
  return merged as unknown as AppSettings;
}

export const GET = withApiHandler(async () => {
  const settings = await loadSettings();
  return NextResponse.json({ settings });
}, { module: "api.settings" });

// Partial AppSettings schema for the PUT body.
const UpdateSchema = z
  .object({
    demoMode: z.boolean().optional(),
    telemetryIntervalMs: z.number().int().min(100).max(60_000).optional(),
    maxLiveEvents: z.number().int().min(50).max(10_000).optional(),
    enableNetworkCollector: z.boolean().optional(),
    enableSystemLogsCollector: z.boolean().optional(),
    enableWebLogsCollector: z.boolean().optional(),
    enableFirewallCollector: z.boolean().optional(),
    enableIdsCollector: z.boolean().optional(),
    scanTimeoutSec: z.number().int().min(5).max(600).optional(),
    scanTopPorts: z.number().int().min(1).max(1000).optional(),
    authorizedScopeNote: z.string().min(1).max(500).optional(),
  })
  .strict();

export const PUT = withApiHandler(async (req: NextRequest) => {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body." },
      { status: 400 },
    );
  }

  const parsed = UpdateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid settings.", details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const updates = parsed.data;
  const keys = Object.keys(updates) as (keyof AppSettings)[];

  if (keys.length === 0) {
    const settings = await loadSettings();
    return NextResponse.json({ settings });
  }

  // Upsert each key into the AppSetting table.
  await Promise.all(
    keys.map((key) =>
      db.appSetting.upsert({
        where: { key },
        create: {
          key,
          value: String(updates[key]),
        },
        update: {
          value: String(updates[key]),
        },
      }),
    ),
  );

  await auditLog("info", "api.settings", "Settings updated", { keys });

  const settings = await loadSettings();
  return NextResponse.json({ settings });
}, { module: "api.settings" });
