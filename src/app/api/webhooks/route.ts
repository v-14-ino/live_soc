// ============================================================
// LiveSOC - /api/webhooks
//
// GET  → list all webhook configs
// POST → create a new webhook config
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";
import type { WebhookConfig, WebhookInput } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function serializeWebhook(r: {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  severities: string;
  secret: string | null;
  cooldownSec: number;
  lastCalled: Date | null;
  callCount: number;
  failCount: number;
  lastError: string | null;
  createdAt: Date;
  updatedAt: Date;
}): WebhookConfig {
  return {
    id: r.id,
    name: r.name,
    url: r.url,
    enabled: r.enabled,
    severities: r.severities.split(",").map((s) => s.trim()).filter(Boolean),
    secret: r.secret,
    cooldownSec: r.cooldownSec,
    lastCalled: r.lastCalled?.toISOString() ?? null,
    callCount: r.callCount,
    failCount: r.failCount,
    lastError: r.lastError,
    createdAt: r.createdAt.toISOString(),
    updatedAt: r.updatedAt.toISOString(),
  };
}

export const GET = withApiHandler(async () => {
  const rows = await db.webhookConfig.findMany({
    orderBy: { createdAt: "desc" },
  });
  const webhooks = rows.map(serializeWebhook);
  return NextResponse.json({ webhooks, total: webhooks.length });
}, { module: "api.webhooks" });

export const POST = withApiHandler(async (req: NextRequest) => {
  const body = (await req.json()) as WebhookInput;

  if (!body.name || body.name.trim().length === 0) {
    return NextResponse.json({ error: "Webhook name is required" }, { status: 400 });
  }
  if (!body.url || !body.url.startsWith("http")) {
    return NextResponse.json({ error: "Valid webhook URL is required (must start with http)" }, { status: 400 });
  }

  const severities = body.severities ?? ["critical", "high"];
  if (!Array.isArray(severities) || severities.length === 0) {
    return NextResponse.json({ error: "At least one severity is required" }, { status: 400 });
  }

  const row = await db.webhookConfig.create({
    data: {
      name: body.name.trim(),
      url: body.url.trim(),
      enabled: body.enabled ?? true,
      severities: severities.join(","),
      secret: body.secret ?? null,
      cooldownSec: body.cooldownSec ?? 10,
    },
  });

  await auditLog("info", "api.webhooks", `Webhook created: ${row.name} (${row.url})`);

  return NextResponse.json({ webhook: serializeWebhook(row) }, { status: 201 });
}, { module: "api.webhooks" });
