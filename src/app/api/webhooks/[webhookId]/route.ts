// ============================================================
// LiveSOC - /api/webhooks/[webhookId]
//
// PATCH  → update a webhook config
// DELETE → delete a webhook config
// POST   → test a webhook (send a test payload)
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { withApiHandler } from "@/lib/server/monitor-proxy";
import { auditLog } from "@/lib/monitoring/audit";
import type { WebhookInput } from "@/lib/types";

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
}) {
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

export const PATCH = withApiHandler(
  async (req: NextRequest, ctx: { params: Promise<{ webhookId: string }> }) => {
    const { webhookId } = await ctx.params;
    const body = (await req.json()) as Partial<WebhookInput>;

    const existing = await db.webhookConfig.findUnique({ where: { id: webhookId } });
    if (!existing) {
      return NextResponse.json({ error: "Webhook not found" }, { status: 404 });
    }

    const data: Record<string, unknown> = {};
    if (body.name !== undefined) data.name = body.name.trim();
    if (body.url !== undefined) data.url = body.url.trim();
    if (body.enabled !== undefined) data.enabled = body.enabled;
    if (body.severities !== undefined) data.severities = body.severities.join(",");
    if (body.secret !== undefined) data.secret = body.secret || null;
    if (body.cooldownSec !== undefined) data.cooldownSec = body.cooldownSec;

    const row = await db.webhookConfig.update({
      where: { id: webhookId },
      data,
    });

    await auditLog("info", "api.webhooks", `Webhook updated: ${row.name}`);

    return NextResponse.json({ webhook: serializeWebhook(row) });
  },
  { module: "api.webhooks" },
);

export const DELETE = withApiHandler(
  async (_req: NextRequest, ctx: { params: Promise<{ webhookId: string }> }) => {
    const { webhookId } = await ctx.params;
    const existing = await db.webhookConfig.findUnique({ where: { id: webhookId } });
    if (!existing) {
      return NextResponse.json({ error: "Webhook not found" }, { status: 404 });
    }
    await db.webhookConfig.delete({ where: { id: webhookId } });
    await auditLog("warning", "api.webhooks", `Webhook deleted: ${existing.name}`);
    return NextResponse.json({ ok: true, webhookId });
  },
  { module: "api.webhooks" },
);

export const POST = withApiHandler(
  async (_req: NextRequest, ctx: { params: Promise<{ webhookId: string }> }) => {
    const { webhookId } = await ctx.params;
    const existing = await db.webhookConfig.findUnique({ where: { id: webhookId } });
    if (!existing) {
      return NextResponse.json({ error: "Webhook not found" }, { status: 404 });
    }

    // Send a test payload
    const testPayload = {
      platform: "LiveSOC",
      event: "test",
      message: "Test webhook delivery from LiveSOC",
      webhookId: existing.id,
      webhookName: existing.name,
      timestamp: new Date().toISOString(),
    };
    const body = JSON.stringify(testPayload);

    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "User-Agent": "LiveSOC-Webhook/1.0",
      };
      if (existing.secret) {
        const { createHmac } = await import("crypto");
        const sig = createHmac("sha256", existing.secret).update(body).digest("hex");
        headers["X-LiveSOC-Signature"] = `sha256=${sig}`;
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(existing.url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!res.ok) {
        return NextResponse.json({
          ok: false,
          status: res.status,
          message: `Webhook returned HTTP ${res.status}`,
        });
      }

      await db.webhookConfig.update({
        where: { id: webhookId },
        data: { lastCalled: new Date(), lastError: null },
      });

      return NextResponse.json({ ok: true, status: res.status, message: "Test delivered successfully" });
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Unknown error";
      await db.webhookConfig.update({
        where: { id: webhookId },
        data: { lastCalled: new Date(), lastError: errMsg.slice(0, 500) },
      });
      return NextResponse.json({ ok: false, message: errMsg });
    }
  },
  { module: "api.webhooks" },
);
