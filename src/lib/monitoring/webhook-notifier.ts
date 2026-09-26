// ============================================================
// LiveSOC - Webhook Notifier
//
// Fires HTTP POST requests to configured webhook URLs when
// high-severity alerts are generated. Runs in the session
// manager (monitor-service process) alongside the detection
// engine. Respects per-webhook severity filters + cooldown.
// ============================================================

import { db } from "@/lib/db";
import type { SecurityAlert, WebhookConfig } from "@/lib/types";
import { auditLog } from "./audit";

interface WebhookRow {
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
}

function serializeWebhook(r: WebhookRow): WebhookConfig {
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
    createdAt: "",
    updatedAt: "",
  };
}

/**
 * Load all enabled webhooks from the DB.
 */
export async function loadEnabledWebhooks(): Promise<WebhookConfig[]> {
  try {
    const rows = await db.webhookConfig.findMany({
      where: { enabled: true },
    });
    return rows.map(serializeWebhook);
  } catch (err) {
    console.error("[webhook] failed to load webhooks:", err);
    return [];
  }
}

/**
 * Notify all matching webhooks about a new alert.
 * Respects severity filter + per-webhook cooldown.
 * Non-throwing — logs errors to audit log.
 */
export async function notifyWebhooks(
  alert: SecurityAlert,
  webhooks: WebhookConfig[],
): Promise<void> {
  if (webhooks.length === 0) return;

  const now = Date.now();

  for (const wh of webhooks) {
    // Check severity filter
    if (!wh.severities.includes(alert.severity)) continue;

    // Check cooldown
    if (wh.lastCalled) {
      const lastMs = new Date(wh.lastCalled).getTime();
      if (now - lastMs < wh.cooldownSec * 1000) continue;
    }

    // Build payload
    const payload = {
      platform: "LiveSOC",
      event: "alert",
      alert: {
        alertId: alert.alertId,
        ruleId: alert.ruleId,
        ruleName: alert.ruleName,
        severity: alert.severity,
        confidence: alert.confidence,
        message: alert.message,
        recommendedAction: alert.recommendedAction,
        timestamp: alert.timestamp,
        eventId: alert.eventId,
      },
    };

    const body = JSON.stringify(payload);
    const startedAt = Date.now();

    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "User-Agent": "LiveSOC-Webhook/1.0",
      };

      // HMAC signing with secret (if configured)
      if (wh.secret) {
        try {
          const { createHmac } = await import("crypto");
          const sig = createHmac("sha256", wh.secret).update(body).digest("hex");
          headers["X-LiveSOC-Signature"] = `sha256=${sig}`;
        } catch {
          // crypto unavailable — skip signing
        }
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      const res = await fetch(wh.url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      const latencyMs = Date.now() - startedAt;
      const responseText = await res.text().catch(() => "");
      const responseExcerpt = responseText.slice(0, 500) || null;

      if (!res.ok) {
        throw new Error(`HTTP ${res.status} ${res.statusText}`);
      }

      // Success — update config + log delivery
      await db.webhookConfig.update({
        where: { id: wh.id },
        data: {
          lastCalled: new Date(),
          callCount: { increment: 1 },
          lastError: null,
        },
      });

      await db.webhookDelivery.create({
        data: {
          webhookId: wh.id,
          alertId: alert.alertId,
          eventType: "alert",
          statusCode: res.status,
          status: "success",
          responseExcerpt,
          latencyMs,
          payload: body.slice(0, 4096),
        },
      }).catch(() => { /* ignore delivery log errors */ });

      await auditLog("info", "webhook", `Webhook delivered: ${wh.name}`, {
        webhookId: wh.id,
        alertId: alert.alertId,
        status: res.status,
        latencyMs,
      });
    } catch (fetchErr) {
      const errMsg = fetchErr instanceof Error ? fetchErr.message : "Unknown error";
      const latencyMs = Date.now() - startedAt;
      const isTimeout = fetchErr instanceof Error && fetchErr.name === "AbortError";
      const deliveryStatus = isTimeout ? "timeout" : "error";

      // Update config with failure
      try {
        await db.webhookConfig.update({
          where: { id: wh.id },
          data: {
            lastCalled: new Date(),
            callCount: { increment: 1 },
            failCount: { increment: 1 },
            lastError: errMsg.slice(0, 500),
          },
        });
      } catch {
        // ignore DB errors
      }

      // Log delivery failure
      await db.webhookDelivery.create({
        data: {
          webhookId: wh.id,
          alertId: alert.alertId,
          eventType: "alert",
          statusCode: null,
          status: deliveryStatus,
          errorMessage: errMsg.slice(0, 500),
          latencyMs,
          payload: body.slice(0, 4096),
        },
      }).catch(() => { /* ignore delivery log errors */ });

      await auditLog("warning", "webhook", `Webhook failed: ${wh.name}`, {
        webhookId: wh.id,
        alertId: alert.alertId,
        error: errMsg,
        latencyMs,
      });
    }
  }
}
