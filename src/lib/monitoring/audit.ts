// ============================================================
// LiveSOC - Structured audit logging to DB
// Non-throwing: failures are logged to console only.
// ============================================================

import { db } from "@/lib/db";

export type AuditLevel = "debug" | "info" | "warning" | "error" | "critical";

export async function auditLog(
  level: AuditLevel,
  module: string,
  message: string,
  meta?: Record<string, unknown>,
): Promise<void> {
  try {
    await db.auditLog.create({
      data: {
        level,
        module,
        message,
        meta: meta ? JSON.stringify(meta) : null,
      },
    });
  } catch (err) {
    // Non-throwing: swallow errors so callers never crash on audit failures.
     
    console.error("[auditLog] failed to persist audit entry:", err);
  }
}
