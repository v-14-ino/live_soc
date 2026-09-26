// ============================================================
// LiveSOC - Server-side proxy helpers for the monitor-service
//
// The monitor-service (port 3003) owns the in-memory sessionManager.
// Next.js API routes proxy browser requests to it via these helpers.
// This is server-to-server and always uses http://127.0.0.1:3003.
//
// All functions here run on the Node.js runtime only.
// ============================================================

import { NextResponse } from "next/server";
import { auditLog } from "@/lib/monitoring/audit";

/** Base URL of the internal monitor-service REST surface. */
export const MONITOR_SERVICE_BASE = "http://127.0.0.1:3003";

/** Default per-request timeout (10s). */
const DEFAULT_TIMEOUT_MS = 10_000;

export type MonitorServiceErrorCode =
  | "UNREACHABLE"
  | "BAD_REQUEST"
  | "NOT_FOUND"
  | "INTERNAL";

/**
 * Error thrown by `monitorFetch` when the monitor-service is unreachable,
 * returns a non-2xx status, or produces a malformed response. The `code`
 * is mapped from the HTTP status / failure mode so callers can translate
 * it into a user-friendly response.
 */
export class MonitorServiceError extends Error {
  code: MonitorServiceErrorCode;
  status?: number;
  upstream?: unknown;

  constructor(
    message: string,
    code: MonitorServiceErrorCode,
    options?: { status?: number; upstream?: unknown },
  ) {
    super(message);
    this.name = "MonitorServiceError";
    this.code = code;
    this.status = options?.status;
    this.upstream = options?.upstream;
  }
}

function classifyStatus(status: number): MonitorServiceErrorCode {
  if (status === 400 || status === 422) return "BAD_REQUEST";
  if (status === 404) return "NOT_FOUND";
  if (status >= 500) return "INTERNAL";
  if (status >= 400) return "BAD_REQUEST";
  return "INTERNAL";
}

/**
 * Wrap a fetch to the monitor-service with a timeout + status check.
 * Throws `MonitorServiceError` on any non-2xx response or network failure.
 */
export async function monitorFetch<T>(
  path: string,
  init?: RequestInit & { timeoutMs?: number },
): Promise<T> {
  const url = path.startsWith("http")
    ? path
    : `${MONITOR_SERVICE_BASE}${path.startsWith("/") ? path : `/${path}`}`;

  const timeoutMs = init?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...(init?.headers ?? {}),
      },
    });
  } catch (err) {
    clearTimeout(timer);
    // Either aborted (timeout) or network error.
    if ((err as Error)?.name === "AbortError") {
      throw new MonitorServiceError(
        "Monitor service request timed out",
        "UNREACHABLE",
      );
    }
    throw new MonitorServiceError(
      "Unable to connect to monitoring service",
      "UNREACHABLE",
      { upstream: String(err) },
    );
  }
  clearTimeout(timer);

  let payload: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!res.ok) {
    throw new MonitorServiceError(
      `Monitor service returned ${res.status}`,
      classifyStatus(res.status),
      { status: res.status, upstream: payload },
    );
  }

  return payload as T;
}

/**
 * Lightweight per-IP rate limiter for the start endpoint.
 * Limits to `maxPerWindow` starts per `windowMs` per IP.
 * Not distributed — only useful for a single server process.
 */
interface RateBucket {
  count: number;
  windowStart: number;
}

const rateBuckets = new Map<string, RateBucket>();

export function checkRateLimit(
  ip: string,
  maxPerWindow = 10,
  windowMs = 60_000,
): { ok: boolean; remaining: number; resetInMs: number } {
  const now = Date.now();
  const bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.windowStart > windowMs) {
    rateBuckets.set(ip, { count: 1, windowStart: now });
    return { ok: true, remaining: maxPerWindow - 1, resetInMs: windowMs };
  }
  if (bucket.count >= maxPerWindow) {
    return {
      ok: false,
      remaining: 0,
      resetInMs: bucket.windowStart + windowMs - now,
    };
  }
  bucket.count += 1;
  return {
    ok: true,
    remaining: maxPerWindow - bucket.count,
    resetInMs: bucket.windowStart + windowMs - now,
  };
}

/**
 * Best-effort extraction of the caller's IP from a Next.js Request.
 * Falls back to "unknown" if no headers are available.
 */
export function getClientIp(req: Request): string {
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) {
    const first = fwd.split(",")[0]?.trim();
    if (first) return first;
  }
  const real = req.headers.get("x-real-ip");
  if (real) return real.trim();
  return "unknown";
}

/**
 * Maps a MonitorServiceError code to an HTTP status + user-friendly message.
 */
export function monitorErrorToResponse(err: unknown): NextResponse {
  if (err instanceof MonitorServiceError) {
    switch (err.code) {
      case "UNREACHABLE":
        return NextResponse.json(
          { error: "Unable to connect to monitoring service." },
          { status: 503 },
        );
      case "BAD_REQUEST":
        return NextResponse.json(
          { error: "Bad request to monitoring service." },
          { status: 400 },
        );
      case "NOT_FOUND":
        return NextResponse.json(
          { error: "Monitoring session not found." },
          { status: 404 },
        );
      case "INTERNAL":
      default:
        return NextResponse.json(
          { error: "Monitoring service error." },
          { status: 502 },
        );
    }
  }
  return NextResponse.json(
    { error: err instanceof Error ? err.message : "Internal server error" },
    { status: 500 },
  );
}

/**
 * Higher-order wrapper for API route handlers. Centralises try/catch,
 * audit logging on errors, and user-friendly responses.
 *
 * The handler may return a NextResponse directly. If it throws a
 * MonitorServiceError, a translated response is returned. For other
 * errors, a generic 500 is returned with a safe message and an audit
 * log entry is recorded.
 */
export function withApiHandler<TArgs extends unknown[]>(
  fn: (...args: TArgs) => Promise<NextResponse>,
  options?: { module?: string },
): (...args: TArgs) => Promise<NextResponse> {
  const moduleName = options?.module ?? "api";
  return async (...args: TArgs) => {
    try {
      return await fn(...args);
    } catch (err) {
      // Audit log the error (non-throwing).
      await auditLog(
        "error",
        moduleName,
        err instanceof Error ? err.message : "Unhandled API error",
        {
          code: err instanceof MonitorServiceError ? err.code : undefined,
          status: err instanceof MonitorServiceError ? err.status : undefined,
          stack: err instanceof Error ? err.stack : undefined,
        },
      ).catch(() => {
        /* never throw from audit */
      });

      if (err instanceof MonitorServiceError) {
        return monitorErrorToResponse(err);
      }

      // Don't leak raw stack traces.
      return NextResponse.json(
        { error: "Internal server error" },
        { status: 500 },
      );
    }
  };
}

/**
 * Quick connectivity ping to the monitor-service. Returns true if it
 * responds within the given timeout. Used by /api/health.
 */
export async function pingMonitorService(
  timeoutMs = 2_000,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${MONITOR_SERVICE_BASE}/internal/active`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
