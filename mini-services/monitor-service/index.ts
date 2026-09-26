// ============================================================
// LiveSOC - Monitor Mini-Service (socket.io + internal REST)
//
// This is the SINGLE owner of the in-memory `sessionManager`.
// Next.js API routes (a separate process) do NOT touch
// sessionManager directly; instead they proxy to the internal
// REST endpoints exposed on this same HTTP server.
//
// Architecture:
//   - HTTP server on port 3003 (hardcoded, not env).
//   - socket.io attached with path "/" so Caddy's
//     `?XTransformPort=3003` forwarding works for browser clients.
//   - Internal REST endpoints under `/internal/*` are intercepted
//     via `io.engine.use(...)` BEFORE engine.io's verify runs.
//     They are intended for server-to-server calls from Next.js
//     API routes (localhost only, never exposed via Caddy).
//
// Run: `bun run dev` (uses `bun --hot` for auto-restart on change).
// ============================================================

import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { Server as IoServer, type Socket } from "socket.io";

import { sessionManager } from "@/lib/monitoring";
import { auditLog } from "@/lib/monitoring/audit";
import { db } from "@/lib/db";
import type {
  MonitorStatus,
  WSMessage,
  WSClientCommand,
  SecurityEvent,
} from "@/lib/types";

const PORT = 3003;

// ============================================================
// Per-socket state for stream pause + subscription tracking
// ============================================================

interface SocketState {
  paused: boolean;
  // Track all (sessionId, callback) pairs this socket has
  // registered with sessionManager so we can clean up on
  // disconnect.
  subscriptions: Map<string, (msg: WSMessage) => void>;
}

const socketStates = new WeakMap<Socket, SocketState>();

function getSocketState(socket: Socket): SocketState {
  let s = socketStates.get(socket);
  if (!s) {
    s = { paused: false, subscriptions: new Map() };
    socketStates.set(socket, s);
  }
  return s;
}

// ============================================================
// HTTP helpers for /internal/* routes
// ============================================================

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    // Restrict CORS to same-origin (these endpoints are server-to-server
    // only; we don't want browsers to be able to call them).
    "Access-Control-Allow-Origin": "",
  });
  res.end(payload);
}

function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      chunks.push(c);
      // 1 MB hard cap to avoid runaway memory.
      if (chunks.reduce((n, b) => n + b.length, 0) > 1_000_000) {
        reject(new Error("Request body too large"));
        req.destroy();
        return;
      }
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function nowIso(): string {
  return new Date().toISOString();
}

// ============================================================
// Internal REST route handlers
// ============================================================

async function handleInternalRoute(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const pathname = url.pathname;
  const method = req.method ?? "GET";

  try {
    // ---- POST /internal/start ----
    if (pathname === "/internal/start" && method === "POST") {
      const body = (await readJsonBody(req)) as {
        target?: string;
        mode?: "demo" | "live";
      };
      const target = (body.target ?? "").trim();
      const mode = body.mode === "live" ? "live" : "demo";
      if (!target) {
        sendJson(res, 400, { error: "Missing 'target' in body" });
        return;
      }
      try {
        const { session, assessment } = await sessionManager.startSession(
          target,
          mode,
        );
        sendJson(res, 200, {
          sessionId: session.id,
          session: {
            id: session.id,
            targetId: session.targetId,
            assessmentId: session.assessmentId,
            status: session.status,
            mode: session.mode,
            startedAt: session.startedAt,
          },
          assessment,
        });
      } catch (err) {
        await auditLog(
          "error",
          "monitor-service",
          `startSession failed for ${target}: ${(err as Error).message}`,
          { target, mode, stack: (err as Error).stack },
        );
        sendJson(res, 400, {
          error: (err as Error).message,
          code: "START_FAILED",
        });
      }
      return;
    }

    // ---- POST /internal/stop ----
    if (pathname === "/internal/stop" && method === "POST") {
      const body = (await readJsonBody(req)) as { sessionId?: string };
      const sessionId = (body.sessionId ?? "").trim();
      if (!sessionId) {
        sendJson(res, 400, { error: "Missing 'sessionId' in body" });
        return;
      }
      await sessionManager.stopSession(sessionId);
      sendJson(res, 200, { ok: true, sessionId });
      return;
    }

    // ---- POST /internal/ingest (Phase 5: real telemetry ingestion) ----
    if (pathname === "/internal/ingest" && method === "POST") {
      const body = (await readJsonBody(req)) as {
        sessionId?: string;
        event?: SecurityEvent;
        rawLog?: {
          sourceType: string;
          rawPayload: string;
          parser?: string;
          agentId?: string;
          hostId?: string;
          hostname?: string;
          metadata?: string;
        };
      };
      if (!body.sessionId || !body.event || !body.rawLog) {
        sendJson(res, 400, { error: "Missing sessionId, event, or rawLog" });
        return;
      }
      const result = await sessionManager.ingestEvent(
        body.sessionId,
        body.event,
        body.rawLog,
      );
      if (!result.ok) {
        sendJson(res, 409, { ok: false, error: result.error });
        return;
      }
      sendJson(res, 200, { ok: true, eventId: result.eventId });
      return;
    }

    // ---- POST /internal/heartbeat (Phase 4: agent heartbeat) ----
    if (pathname === "/internal/heartbeat" && method === "POST") {
      const body = (await readJsonBody(req)) as {
        agentId?: string;
        hostname?: string;
        os?: string;
        version?: string;
        ip?: string;
        status?: string;
        metadata?: string;
      };
      if (!body.agentId) {
        sendJson(res, 400, { error: "Missing 'agentId' in body" });
        return;
      }
      await sessionManager.recordHeartbeat(body.agentId, {
        hostname: body.hostname,
        os: body.os,
        version: body.version,
        ip: body.ip,
        status: body.status,
        metadata: body.metadata,
      });
      sendJson(res, 200, { ok: true, agentId: body.agentId });
      return;
    }

    // ---- GET /internal/active ----
    if (pathname === "/internal/active" && method === "GET") {
      const sessions = sessionManager.getActiveAll().map((a) => ({
        id: a.session.id,
        targetId: a.session.targetId,
        targetAddress: a.assessment.hostname ?? "",
        assessmentId: a.session.assessmentId,
        status: a.session.status as MonitorStatus,
        mode: a.session.mode,
        startedAt: a.session.startedAt,
        eventCount: a.eventCounter.value,
        alertCount: a.alertCounter.value,
        openPorts: a.assessment.ports.length,
      }));
      sendJson(res, 200, { sessions });
      return;
    }

    // Path-param routes: /internal/status/:sessionId, etc.
    const segments = pathname.split("/").filter(Boolean); // ["internal", "status", "<id>"]
    if (segments[0] !== "internal" || segments.length < 3) {
      sendJson(res, 404, { error: `Not found: ${method} ${pathname}` });
      return;
    }
    const sub = segments[1];
    const sessionId = decodeURIComponent(segments[2]);

    // ---- PATCH /internal/alerts/:alertId ----
    // Body: { sessionId, status }
    // Updates the alert status. If the session is still active in the
    // sessionManager, both the in-memory list and the DB are updated and
    // an `alert` message is broadcast to all WS subscribers. If the
    // session is no longer active (historical), only the DB row is
    // updated.
    if (sub === "alerts" && method === "PATCH") {
      const alertId = decodeURIComponent(segments[2]);
      const body = (await readJsonBody(req)) as {
        sessionId?: string;
        status?: string;
      };
      const targetSessionId = (body.sessionId ?? "").trim();
      const rawStatus = (body.status ?? "").trim();
      if (!targetSessionId) {
        sendJson(res, 400, { error: "Missing 'sessionId' in body" });
        return;
      }
      if (rawStatus !== "acknowledged" && rawStatus !== "resolved" && rawStatus !== "active") {
        sendJson(res, 400, {
          error: "Invalid 'status' — must be one of acknowledged|resolved|active",
        });
        return;
      }
      const status = rawStatus as "acknowledged" | "resolved" | "active";

      const active = sessionManager.getActive(targetSessionId);
      if (active) {
        // Active session — update in-memory + DB + broadcast.
        const updated = await sessionManager.updateAlertStatus(
          targetSessionId,
          alertId,
          status,
        );
        if (!updated) {
          sendJson(res, 404, {
            error: `Alert not found in active session: ${alertId}`,
            code: "ALERT_NOT_FOUND",
          });
          return;
        }
        sendJson(res, 200, { ok: true, alertId, status });
        return;
      }

      // Session not active — historical alert, update DB only.
      try {
        await db.alert.update({
          where: { alertId },
          data: { status },
        });
        await auditLog("info", "alert", `Historical alert ${alertId} status → ${status}`, {
          sessionId: targetSessionId,
          alertId,
          status,
        });
        sendJson(res, 200, { ok: true, alertId, status });
        return;
      } catch (err) {
        await auditLog(
          "error",
          "monitor-service",
          `Historical alert status update failed for ${alertId}: ${(err as Error).message}`,
          { sessionId: targetSessionId, alertId, status },
        );
        sendJson(res, 404, {
          error: `Alert not found: ${alertId}`,
          code: "ALERT_NOT_FOUND",
        });
        return;
      }
    }

    const active = sessionManager.getActive(sessionId);
    if (!active) {
      sendJson(res, 404, {
        error: `Session not active: ${sessionId}`,
        code: "SESSION_NOT_ACTIVE",
      });
      return;
    }

    // ---- GET /internal/status/:sessionId ----
    if (sub === "status" && method === "GET") {
      sendJson(res, 200, {
        sessionId,
        session: {
          id: active.session.id,
          targetId: active.session.targetId,
          assessmentId: active.session.assessmentId,
          status: active.session.status as MonitorStatus,
          mode: active.session.mode,
          startedAt: active.session.startedAt,
        },
        assessment: active.assessment,
        kpi: active.kpi,
        networkActivity: active.networkActivity,
        eventCount: active.eventCounter.value,
        alertCount: active.alertCounter.value,
        offenseScenarios: Array.from(
          active.correlationState.offenseScenarios.values(),
        ),
        defenseScenarios: Array.from(
          active.correlationState.defenseScenarios.values(),
        ),
      });
      return;
    }

    // ---- GET /internal/scenarios/:sessionId ----
    if (sub === "scenarios" && method === "GET") {
      sendJson(res, 200, {
        sessionId,
        offense: Array.from(
          active.correlationState.offenseScenarios.values(),
        ),
        defense: Array.from(
          active.correlationState.defenseScenarios.values(),
        ),
      });
      return;
    }

    // ---- GET /internal/telemetry-sources/:sessionId (Phase 9) ----
    if (sub === "telemetry-sources" && method === "GET") {
      sendJson(res, 200, {
        sessionId,
        sources: sessionManager.getTelemetrySources(sessionId),
      });
      return;
    }

    // ---- GET /internal/events/:sessionId?limit=N ----
    if (sub === "events" && method === "GET") {
      const limit = Math.max(
        1,
        Math.min(500, Number(url.searchParams.get("limit") ?? "50") || 50),
      );
      // recentEvents is newest-last; return newest-first slice.
      const events = active.recentEvents.slice(-limit).reverse();
      sendJson(res, 200, { sessionId, events });
      return;
    }

    // ---- GET /internal/alerts/:sessionId?limit=N ----
    if (sub === "alerts" && method === "GET") {
      const limit = Math.max(
        1,
        Math.min(200, Number(url.searchParams.get("limit") ?? "50") || 50),
      );
      const alerts = active.recentAlerts.slice(-limit).reverse();
      sendJson(res, 200, { sessionId, alerts });
      return;
    }

    sendJson(res, 404, { error: `Not found: ${method} ${pathname}` });
  } catch (err) {
    await auditLog(
      "error",
      "monitor-service",
      `Internal route error: ${(err as Error).message}`,
      { method, pathname, stack: (err as Error).stack },
    );
    sendJson(res, 500, { error: (err as Error).message });
  }
}

// ============================================================
// HTTP server + socket.io
// ============================================================

const httpServer = createServer();

const io = new IoServer(httpServer, {
  // DO NOT change the path; Caddy uses it to forward browser requests
  // marked with ?XTransformPort=3003.
  path: "/",
  cors: { origin: "*", methods: ["GET", "POST"] },
  pingTimeout: 60_000,
  pingInterval: 25_000,
});

// Intercept /internal/* requests BEFORE engine.io's verify runs.
// (engine.io with path "/" matches every URL; without this middleware,
//  /internal/* would fall through to verify() and return 400.)
io.engine.use((req: IncomingMessage, res: ServerResponse, next: () => void) => {
  const url = req.url ?? "/";
  if (url.startsWith("/internal/")) {
    void handleInternalRoute(req, res);
    return; // do NOT call next()
  }
  // For OPTIONS preflight on /internal/* we also want to short-circuit.
  next();
});

// ============================================================
// Socket.io connection lifecycle
// ============================================================

io.on("connection", (socket: Socket) => {
   
  console.log(`[monitor-service] socket connected: ${socket.id}`);
  const state = getSocketState(socket);

  // Greet the client immediately.
  socket.emit("message", {
    type: "hello",
    sessionId: "",
    serverTime: nowIso(),
  } satisfies WSMessage);

  // ---- handle client commands ----

  socket.on("message", (cmd: WSClientCommand) => {
    handleClientCommand(socket, state, cmd).catch((err) => {
       
      console.error("[monitor-service] command handler error:", err);
      socket.emit("message", {
        type: "error",
        message: (err as Error).message,
      } satisfies WSMessage);
    });
  });

  socket.on("disconnect", (reason) => {
     
    console.log(
      `[monitor-service] socket disconnected: ${socket.id} (${reason})`,
    );
    // Clean up all subscriptions.
    for (const [sessionId, cb] of state.subscriptions) {
      sessionManager.unsubscribe(sessionId, cb);
    }
    state.subscriptions.clear();
  });

  socket.on("error", (err) => {
     
    console.error(`[monitor-service] socket error (${socket.id}):`, err);
  });
});

async function handleClientCommand(
  socket: Socket,
  state: SocketState,
  cmd: WSClientCommand,
): Promise<void> {
  if (!cmd || typeof cmd !== "object" || typeof cmd.type !== "string") {
    socket.emit("message", {
      type: "error",
      message: "Invalid command (missing type)",
    } satisfies WSMessage);
    return;
  }

  switch (cmd.type) {
    case "ping": {
      socket.emit("message", {
        type: "heartbeat",
        serverTime: nowIso(),
      } satisfies WSMessage);
      return;
    }

    case "pause_stream": {
      state.paused = true;
      socket.emit("message", {
        type: "log",
        message: "Stream paused (client-side)",
        level: "info",
        timestamp: nowIso(),
      } satisfies WSMessage);
      return;
    }

    case "resume_stream": {
      state.paused = false;
      socket.emit("message", {
        type: "log",
        message: "Stream resumed",
        level: "info",
        timestamp: nowIso(),
      } satisfies WSMessage);
      return;
    }

    case "subscribe": {
      const { sessionId } = cmd;
      if (!sessionId) {
        socket.emit("message", {
          type: "error",
          message: "subscribe requires sessionId",
        } satisfies WSMessage);
        return;
      }
      // If already subscribed to this session, no-op.
      if (state.subscriptions.has(sessionId)) {
        return;
      }

      const active = sessionManager.getActive(sessionId);
      if (!active) {
        socket.emit("message", {
          type: "session_status",
          sessionId,
          status: "stopped",
        } satisfies WSMessage);
        socket.emit("message", {
          type: "error",
          message: `Session ${sessionId} is not active`,
          code: "SESSION_NOT_ACTIVE",
        } satisfies WSMessage);
        return;
      }

      // Register subscriber that forwards broadcasts to this socket.
      // Server keeps broadcasting even if the client visually paused;
      // the client simply ignores messages until resume.
      const cb = (msg: WSMessage) => {
        socket.emit("message", msg);
      };
      const ok = sessionManager.subscribe(sessionId, cb);
      if (!ok) {
        socket.emit("message", {
          type: "error",
          message: `Failed to subscribe to ${sessionId}`,
        } satisfies WSMessage);
        return;
      }
      state.subscriptions.set(sessionId, cb);
      socket.join(`session:${sessionId}`);

      // Send current status + a burst of immediate state.
      socket.emit("message", {
        type: "session_status",
        sessionId,
        status: active.session.status as MonitorStatus,
        target: active.assessment.hostname ?? undefined,
        mode: active.session.mode,
      } satisfies WSMessage);

      socket.emit("message", {
        type: "assessment_update",
        assessment: {
          id: active.assessment.id,
          status: active.assessment.status,
          reachability: active.assessment.reachability,
          latencyMs: active.assessment.latencyMs,
          hostname: active.assessment.hostname,
          osGuess: active.assessment.osGuess,
          ports: active.assessment.ports,
          services: active.assessment.services,
        },
      } satisfies WSMessage);

      socket.emit("message", {
        type: "kpi",
        kpi: active.kpi,
      } satisfies WSMessage);

      socket.emit("message", {
        type: "network_activity",
        stats: active.networkActivity,
      } satisfies WSMessage);

      // Send the last 50 events (oldest-first so the client can append).
      const recentEvents = active.recentEvents.slice(-50);
      for (const event of recentEvents) {
        socket.emit("message", { type: "event", event } satisfies WSMessage);
      }
      // Send the last 50 alerts.
      const recentAlerts = active.recentAlerts.slice(-50);
      for (const alert of recentAlerts) {
        socket.emit("message", { type: "alert", alert } satisfies WSMessage);
      }
      // Send current scenarios.
      for (const scenario of active.correlationState.offenseScenarios.values()) {
        socket.emit(
          "message",
          { type: "offense_scenario", scenario } satisfies WSMessage,
        );
      }
      for (const scenario of active.correlationState.defenseScenarios.values()) {
        socket.emit(
          "message",
          { type: "defense_scenario", scenario } satisfies WSMessage,
        );
      }
      return;
    }

    case "unsubscribe": {
      const { sessionId } = cmd;
      const cb = state.subscriptions.get(sessionId);
      if (cb) {
        sessionManager.unsubscribe(sessionId, cb);
        state.subscriptions.delete(sessionId);
        socket.leave(`session:${sessionId}`);
      }
      return;
    }

    default: {
      // Exhaustiveness check
      const _exhaustive: never = cmd;
      void _exhaustive;
      socket.emit("message", {
        type: "error",
        message: `Unknown command type: ${(cmd as { type: string }).type}`,
      } satisfies WSMessage);
    }
  }
}

// ============================================================
// Heartbeat interval (every 25s to all connected sockets)
// ============================================================

const heartbeatInterval = setInterval(() => {
  const msg: WSMessage = { type: "heartbeat", serverTime: nowIso() };
  io.emit("message", msg);
}, 25_000);

// ============================================================
// PHASE D — Agent health monitoring
//
// Every 30s, checks all agents for stale heartbeats:
//   - DEGRADED: no heartbeat for 60s (configurable)
//   - OFFLINE: no heartbeat for 120s (configurable)
//   - Generates an agent-health alert when an agent goes OFFLINE
//   - Resolves the alert when the agent comes back ONLINE
// ============================================================

const AGENT_HEALTH_CHECK_MS = 30_000;
const AGENT_DEGRADED_SEC = 60;
const AGENT_OFFLINE_SEC = 120;

const agentHealthInterval = setInterval(async () => {
  try {
    const agents = await db.agent.findMany();
    const now = Date.now();

    for (const agent of agents) {
      if (!agent.lastHeartbeat) continue;

      const lastMs = agent.lastHeartbeat.getTime();
      const elapsedSec = Math.floor((now - lastMs) / 1000);

      let newStatus = agent.status;
      if (elapsedSec >= AGENT_OFFLINE_SEC) {
        newStatus = "OFFLINE";
      } else if (elapsedSec >= AGENT_DEGRADED_SEC) {
        newStatus = "DEGRADED";
      } else {
        newStatus = "ONLINE";
      }

      if (newStatus !== agent.status) {
        await db.agent.update({
          where: { id: agent.id },
          data: { status: newStatus },
        });

        // Broadcast agent status change to all connected clients
        const statusMsg: WSMessage = {
          type: "log",
          message: `Agent ${agent.agentId} status changed: ${agent.status} → ${newStatus}`,
          level: newStatus === "OFFLINE" ? "warning" : "info",
          timestamp: nowIso(),
        };
        io.emit("message", statusMsg);

        // Generate agent-health alert when going OFFLINE
        if (newStatus === "OFFLINE" && agent.status !== "OFFLINE") {
          try {
            // Check if there's an existing active agent-health alert
            const existing = await db.alert.findFirst({
              where: {
                ruleId: "AGENT-HEALTH",
                status: "active",
                message: { contains: agent.agentId },
              },
            });

            if (!existing) {
              await db.alert.create({
                data: {
                  alertId: `ALR-AGENT-${agent.agentId}-${Date.now()}`,
                  ruleId: "AGENT-HEALTH",
                  ruleName: "Agent Offline",
                  severity: "high",
                  confidence: 95,
                  message: `Agent ${agent.agentId} (${agent.hostname ?? "unknown"}) went OFFLINE. Last heartbeat: ${agent.lastHeartbeat.toISOString()}. Elapsed: ${elapsedSec}s.`,
                  recommendedAction: `Check the agent host (${agent.hostname ?? agent.agentId}). Verify network connectivity and agent process. Restart the agent if needed.`,
                  status: "active",
                },
              });

              await auditLog("warning", "agent-health", `Agent OFFLINE: ${agent.agentId}`, {
                agentId: agent.agentId,
                hostname: agent.hostname,
                lastHeartbeat: agent.lastHeartbeat,
                elapsedSec,
              });
            }
          } catch (err) {
            console.error("[agent-health] alert creation failed:", err);
          }
        }

        // Resolve agent-health alert when coming back ONLINE
        if (newStatus === "ONLINE" && agent.status === "OFFLINE") {
          try {
            await db.alert.updateMany({
              where: {
                ruleId: "AGENT-HEALTH",
                status: "active",
                message: { contains: agent.agentId },
              },
              data: { status: "resolved" },
            });

            await auditLog("info", "agent-health", `Agent ONLINE: ${agent.agentId}`, {
              agentId: agent.agentId,
            });
          } catch (err) {
            console.error("[agent-health] alert resolution failed:", err);
          }
        }
      }
    }
  } catch (err) {
    console.error("[agent-health] check failed:", err);
  }
}, AGENT_HEALTH_CHECK_MS);

// ============================================================
// Startup + graceful shutdown
// ============================================================

httpServer.listen(PORT, () => {
   
  console.log(`LiveSOC monitor service listening on :${PORT}`);
  void auditLog("info", "monitor-service", `Monitor service started on :${PORT}`);
});

async function shutdown(signal: string): Promise<void> {
   
  console.log(`[monitor-service] received ${signal}, shutting down...`);
  clearInterval(heartbeatInterval);
  clearInterval(agentHealthInterval);

  // Stop all active sessions (this also broadcasts session_ended).
  const activeIds = sessionManager.getActiveAll().map((a) => a.session.id);
  for (const id of activeIds) {
    try {
      await sessionManager.stopSession(id);
    } catch (err) {
       
      console.error(`[monitor-service] stopSession(${id}) failed:`, err);
    }
  }

  // Close socket.io (disconnects all clients).
  await new Promise<void>((resolve) => {
    io.close(() => resolve());
  });

  // Close HTTP server.
  httpServer.close();

  // Disconnect Prisma.
  try {
    await db.$disconnect();
  } catch {
    // ignore
  }

  await auditLog("info", "monitor-service", `Monitor service stopped (${signal})`);
  process.exit(0);
}

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

// Catch uncaught errors so the service doesn't silently die.
process.on("uncaughtException", (err) => {
   
  console.error("[monitor-service] uncaughtException:", err);
  void auditLog("critical", "monitor-service", `uncaughtException: ${err.message}`, {
    stack: err.stack,
  });
});
process.on("unhandledRejection", (reason) => {
   
  console.error("[monitor-service] unhandledRejection:", reason);
  void auditLog(
    "critical",
    "monitor-service",
    `unhandledRejection: ${(reason as Error)?.message ?? String(reason)}`,
  );
});
