"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { io, type Socket } from "socket.io-client";
import type { WSMessage, WSClientCommand } from "@/lib/types";
import { useAppStore } from "@/lib/store";

interface UseMonitorWsOptions {
  sessionId: string | null;
  enabled?: boolean;
}

interface UseMonitorWsResult {
  connected: boolean;
  reconnect: () => void;
}

/**
 * WebSocket hook for LiveSOC live monitoring.
 * Connects to the monitor-service (port 3003) via the gateway:
 *   io("/?XTransformPort=3003")
 * The path MUST be "/" so Caddy forwards to port 3003.
 */
export function useMonitorWs({
  sessionId,
  enabled = true,
}: UseMonitorWsOptions): UseMonitorWsResult {
  const [connected, setConnected] = useState(false);
  const socketRef = useRef<Socket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const store = useAppStore;

  const handleMessage = useCallback(
    (msg: WSMessage) => {
      const s = store.getState();
      switch (msg.type) {
        case "hello":
          s.setConnected(true);
          break;
        case "heartbeat":
          // presence ping
          break;
        case "session_status":
          s.setStatus(msg.status);
          if (msg.target) {
            // target already known
          }
          break;
        case "event":
          s.pushEvent(msg.event);
          break;
        case "alert":
          // Use upsert so an incoming alert with the same alertId (e.g.
          // a status update broadcast by sessionManager.updateAlertStatus)
          // replaces the existing entry instead of being added as a
          // duplicate.
          s.upsertAlert(msg.alert);
          break;
        case "kpi":
          s.setKpi(msg.kpi);
          break;
        case "network_activity":
          s.setNetworkActivity(msg.stats);
          break;
        case "offense_scenario":
          s.upsertOffenseScenario(msg.scenario);
          break;
        case "offense_scenario_update":
          s.upsertOffenseScenario(msg.scenario);
          break;
        case "defense_scenario":
          s.upsertDefenseScenario(msg.scenario);
          break;
        case "defense_scenario_update":
          s.upsertDefenseScenario(msg.scenario);
          break;
        case "assessment_update":
          if (s.assessment) {
            s.setAssessment({ ...s.assessment, ...msg.assessment } as never);
          }
          break;
        case "session_ended":
          s.setStatus("completed");
          s.setConnected(false);
          break;
        case "error":
          console.warn("[LiveSOC WS] server error:", msg.message);
          break;
        case "log":
          // optional log line
          break;
      }
    },
    [store],
  );

  useEffect(() => {
    if (!enabled || !sessionId) {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
        setConnected(false);
        useAppStore.getState().setConnected(false);
      }
      return;
    }

    let cancelled = false;

    const connect = () => {
      if (cancelled) return;
      const socket = io("/?XTransformPort=3003", {
        path: "/",
        transports: ["websocket", "polling"],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        timeout: 10000,
      });
      socketRef.current = socket;

      socket.on("connect", () => {
        setConnected(true);
        useAppStore.getState().setConnected(true);
        const cmd: WSClientCommand = { type: "subscribe", sessionId };
        socket.emit("message", cmd);
      });

      socket.on("message", (msg: WSMessage) => {
        handleMessage(msg);
      });

      socket.on("disconnect", () => {
        setConnected(false);
        useAppStore.getState().setConnected(false);
        useAppStore.getState().setStatus("reconnecting");
      });

      socket.on("reconnect_attempt", () => {
        useAppStore.getState().setStatus("reconnecting");
      });

      socket.on("reconnect", () => {
        setConnected(true);
        useAppStore.getState().setConnected(true);
        useAppStore.getState().setStatus("monitoring");
      });

      socket.on("connect_error", () => {
        setConnected(false);
        useAppStore.getState().setConnected(false);
      });
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (socketRef.current) {
        const cmd: WSClientCommand = { type: "unsubscribe", sessionId };
        try {
          socketRef.current.emit("message", cmd);
        } catch {
          /* ignore */
        }
        socketRef.current.removeAllListeners();
        socketRef.current.disconnect();
        socketRef.current = null;
      }
      setConnected(false);
      useAppStore.getState().setConnected(false);
    };
  }, [sessionId, enabled, handleMessage]);

  const reconnect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current.connect();
    }
  }, []);

  return { connected, reconnect };
}
