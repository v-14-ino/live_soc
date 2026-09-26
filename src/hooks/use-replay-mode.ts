"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useAppStore } from "@/lib/store";
import { api } from "@/lib/api-client";
import type { SecurityEvent } from "@/lib/types";
import { toast } from "sonner";

// ============================================================
// Replay Live Mode
//
// Replays a historical session's events in real-time (or at an
// adjustable speed) into the Live Monitor view. This simulates
// live monitoring without starting a new session or connecting
// to the monitor-service WebSocket.
//
// Flow:
// 1. User clicks "Replay Live" in History detail → Actions tab
// 2. Frontend fetches the session's events via api.getHistoryDetail
// 3. Events are sorted by timestamp (oldest first)
// 4. A timer pushes events one-by-one into the store at the chosen speed
// 5. KPIs, charts, threat map, etc. all update as if live
// 6. User can pause/resume/stop the replay
// ============================================================

export type ReplayState = "idle" | "loading" | "playing" | "paused" | "stopped";

export interface ReplayControls {
  state: ReplayState;
  speed: number; // multiplier (0.5, 1, 2, 4, 8)
  progress: number; // 0..1
  currentIndex: number;
  totalCount: number;
  start: (sessionId: string) => Promise<void>;
  pause: () => void;
  resume: () => void;
  stop: () => void;
  setSpeed: (s: number) => void;
  seek: (fraction: number) => void;
}

const BASE_INTERVAL_MS = 500; // base interval between events at 1x speed

const SPEEDS = [0.5, 1, 2, 4, 8];

export function useReplayMode(): ReplayControls {
  const [state, setState] = useState<ReplayState>("idle");
  const [speed, setSpeedState] = useState(1);
  const [progress, setProgress] = useState(0);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [totalCount, setTotalCount] = useState(0);

  const eventsRef = useRef<SecurityEvent[]>([]);
  const indexRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sessionIdRef = useRef<string | null>(null);

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const pushNextEvent = useCallback(() => {
    const events = eventsRef.current;
    const idx = indexRef.current;

    if (idx >= events.length) {
      setState("stopped");
      setProgress(1);
      toast.success("Replay completed");
      return;
    }

    const event = events[idx];
    // Push to the store — use upsertAlert-style pushEvent
    useAppStore.getState().pushEvent(event);

    indexRef.current = idx + 1;
    setCurrentIndex(idx + 1);
    setProgress((idx + 1) / events.length);

    // Schedule next event
    const interval = BASE_INTERVAL_MS / speed;
    // eslint-disable-next-line react-hooks/immutability
    timerRef.current = setTimeout(() => pushNextEvent(), interval);
  }, [speed]);

  const start = useCallback(async (sessionId: string) => {
    setState("loading");
    sessionIdRef.current = sessionId;

    // Reset the store to a "monitoring-like" state for replay
    const store = useAppStore.getState();
    store.clearLiveView();
    store.setPaused(false);

    try {
      // Fetch the session detail to get events + assessment
      const detail = await api.getHistoryDetail(sessionId);

      if (!detail.events || detail.events.length === 0) {
        toast.info("This session has no events to replay");
        setState("idle");
        return;
      }

      // Sort events oldest-first for replay
      const sorted = [...detail.events].sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
      );

      eventsRef.current = sorted;
      indexRef.current = 0;
      setTotalCount(sorted.length);
      setCurrentIndex(0);
      setProgress(0);

      // Set up the store as if monitoring is active
      store.startSession({
        sessionId: `replay-${sessionId}`,
        targetAddress: detail.session.targetAddress || "replay",
        mode: detail.session.mode || "demo",
        assessment: detail.assessment ?? {
          id: detail.session.assessmentId || "",
          targetId: detail.session.targetId,
          status: "completed",
          reachability: "reachable",
          ports: [],
          services: [],
        },
      });
      store.setStatus("monitoring");
      store.setConnected(true);

      setState("playing");
      toast.success(`Replaying ${sorted.length} events from ${detail.session.targetAddress || "session"}`);

      // Start pushing events
      const interval = BASE_INTERVAL_MS / speed;
      timerRef.current = setTimeout(pushNextEvent, interval);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to start replay");
      setState("idle");
    }
  }, [speed, pushNextEvent]);

  const pause = useCallback(() => {
    if (state !== "playing") return;
    clearTimer();
    setState("paused");
    useAppStore.getState().setPaused(true);
    toast.info("Replay paused");
  }, [state, clearTimer]);

  const resume = useCallback(() => {
    if (state !== "paused") return;
    setState("playing");
    useAppStore.getState().setPaused(false);
    const interval = BASE_INTERVAL_MS / speed;
    timerRef.current = setTimeout(pushNextEvent, interval);
    toast.info("Replay resumed");
  }, [state, speed, pushNextEvent]);

  const stop = useCallback(() => {
    clearTimer();
    setState("stopped");
    useAppStore.getState().setPaused(false);
    useAppStore.getState().setStatus("completed");
    useAppStore.getState().setConnected(false);
    if (progress < 1) {
      toast.info(`Replay stopped at ${Math.round(progress * 100)}%`);
    }
  }, [clearTimer, progress]);

  const setSpeed = useCallback((s: number) => {
    setSpeedState(s);
    // If currently playing, the next scheduled event will use the new speed
    if (state === "playing") {
      clearTimer();
      const interval = BASE_INTERVAL_MS / s;
      timerRef.current = setTimeout(pushNextEvent, interval);
    }
  }, [state, clearTimer, pushNextEvent]);

  const seek = useCallback((fraction: number) => {
    const events = eventsRef.current;
    const newIdx = Math.max(0, Math.min(events.length - 1, Math.floor(fraction * events.length)));
    indexRef.current = newIdx;
    setCurrentIndex(newIdx);
    setProgress(newIdx / events.length);
    // Clear the live view and re-push all events up to the new index
    useAppStore.getState().clearLiveView();
    for (let i = 0; i < newIdx; i++) {
      useAppStore.getState().pushEvent(events[i]);
    }
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      clearTimer();
    };
  }, [clearTimer]);

  return {
    state,
    speed,
    progress,
    currentIndex,
    totalCount,
    start,
    pause,
    resume,
    stop,
    setSpeed,
    seek,
  };
}

export { SPEEDS };
