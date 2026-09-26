"use client";

import { create } from "zustand";
import type {
  ViewKey,
  MonitorStatus,
  SecurityEvent,
  SecurityAlert,
  KpiStats,
  NetworkActivityStats,
  OffenseScenario,
  DefenseScenario,
  AssessmentResult,
  MonitoringSessionInfo,
  AppSettings,
} from "@/lib/types";
import { DEFAULT_SETTINGS } from "@/lib/constants";

interface MonitorLiveState {
  // current active session
  sessionId: string | null;
  targetAddress: string;
  status: MonitorStatus;
  mode: "demo" | "live";
  assessment: AssessmentResult | null;
  connected: boolean;
  // live data (kept bounded)
  events: SecurityEvent[];
  alerts: SecurityAlert[];
  kpi: KpiStats | null;
  networkActivity: NetworkActivityStats | null;
  offenseScenarios: OffenseScenario[];
  defenseScenarios: DefenseScenario[];
  // stream controls
  paused: boolean;
  // counters for header
  totalEvents: number;
  totalAlerts: number;
  startedAt: number | null;
}

interface MonitorActions {
  setView: (v: ViewKey) => void;
  startSession: (params: {
    sessionId: string;
    targetAddress: string;
    mode: "demo" | "live";
    assessment: AssessmentResult;
  }) => void;
  setStatus: (s: MonitorStatus) => void;
  setConnected: (c: boolean) => void;
  setAssessment: (a: AssessmentResult) => void;
  setPaused: (p: boolean) => void;
  pushEvent: (e: SecurityEvent) => void;
  pushAlert: (a: SecurityAlert) => void;
  setKpi: (k: KpiStats) => void;
  setNetworkActivity: (n: NetworkActivityStats) => void;
  upsertOffenseScenario: (s: OffenseScenario) => void;
  upsertDefenseScenario: (s: DefenseScenario) => void;
  setOffenseScenarios: (s: OffenseScenario[]) => void;
  setDefenseScenarios: (s: DefenseScenario[]) => void;
  clearLiveView: () => void; // visual clear only — does NOT delete history
  stopSession: () => void;
  resetSession: () => void;
  setSettings: (s: Partial<AppSettings>) => void;
}

interface AppState extends MonitorLiveState, MonitorActions {
  view: ViewKey;
  settings: AppSettings;
  selectedOffenseId: string | null;
  selectedDefenseId: string | null;
  setSelectedOffense: (id: string | null) => void;
  setSelectedDefense: (id: string | null) => void;
  historicalSession: MonitoringSessionInfo | null;
  setHistoricalSession: (s: MonitoringSessionInfo | null) => void;
}

const MAX_LIVE_EVENTS = 500;
const MAX_LIVE_ALERTS = 200;

const emptyKpi: KpiStats = {
  events: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  activeConnections: 0,
  eventsPerSec: 0,
  trafficRate: 0,
  openPorts: 0,
};

export const useAppStore = create<AppState>((set, get) => ({
  view: "monitor",
  settings: DEFAULT_SETTINGS,

  sessionId: null,
  targetAddress: "",
  status: "ready",
  mode: "demo",
  assessment: null,
  connected: false,
  events: [],
  alerts: [],
  kpi: null,
  networkActivity: null,
  offenseScenarios: [],
  defenseScenarios: [],
  paused: false,
  totalEvents: 0,
  totalAlerts: 0,
  startedAt: null,

  selectedOffenseId: null,
  selectedDefenseId: null,
  historicalSession: null,

  setView: (v) => set({ view: v }),
  setSelectedOffense: (id) => set({ selectedOffenseId: id }),
  setSelectedDefense: (id) => set({ selectedDefenseId: id }),
  setHistoricalSession: (s) => set({ historicalSession: s }),
  setSettings: (s) => set((state) => ({ settings: { ...state.settings, ...s } })),

  startSession: ({ sessionId, targetAddress, mode, assessment }) =>
    set({
      sessionId,
      targetAddress,
      mode,
      assessment,
      status: "monitoring",
      connected: false,
      events: [],
      alerts: [],
      kpi: { ...emptyKpi, openPorts: assessment.ports.length },
      networkActivity: null,
      offenseScenarios: [],
      defenseScenarios: [],
      paused: false,
      totalEvents: 0,
      totalAlerts: 0,
      startedAt: Date.now(),
      selectedOffenseId: null,
      selectedDefenseId: null,
    }),

  setStatus: (s) => set({ status: s }),
  setConnected: (c) => set({ connected: c }),
  setAssessment: (a) => set({ assessment: a }),
  setPaused: (p) => set({ paused: p }),

  pushEvent: (e) => {
    if (get().paused) return; // visual pause: drop incoming from the live view
    set((state) => {
      const events = [e, ...state.events].slice(0, MAX_LIVE_EVENTS);
      return { events, totalEvents: state.totalEvents + 1 };
    });
  },

  pushAlert: (a) => {
    if (get().paused) return;
    set((state) => {
      const alerts = [a, ...state.alerts].slice(0, MAX_LIVE_ALERTS);
      return { alerts, totalAlerts: state.totalAlerts + 1 };
    });
  },

  setKpi: (k) => set({ kpi: k }),
  setNetworkActivity: (n) => set({ networkActivity: n }),

  upsertOffenseScenario: (s) =>
    set((state) => {
      const idx = state.offenseScenarios.findIndex(
        (x) => x.scenarioId === s.scenarioId || x.category === s.category,
      );
      if (idx >= 0) {
        const next = [...state.offenseScenarios];
        next[idx] = s;
        return { offenseScenarios: next };
      }
      return { offenseScenarios: [s, ...state.offenseScenarios] };
    }),

  upsertDefenseScenario: (s) =>
    set((state) => {
      const idx = state.defenseScenarios.findIndex(
        (x) => x.scenarioId === s.scenarioId || x.category === s.category,
      );
      if (idx >= 0) {
        const next = [...state.defenseScenarios];
        next[idx] = s;
        return { defenseScenarios: next };
      }
      return { defenseScenarios: [s, ...state.defenseScenarios] };
    }),

  setOffenseScenarios: (s) => set({ offenseScenarios: s }),
  setDefenseScenarios: (s) => set({ defenseScenarios: s }),

  clearLiveView: () => set({ events: [], alerts: [] }),

  stopSession: () =>
    set({
      status: "stopped",
      connected: false,
    }),

  resetSession: () =>
    set({
      sessionId: null,
      targetAddress: "",
      status: "ready",
      assessment: null,
      connected: false,
      events: [],
      alerts: [],
      kpi: null,
      networkActivity: null,
      offenseScenarios: [],
      defenseScenarios: [],
      paused: false,
      totalEvents: 0,
      totalAlerts: 0,
      startedAt: null,
      selectedOffenseId: null,
      selectedDefenseId: null,
    }),
}));
