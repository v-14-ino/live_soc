"use client";

import type {
  AssessmentResult,
  SecurityEvent,
  SecurityAlert,
  KpiStats,
  NetworkActivityStats,
  OffenseScenario,
  DefenseScenario,
  MonitoringSessionInfo,
  ReportInfo,
  AppSettings,
  CustomRule,
  CustomRuleInput,
  WebhookConfig,
  WebhookInput,
} from "@/lib/types";
import type { AdapterConfig, AdapterInfo } from "@/lib/monitoring/adapters";

export interface StartMonitoringResponse {
  sessionId: string;
  session: MonitoringSessionInfo;
  assessment: AssessmentResult;
}

export interface ActiveSessionSummary {
  id: string;
  targetId: string;
  targetAddress: string;
  assessmentId: string;
  status: string;
  mode: string;
  startedAt: string;
  eventCount: number;
  alertCount: number;
  openPorts: number;
}

export interface StatusSnapshot {
  sessionId: string;
  session: MonitoringSessionInfo;
  assessment: AssessmentResult;
  kpi: KpiStats;
  networkActivity: NetworkActivityStats;
  eventCount: number;
  alertCount: number;
  offenseScenarios: OffenseScenario[];
  defenseScenarios: DefenseScenario[];
}

export interface HistoryListResponse {
  sessions: MonitoringSessionInfo[];
  total: number;
  page: number;
  pageSize: number;
}

export interface HistoryDetailResponse {
  session: MonitoringSessionInfo;
  assessment: AssessmentResult | null;
  events: SecurityEvent[];
  alerts: SecurityAlert[];
  offenseScenarios: OffenseScenario[];
  defenseScenarios: DefenseScenario[];
}

export interface ReportListResponse {
  reports: ReportInfo[];
  total: number;
}

export interface ReportDetailResponse {
  report: ReportInfo;
  summary: unknown;
  data: unknown;
}

export interface ReportGenerateResponse {
  report: ReportInfo;
  data: unknown;
}

async function http<T>(
  url: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const message =
      typeof data === "object" && data && "error" in data
        ? String((data as { error: unknown }).error)
        : `Request failed (${res.status})`;
    const error = new Error(message) as Error & { status: number; code?: string };
    error.status = res.status;
    if (typeof data === "object" && data && "code" in data) {
      error.code = String((data as { code: unknown }).code);
    }
    throw error;
  }
  return data as T;
}

export const api = {
  health: () => http<{ status: string; monitorService: string; db: string; time: string }>("/api/health"),

  startMonitoring: (target: string, mode: "demo" | "live") =>
    http<StartMonitoringResponse>("/api/monitoring", {
      method: "POST",
      body: JSON.stringify({ target, mode }),
    }),

  stopMonitoring: (sessionId: string) =>
    http<{ ok: boolean; sessionId: string }>(`/api/monitoring/${encodeURIComponent(sessionId)}`, {
      method: "DELETE",
    }),

  getActiveSessions: () =>
    http<{ sessions: ActiveSessionSummary[] }>("/api/monitoring"),

  getStatus: (sessionId: string) =>
    http<StatusSnapshot>(`/api/monitoring/${encodeURIComponent(sessionId)}`),

  getEvents: (sessionId: string, limit = 100) =>
    http<{ sessionId: string; events: SecurityEvent[] }>(
      `/api/monitoring/${encodeURIComponent(sessionId)}/events?limit=${limit}`,
    ),

  getAlerts: (sessionId: string, limit = 100) =>
    http<{ sessionId: string; alerts: SecurityAlert[] }>(
      `/api/monitoring/${encodeURIComponent(sessionId)}/alerts?limit=${limit}`,
    ),

  updateAlertStatus: (
    sessionId: string,
    alertId: string,
    status: "acknowledged" | "resolved" | "active",
  ) =>
    http<{ ok: boolean; alertId: string; status: string }>(
      `/api/monitoring/${encodeURIComponent(sessionId)}/alerts`,
      {
        method: "PATCH",
        body: JSON.stringify({ alertId, status }),
      },
    ),

  getScenarios: (sessionId: string) =>
    http<{ sessionId: string; offense: OffenseScenario[]; defense: DefenseScenario[] }>(
      `/api/monitoring/${encodeURIComponent(sessionId)}/scenarios`,
    ),

  getHistory: (params: { page?: number; pageSize?: number; status?: string; target?: string } = {}) => {
    const q = new URLSearchParams();
    if (params.page) q.set("page", String(params.page));
    if (params.pageSize) q.set("pageSize", String(params.pageSize));
    if (params.status) q.set("status", params.status);
    if (params.target) q.set("target", params.target);
    return http<HistoryListResponse>(`/api/history?${q.toString()}`);
  },

  getHistoryDetail: (sessionId: string) =>
    http<HistoryDetailResponse>(`/api/history/${encodeURIComponent(sessionId)}`),

  getReports: (params: { page?: number; pageSize?: number } = {}) => {
    const q = new URLSearchParams();
    if (params.page) q.set("page", String(params.page));
    if (params.pageSize) q.set("pageSize", String(params.pageSize));
    return http<ReportListResponse>(`/api/reports?${q.toString()}`);
  },

  generateReport: (sessionId: string) =>
    http<ReportGenerateResponse>("/api/reports", {
      method: "POST",
      body: JSON.stringify({ sessionId }),
    }),

  getReport: (reportId: string) =>
    http<ReportDetailResponse>(`/api/reports/${encodeURIComponent(reportId)}`),

  getSettings: () =>
    http<{ settings: AppSettings }>("/api/settings").then((r) => r.settings),

  updateSettings: (patch: Partial<AppSettings>) =>
    http<{ settings: AppSettings }>("/api/settings", {
      method: "PUT",
      body: JSON.stringify(patch),
    }).then((r) => r.settings),

  getTargets: () =>
    http<{ targets: { address: string; hostname: string | null; lastAssessedAt: string | null }[] }>(
      "/api/targets",
    ),

  // ---- Telemetry Adapters ----

  getAdapters: (force = false) =>
    http<{
      adapters: AdapterInfo[];
      summary: { available: number; total: number };
      cached: boolean;
    }>(`/api/adapters${force ? "?force=1" : ""}`),

  getAdapter: (name: string, force = false) =>
    http<{ adapter: AdapterInfo }>(
      `/api/adapters/${encodeURIComponent(name)}${force ? "?force=1" : ""}`,
    ),

  testAdapter: (name: string, config: AdapterConfig) =>
    http<{ valid: boolean; issues: string[]; name: string }>("/api/adapters", {
      method: "POST",
      body: JSON.stringify({ name, config }),
    }),

  // ---- Custom Detection Rules ----
  getCustomRules: () =>
    http<{ rules: CustomRule[]; total: number }>("/api/rules"),

  createCustomRule: (input: CustomRuleInput) =>
    http<{ rule: CustomRule }>("/api/rules", {
      method: "POST",
      body: JSON.stringify(input),
    }),

  updateCustomRule: (ruleId: string, patch: Partial<CustomRuleInput>) =>
    http<{ rule: CustomRule }>(`/api/rules/${encodeURIComponent(ruleId)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),

  deleteCustomRule: (ruleId: string) =>
    http<{ ok: boolean; ruleId: string }>(`/api/rules/${encodeURIComponent(ruleId)}`, {
      method: "DELETE",
    }),

  // ---- Webhooks ----
  getWebhooks: () =>
    http<{ webhooks: WebhookConfig[]; total: number }>("/api/webhooks"),

  createWebhook: (input: WebhookInput) =>
    http<{ webhook: WebhookConfig }>("/api/webhooks", {
      method: "POST",
      body: JSON.stringify(input),
    }),

  updateWebhook: (webhookId: string, patch: Partial<WebhookInput>) =>
    http<{ webhook: WebhookConfig }>(`/api/webhooks/${encodeURIComponent(webhookId)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),

  deleteWebhook: (webhookId: string) =>
    http<{ ok: boolean; webhookId: string }>(`/api/webhooks/${encodeURIComponent(webhookId)}`, {
      method: "DELETE",
    }),

  testWebhook: (webhookId: string) =>
    http<{ ok: boolean; status?: number; message: string }>(`/api/webhooks/${encodeURIComponent(webhookId)}`, {
      method: "POST",
    }),

  getWebhookDeliveries: (webhookId: string, limit = 50) =>
    http<{
      webhookId: string;
      deliveries: WebhookDelivery[];
      total: number;
    }>(`/api/webhooks/${encodeURIComponent(webhookId)}/deliveries?limit=${limit}`),

  clearWebhookDeliveries: (webhookId: string, olderThanDays?: number) =>
    http<{ ok: boolean; webhookId: string; deleted: number }>(
      `/api/webhooks/${encodeURIComponent(webhookId)}/deliveries${olderThanDays ? `?olderThanDays=${olderThanDays}` : ""}`,
      { method: "DELETE" },
    ),
};
