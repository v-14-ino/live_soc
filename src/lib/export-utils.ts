// ============================================================
// LiveSOC - Data Export Utilities (CSV + JSON)
//
// Client-side export helpers for events and alerts.
// Generates downloadable files without server round-trips.
// ============================================================

import type { SecurityEvent, SecurityAlert } from "@/lib/types";

// ---- CSV helpers ----

function csvEscape(value: unknown): string {
  if (value == null) return "";
  const s = String(value);
  if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function toCsv(rows: (string | number | null | undefined)[][], headers: string[]): string {
  const lines = [headers.map(csvEscape).join(",")];
  for (const row of rows) {
    lines.push(row.map(csvEscape).join(","));
  }
  return lines.join("\r\n");
}

function downloadFile(content: string, filename: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function timestampForFilename(d = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

// ---- Event export ----

export function eventsToCsv(events: SecurityEvent[]): string {
  const headers = [
    "Event ID",
    "Timestamp",
    "Source Collector",
    "Source IP",
    "Source Port",
    "Dest IP",
    "Dest Port",
    "Protocol",
    "Event Type",
    "Severity",
    "Status",
    "Message",
    "Is Demo",
  ];
  const rows = events.map((e) => [
    e.eventId,
    e.timestamp,
    e.source,
    e.sourceIp ?? "",
    e.sourcePort ?? "",
    e.destIp ?? "",
    e.destPort ?? "",
    e.protocol ?? "",
    e.eventType,
    e.severity,
    e.status,
    e.message,
    e.isDemo ? "true" : "false",
  ]);
  return toCsv(rows, headers);
}

export function eventsToJson(events: SecurityEvent[]): string {
  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      count: events.length,
      events,
    },
    null,
    2,
  );
}

export function exportEventsCsv(events: SecurityEvent[], targetLabel: string): void {
  const csv = eventsToCsv(events);
  downloadFile(csv, `livesoc_events_${targetLabel}_${timestampForFilename()}.csv`, "text/csv;charset=utf-8");
}

export function exportEventsJson(events: SecurityEvent[], targetLabel: string): void {
  const json = eventsToJson(events);
  downloadFile(json, `livesoc_events_${targetLabel}_${timestampForFilename()}.json`, "application/json");
}

// ---- Alert export ----

export function alertsToCsv(alerts: SecurityAlert[]): string {
  const headers = [
    "Alert ID",
    "Timestamp",
    "Rule ID",
    "Rule Name",
    "Severity",
    "Confidence",
    "Status",
    "Message",
    "Recommended Action",
    "Event ID",
  ];
  const rows = alerts.map((a) => [
    a.alertId,
    a.timestamp,
    a.ruleId,
    a.ruleName,
    a.severity,
    a.confidence,
    a.status,
    a.message,
    a.recommendedAction ?? "",
    a.eventId ?? "",
  ]);
  return toCsv(rows, headers);
}

export function alertsToJson(alerts: SecurityAlert[]): string {
  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      count: alerts.length,
      alerts,
    },
    null,
    2,
  );
}

export function exportAlertsCsv(alerts: SecurityAlert[], targetLabel: string): void {
  const csv = alertsToCsv(alerts);
  downloadFile(csv, `livesoc_alerts_${targetLabel}_${timestampForFilename()}.csv`, "text/csv;charset=utf-8");
}

export function exportAlertsJson(alerts: SecurityAlert[], targetLabel: string): void {
  const json = alertsToJson(alerts);
  downloadFile(json, `livesoc_alerts_${targetLabel}_${timestampForFilename()}.json`, "application/json");
}

// ---- Combined export (events + alerts + scenarios summary) ----

export interface ExportBundle {
  events: SecurityEvent[];
  alerts: SecurityAlert[];
  meta: Record<string, unknown>;
}

export function exportBundleJson(bundle: ExportBundle, targetLabel: string): void {
  const json = JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      platform: "LiveSOC — Live Security Monitoring & Detection Platform",
      target: targetLabel,
      ...bundle.meta,
      eventCount: bundle.events.length,
      alertCount: bundle.alerts.length,
      events: bundle.events,
      alerts: bundle.alerts,
    },
    null,
    2,
  );
  downloadFile(json, `livesoc_bundle_${targetLabel}_${timestampForFilename()}.json`, "application/json");
}

// ---- Custom Rules export/import ----

import type { CustomRule } from "@/lib/types";

export function exportRulesJson(rules: CustomRule[]): void {
  const payload = {
    platform: "LiveSOC — Live Security Monitoring & Detection Platform",
    exportedAt: new Date().toISOString(),
    format: "livesoc-custom-rules-v1",
    ruleCount: rules.length,
    rules: rules.map((r) => ({
      name: r.name,
      description: r.description,
      severity: r.severity,
      enabled: r.enabled,
      conditions: r.conditions,
      threshold: r.threshold,
      windowMs: r.windowMs,
      confidence: r.confidence,
      recommendedAction: r.recommendedAction,
    })),
  };
  const json = JSON.stringify(payload, null, 2);
  downloadFile(json, `livesoc_custom_rules_${timestampForFilename()}.json`, "application/json");
}

export interface ImportedRulesFile {
  platform?: string;
  format?: string;
  ruleCount?: number;
  rules: Array<{
    name: string;
    description?: string;
    severity?: string;
    enabled?: boolean;
    conditions: Array<{
      field: string;
      operator: string;
      value: string | number | string[];
    }>;
    threshold?: number;
    windowMs?: number;
    confidence?: number;
    recommendedAction?: string;
  }>;
}

export function parseRulesJson(jsonText: string): ImportedRulesFile {
  const parsed = JSON.parse(jsonText) as ImportedRulesFile;
  if (!parsed || !Array.isArray(parsed.rules)) {
    throw new Error("Invalid rules file: missing 'rules' array");
  }
  return parsed;
}
