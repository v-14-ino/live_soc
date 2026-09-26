"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  GitCompare,
  ArrowUp,
  ArrowDown,
  ArrowRight,
  Activity,
  AlertTriangle,
  Clock,
  Gauge,
  Network,
  Swords,
  Shield,
  Server,
  TrendingUp,
  TrendingDown,
  Minus,
  type LucideIcon,
} from "lucide-react";
import { api, type HistoryDetailResponse } from "@/lib/api-client";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { severityColor, SEVERITY_ORDER, SEVERITY_LABEL } from "@/lib/constants";
import type {
  Severity,
  ScenarioStatus,
  SecurityEvent,
  SecurityAlert,
  OffenseScenario,
  DefenseScenario,
  MonitoringSessionInfo,
  AssessmentResult,
} from "@/lib/types";

// ============================================================
// Normalizers (mirror history-view.tsx — kept local to avoid
// circular imports / because they are not exported from there)
// ============================================================

function normalizeSession(raw: unknown): MonitoringSessionInfo {
  const r = raw as Record<string, unknown>;
  const target = (r.target ?? null) as { address?: string; hostname?: string | null } | null;
  return {
    id: String(r.id),
    targetId: String(r.targetId),
    targetAddress: String(r.targetAddress ?? target?.address ?? "—"),
    assessmentId: r.assessmentId ? String(r.assessmentId) : null,
    status: r.status as MonitoringSessionInfo["status"],
    mode: r.mode as MonitoringSessionInfo["mode"],
    startedAt: typeof r.startedAt === "string" ? r.startedAt : new Date(r.startedAt as Date).toISOString(),
    endedAt: r.endedAt ? (typeof r.endedAt === "string" ? r.endedAt : new Date(r.endedAt as Date).toISOString()) : null,
    durationSec: Number(r.durationSec ?? 0),
    eventCount: Number(r.eventCount ?? 0),
    alertCount: Number(r.alertCount ?? 0),
    riskSummary: r.riskSummary ? String(r.riskSummary) : null,
  };
}

function normalizeEvent(raw: unknown): SecurityEvent {
  const r = raw as Record<string, unknown>;
  let rawField: Record<string, unknown> | null = null;
  if (typeof r.rawJson === "string" && r.rawJson) {
    try {
      rawField = JSON.parse(r.rawJson);
    } catch {
      rawField = null;
    }
  } else if (r.raw && typeof r.raw === "object") {
    rawField = r.raw as Record<string, unknown>;
  }
  return {
    id: String(r.id),
    eventId: String(r.eventId),
    sessionId: r.sessionId ? String(r.sessionId) : null,
    timestamp: typeof r.timestamp === "string" ? r.timestamp : new Date(r.timestamp as Date).toISOString(),
    source: r.source as string,
    sourceIp: (r.sourceIp as string | null) ?? null,
    sourcePort: r.sourcePort != null ? Number(r.sourcePort) : null,
    destIp: (r.destIp as string | null) ?? null,
    destPort: r.destPort != null ? Number(r.destPort) : null,
    protocol: (r.protocol as string | null) ?? null,
    eventType: String(r.eventType),
    severity: r.severity as Severity,
    status: String(r.status ?? "new"),
    message: String(r.message ?? ""),
    isDemo: Boolean(r.isDemo),
    raw: rawField,
  };
}

function normalizeAlert(raw: unknown): SecurityAlert {
  const r = raw as Record<string, unknown>;
  return {
    id: String(r.id),
    alertId: String(r.alertId),
    sessionId: r.sessionId ? String(r.sessionId) : null,
    eventId: r.eventId ? String(r.eventId) : null,
    ruleId: String(r.ruleId),
    ruleName: String(r.ruleName),
    severity: r.severity as Severity,
    confidence: Number(r.confidence ?? 0),
    message: String(r.message ?? ""),
    recommendedAction: r.recommendedAction ? String(r.recommendedAction) : null,
    status: String(r.status ?? "active"),
    timestamp: typeof r.timestamp === "string" ? r.timestamp : new Date(r.timestamp as Date).toISOString(),
  };
}

function parseRelatedEventIds(ids: string | string[] | null | undefined): string[] {
  if (ids == null) return [];
  if (Array.isArray(ids)) return ids.map(String).filter(Boolean);
  const s = String(ids).trim();
  if (!s) return [];
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

function normalizeOffenseScenario(raw: unknown): OffenseScenario {
  const r = raw as Record<string, unknown>;
  return {
    id: String(r.id),
    scenarioId: String(r.scenarioId),
    sessionId: r.sessionId ? String(r.sessionId) : null,
    title: String(r.title ?? ""),
    category: String(r.category ?? ""),
    severity: (r.severity as Severity) ?? "medium",
    confidence: Number(r.confidence ?? 0),
    affectedTarget: (r.affectedTarget as string | null) ?? null,
    affectedService: (r.affectedService as string | null) ?? null,
    technique: (r.technique as string | null) ?? null,
    techniqueMitre: (r.techniqueMitre as string | null) ?? null,
    attackPath: (r.attackPath as string | null) ?? null,
    potentialImpact: (r.potentialImpact as string | null) ?? null,
    relatedEventIds: parseRelatedEventIds(r.relatedEventIds as string | string[] | null | undefined),
    eventCount: Number(r.eventCount ?? 0),
    sourceCount: Number(r.sourceCount ?? 0),
    status: (r.status as ScenarioStatus) ?? "active",
    firstObserved: typeof r.firstObserved === "string" ? r.firstObserved : new Date(r.firstObserved as Date).toISOString(),
    lastObserved: typeof r.lastObserved === "string" ? r.lastObserved : new Date(r.lastObserved as Date).toISOString(),
  };
}

function normalizeDefenseScenario(raw: unknown): DefenseScenario {
  const r = raw as Record<string, unknown>;
  return {
    id: String(r.id),
    scenarioId: String(r.scenarioId),
    sessionId: r.sessionId ? String(r.sessionId) : null,
    relatedOffenseId: (r.relatedOffenseId as string | null) ?? null,
    title: String(r.title ?? ""),
    category: String(r.category ?? ""),
    priority: (r.priority as Severity) ?? "medium",
    affectedService: (r.affectedService as string | null) ?? null,
    detect: (r.detect as string | null) ?? null,
    monitor: (r.monitor as string | null) ?? null,
    prevent: (r.prevent as string | null) ?? null,
    respond: (r.respond as string | null) ?? null,
    recommendedAction: (r.recommendedAction as string | null) ?? null,
    relatedEventIds: parseRelatedEventIds(r.relatedEventIds as string | string[] | null | undefined),
    status: (r.status as ScenarioStatus) ?? "active",
    firstObserved: typeof r.firstObserved === "string" ? r.firstObserved : new Date(r.firstObserved as Date).toISOString(),
    lastObserved: typeof r.lastObserved === "string" ? r.lastObserved : new Date(r.lastObserved as Date).toISOString(),
  };
}

// ============================================================
// Formatting & diff helpers
// ============================================================

function formatDateTime(ts: string | Date | null | undefined): string {
  if (ts == null) return "—";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "----/--/-- --:--:--";
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  } catch {
    return "----/--/-- --:--:--";
  }
}

function durationLabel(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "—";
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function severityRank(s: Severity): number {
  return SEVERITY_ORDER[s] ?? 0;
}

// Accent colors per side
const ACCENT_A = "var(--soc-low)"; // cyan
const ACCENT_B = "var(--soc-medium)"; // amber

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function severityCounts(events: SecurityEvent[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const e of events) {
    const s = e.severity;
    if (counts[s] != null) counts[s]++;
  }
  return counts;
}

function sourceIpMap(events: SecurityEvent[]): Map<string, number> {
  const map = new Map<string, number>();
  for (const e of events) {
    if (!e.sourceIp) continue;
    map.set(e.sourceIp, (map.get(e.sourceIp) ?? 0) + 1);
  }
  return map;
}

function destPortMap(events: SecurityEvent[]): Map<number, number> {
  const map = new Map<number, number>();
  for (const e of events) {
    if (e.destPort == null) continue;
    map.set(e.destPort, (map.get(e.destPort) ?? 0) + 1);
  }
  return map;
}

// Compute a risk score (0-100) from alerts, mirroring risk-gauge-panel logic.
function riskScore(alerts: SecurityAlert[]): number {
  let score = 0;
  for (const a of alerts) {
    switch (a.severity) {
      case "critical":
        score += 25;
        break;
      case "high":
        score += 15;
        break;
      case "medium":
        score += 8;
        break;
      case "low":
        score += 3;
        break;
      case "info":
        score += 1;
        break;
    }
  }
  return Math.min(100, score);
}

function riskBand(score: number): { label: string; color: string } {
  if (score >= 71) return { label: "CRITICAL", color: "var(--soc-critical)" };
  if (score >= 41) return { label: "HIGH", color: "var(--soc-high)" };
  if (score >= 21) return { label: "MEDIUM", color: "var(--soc-medium)" };
  return { label: "LOW", color: "var(--soc-low)" };
}

// ============================================================
// Diff types
// ============================================================

interface SourceIpDiff {
  newInB: { ip: string; countB: number }[];
  disappeared: { ip: string; countA: number }[];
  common: { ip: string; countA: number; countB: number; delta: number }[];
}

interface ScenarioDiffEntry<T> {
  category: string;
  a?: T;
  b?: T;
  status: "new" | "gone" | "escalated" | "de-escalated" | "same";
}

// ============================================================
// UI atoms
// ============================================================

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="font-mono-data text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/80">
      {children}
    </div>
  );
}

function DeltaIndicator({ delta }: { delta: number }) {
  // delta > 0 = ↑ red (worsening/increased)
  // delta < 0 = ↓ green (improving/decreased)
  // delta === 0 = → muted
  if (delta > 0) {
    return (
      <span
        className="inline-flex items-center gap-0.5 font-mono-data text-[10px] font-bold"
        style={{ color: "var(--soc-critical)" }}
        title={`+${delta} (increased)`}
      >
        <ArrowUp className="h-3 w-3" />+{delta}
      </span>
    );
  }
  if (delta < 0) {
    return (
      <span
        className="inline-flex items-center gap-0.5 font-mono-data text-[10px] font-bold"
        style={{ color: "var(--soc-success)" }}
        title={`${delta} (decreased)`}
      >
        <ArrowDown className="h-3 w-3" />
        {delta}
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-0.5 font-mono-data text-[10px] font-bold text-muted-foreground"
      title="No change"
    >
      <ArrowRight className="h-3 w-3" />0
    </span>
  );
}

function EmptyDiffState({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border/40 bg-card/20 px-3 py-4 text-center text-[10px] text-muted-foreground">
      <Minus className="h-3 w-3 opacity-50" />
      {message}
    </div>
  );
}

function SideHeader({
  side,
  color,
  label,
  id,
  target,
  start,
  end,
}: {
  side: "A" | "B";
  color: string;
  label: string;
  id: string;
  target: string;
  start: string;
  end: string;
}) {
  return (
    <div
      className="relative overflow-hidden rounded-md border bg-card/40 p-2.5 pl-3"
      style={{ borderColor: `color-mix(in oklch, ${color} 35%, transparent)` }}
    >
      <div
        className="absolute left-0 top-0 h-full w-1"
        style={{ backgroundColor: color }}
        aria-hidden
      />
      <div className="flex items-center gap-1.5">
        <span
          className="inline-flex h-4 min-w-4 items-center justify-center rounded-sm px-1 font-mono-data text-[9px] font-bold"
          style={{
            color,
            backgroundColor: `color-mix(in oklch, ${color} 15%, transparent)`,
            border: `1px solid color-mix(in oklch, ${color} 40%, transparent)`,
          }}
        >
          {side}
        </span>
        <span
          className="font-mono-data text-[10px] font-semibold uppercase tracking-wider"
          style={{ color }}
        >
          {label}
        </span>
      </div>
      <div className="mt-1 truncate font-mono-data text-[10px] text-foreground/90" title={id}>
        {id}
      </div>
      <div className="mt-0.5 truncate font-mono-data text-[9px] text-muted-foreground" title={target}>
        Target: {target}
      </div>
      <div className="mt-0.5 font-mono-data text-[9px] text-muted-foreground" title={`${start} → ${end}`}>
        {start} → {end}
      </div>
    </div>
  );
}

// ============================================================
// Section components
// ============================================================

function SummaryKpiRow({
  sessionA,
  sessionB,
  eventsA,
  eventsB,
  alertsA,
  alertsB,
}: {
  sessionA: MonitoringSessionInfo;
  sessionB: MonitoringSessionInfo;
  eventsA: SecurityEvent[];
  eventsB: SecurityEvent[];
  alertsA: SecurityAlert[];
  alertsB: SecurityAlert[];
}) {
  const eventDelta = sessionB.eventCount - sessionA.eventCount;
  const alertDelta = sessionB.alertCount - sessionA.alertCount;
  const durationDelta = sessionB.durationSec - sessionA.durationSec;
  const riskA = riskScore(alertsA);
  const riskB = riskScore(alertsB);
  const riskDelta = riskB - riskA;
  const bandA = riskBand(riskA);
  const bandB = riskBand(riskB);

  const cards: {
    label: string;
    icon: LucideIcon;
    valueA: ReactNode;
    valueB: ReactNode;
    delta: number;
    accentA: string;
    accentB: string;
    deltaNode?: ReactNode;
  }[] = [
    {
      label: "Events",
      icon: Activity,
      valueA: sessionA.eventCount,
      valueB: sessionB.eventCount,
      delta: eventDelta,
      accentA: ACCENT_A,
      accentB: ACCENT_B,
    },
    {
      label: "Alerts",
      icon: AlertTriangle,
      valueA: sessionA.alertCount,
      valueB: sessionB.alertCount,
      delta: alertDelta,
      accentA: ACCENT_A,
      accentB: ACCENT_B,
    },
    {
      label: "Duration",
      icon: Clock,
      valueA: durationLabel(sessionA.durationSec),
      valueB: durationLabel(sessionB.durationSec),
      delta: durationDelta,
      accentA: ACCENT_A,
      accentB: ACCENT_B,
    },
    {
      label: "Risk Level",
      icon: Gauge,
      valueA: (
        <span className="flex items-center gap-1">
          <span style={{ color: bandA.color }}>{bandA.label}</span>
          <span className="font-mono-data text-[10px] text-muted-foreground">{riskA}/100</span>
        </span>
      ),
      valueB: (
        <span className="flex items-center gap-1">
          <span style={{ color: bandB.color }}>{bandB.label}</span>
          <span className="font-mono-data text-[10px] text-muted-foreground">{riskB}/100</span>
        </span>
      ),
      delta: riskDelta,
      accentA: bandA.color,
      accentB: bandB.color,
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
      {cards.map((c) => {
        const Icon = c.icon;
        const deltaWorsening = c.delta > 0;
        const deltaImproving = c.delta < 0;
        const deltaColor = deltaWorsening
          ? "var(--soc-critical)"
          : deltaImproving
            ? "var(--soc-success)"
            : "var(--muted-foreground)";
        return (
          <div
            key={c.label}
            className="relative overflow-hidden rounded-md border border-border/40 bg-card/40 p-2.5"
          >
            <div className="flex items-center gap-1.5">
              <Icon className="h-3 w-3 text-muted-foreground" />
              <SectionLabel>{c.label}</SectionLabel>
            </div>
            <div className="mt-1.5 grid grid-cols-[1fr_auto_1fr] items-center gap-1.5">
              <div className="min-w-0">
                <div
                  className="font-mono-data text-[9px] uppercase tracking-wider"
                  style={{ color: c.accentA }}
                >
                  A
                </div>
                <div
                  className="truncate font-mono-data-lg text-base font-bold tabular-nums"
                  style={{ color: c.accentA }}
                  title={String(c.valueA)}
                >
                  {c.valueA}
                </div>
              </div>
              <div className="flex flex-col items-center justify-center px-1">
                {c.label === "Duration" || c.label === "Risk Level" ? (
                  <span
                    className="font-mono-data text-[9px] font-bold"
                    style={{ color: deltaColor }}
                    title={`${c.delta >= 0 ? "+" : ""}${c.delta}`}
                  >
                    {c.delta > 0 ? "↑" : c.delta < 0 ? "↓" : "→"}
                  </span>
                ) : (
                  <DeltaIndicator delta={c.delta} />
                )}
              </div>
              <div className="min-w-0 text-right">
                <div
                  className="font-mono-data text-[9px] uppercase tracking-wider"
                  style={{ color: c.accentB }}
                >
                  B
                </div>
                <div
                  className="truncate font-mono-data-lg text-base font-bold tabular-nums"
                  style={{ color: c.accentB }}
                  title={String(c.valueB)}
                >
                  {c.valueB}
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SeverityDistributionSection({
  eventsA,
  eventsB,
}: {
  eventsA: SecurityEvent[];
  eventsB: SecurityEvent[];
}) {
  const countsA = useMemo(() => severityCounts(eventsA), [eventsA]);
  const countsB = useMemo(() => severityCounts(eventsB), [eventsB]);
  const maxCount = useMemo(() => {
    let m = 1;
    for (const s of SEVERITIES) {
      m = Math.max(m, countsA[s], countsB[s]);
    }
    return m;
  }, [countsA, countsB]);

  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-1.5">
        <Activity className="h-3 w-3 text-muted-foreground" />
        <SectionLabel>Severity Distribution</SectionLabel>
      </div>
      <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
        {([
          { side: "A", color: ACCENT_A, counts: countsA },
          { side: "B", color: ACCENT_B, counts: countsB },
        ] as const).map((col) => (
          <div
            key={col.side}
            className="rounded-md border border-border/40 bg-card/30 p-2.5"
          >
            <div className="mb-1.5 flex items-center justify-between">
              <span
                className="font-mono-data text-[10px] font-bold uppercase tracking-wider"
                style={{ color: col.color }}
              >
                Session {col.side}
              </span>
              <span className="font-mono-data text-[9px] text-muted-foreground">
                {SEVERITIES.reduce((acc, s) => acc + col.counts[s], 0)} events
              </span>
            </div>
            <div className="flex flex-col gap-1">
              {SEVERITIES.map((s) => {
                const countA = countsA[s];
                const countB = countsB[s];
                const count = col.side === "A" ? countA : countB;
                const delta = countB - countA;
                const pct = Math.max(2, Math.round((count / maxCount) * 100));
                const sevColor = severityColor(s);
                return (
                  <div key={s} className="flex items-center gap-1.5">
                    <div className="w-[52px] shrink-0">
                      <SeverityBadge severity={s} size="sm" />
                    </div>
                    <div className="relative h-4 flex-1 overflow-hidden rounded-sm bg-muted/30">
                      <div
                        className="absolute inset-y-0 left-0 rounded-sm transition-all"
                        style={{
                          width: `${pct}%`,
                          backgroundColor: `color-mix(in oklch, ${sevColor} 55%, transparent)`,
                          boxShadow: count > 0 ? `0 0 6px -2px ${sevColor}` : "none",
                        }}
                      />
                      <span className="absolute inset-y-0 right-1.5 flex items-center font-mono-data text-[9px] font-bold tabular-nums text-foreground/90">
                        {count}
                      </span>
                    </div>
                    {col.side === "B" && (
                      <div className="w-[44px] shrink-0 text-right">
                        <DeltaIndicator delta={delta} />
                      </div>
                    )}
                    {col.side === "A" && <div className="w-[44px] shrink-0" />}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function SourceIpComparisonSection({
  eventsA,
  eventsB,
}: {
  eventsA: SecurityEvent[];
  eventsB: SecurityEvent[];
}) {
  const diff = useMemo<SourceIpDiff>(() => {
    const mapA = sourceIpMap(eventsA);
    const mapB = sourceIpMap(eventsB);
    const newInB: { ip: string; countB: number }[] = [];
    const disappeared: { ip: string; countA: number }[] = [];
    const common: { ip: string; countA: number; countB: number; delta: number }[] = [];
    for (const [ip, countB] of mapB.entries()) {
      if (!mapA.has(ip)) newInB.push({ ip, countB });
    }
    for (const [ip, countA] of mapA.entries()) {
      if (!mapB.has(ip)) disappeared.push({ ip, countA });
    }
    for (const [ip, countA] of mapA.entries()) {
      const countB = mapB.get(ip);
      if (countB != null) {
        common.push({ ip, countA, countB, delta: countB - countA });
      }
    }
    // Sort: most active first
    newInB.sort((a, b) => b.countB - a.countB);
    disappeared.sort((a, b) => b.countA - a.countA);
    common.sort((a, b) => b.countB - a.countB);
    // Cap to top 20 each
    return {
      newInB: newInB.slice(0, 20),
      disappeared: disappeared.slice(0, 20),
      common: common.slice(0, 20),
    };
  }, [eventsA, eventsB]);

  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-1.5">
        <Network className="h-3 w-3 text-muted-foreground" />
        <SectionLabel>Source IP Comparison</SectionLabel>
      </div>
      <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-3">
        {/* New in B */}
        <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
          <div className="border-b border-border/40 px-2.5 py-1.5">
            <div className="flex items-center gap-1.5">
              <TrendingUp className="h-3 w-3" style={{ color: "var(--soc-critical)" }} />
              <span
                className="font-mono-data text-[10px] font-bold uppercase tracking-wider"
                style={{ color: "var(--soc-critical)" }}
              >
                New in B
              </span>
              <span className="ml-auto font-mono-data text-[9px] text-muted-foreground">
                {diff.newInB.length}
              </span>
            </div>
          </div>
          <div className="soc-scrollbar max-h-60 overflow-y-auto">
            {diff.newInB.length === 0 ? (
              <EmptyDiffState message="No new source IPs in B" />
            ) : (
              <ul className="divide-y divide-border/20">
                {diff.newInB.map((it) => (
                  <li
                    key={it.ip}
                    className="flex items-center justify-between gap-2 px-2.5 py-1.5"
                    style={{
                      backgroundColor: `color-mix(in oklch, var(--soc-critical) 6%, transparent)`,
                    }}
                  >
                    <span
                      className="truncate font-mono-data text-[10px] text-foreground/90"
                      title={it.ip}
                    >
                      {it.ip}
                    </span>
                    <span className="shrink-0 font-mono-data text-[10px] font-bold text-[color:var(--soc-critical)]">
                      ×{it.countB}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Disappeared */}
        <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
          <div className="border-b border-border/40 px-2.5 py-1.5">
            <div className="flex items-center gap-1.5">
              <TrendingDown className="h-3 w-3 text-muted-foreground" />
              <span className="font-mono-data text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                Disappeared
              </span>
              <span className="ml-auto font-mono-data text-[9px] text-muted-foreground">
                {diff.disappeared.length}
              </span>
            </div>
          </div>
          <div className="soc-scrollbar max-h-60 overflow-y-auto">
            {diff.disappeared.length === 0 ? (
              <EmptyDiffState message="No disappeared source IPs" />
            ) : (
              <ul className="divide-y divide-border/20">
                {diff.disappeared.map((it) => (
                  <li
                    key={it.ip}
                    className="flex items-center justify-between gap-2 px-2.5 py-1.5 opacity-60"
                  >
                    <span
                      className="truncate font-mono-data text-[10px] text-muted-foreground line-through decoration-muted-foreground/50"
                      title={it.ip}
                    >
                      {it.ip}
                    </span>
                    <span className="shrink-0 font-mono-data text-[10px] text-muted-foreground">
                      ×{it.countA}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Common */}
        <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
          <div className="border-b border-border/40 px-2.5 py-1.5">
            <div className="flex items-center gap-1.5">
              <ArrowRight className="h-3 w-3 text-[color:var(--soc-low)]" />
              <span
                className="font-mono-data text-[10px] font-bold uppercase tracking-wider"
                style={{ color: "var(--soc-low)" }}
              >
                Common (A → B)
              </span>
              <span className="ml-auto font-mono-data text-[9px] text-muted-foreground">
                {diff.common.length}
              </span>
            </div>
          </div>
          <div className="soc-scrollbar max-h-60 overflow-y-auto">
            {diff.common.length === 0 ? (
              <EmptyDiffState message="No common source IPs" />
            ) : (
              <ul className="divide-y divide-border/20">
                {diff.common.map((it) => (
                  <li
                    key={it.ip}
                    className="flex items-center justify-between gap-2 px-2.5 py-1.5"
                  >
                    <span
                      className="truncate font-mono-data text-[10px] text-foreground/90"
                      title={it.ip}
                    >
                      {it.ip}
                    </span>
                    <span className="flex shrink-0 items-center gap-1 font-mono-data text-[10px]">
                      <span className="text-muted-foreground">{it.countA}</span>
                      <ArrowRight className="h-2.5 w-2.5 text-muted-foreground/60" />
                      <span
                        className="font-bold"
                        style={{
                          color:
                            it.delta > 0
                              ? "var(--soc-critical)"
                              : it.delta < 0
                                ? "var(--soc-success)"
                                : "var(--foreground)",
                        }}
                      >
                        {it.countB}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function ScenarioComparisonSection({
  offensesA,
  offensesB,
  defensesA,
  defensesB,
}: {
  offensesA: OffenseScenario[];
  offensesB: OffenseScenario[];
  defensesA: DefenseScenario[];
  defensesB: DefenseScenario[];
}) {
  const offenseDiff = useMemo(() => {
    return buildScenarioDiff(offensesA, offensesB, (s) => s.severity);
  }, [offensesA, offensesB]);

  const defenseDiff = useMemo(() => {
    return buildScenarioDiff(defensesA, defensesB, (s) => s.priority);
  }, [defensesA, defensesB]);

  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-1.5">
        <Swords className="h-3 w-3 text-muted-foreground" />
        <SectionLabel>Scenario Comparison</SectionLabel>
      </div>
      <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
        <ScenarioColumn
          title="Offense Scenarios"
          icon={Swords}
          accentColor="var(--soc-critical)"
          diff={offenseDiff}
          renderTitle={(s) => s.title}
          renderSeverity={(s) => s.severity}
        />
        <ScenarioColumn
          title="Defense Scenarios"
          icon={Shield}
          accentColor="var(--soc-low)"
          diff={defenseDiff as ScenarioDiffEntry<DefenseScenario>[]}
          renderTitle={(s) => s.title}
          renderSeverity={(s) => s.priority}
        />
      </div>
    </section>
  );
}

function buildScenarioDiff<
  T extends { category: string; title: string },
>(
  listA: T[],
  listB: T[],
  getSeverity: (s: T) => Severity,
): ScenarioDiffEntry<T>[] {
  const mapA = new Map<string, T>();
  const mapB = new Map<string, T>();
  for (const s of listA) {
    // Keep highest-severity per category in A
    const existing = mapA.get(s.category);
    if (!existing || severityRank(getSeverity(s)) > severityRank(getSeverity(existing))) {
      mapA.set(s.category, s);
    }
  }
  for (const s of listB) {
    const existing = mapB.get(s.category);
    if (!existing || severityRank(getSeverity(s)) > severityRank(getSeverity(existing))) {
      mapB.set(s.category, s);
    }
  }

  const out: ScenarioDiffEntry<T>[] = [];
  for (const [cat, b] of mapB.entries()) {
    const a = mapA.get(cat);
    if (!a) {
      out.push({ category: cat, b, status: "new" });
      continue;
    }
    const ra = severityRank(getSeverity(a));
    const rb = severityRank(getSeverity(b));
    if (rb > ra) out.push({ category: cat, a, b, status: "escalated" });
    else if (rb < ra) out.push({ category: cat, a, b, status: "de-escalated" });
    else out.push({ category: cat, a, b, status: "same" });
  }
  for (const [cat, a] of mapA.entries()) {
    if (!mapB.has(cat)) out.push({ category: cat, a, status: "gone" });
  }
  // Sort: escalated, new, de-escalated, same, gone
  const rank: Record<ScenarioDiffEntry<T>["status"], number> = {
    escalated: 0,
    new: 1,
    "de-escalated": 2,
    same: 3,
    gone: 4,
  };
  out.sort((x, y) => rank[x.status] - rank[y.status]);
  return out;
}

function ScenarioColumn<T extends { category: string; title: string }>({
  title,
  icon: Icon,
  accentColor,
  diff,
  renderTitle,
  renderSeverity,
}: {
  title: string;
  icon: LucideIcon;
  accentColor: string;
  diff: ScenarioDiffEntry<T>[];
  renderTitle: (s: T) => string;
  renderSeverity: (s: T) => Severity;
}) {
  const counts = useMemo(() => {
    let escalated = 0;
    let deEscalated = 0;
    let newlyObserved = 0;
    let gone = 0;
    let same = 0;
    for (const d of diff) {
      if (d.status === "escalated") escalated++;
      else if (d.status === "de-escalated") deEscalated++;
      else if (d.status === "new") newlyObserved++;
      else if (d.status === "gone") gone++;
      else same++;
    }
    return { escalated, deEscalated, newlyObserved, gone, same, total: diff.length };
  }, [diff]);

  return (
    <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
      <div className="border-b border-border/40 px-2.5 py-1.5">
        <div className="flex items-center gap-1.5">
          <Icon className="h-3 w-3" style={{ color: accentColor }} />
          <span
            className="font-mono-data text-[10px] font-bold uppercase tracking-wider"
            style={{ color: accentColor }}
          >
            {title}
          </span>
          <span className="ml-auto flex items-center gap-1.5 font-mono-data text-[9px] text-muted-foreground">
            {counts.escalated > 0 && (
              <span title="Escalated">
                <span className="text-[color:var(--soc-critical)]">↑{counts.escalated}</span>
              </span>
            )}
            {counts.newlyObserved > 0 && (
              <span title="New">
                <span className="text-[color:var(--soc-critical)]">+{counts.newlyObserved}</span>
              </span>
            )}
            {counts.deEscalated > 0 && (
              <span title="De-escalated">
                <span className="text-[color:var(--soc-success)]">↓{counts.deEscalated}</span>
              </span>
            )}
            {counts.gone > 0 && (
              <span title="Gone">
                <span className="text-muted-foreground">−{counts.gone}</span>
              </span>
            )}
            {counts.same > 0 && (
              <span title="Same">
                <span className="text-muted-foreground">={counts.same}</span>
              </span>
            )}
            <span>· {counts.total} total</span>
          </span>
        </div>
      </div>
      <div className="soc-scrollbar max-h-72 overflow-y-auto">
        {diff.length === 0 ? (
          <EmptyDiffState message="No scenarios in either session" />
        ) : (
          <ul className="divide-y divide-border/20">
            {diff.map((d) => {
              const statusColor =
                d.status === "escalated" || d.status === "new"
                  ? "var(--soc-critical)"
                  : d.status === "de-escalated"
                    ? "var(--soc-success)"
                    : d.status === "gone"
                      ? "var(--muted-foreground)"
                      : "var(--foreground)";
              const statusLabel =
                d.status === "escalated"
                  ? "ESCALATED"
                  : d.status === "de-escalated"
                    ? "DE-ESCALATED"
                    : d.status === "new"
                      ? "NEW"
                      : d.status === "gone"
                        ? "GONE"
                        : "SAME";
              return (
                <li key={d.category} className="px-2.5 py-1.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span
                      className="inline-flex items-center gap-0.5 rounded-sm border px-1 py-0.5 font-mono-data text-[8px] font-bold uppercase tracking-wider"
                      style={{
                        color: statusColor,
                        borderColor: `color-mix(in oklch, ${statusColor} 40%, transparent)`,
                        backgroundColor: `color-mix(in oklch, ${statusColor} 10%, transparent)`,
                      }}
                    >
                      {d.status === "escalated" && <ArrowUp className="h-2.5 w-2.5" />}
                      {d.status === "de-escalated" && <ArrowDown className="h-2.5 w-2.5" />}
                      {d.status === "new" && <TrendingUp className="h-2.5 w-2.5" />}
                      {d.status === "gone" && <Minus className="h-2.5 w-2.5" />}
                      {d.status === "same" && <ArrowRight className="h-2.5 w-2.5" />}
                      {statusLabel}
                    </span>
                    <span className="truncate font-mono-data text-[10px] text-foreground/90" title={d.category}>
                      {d.category}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center gap-1.5">
                    {d.a ? (
                      <>
                        <SeverityBadge severity={renderSeverity(d.a)} size="sm" />
                        <span
                          className="truncate font-mono-data text-[9px] text-muted-foreground"
                          title={renderTitle(d.a)}
                        >
                          {renderTitle(d.a)}
                        </span>
                      </>
                    ) : (
                      <span className="font-mono-data text-[9px] text-muted-foreground/60">— not in A —</span>
                    )}
                  </div>
                  <div className="mt-0.5 flex items-center gap-1.5">
                    {d.b ? (
                      <>
                        <SeverityBadge severity={renderSeverity(d.b)} size="sm" />
                        <span
                          className="truncate font-mono-data text-[9px] text-foreground/80"
                          title={renderTitle(d.b)}
                        >
                          {renderTitle(d.b)}
                        </span>
                      </>
                    ) : (
                      <span className="font-mono-data text-[9px] text-muted-foreground/60">— not in B —</span>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

function DestPortComparisonSection({
  eventsA,
  eventsB,
}: {
  eventsA: SecurityEvent[];
  eventsB: SecurityEvent[];
}) {
  const topA = useMemo(() => {
    const m = destPortMap(eventsA);
    return Array.from(m.entries())
      .map(([port, count]) => ({ port, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [eventsA]);
  const topB = useMemo(() => {
    const m = destPortMap(eventsB);
    return Array.from(m.entries())
      .map(([port, count]) => ({ port, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [eventsB]);
  const maxCount = Math.max(1, ...topA.map((x) => x.count), ...topB.map((x) => x.count));
  const allPorts = useMemo(() => {
    const s = new Set<number>();
    topA.forEach((x) => s.add(x.port));
    topB.forEach((x) => s.add(x.port));
    return Array.from(s).sort((a, b) => a - b);
  }, [topA, topB]);
  const lookupA = useMemo(() => new Map(topA.map((x) => [x.port, x.count])), [topA]);
  const lookupB = useMemo(() => new Map(topB.map((x) => [x.port, x.count])), [topB]);

  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-1.5">
        <Server className="h-3 w-3 text-muted-foreground" />
        <SectionLabel>Top Destination Ports</SectionLabel>
      </div>
      <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
        <div className="grid grid-cols-[1fr_70px_1fr] border-b border-border/40">
          <div
            className="px-2.5 py-1.5 font-mono-data text-[10px] font-bold uppercase tracking-wider"
            style={{ color: ACCENT_A }}
          >
            Session A
          </div>
          <div className="px-2.5 py-1.5 text-center font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
            Port
          </div>
          <div
            className="px-2.5 py-1.5 text-right font-mono-data text-[10px] font-bold uppercase tracking-wider"
            style={{ color: ACCENT_B }}
          >
            Session B
          </div>
        </div>
        <div className="soc-scrollbar max-h-60 overflow-y-auto">
          {allPorts.length === 0 ? (
            <EmptyDiffState message="No destination ports recorded" />
          ) : (
            <ul className="divide-y divide-border/20">
              {allPorts.map((port) => {
                const ca = lookupA.get(port) ?? 0;
                const cb = lookupB.get(port) ?? 0;
                const pa = Math.max(2, Math.round((ca / maxCount) * 100));
                const pb = Math.max(2, Math.round((cb / maxCount) * 100));
                const delta = cb - ca;
                return (
                  <li
                    key={port}
                    className="grid grid-cols-[1fr_70px_1fr] items-center gap-1 px-2.5 py-1.5"
                  >
                    {/* A side bar (right-aligned toward center) */}
                    <div className="flex items-center justify-end gap-1.5">
                      <span
                        className={cn(
                          "font-mono-data text-[10px] font-bold tabular-nums",
                          ca > 0 ? "text-foreground/90" : "text-muted-foreground/40",
                        )}
                      >
                        {ca > 0 ? ca : "—"}
                      </span>
                      <div className="relative h-3 w-[80px] overflow-hidden rounded-sm bg-muted/20">
                        <div
                          className="absolute inset-y-0 right-0 rounded-sm"
                          style={{
                            width: `${pa}%`,
                            backgroundColor: `color-mix(in oklch, ${ACCENT_A} 55%, transparent)`,
                          }}
                        />
                      </div>
                    </div>
                    {/* Center port + delta */}
                    <div className="flex flex-col items-center">
                      <span
                        className="font-mono-data text-[11px] font-bold tabular-nums text-foreground"
                        title={`Port ${port}`}
                      >
                        {port}
                      </span>
                      {ca > 0 && cb > 0 && (
                        <span
                          className="font-mono-data text-[8px] font-bold"
                          style={{
                            color:
                              delta > 0
                                ? "var(--soc-critical)"
                                : delta < 0
                                  ? "var(--soc-success)"
                                  : "var(--muted-foreground)",
                          }}
                        >
                          {delta > 0 ? `+${delta}` : delta < 0 ? `${delta}` : "=0"}
                        </span>
                      )}
                    </div>
                    {/* B side bar (left-aligned toward center) */}
                    <div className="flex items-center gap-1.5">
                      <div className="relative h-3 w-[80px] overflow-hidden rounded-sm bg-muted/20">
                        <div
                          className="absolute inset-y-0 left-0 rounded-sm"
                          style={{
                            width: `${pb}%`,
                            backgroundColor: `color-mix(in oklch, ${ACCENT_B} 55%, transparent)`,
                          }}
                        />
                      </div>
                      <span
                        className={cn(
                          "font-mono-data text-[10px] font-bold tabular-nums",
                          cb > 0 ? "text-foreground/90" : "text-muted-foreground/40",
                        )}
                      >
                        {cb > 0 ? cb : "—"}
                      </span>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}

// ============================================================
// Compare content (fetches both sessions in parallel)
// ============================================================

function CompareContent({
  sessionAId,
  sessionBId,
}: {
  sessionAId: string;
  sessionBId: string;
}) {
  const [detailA, setDetailA] = useState<HistoryDetailResponse | null>(null);
  const [detailB, setDetailB] = useState<HistoryDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      setError(null);
      try {
        const [rawA, rawB] = await Promise.all([
          api.getHistoryDetail(sessionAId),
          api.getHistoryDetail(sessionBId),
        ]);
        if (cancelled) return;
        const normA: HistoryDetailResponse = {
          session: normalizeSession(rawA.session),
          assessment: normalizeAssessment(rawA.assessment),
          events: (rawA.events ?? []).map(normalizeEvent),
          alerts: (rawA.alerts ?? []).map(normalizeAlert),
          offenseScenarios: (rawA.offenseScenarios ?? []).map(normalizeOffenseScenario),
          defenseScenarios: (rawA.defenseScenarios ?? []).map(normalizeDefenseScenario),
        };
        const normB: HistoryDetailResponse = {
          session: normalizeSession(rawB.session),
          assessment: normalizeAssessment(rawB.assessment),
          events: (rawB.events ?? []).map(normalizeEvent),
          alerts: (rawB.alerts ?? []).map(normalizeAlert),
          offenseScenarios: (rawB.offenseScenarios ?? []).map(normalizeOffenseScenario),
          defenseScenarios: (rawB.defenseScenarios ?? []).map(normalizeDefenseScenario),
        };
        setDetailA(normA);
        setDetailB(normB);
      } catch (e) {
        if (cancelled) return;
        const msg = e instanceof Error ? e.message : "Failed to load session details for comparison.";
        setError(msg);
        toast.error("Failed to load comparison", { description: msg });
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [sessionAId, sessionBId]);

  if (loading) {
    return (
      <div className="flex flex-col gap-3 p-4">
        <div className="grid grid-cols-2 gap-2.5">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4">
        <div className="rounded-md border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 px-3 py-3 text-[11px] text-[color:var(--soc-critical)]">
          {error}
        </div>
      </div>
    );
  }

  if (!detailA || !detailB) return null;

  const sessionA = detailA.session;
  const sessionB = detailB.session;

  return (
    <div className="flex flex-col gap-4 p-4">
      {/* Side headers */}
      <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
        <SideHeader
          side="A"
          color={ACCENT_A}
          label="Session A"
          id={sessionA.id}
          target={sessionA.targetAddress}
          start={formatDateTime(sessionA.startedAt)}
          end={formatDateTime(sessionA.endedAt)}
        />
        <SideHeader
          side="B"
          color={ACCENT_B}
          label="Session B"
          id={sessionB.id}
          target={sessionB.targetAddress}
          start={formatDateTime(sessionB.startedAt)}
          end={formatDateTime(sessionB.endedAt)}
        />
      </div>

      {/* Summary KPI row */}
      <SummaryKpiRow
        sessionA={sessionA}
        sessionB={sessionB}
        eventsA={detailA.events}
        eventsB={detailB.events}
        alertsA={detailA.alerts}
        alertsB={detailB.alerts}
      />

      {/* Severity distribution */}
      <SeverityDistributionSection eventsA={detailA.events} eventsB={detailB.events} />

      {/* Source IP comparison */}
      <SourceIpComparisonSection eventsA={detailA.events} eventsB={detailB.events} />

      {/* Scenario comparison */}
      <ScenarioComparisonSection
        offensesA={detailA.offenseScenarios}
        offensesB={detailB.offenseScenarios}
        defensesA={detailA.defenseScenarios}
        defensesB={detailB.defenseScenarios}
      />

      {/* Top destination ports */}
      <DestPortComparisonSection eventsA={detailA.events} eventsB={detailB.events} />

      {/* Footer disclaimer */}
      <div className="mt-1 flex items-center gap-1.5 border-t border-border/40 pt-2 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/60">
        <Minus className="h-2.5 w-2.5" />
        Generated from historical session data · Comparison is computed from persisted events
        (capped at the API limit) and recorded scenarios.
      </div>
    </div>
  );
}

// Assessment normalizer (needed for completeness, though not displayed in compare)
function normalizeAssessment(raw: unknown): AssessmentResult | null {
  if (!raw) return null;
  const r = raw as Record<string, unknown>;
  const ports = Array.isArray(r.ports) ? r.ports : [];
  const services = Array.isArray(r.services) ? r.services : [];
  const serviceNameById = new Map<string, string>();
  for (const s of services) {
    const sr = s as Record<string, unknown>;
    if (sr.id && sr.name) serviceNameById.set(String(sr.id), String(sr.name));
  }
  return {
    id: String(r.id),
    targetId: String(r.targetId),
    status: String(r.status ?? "pending"),
    reachability: String(r.reachability ?? "unknown"),
    latencyMs: r.latencyMs != null ? Number(r.latencyMs) : null,
    hostname: (r.hostname as string | null) ?? null,
    osGuess: (r.osGuess as string | null) ?? null,
    startedAt: typeof r.startedAt === "string" ? r.startedAt : new Date(r.startedAt as Date).toISOString(),
    completedAt: r.completedAt
      ? typeof r.completedAt === "string"
        ? r.completedAt
        : new Date(r.completedAt as Date).toISOString()
      : null,
    ports: ports.map((p) => {
      const pr = p as Record<string, unknown>;
      const sid = pr.serviceId ? String(pr.serviceId) : null;
      return {
        id: String(pr.id),
        number: Number(pr.number),
        protocol: String(pr.protocol ?? "tcp"),
        state: String(pr.state ?? "open"),
        serviceName:
          (pr.serviceName as string | undefined) ??
          (sid ? serviceNameById.get(sid) : undefined),
      };
    }),
    services: services.map((s) => ({
      id: String((s as Record<string, unknown>).id),
      name: String((s as Record<string, unknown>).name),
      port: Number((s as Record<string, unknown>).port),
      protocol: String((s as Record<string, unknown>).protocol ?? "tcp"),
      product: ((s as Record<string, unknown>).product as string | null) ?? null,
      version: ((s as Record<string, unknown>).version as string | null) ?? null,
      extrainfo: ((s as Record<string, unknown>).extrainfo as string | null) ?? null,
      method: String((s as Record<string, unknown>).method ?? "table"),
      confidence: Number((s as Record<string, unknown>).confidence ?? 50),
    })),
  };
}

// ============================================================
// Public dialog component
// ============================================================

export interface CompareSessionsDialogProps {
  sessionAId: string | null;
  sessionBId: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CompareSessionsDialog({
  sessionAId,
  sessionBId,
  open,
  onOpenChange,
}: CompareSessionsDialogProps) {
  const ready = open && !!sessionAId && !!sessionBId;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] max-w-5xl gap-0 overflow-hidden p-0 sm:max-w-5xl">
        <DialogHeader className="border-b border-border/40 px-4 py-3 text-left">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <GitCompare className="h-4 w-4 text-[color:var(--soc-low)]" />
            Session Comparison
            {sessionAId && sessionBId && (
              <span className="font-mono-data text-[10px] font-normal text-muted-foreground">
                {sessionAId.slice(0, 12)}… vs {sessionBId.slice(0, 12)}…
              </span>
            )}
          </DialogTitle>
          <DialogDescription className="text-[10px] uppercase tracking-wider text-muted-foreground">
            Side-by-side diff of two historical monitoring sessions.
          </DialogDescription>
        </DialogHeader>
        <div className="soc-scrollbar max-h-[calc(92vh-64px)] overflow-y-auto">
          {ready ? (
            <CompareContent sessionAId={sessionAId!} sessionBId={sessionBId!} />
          ) : (
            <div className="p-4 text-[11px] text-muted-foreground">
              Select two sessions to compare.
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// Re-export so callers can build summary chips if needed.
export { SEVERITY_LABEL };
