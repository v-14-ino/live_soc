"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Radar,
  Search,
  Eye,
  Activity,
  Siren,
  CheckCircle2,
  ChevronRight,
  Clock,
  Server,
  ArrowDown,
  Link2,
  Swords,
  Crosshair,
  AlertTriangle,
  type LucideIcon,
} from "lucide-react";
import { useAppStore } from "@/lib/store";
import { api } from "@/lib/api-client";
import { KpiCard } from "@/components/soc/kpi-card";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { StatusDot } from "@/components/soc/status-dot";
import { AuthWarning } from "@/components/soc/auth-warning";
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
import { severityColor, SEVERITY_ORDER } from "@/lib/constants";
import type {
  Severity,
  DefenseScenario,
  ScenarioStatus,
  SecurityEvent,
} from "@/lib/types";

// ============================================================
// Helpers
// ============================================================

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "--:--:--";
    return d.toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return "--:--:--";
  }
}

function formatDateTime(ts: string): string {
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "----/--/-- --:--:--";
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  } catch {
    return "----/--/-- --:--:--";
  }
}

function durationLabel(first: string, last: string): string {
  try {
    const a = new Date(first).getTime();
    const b = new Date(last).getTime();
    if (!isFinite(a) || !isFinite(b)) return "—";
    const sec = Math.max(0, Math.round((b - a) / 1000));
    if (sec < 60) return `${sec}s`;
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    if (m < 60) return `${m}m ${s}s`;
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m`;
  } catch {
    return "—";
  }
}

// relatedEventIds: live = real array; historical (raw Prisma row) = comma string.
function parseRelatedEventIds(
  ids: string | string[] | null | undefined,
): string[] {
  if (ids == null) return [];
  if (Array.isArray(ids)) return ids.map(String).filter(Boolean);
  const s = String(ids).trim();
  if (!s) return [];
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

// Normalize a raw scenario (from either source) into a consistent shape.
function normalizeScenario(raw: DefenseScenario): DefenseScenario {
  return {
    ...raw,
    priority: (raw.priority ?? "medium") as Severity,
    status: (raw.status ?? "active") as ScenarioStatus,
    relatedEventIds: parseRelatedEventIds(
      raw.relatedEventIds as unknown as string | string[] | null | undefined,
    ),
  };
}

// Short, ALL-CAPS label derived from a defense scenario category.
function categoryShortLabel(category: string | null | undefined): string {
  if (!category) return "—";
  const map: Record<string, string> = {
    network_scan_monitoring: "NETWORK SCAN",
    ssh_auth_monitoring: "SSH AUTH",
    http_anomaly_monitoring: "HTTP ANOMALY",
    connection_rate_monitoring: "CONN RATE",
    exposed_service_monitoring: "EXPOSED SVC",
    suspicious_source_monitoring: "SUSPICIOUS SRC",
  };
  if (map[category]) return map[category];
  // Fallback: prettify snake_case → SPACE-separated upper-case, truncated.
  const pretty = category.replace(/_/g, " ").toUpperCase();
  return pretty.length > 24 ? pretty.slice(0, 24) + "…" : pretty;
}

function severityRank(s: Severity): number {
  return SEVERITY_ORDER[s] ?? 0;
}

function sortScenarios(list: DefenseScenario[]): DefenseScenario[] {
  return list.slice().sort((a, b) => {
    const sev = severityRank(b.priority) - severityRank(a.priority);
    if (sev !== 0) return sev;
    const ta = new Date(a.lastObserved).getTime() || 0;
    const tb = new Date(b.lastObserved).getTime() || 0;
    return tb - ta;
  });
}

// Cyan is the Defense identity color, but each card uses its priority color
// for the accent bar so high-priority items still stand out.
function priorityColor(s: DefenseScenario): string {
  return severityColor(s.priority);
}

// ============================================================
// Small UI atoms
// ============================================================

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="font-mono-data text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/80">
      {children}
    </div>
  );
}

function MetaField({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: ReactNode;
  icon?: LucideIcon;
}) {
  return (
    <div className="min-w-0">
      <div className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
        {label}
      </div>
      <div className="mt-0.5 flex items-center gap-1 text-[11px] text-foreground/90">
        {Icon && <Icon className="h-3 w-3 shrink-0 text-muted-foreground" />}
        <span
          className="truncate font-mono-data"
          title={typeof value === "string" ? value : undefined}
        >
          {value ?? "—"}
        </span>
      </div>
    </div>
  );
}

// One of the four guidance panels on a card / dialog section.
function GuidanceBlock({
  label,
  icon: Icon,
  text,
  accent,
}: {
  label: string;
  icon: LucideIcon;
  text: string | null | undefined;
  accent: string;
}) {
  return (
    <div className="rounded-md border border-border/40 bg-card/20 p-2.5">
      <div className="mb-1 flex items-center gap-1.5">
        <Icon
          className="h-3.5 w-3.5 shrink-0"
          style={{ color: accent }}
        />
        <SectionLabel>{label}</SectionLabel>
      </div>
      <p className="text-[11px] leading-snug text-foreground/80">
        {text && text.trim().length > 0
          ? text
          : "No specific guidance recorded for this scenario."}
      </p>
    </div>
  );
}

// ============================================================
// Scenario Card
// ============================================================

function ScenarioCard({
  scenario,
  onOpen,
  onJumpToOffense,
}: {
  scenario: DefenseScenario;
  onOpen: () => void;
  onJumpToOffense: (relatedOffenseId: string) => void;
}) {
  const color = priorityColor(scenario);
  const relatedIds = parseRelatedEventIds(
    scenario.relatedEventIds as unknown as string | string[] | null | undefined,
  );
  const shown = relatedIds.slice(0, 6);
  const more = Math.max(0, relatedIds.length - shown.length);
  const relatedOffense = scenario.relatedOffenseId ?? null;

  return (
    <div
      className="defense-surface relative flex flex-col overflow-hidden rounded-lg border bg-card/50 backdrop-blur-sm transition-all hover:shadow-lg"
      style={{ borderColor: `color-mix(in oklch, ${color} 35%, transparent)` }}
    >
      {/* Priority accent bar */}
      <div
        className="absolute left-0 top-0 h-full w-1"
        style={{ backgroundColor: color }}
        aria-hidden
      />

      {/* Header */}
      <div className="px-3.5 pt-3 pl-4">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={scenario.priority} size="sm" label={scenario.priority.toUpperCase()} />
          <StatusDot
            status={scenario.status as ScenarioStatus}
            label={scenario.status.toUpperCase()}
            className="text-[9px]"
          />
          {relatedOffense && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onJumpToOffense(relatedOffense);
              }}
              title={`Switch to Offense view and open ${relatedOffense}`}
              className="ml-auto inline-flex items-center gap-1 rounded-sm border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 px-1.5 py-0.5 font-mono-data text-[9px] font-semibold uppercase tracking-wider text-[color:var(--soc-critical)] transition-colors hover:bg-[color:var(--soc-critical)]/20"
            >
              <Link2 className="h-3 w-3" />
              {relatedOffense}
            </button>
          )}
        </div>
        <h4
          className="mt-1.5 truncate font-mono-data text-sm font-bold leading-tight text-foreground"
          title={scenario.title}
        >
          {scenario.title}
        </h4>
        <div className="mt-0.5 truncate font-mono-data text-[9px] text-muted-foreground">
          {scenario.scenarioId} · {scenario.category}
        </div>
      </div>

      {/* Meta grid */}
      <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 px-3.5 pl-4">
        <MetaField
          label="Affected Service"
          value={scenario.affectedService ?? "—"}
          icon={Server}
        />
        <MetaField
          label="Related Activity"
          value={categoryShortLabel(scenario.category)}
          icon={Crosshair}
        />
      </div>

      {/* Four guidance panels: DETECT / MONITOR / PREVENT / RESPOND */}
      <div className="mt-3 grid grid-cols-1 gap-2 px-3.5 pl-4">
        <GuidanceBlock
          label="Detect"
          icon={Search}
          text={scenario.detect}
          accent="var(--soc-low)"
        />
        <GuidanceBlock
          label="Monitor"
          icon={Activity}
          text={scenario.monitor}
          accent="var(--soc-low)"
        />
        <GuidanceBlock
          label="Prevent"
          icon={Shield}
          text={scenario.prevent}
          accent="var(--soc-low)"
        />
        <GuidanceBlock
          label="Respond"
          icon={Siren}
          text={scenario.respond}
          accent="var(--soc-low)"
        />
      </div>

      {/* Recommended Action (highlighted) */}
      <div className="mt-3 px-3.5 pl-4">
        <div
          className="rounded-md border p-2.5"
          style={{
            borderColor: `color-mix(in oklch, var(--soc-success) 35%, transparent)`,
            backgroundColor: `color-mix(in oklch, var(--soc-success) 8%, transparent)`,
          }}
        >
          <div className="mb-1 flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-[color:var(--soc-success)]" />
            <SectionLabel>Recommended Action</SectionLabel>
          </div>
          <p className="text-[11px] leading-snug text-foreground/90">
            {scenario.recommendedAction && scenario.recommendedAction.trim().length > 0
              ? scenario.recommendedAction
              : "Review and apply the relevant prevent / respond guidance for this scenario."}
          </p>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-3 flex items-center gap-3 border-t border-border/40 bg-card/30 px-3.5 py-1.5 pl-4 font-mono-data text-[9px] text-muted-foreground">
        <span
          className="flex items-center gap-1 whitespace-nowrap"
          title={`First observed: ${formatDateTime(scenario.firstObserved)}`}
        >
          <Clock className="h-3 w-3" />
          {formatTime(scenario.firstObserved)}
        </span>
        <span className="text-muted-foreground/40">→</span>
        <span
          className="flex items-center gap-1 whitespace-nowrap"
          title={`Last observed: ${formatDateTime(scenario.lastObserved)}`}
        >
          <Clock className="h-3 w-3" />
          {formatTime(scenario.lastObserved)}
        </span>
        <span className="ml-auto whitespace-nowrap">
          EVTS {relatedIds.length}
        </span>
      </div>

      {/* Related event IDs */}
      {shown.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 border-t border-border/40 px-3.5 py-1.5 pl-4">
          <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
            Events:
          </span>
          {shown.map((id) => (
            <span
              key={id}
              className="rounded-sm border border-border/40 bg-muted/30 px-1 py-0.5 font-mono-data text-[9px] text-muted-foreground"
              title={id}
            >
              {id}
            </span>
          ))}
          {more > 0 && (
            <span className="font-mono-data text-[9px] text-muted-foreground/70">
              +{more} more
            </span>
          )}
        </div>
      )}

      {/* View details */}
      <div className="mt-auto border-t border-border/40 px-3.5 py-2 pl-4">
        <Button
          size="sm"
          variant="ghost"
          className="h-7 w-full gap-1 px-2 text-[11px] text-muted-foreground hover:text-[color:var(--soc-low)]"
          onClick={onOpen}
        >
          <Eye className="h-3 w-3" />
          View Details
          <ChevronRight className="ml-auto h-3 w-3" />
        </Button>
      </div>
    </div>
  );
}

// ============================================================
// Scenario Detail Dialog
// ============================================================

function ScenarioDetailContent({
  scenario,
  events,
  eventsLoading,
  sessionMode,
  onJumpToOffense,
}: {
  scenario: DefenseScenario;
  events: SecurityEvent[];
  eventsLoading: boolean;
  sessionMode: "live" | "historical";
  onJumpToOffense: (relatedOffenseId: string) => void;
}) {
  const color = priorityColor(scenario);
  const relatedIds = parseRelatedEventIds(
    scenario.relatedEventIds as unknown as string | string[] | null | undefined,
  );
  const relatedSet = useMemo(() => new Set(relatedIds), [relatedIds]);

  const relatedEvents = useMemo(() => {
    if (relatedSet.size === 0) return [];
    return events
      .filter((e) => relatedSet.has(e.eventId) || relatedSet.has(e.id))
      .slice()
      .sort(
        (a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
      );
  }, [events, relatedSet]);

  const relatedOffense = scenario.relatedOffenseId ?? null;

  return (
    <div className="flex flex-col gap-4">
      {/* Overview */}
      <div
        className="relative overflow-hidden rounded-lg border bg-card/40 p-3 pl-4"
        style={{ borderColor: `color-mix(in oklch, ${color} 35%, transparent)` }}
      >
        <div
          className="absolute left-0 top-0 h-full w-1"
          style={{ backgroundColor: color }}
          aria-hidden
        />
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge
            severity={scenario.priority}
            size="sm"
            label={`PRIORITY · ${scenario.priority.toUpperCase()}`}
          />
          <StatusDot
            status={scenario.status as ScenarioStatus}
            label={scenario.status.toUpperCase()}
            className="text-[9px]"
          />
          <span className="ml-auto font-mono-data text-[10px] text-muted-foreground">
            {scenario.scenarioId}
          </span>
        </div>
        <h3 className="mt-2 font-mono-data text-base font-bold leading-tight text-foreground">
          {scenario.title}
        </h3>
        <div className="mt-0.5 font-mono-data text-[10px] text-muted-foreground">
          Category: {scenario.category}
        </div>

        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <MetaField
            label="Affected Service"
            value={scenario.affectedService ?? "—"}
            icon={Server}
          />
          <MetaField
            label="Related Activity"
            value={categoryShortLabel(scenario.category)}
            icon={Crosshair}
          />
          <MetaField
            label="Related Offense"
            value={relatedOffense ?? "—"}
            icon={Link2}
          />
        </div>
      </div>

      {/* Affected Service */}
      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
          <SectionLabel>Affected Service</SectionLabel>
          <div className="mt-1 flex items-center gap-1.5 font-mono-data text-xs text-foreground/90">
            <Server className="h-3.5 w-3.5 text-muted-foreground" />
            {scenario.affectedService ?? "—"}
          </div>
        </div>
        <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
          <SectionLabel>Related Activity</SectionLabel>
          <div className="mt-1 flex items-center gap-1.5 font-mono-data text-xs text-foreground/90">
            <Crosshair className="h-3.5 w-3.5 text-muted-foreground" />
            {categoryShortLabel(scenario.category)}
          </div>
        </div>
      </section>

      {/* Detection */}
      <section>
        <SectionLabel>Detection</SectionLabel>
        <div className="mt-1.5">
          <GuidanceBlock
            label="Detect"
            icon={Search}
            text={scenario.detect}
            accent="var(--soc-low)"
          />
        </div>
      </section>

      {/* Monitoring */}
      <section>
        <SectionLabel>Monitoring</SectionLabel>
        <div className="mt-1.5">
          <GuidanceBlock
            label="Monitor"
            icon={Activity}
            text={scenario.monitor}
            accent="var(--soc-low)"
          />
        </div>
      </section>

      {/* Prevention */}
      <section>
        <SectionLabel>Prevention</SectionLabel>
        <div className="mt-1.5">
          <GuidanceBlock
            label="Prevent"
            icon={Shield}
            text={scenario.prevent}
            accent="var(--soc-low)"
          />
        </div>
      </section>

      {/* Response */}
      <section>
        <SectionLabel>Response</SectionLabel>
        <div className="mt-1.5">
          <GuidanceBlock
            label="Respond"
            icon={Siren}
            text={scenario.respond}
            accent="var(--soc-low)"
          />
        </div>
      </section>

      {/* Recommended Action (highlighted) */}
      <section
        className="rounded-md border p-3"
        style={{
          borderColor: `color-mix(in oklch, var(--soc-success) 35%, transparent)`,
          backgroundColor: `color-mix(in oklch, var(--soc-success) 8%, transparent)`,
        }}
      >
        <div className="mb-1 flex items-center gap-1.5">
          <CheckCircle2 className="h-4 w-4 text-[color:var(--soc-success)]" />
          <SectionLabel>Recommended Action</SectionLabel>
        </div>
        <p className="text-xs leading-relaxed text-foreground/90">
          {scenario.recommendedAction && scenario.recommendedAction.trim().length > 0
            ? scenario.recommendedAction
            : "Review and apply the relevant prevent / respond guidance for this scenario."}
        </p>
      </section>

      {/* Relationship to Offense */}
      {relatedOffense && (
        <section
          className="rounded-md border p-3"
          style={{
            borderColor: `color-mix(in oklch, var(--soc-critical) 30%, transparent)`,
            backgroundColor: `color-mix(in oklch, var(--soc-critical) 6%, transparent)`,
          }}
        >
          <div className="mb-1.5 flex items-center gap-1.5">
            <Swords className="h-3.5 w-3.5 text-[color:var(--soc-critical)]" />
            <SectionLabel>Relationship to Offense</SectionLabel>
          </div>
          <p className="text-[11px] leading-snug text-foreground/80">
            This defense addresses offense scenario{" "}
            <span className="font-mono-data font-bold text-[color:var(--soc-critical)]">
              {relatedOffense}
            </span>
            . Open the offense analysis to inspect the observed activity and
            potential attack pattern this defense is responding to.
          </p>
          <div className="mt-2">
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1.5 border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 text-[10px] uppercase tracking-wider text-[color:var(--soc-critical)] hover:bg-[color:var(--soc-critical)]/20 hover:text-[color:var(--soc-critical)]"
              onClick={() => onJumpToOffense(relatedOffense)}
            >
              <Swords className="h-3.5 w-3.5" />
              View Offense Scenario
              <ChevronRight className="h-3 w-3" />
            </Button>
          </div>
        </section>
      )}

      {/* Related events timeline */}
      <section>
        <div className="mb-1.5 flex items-center justify-between">
          <SectionLabel>Related Events Timeline</SectionLabel>
          <span className="font-mono-data text-[9px] text-muted-foreground">
            {relatedEvents.length} / {relatedIds.length} shown · {sessionMode}
          </span>
        </div>
        {eventsLoading ? (
          <div className="space-y-1.5">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : relatedEvents.length === 0 ? (
          <div className="flex items-center gap-2 rounded-md border border-border/40 bg-card/30 px-3 py-3 text-[11px] text-muted-foreground">
            <Activity className="h-3.5 w-3.5 opacity-50" />
            <span>
              No matching event records available
              {sessionMode === "live"
                ? " in the current live window. Older events may have aged out."
                : "."}
            </span>
          </div>
        ) : (
          <div className="soc-scrollbar max-h-64 overflow-y-auto rounded-md border border-border/40 bg-card/20">
            {relatedEvents.map((e, i) => (
              <div
                key={e.id}
                className="flex items-start gap-2 border-b border-border/20 px-2.5 py-1.5 last:border-b-0"
              >
                <div className="flex flex-col items-center pt-0.5">
                  <span
                    className="font-mono-data text-[9px] tabular-nums text-muted-foreground"
                    title={formatDateTime(e.timestamp)}
                  >
                    {formatTime(e.timestamp)}
                  </span>
                  {i < relatedEvents.length - 1 && (
                    <span
                      className="mt-0.5 h-3 w-px bg-border/60"
                      aria-hidden
                    />
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <SeverityBadge severity={e.severity} size="sm" />
                    <span className="truncate font-mono-data text-[10px] text-muted-foreground">
                      {e.eventId}
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-center gap-1 font-mono-data text-[10px] text-foreground/80">
                    <span className="truncate">{e.sourceIp ?? "?"}</span>
                    <ArrowDown className="h-3 w-3 rotate-[-90deg] text-muted-foreground/40" />
                    <span className="truncate">
                      {e.destIp ?? "?"}
                      {e.destPort ? `:${e.destPort}` : ""}
                    </span>
                    <span className="ml-1 rounded-sm border border-border/40 bg-muted/30 px-1 py-0.5 text-[9px] uppercase">
                      {e.protocol ?? "?"}
                    </span>
                  </div>
                  <div className="mt-0.5 text-[11px] leading-snug text-foreground/70">
                    <span className="font-mono-data text-[10px] text-muted-foreground">
                      [{e.eventType}]
                    </span>{" "}
                    {e.message}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Timeline summary */}
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
          <SectionLabel>First Observed</SectionLabel>
          <div className="mt-0.5 font-mono-data text-[11px] text-foreground/90">
            {formatDateTime(scenario.firstObserved)}
          </div>
        </div>
        <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
          <SectionLabel>Last Observed</SectionLabel>
          <div className="mt-0.5 font-mono-data text-[11px] text-foreground/90">
            {formatDateTime(scenario.lastObserved)}
          </div>
        </div>
        <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
          <SectionLabel>Duration</SectionLabel>
          <div className="mt-0.5 font-mono-data text-[11px] text-foreground/90">
            {durationLabel(scenario.firstObserved, scenario.lastObserved)}
          </div>
        </div>
      </section>
    </div>
  );
}

function ScenarioDetailDialog({
  scenario,
  open,
  onOpenChange,
  events,
  eventsLoading,
  sessionMode,
  onJumpToOffense,
}: {
  scenario: DefenseScenario | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  events: SecurityEvent[];
  eventsLoading: boolean;
  sessionMode: "live" | "historical";
  onJumpToOffense: (relatedOffenseId: string) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="defense-surface max-h-[90vh] max-w-3xl gap-0 overflow-y-auto p-0 sm:max-w-3xl">
        <DialogHeader className="border-b border-border/40 px-4 py-3 text-left">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <ShieldCheck className="h-4 w-4 text-[color:var(--soc-low)]" />
            Defensive Monitoring &amp; Response
          </DialogTitle>
          <DialogDescription className="text-[10px] uppercase tracking-wider text-muted-foreground">
            Monitoring, detection, prevention and response guidance derived
            from observed security activity.
          </DialogDescription>
        </DialogHeader>
        <div className="p-4">
          {scenario && (
            <ScenarioDetailContent
              scenario={scenario}
              events={events}
              eventsLoading={eventsLoading}
              sessionMode={sessionMode}
              onJumpToOffense={onJumpToOffense}
            />
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ============================================================
// Loading / Empty skeletons
// ============================================================

function ScenarioCardSkeleton() {
  return (
    <div className="defense-surface relative overflow-hidden rounded-lg border p-3 pl-4">
      <div className="absolute left-0 top-0 h-full w-1 bg-[color:var(--soc-low)]/40" />
      <div className="flex items-center gap-1.5">
        <Skeleton className="h-4 w-20" />
        <Skeleton className="h-3 w-12" />
      </div>
      <Skeleton className="mt-2 h-4 w-3/4" />
      <Skeleton className="mt-1 h-3 w-1/2" />
      <div className="mt-3 grid grid-cols-2 gap-2">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-full" />
      </div>
      <Skeleton className="mt-3 h-12 w-full" />
      <Skeleton className="mt-2 h-12 w-full" />
      <Skeleton className="mt-2 h-12 w-full" />
      <Skeleton className="mt-2 h-12 w-full" />
      <Skeleton className="mt-3 h-12 w-full" />
    </div>
  );
}

function NoSessionEmptyState() {
  const setView = useAppStore((s) => s.setView);
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 py-12 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full border border-[color:var(--soc-low)]/30 bg-[color:var(--soc-low)]/10">
        <Shield className="h-8 w-8 text-[color:var(--soc-low)]" />
      </div>
      <div>
        <h3 className="font-mono-data text-base font-bold uppercase tracking-wider text-foreground">
          No Active Session
        </h3>
        <p className="mt-1.5 max-w-md text-sm text-muted-foreground">
          Start monitoring or open a historical session to view defensive
          guidance. Defense scenarios are derived from observed activity and
          paired with potential offense scenarios.
        </p>
      </div>
      <Button
        size="sm"
        className="gap-1.5"
        onClick={() => setView("monitor")}
      >
        <Activity className="h-4 w-4" />
        Go to Live Monitor
      </Button>
    </div>
  );
}

function NoScenariosEmptyState({ mode }: { mode: "live" | "historical" }) {
  return (
    <div className="flex min-h-[280px] flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border/50 bg-card/30 px-6 py-12 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-full border border-border/40 bg-muted/30">
        <ShieldAlert className="h-7 w-7 text-muted-foreground/60" />
      </div>
      <div>
        <h4 className="font-mono-data text-sm font-semibold uppercase tracking-wider text-foreground/80">
          No Defensive Scenarios Yet
        </h4>
        <p className="mx-auto mt-1.5 max-w-md text-xs text-muted-foreground">
          {mode === "live"
            ? "Defense guidance appears as detection rules observe patterns. Live telemetry is being collected and correlated."
            : "This historical session did not trigger any defense scenarios."}
        </p>
      </div>
    </div>
  );
}

// ============================================================
// Summary row
// ============================================================

function SummaryRow({
  scenarios,
  offenseProxyCount,
}: {
  scenarios: DefenseScenario[];
  offenseProxyCount: number;
}) {
  const counts = useMemo(() => {
    const c = {
      activeControls: scenarios.length,
      highPriority: 0,
      activeMonitoring: 0,
    };
    for (const s of scenarios) {
      if (s.priority === "high" || s.priority === "critical") c.highPriority++;
      if (s.status === "active") c.activeMonitoring++;
    }
    return c;
  }, [scenarios]);

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <KpiCard
        label="Active Controls"
        value={counts.activeControls}
        icon={Shield}
        accent="low"
      />
      <KpiCard
        label="Detection Rules Triggered"
        value={offenseProxyCount}
        icon={Radar}
        accent="info"
        sublabel="Offense patterns observed"
      />
      <KpiCard
        label="High Priority Responses"
        value={counts.highPriority}
        icon={AlertTriangle}
        accent="high"
      />
      <KpiCard
        label="Monitoring Recommendations"
        value={counts.activeMonitoring}
        icon={Activity}
        accent="low"
        live={counts.activeMonitoring > 0}
      />
    </div>
  );
}

// ============================================================
// Main View
// ============================================================

export function DefenseView() {
  const sessionId = useAppStore((s) => s.sessionId);
  const historicalSession = useAppStore((s) => s.historicalSession);
  const liveScenarios = useAppStore((s) => s.defenseScenarios);
  const liveOffenseScenarios = useAppStore((s) => s.offenseScenarios);
  const setDefenseScenarios = useAppStore((s) => s.setDefenseScenarios);
  const setView = useAppStore((s) => s.setView);
  const setSelectedOffense = useAppStore((s) => s.setSelectedOffense);

  // Determine mode
  const mode: "live" | "historical" | "empty" =
    historicalSession != null
      ? "historical"
      : sessionId != null
        ? "live"
        : "empty";

  // Historical state
  const [histScenarios, setHistScenarios] = useState<DefenseScenario[]>([]);
  const [histOffenseCount, setHistOffenseCount] = useState(0);
  const [histEvents, setHistEvents] = useState<SecurityEvent[]>([]);
  const [histLoading, setHistLoading] = useState(false);
  const [histError, setHistError] = useState<string | null>(null);

  // Live seed state
  const [liveSeeding, setLiveSeeding] = useState(false);

  // Dialog state
  const [dialogScenarioId, setDialogScenarioId] = useState<string | null>(null);
  const [dialogEvents, setDialogEvents] = useState<SecurityEvent[]>([]);
  const [dialogEventsLoading, setDialogEventsLoading] = useState(false);

  // ---------------- Historical fetch ----------------
  useEffect(() => {
    if (mode !== "historical" || !historicalSession) return;
    let cancelled = false;
    const run = async () => {
      setHistLoading(true);
      setHistError(null);
      try {
        const res = await api.getHistoryDetail(historicalSession.id);
        if (cancelled) return;
        setHistScenarios((res.defenseScenarios ?? []).map(normalizeScenario));
        setHistOffenseCount(res.offenseScenarios?.length ?? 0);
        setHistEvents(res.events ?? []);
      } catch (e: unknown) {
        if (cancelled) return;
        const msg =
          e instanceof Error ? e.message : "Failed to load historical session.";
        setHistError(msg);
        toast.error(msg);
      } finally {
        if (!cancelled) setHistLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [mode, historicalSession]);

  // ---------------- Live seed fetch ----------------
  useEffect(() => {
    if (mode !== "live" || !sessionId) return;
    let cancelled = false;
    const run = async () => {
      setLiveSeeding(true);
      try {
        const res = await api.getScenarios(sessionId);
        if (cancelled) return;
        const defense = (res.defense ?? []).map(normalizeScenario);
        // Replace the live scenario list with the authoritative snapshot.
        // Any WS updates that arrive afterward will upsert on top.
        setDefenseScenarios(defense);
      } catch (e: unknown) {
        if (cancelled) return;
        // Silent — store may already have streamed scenarios via WS.
        console.warn("[DefenseView] failed to seed scenarios:", e);
      } finally {
        if (!cancelled) setLiveSeeding(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [mode, sessionId, setDefenseScenarios]);

  // ---------------- Dialog events fetch (live mode only) ----------------
  const dialogScenario = useMemo<DefenseScenario | null>(() => {
    if (!dialogScenarioId) return null;
    const pool = mode === "historical" ? histScenarios : liveScenarios;
    return (
      pool.find((s) => s.scenarioId === dialogScenarioId) ??
      pool.find((s) => s.id === dialogScenarioId) ??
      null
    );
  }, [dialogScenarioId, mode, histScenarios, liveScenarios]);

  useEffect(() => {
    if (!dialogScenarioId || mode !== "live" || !sessionId) return;
    let cancelled = false;
    const run = async () => {
      setDialogEventsLoading(true);
      setDialogEvents([]);
      try {
        const res = await api.getEvents(sessionId, 500);
        if (cancelled) return;
        setDialogEvents(res.events ?? []);
      } catch (e: unknown) {
        if (cancelled) return;
        console.warn("[DefenseView] failed to load events for dialog:", e);
      } finally {
        if (!cancelled) setDialogEventsLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [dialogScenarioId, mode, sessionId]);

  // ---------------- Active scenarios (sorted) ----------------
  const scenarios = useMemo<DefenseScenario[]>(() => {
    const raw = mode === "historical" ? histScenarios : liveScenarios;
    return sortScenarios(raw.map(normalizeScenario));
  }, [mode, histScenarios, liveScenarios]);

  const offenseProxyCount =
    mode === "historical" ? histOffenseCount : liveOffenseScenarios.length;

  const dialogOpen = !!dialogScenarioId;
  const dialogEventsForMode: SecurityEvent[] =
    mode === "historical" ? histEvents : dialogEvents;

  // ---------------- Cross-view jump: Defense → Offense ----------------
  const jumpToOffense = (relatedOffenseId: string) => {
    // Close this dialog first (if it was open), then hand off to Offense view.
    setDialogScenarioId(null);
    setSelectedOffense(relatedOffenseId);
    setView("offense");
  };

  // ---------------- Empty mode ----------------
  if (mode === "empty") {
    return (
      <div className="flex h-full flex-col overflow-hidden">
        <DefenseHeader mode="empty" subtitle="" />
        <div className="flex-1 overflow-y-auto">
          <NoSessionEmptyState />
        </div>
      </div>
    );
  }

  const sessionMode: "live" | "historical" = mode;
  const subtitle =
    mode === "live"
      ? `Live session · ${scenarios.length} defense scenario${scenarios.length === 1 ? "" : "s"} active`
      : historicalSession
        ? `Historical session · ${historicalSession.targetAddress} · ${historicalSession.startedAt ? new Date(historicalSession.startedAt).toLocaleString() : ""}`
        : "";

  const isLoading =
    (mode === "historical" && histLoading) ||
    (mode === "live" && liveSeeding && scenarios.length === 0);

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <DefenseHeader mode={sessionMode} subtitle={subtitle} />

      {/* Summary row */}
      <div className="shrink-0 border-b border-border/40 px-3 py-3">
        <SummaryRow
          scenarios={scenarios}
          offenseProxyCount={offenseProxyCount}
        />
      </div>

      {/* Scrollable body */}
      <div className="soc-scrollbar min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
        <div className="flex flex-col gap-3 p-3">
          {/* Section header */}
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <h3 className="font-mono-data text-xs font-semibold uppercase tracking-wider text-foreground">
                Defensive Monitoring / Response Scenarios
              </h3>
              <span className="rounded-sm border border-[color:var(--soc-low)]/40 bg-[color:var(--soc-low)]/10 px-1.5 py-0.5 font-mono-data text-[10px] font-bold text-[color:var(--soc-low)]">
                {scenarios.length}
              </span>
            </div>
            {mode === "historical" && histError && (
              <span className="font-mono-data text-[10px] text-[color:var(--soc-critical)]">
                ERROR: {histError}
              </span>
            )}
          </div>

          {/* Cards grid */}
          {isLoading ? (
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
              {[0, 1, 2, 3].map((i) => (
                <ScenarioCardSkeleton key={i} />
              ))}
            </div>
          ) : scenarios.length === 0 ? (
            <NoScenariosEmptyState mode={sessionMode} />
          ) : (
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
              {scenarios.map((s) => (
                <ScenarioCard
                  key={s.scenarioId}
                  scenario={s}
                  onOpen={() => setDialogScenarioId(s.scenarioId)}
                  onJumpToOffense={jumpToOffense}
                />
              ))}
            </div>
          )}

          {/* Footer disclaimer */}
          <div className="mt-1 rounded-md border border-[color:var(--soc-low)]/30 bg-[color:var(--soc-low)]/5 px-3 py-2">
            <p className="text-[10px] leading-snug text-muted-foreground">
              <span className="font-mono-data font-semibold uppercase tracking-wider text-[color:var(--soc-low)]">
                Defensive Guidance:
              </span>{" "}
              Each scenario provides monitoring, detection, prevention and
              response recommendations derived from observed telemetry and
              paired offense scenarios. Apply recommendations within your
              authorized operational scope.
            </p>
          </div>
        </div>
      </div>

      {/* Detail dialog */}
      <ScenarioDetailDialog
        scenario={dialogScenario}
        open={dialogOpen}
        onOpenChange={(o) => {
          if (!o) setDialogScenarioId(null);
        }}
        events={dialogEventsForMode}
        eventsLoading={mode === "live" && dialogEventsLoading}
        sessionMode={sessionMode}
        onJumpToOffense={jumpToOffense}
      />
    </div>
  );
}

// ============================================================
// Header
// ============================================================

function DefenseHeader({
  mode,
  subtitle,
}: {
  mode: "live" | "historical" | "empty";
  subtitle: string;
}) {
  return (
    <div className="shrink-0 border-b border-[color:var(--soc-low)]/30 bg-[color:var(--soc-low)]/5 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-md border border-[color:var(--soc-low)]/40 bg-[color:var(--soc-low)]/15">
            <Shield className="h-4 w-4 text-[color:var(--soc-low)]" />
          </div>
          <div className="min-w-0">
            <h2 className="font-mono-data text-sm font-bold uppercase tracking-wider text-foreground">
              Defense
            </h2>
            <p className="truncate text-[10px] text-muted-foreground">
              {subtitle ||
                "Monitoring, detection, prevention and response guidance derived from observed security activity."}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {mode === "live" && (
            <span className="flex items-center gap-1.5 rounded-sm border border-[color:var(--soc-success)]/40 bg-[color:var(--soc-success)]/10 px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider text-[color:var(--soc-success)]">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-[color:var(--soc-success)] live-pulse" />
              Live
            </span>
          )}
          {mode === "historical" && (
            <span className="flex items-center gap-1.5 rounded-sm border border-[color:var(--soc-info)]/40 bg-[color:var(--soc-info)]/10 px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider text-[color:var(--soc-info)]">
              Historical
            </span>
          )}
          <AuthWarning variant="inline" className="hidden sm:flex" />
        </div>
      </div>
    </div>
  );
}
