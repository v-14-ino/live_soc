"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Swords,
  Radar,
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  ChevronRight,
  ArrowDown,
  Clock,
  Crosshair,
  Server,
  Target,
  Eye,
  ShieldAlert,
  Activity,
  ScanLine,
  ListTree,
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
import { cn } from "@/lib/utils";
import { severityColor, SEVERITY_ORDER } from "@/lib/constants";
import type {
  Severity,
  OffenseScenario,
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

// attackPath: live/historical both store as "A -> B -> C" string; tolerate arrays.
function parseAttackPath(ap: string | string[] | null | undefined): string[] {
  if (ap == null) return [];
  if (Array.isArray(ap)) return ap.map(String).filter(Boolean);
  const s = String(ap).trim();
  if (!s) return [];
  if (s.includes("->")) return s.split("->").map((x) => x.trim()).filter(Boolean);
  if (s.includes("\n")) return s.split("\n").map((x) => x.trim()).filter(Boolean);
  if (s.includes(",")) return s.split(",").map((x) => x.trim()).filter(Boolean);
  return [s];
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
function normalizeScenario(raw: OffenseScenario): OffenseScenario {
  return {
    ...raw,
    attackPath: raw.attackPath ?? null,
    relatedEventIds: parseRelatedEventIds(
      raw.relatedEventIds as unknown as string | string[] | null | undefined,
    ),
  };
}

const MITRE_MAP: Record<string, { name: string; description: string }> = {
  T1046: {
    name: "Network Service Discovery",
    description:
      "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods include port scans and tools such as nmap.",
  },
  T1110: {
    name: "Brute Force",
    description:
      "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or obtained password databases are incomplete. Success is NOT confirmed without verified evidence.",
  },
  T1190: {
    name: "Exploit Public-Facing Application",
    description:
      "Adversaries may attempt to exploit a weakness in an internet-facing host or system to initiate execution or compromise. Common targets include web servers, mail servers, and DNS servers.",
  },
  T1595: {
    name: "Active Scanning",
    description:
      "Adversaries may execute active reconnaissance scans to gather information about hosts, services, and vulnerabilities. May include port scanning, vulnerability scanning, and wordlist scanning.",
  },
  T1082: {
    name: "System Information Discovery",
    description:
      "Adversaries may attempt to gather information about the operating system and hardware configuration of a target. Information could include details such as OS version, hostname, and architecture.",
  },
  T1592: {
    name: "Gather Victim Host Information",
    description:
      "Adversaries may gather information about the victim's hosts that can be used during targeting. Information may include hostnames, IP addresses, and system configurations.",
  },
};

function severityRank(s: Severity): number {
  return SEVERITY_ORDER[s] ?? 0;
}

function sortScenarios(list: OffenseScenario[]): OffenseScenario[] {
  return list.slice().sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    const ta = new Date(a.lastObserved).getTime() || 0;
    const tb = new Date(b.lastObserved).getTime() || 0;
    return tb - ta;
  });
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

function ConfidenceBar({ value, color }: { value: number; color: string }) {
  const v = Math.max(0, Math.min(100, value));
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted/40">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${v}%`, backgroundColor: color }}
        />
      </div>
      <span
        className="font-mono-data text-[10px] font-bold tabular-nums"
        style={{ color }}
      >
        {v}%
      </span>
    </div>
  );
}

function AttackPathFlow({ steps, color }: { steps: string[]; color: string }) {
  if (!steps || steps.length === 0) {
    return (
      <span className="font-mono-data text-[10px] text-muted-foreground">
        No attack path data.
      </span>
    );
  }
  return (
    <div className="flex flex-col">
      {steps.map((step, i) => (
        <div key={i} className="flex flex-col">
          <div className="flex items-center gap-1.5">
            <span
              className="flex h-4 w-4 shrink-0 items-center justify-center rounded-sm font-mono-data text-[8px] font-bold"
              style={{
                color,
                backgroundColor: `color-mix(in oklch, ${color} 15%, transparent)`,
                border: `1px solid color-mix(in oklch, ${color} 35%, transparent)`,
              }}
            >
              {i + 1}
            </span>
            <span className="text-[11px] text-foreground/90">{step}</span>
          </div>
          {i < steps.length - 1 && (
            <div className="ml-1.5 flex h-3 items-center">
              <ArrowDown className="h-3 w-3 text-muted-foreground/50" />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ============================================================
// Scenario Card
// ============================================================

function ScenarioCard({
  scenario,
  onOpen,
}: {
  scenario: OffenseScenario;
  onOpen: () => void;
}) {
  const sev = scenario.severity;
  const color = severityColor(sev);
  const steps = parseAttackPath(scenario.attackPath);
  const relatedIds = parseRelatedEventIds(
    scenario.relatedEventIds as unknown as string | string[] | null | undefined,
  );
  const shown = relatedIds.slice(0, 6);
  const more = Math.max(0, relatedIds.length - shown.length);

  return (
    <div
      className="offense-surface relative flex flex-col overflow-hidden rounded-lg border bg-card/50 backdrop-blur-sm transition-all hover:shadow-lg"
      style={{ borderColor: `color-mix(in oklch, ${color} 35%, transparent)` }}
    >
      {/* Severity accent bar */}
      <div
        className="absolute left-0 top-0 h-full w-1"
        style={{ backgroundColor: color }}
        aria-hidden
      />

      {/* Header */}
      <div className="px-3.5 pt-3 pl-4">
        <div className="flex items-center gap-1.5">
          <SeverityBadge severity={sev} size="sm" />
          <StatusDot
            status={scenario.status as ScenarioStatus}
            label={scenario.status.toUpperCase()}
            className="text-[9px]"
          />
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

      {/* Confidence */}
      <div className="mt-2.5 px-3.5 pl-4">
        <div className="mb-1 flex items-center justify-between">
          <SectionLabel>Confidence</SectionLabel>
          <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
            Potential
          </span>
        </div>
        <ConfidenceBar value={scenario.confidence} color={color} />
      </div>

      {/* Meta grid */}
      <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 px-3.5 pl-4">
        <MetaField
          label="Affected Target"
          value={scenario.affectedTarget ?? "—"}
          icon={Target}
        />
        <MetaField
          label="Affected Service"
          value={scenario.affectedService ?? "—"}
          icon={Server}
        />
        <div className="col-span-2">
          <MetaField
            label="Potential Technique"
            value={
              scenario.technique ? (
                <span className="flex items-center gap-1.5">
                  <span className="truncate">{scenario.technique}</span>
                  {scenario.techniqueMitre && (
                    <span
                      className="shrink-0 rounded-sm border px-1 py-0.5 font-mono-data text-[9px] font-bold"
                      style={{
                        color,
                        borderColor: `color-mix(in oklch, ${color} 40%, transparent)`,
                        backgroundColor: `color-mix(in oklch, ${color} 12%, transparent)`,
                      }}
                      title={MITRE_MAP[scenario.techniqueMitre]?.name ?? scenario.techniqueMitre}
                    >
                      {scenario.techniqueMitre}
                    </span>
                  )}
                </span>
              ) : (
                "—"
              )
            }
            icon={Crosshair}
          />
        </div>
      </div>

      {/* Observed evidence */}
      <div className="mt-3 px-3.5 pl-4">
        <SectionLabel>Observed Evidence</SectionLabel>
        <p className="mt-0.5 text-[11px] leading-snug text-foreground/80">
          {scenario.potentialImpact ??
            "Observed activity consistent with the scenario pattern. Success is NOT confirmed without verified evidence."}
        </p>
      </div>

      {/* Potential attack path */}
      <div className="mt-3 px-3.5 pl-4">
        <SectionLabel>Potential Attack Path</SectionLabel>
        <div className="mt-1.5">
          <AttackPathFlow steps={steps} color={color} />
        </div>
      </div>

      {/* Possible impact */}
      <div className="mt-3 px-3.5 pl-4">
        <SectionLabel>Possible Impact</SectionLabel>
        <p className="mt-0.5 text-[11px] leading-snug text-foreground/70">
          {scenario.potentialImpact ?? "Possible impact assessment pending."}
        </p>
      </div>

      {/* Footer */}
      <div className="mt-3 flex items-center gap-3 border-t border-border/40 bg-card/30 px-3.5 py-1.5 pl-4 font-mono-data text-[9px] text-muted-foreground">
        <span className="flex items-center gap-1 whitespace-nowrap" title={`First observed: ${formatDateTime(scenario.firstObserved)}`}>
          <Clock className="h-3 w-3" />
          {formatTime(scenario.firstObserved)}
        </span>
        <span className="text-muted-foreground/40">→</span>
        <span className="flex items-center gap-1 whitespace-nowrap" title={`Last observed: ${formatDateTime(scenario.lastObserved)}`}>
          <Clock className="h-3 w-3" />
          {formatTime(scenario.lastObserved)}
        </span>
        <span className="ml-auto whitespace-nowrap">EVTS {scenario.eventCount}</span>
        <span className="whitespace-nowrap">SRC {scenario.sourceCount}</span>
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
          className="h-7 w-full gap-1 px-2 text-[11px] text-muted-foreground hover:text-[color:var(--soc-critical)]"
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
}: {
  scenario: OffenseScenario;
  events: SecurityEvent[];
  eventsLoading: boolean;
  sessionMode: "live" | "historical";
}) {
  const sev = scenario.severity;
  const color = severityColor(sev);
  const steps = parseAttackPath(scenario.attackPath);
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

  const mitre = scenario.techniqueMitre
    ? MITRE_MAP[scenario.techniqueMitre]
    : null;

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
          <SeverityBadge severity={sev} size="sm" />
          <StatusDot
            status={scenario.status as ScenarioStatus}
            label={scenario.status.toUpperCase()}
            className="text-[9px]"
          />
          {mitre && (
            <span
              className="rounded-sm border px-1.5 py-0.5 font-mono-data text-[10px] font-bold"
              style={{
                color,
                borderColor: `color-mix(in oklch, ${color} 40%, transparent)`,
                backgroundColor: `color-mix(in oklch, ${color} 12%, transparent)`,
              }}
            >
              {scenario.techniqueMitre}
            </span>
          )}
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

        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div>
            <SectionLabel>Confidence</SectionLabel>
            <div className="mt-1">
              <ConfidenceBar value={scenario.confidence} color={color} />
            </div>
          </div>
          <MetaField
            label="Affected Target"
            value={scenario.affectedTarget ?? "—"}
            icon={Target}
          />
          <MetaField
            label="Affected Service"
            value={scenario.affectedService ?? "—"}
            icon={Server}
          />
          <MetaField
            label="Potential Technique"
            value={scenario.technique ?? "—"}
            icon={Crosshair}
          />
        </div>
      </div>

      {/* Observed evidence */}
      <section>
        <SectionLabel>Observed Evidence</SectionLabel>
        <p className="mt-1 text-xs leading-relaxed text-foreground/80">
          {scenario.potentialImpact ??
            "Observed activity consistent with the scenario pattern. Success is NOT confirmed without verified evidence."}
        </p>
      </section>

      {/* Affected service */}
      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
          <SectionLabel>Affected Target</SectionLabel>
          <div className="mt-1 flex items-center gap-1.5 font-mono-data text-xs text-foreground/90">
            <Target className="h-3.5 w-3.5 text-muted-foreground" />
            {scenario.affectedTarget ?? "—"}
          </div>
        </div>
        <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
          <SectionLabel>Affected Service</SectionLabel>
          <div className="mt-1 flex items-center gap-1.5 font-mono-data text-xs text-foreground/90">
            <Server className="h-3.5 w-3.5 text-muted-foreground" />
            {scenario.affectedService ?? "—"}
          </div>
        </div>
      </section>

      {/* Observed events timeline */}
      <section>
        <div className="mb-1.5 flex items-center justify-between">
          <SectionLabel>Observed Events Timeline</SectionLabel>
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
                    <span className="mt-0.5 h-3 w-px bg-border/60" aria-hidden />
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

      {/* Potential attack path */}
      <section>
        <SectionLabel>Potential Attack Path</SectionLabel>
        <div className="mt-1.5 rounded-md border border-border/40 bg-card/30 p-2.5">
          <AttackPathFlow steps={steps} color={color} />
        </div>
      </section>

      {/* Possible impact */}
      <section>
        <SectionLabel>Possible Impact</SectionLabel>
        <p className="mt-1 text-xs leading-relaxed text-foreground/80">
          {scenario.potentialImpact ?? "Possible impact assessment pending."}
        </p>
      </section>

      {/* MITRE ATT&CK */}
      {scenario.techniqueMitre && (
        <section>
          <SectionLabel>Related MITRE ATT&CK Technique</SectionLabel>
          <div className="mt-1.5 flex flex-col gap-1.5 rounded-md border border-border/40 bg-card/30 p-2.5">
            <div className="flex items-center gap-2">
              <span
                className="rounded-sm border px-1.5 py-0.5 font-mono-data text-[10px] font-bold"
                style={{
                  color,
                  borderColor: `color-mix(in oklch, ${color} 40%, transparent)`,
                  backgroundColor: `color-mix(in oklch, ${color} 12%, transparent)`,
                }}
              >
                {scenario.techniqueMitre}
              </span>
              <span className="text-xs font-semibold text-foreground/90">
                {mitre?.name ?? scenario.technique ?? "Unknown technique"}
              </span>
            </div>
            {mitre && (
              <p className="text-[11px] leading-snug text-muted-foreground">
                {mitre.description}
              </p>
            )}
            <p className="text-[10px] italic text-muted-foreground/70">
              Potential technique attribution based on observed pattern — not a
              confirmed adversary action.
            </p>
          </div>
        </section>
      )}

      {/* Timeline summary */}
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
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
        <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
          <SectionLabel>Events / Sources</SectionLabel>
          <div className="mt-0.5 font-mono-data text-[11px] text-foreground/90">
            {scenario.eventCount} / {scenario.sourceCount}
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
}: {
  scenario: OffenseScenario | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  events: SecurityEvent[];
  eventsLoading: boolean;
  sessionMode: "live" | "historical";
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="offense-surface max-h-[90vh] max-w-3xl gap-0 overflow-y-auto p-0 sm:max-w-3xl">
        <DialogHeader className="border-b border-border/40 px-4 py-3 text-left">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <ShieldAlert className="h-4 w-4 text-[color:var(--soc-critical)]" />
            Potential Attack Scenario
          </DialogTitle>
          <DialogDescription className="text-[10px] uppercase tracking-wider text-muted-foreground">
            Defensive analysis — observed activity, not a confirmed attack.
          </DialogDescription>
        </DialogHeader>
        <div className="p-4">
          {scenario && (
            <ScenarioDetailContent
              scenario={scenario}
              events={events}
              eventsLoading={eventsLoading}
              sessionMode={sessionMode}
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
    <div className="offense-surface relative overflow-hidden rounded-lg border p-3 pl-4">
      <div className="absolute left-0 top-0 h-full w-1 bg-[color:var(--soc-critical)]/40" />
      <div className="flex items-center gap-1.5">
        <Skeleton className="h-4 w-16" />
        <Skeleton className="h-3 w-12" />
      </div>
      <Skeleton className="mt-2 h-4 w-3/4" />
      <Skeleton className="mt-1 h-3 w-1/2" />
      <Skeleton className="mt-3 h-1.5 w-full" />
      <div className="mt-3 grid grid-cols-2 gap-2">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-full" />
      </div>
      <Skeleton className="mt-3 h-10 w-full" />
      <Skeleton className="mt-3 h-16 w-full" />
      <Skeleton className="mt-3 h-6 w-full" />
    </div>
  );
}

function NoSessionEmptyState() {
  const setView = useAppStore((s) => s.setView);
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 py-12 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full border border-[color:var(--soc-critical)]/30 bg-[color:var(--soc-critical)]/10">
        <Radar className="h-8 w-8 text-[color:var(--soc-critical)]" />
      </div>
      <div>
        <h3 className="font-mono-data text-base font-bold uppercase tracking-wider text-foreground">
          No Active Session
        </h3>
        <p className="mt-1.5 max-w-md text-sm text-muted-foreground">
          Start monitoring or open a historical session to view offense analysis.
          Potential attack scenarios are derived from observed activity, exposed
          services and detected security patterns.
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
        <ScanLine className="h-7 w-7 text-muted-foreground/60" />
      </div>
      <div>
        <h4 className="font-mono-data text-sm font-semibold uppercase tracking-wider text-foreground/80">
          No Potential Attack Scenarios Yet
        </h4>
        <p className="mx-auto mt-1.5 max-w-md text-xs text-muted-foreground">
          {mode === "live"
            ? "Scenarios appear as detection rules observe suspicious patterns. Live telemetry is being collected and correlated."
            : "This historical session did not trigger any offense scenarios."}
        </p>
      </div>
    </div>
  );
}

// ============================================================
// Summary row
// ============================================================

function SummaryRow({ scenarios }: { scenarios: OffenseScenario[] }) {
  const counts = useMemo(() => {
    const c = { total: scenarios.length, critical: 0, high: 0, mediumLow: 0 };
    for (const s of scenarios) {
      if (s.severity === "critical") c.critical++;
      else if (s.severity === "high") c.high++;
      else if (s.severity === "medium" || s.severity === "low") c.mediumLow++;
    }
    return c;
  }, [scenarios]);

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <KpiCard
        label="Total Scenarios"
        value={counts.total}
        icon={ListTree}
        accent="critical"
      />
      <KpiCard
        label="Critical"
        value={counts.critical}
        icon={AlertOctagon}
        accent="critical"
      />
      <KpiCard
        label="High"
        value={counts.high}
        icon={AlertTriangle}
        accent="high"
      />
      <KpiCard
        label="Medium / Low"
        value={counts.mediumLow}
        icon={AlertCircle}
        accent="medium"
      />
    </div>
  );
}

// ============================================================
// Main View
// ============================================================

export function OffenseView() {
  const sessionId = useAppStore((s) => s.sessionId);
  const historicalSession = useAppStore((s) => s.historicalSession);
  const liveScenarios = useAppStore((s) => s.offenseScenarios);
  const setOffenseScenarios = useAppStore((s) => s.setOffenseScenarios);
  // Cross-view link target: another view (e.g. Defense) may set this to a
  // scenarioId to request that the Offense view auto-open that scenario's
  // detail dialog. We sync it into our local dialogScenarioId state below.
  const selectedOffenseId = useAppStore((s) => s.selectedOffenseId);
  const setSelectedOffense = useAppStore((s) => s.setSelectedOffense);

  // Determine mode
  const mode: "live" | "historical" | "empty" =
    historicalSession != null
      ? "historical"
      : sessionId != null
        ? "live"
        : "empty";

  // Historical state
  const [histScenarios, setHistScenarios] = useState<OffenseScenario[]>([]);
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
        setHistScenarios((res.offenseScenarios ?? []).map(normalizeScenario));
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
        const offense = (res.offense ?? []).map(normalizeScenario);
        // Replace the live scenario list with the authoritative snapshot.
        // Any WS updates that arrive afterward will upsert on top.
        setOffenseScenarios(offense);
      } catch (e: unknown) {
        if (cancelled) return;
        // Silent — store may already have streamed scenarios via WS.
        console.warn("[OffenseView] failed to seed scenarios:", e);
      } finally {
        if (!cancelled) setLiveSeeding(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [mode, sessionId, setOffenseScenarios]);

  // ---------------- Cross-view link: Defense → Offense ----------------
  // When another view sets `selectedOffenseId` to a scenarioId, mirror it
  // into our local dialogScenarioId so the detail dialog opens for that
  // scenario. Cleared when the dialog closes (see onOpenChange below).
  useEffect(() => {
    if (selectedOffenseId) {
      setDialogScenarioId(selectedOffenseId);
    }
  }, [selectedOffenseId]);

  // ---------------- Dialog events fetch (live mode only) ----------------
  const dialogScenario = useMemo<OffenseScenario | null>(() => {
    if (!dialogScenarioId) return null;
    const pool = mode === "historical" ? histScenarios : liveScenarios;
    return pool.find((s) => s.scenarioId === dialogScenarioId) ?? null;
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
        console.warn("[OffenseView] failed to load events for dialog:", e);
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
  const scenarios = useMemo<OffenseScenario[]>(() => {
    const raw = mode === "historical" ? histScenarios : liveScenarios;
    return sortScenarios(raw.map(normalizeScenario));
  }, [mode, histScenarios, liveScenarios]);

  const dialogOpen = !!dialogScenarioId;
  const dialogEventsForMode: SecurityEvent[] =
    mode === "historical" ? histEvents : dialogEvents;

  // ---------------- Empty mode ----------------
  if (mode === "empty") {
    return (
      <div className="flex h-full flex-col overflow-hidden">
        <OffenseHeader mode="empty" subtitle="" />
        <div className="flex-1 overflow-y-auto">
          <NoSessionEmptyState />
        </div>
      </div>
    );
  }

  const sessionMode: "live" | "historical" = mode;
  const subtitle =
    mode === "live"
      ? `Live session · ${scenarios.length} potential scenario${scenarios.length === 1 ? "" : "s"} under analysis`
      : historicalSession
        ? `Historical session · ${historicalSession.targetAddress} · ${historicalSession.startedAt ? new Date(historicalSession.startedAt).toLocaleString() : ""}`
        : "";

  const isLoading =
    (mode === "historical" && histLoading) ||
    (mode === "live" && liveSeeding && scenarios.length === 0);

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <OffenseHeader mode={sessionMode} subtitle={subtitle} />

      {/* Summary row */}
      <div className="shrink-0 border-b border-border/40 px-3 py-3">
        <SummaryRow scenarios={scenarios} />
      </div>

      {/* Scrollable body */}
      <div className="soc-scrollbar min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
        <div className="flex flex-col gap-3 p-3">
          {/* Section header */}
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <h3 className="font-mono-data text-xs font-semibold uppercase tracking-wider text-foreground">
                Potential Attack Scenarios
              </h3>
              <span className="rounded-sm border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 px-1.5 py-0.5 font-mono-data text-[10px] font-bold text-[color:var(--soc-critical)]">
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
                />
              ))}
            </div>
          )}

          {/* Footer disclaimer */}
          <div className="mt-1 rounded-md border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/5 px-3 py-2">
            <p className="text-[10px] leading-snug text-muted-foreground">
              <span className="font-mono-data font-semibold uppercase tracking-wider text-[color:var(--soc-medium)]">
                Defensive Analysis:
              </span>{" "}
              Scenarios represent potential attack patterns derived from observed
              telemetry and exposed services. They do NOT confirm a successful
              attack. Correlate with authorized scope and additional evidence
              before action.
            </p>
          </div>
        </div>
      </div>

      {/* Detail dialog */}
      <ScenarioDetailDialog
        scenario={dialogScenario}
        open={dialogOpen}
        onOpenChange={(o) => {
          if (!o) {
            setDialogScenarioId(null);
            // Clear cross-view link state so the dialog doesn't reopen.
            if (selectedOffenseId) setSelectedOffense(null);
          }
        }}
        events={dialogEventsForMode}
        eventsLoading={mode === "live" && dialogEventsLoading}
        sessionMode={sessionMode}
      />
    </div>
  );
}

// ============================================================
// Header
// ============================================================

function OffenseHeader({
  mode,
  subtitle,
}: {
  mode: "live" | "historical" | "empty";
  subtitle: string;
}) {
  return (
    <div className="shrink-0 border-b border-[color:var(--soc-critical)]/30 bg-[color:var(--soc-critical)]/5 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-md border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/15">
            <Swords className="h-4 w-4 text-[color:var(--soc-critical)]" />
          </div>
          <div className="min-w-0">
            <h2 className="font-mono-data text-sm font-bold uppercase tracking-wider text-foreground">
              Offense
            </h2>
            <p className="truncate text-[10px] text-muted-foreground">
              {subtitle ||
                "Potential attack scenarios derived from observed activity, exposed services and detected security patterns."}
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
