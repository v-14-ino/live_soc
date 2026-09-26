"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  ScrollText,
  RefreshCw,
  Search,
  ChevronLeft,
  ChevronRight,
  Eye,
  CheckCircle,
  RotateCcw,
  Activity,
  ShieldAlert,
  Swords,
  Shield,
  AlertTriangle,
  FileText,
  ArrowRight,
  ArrowDown,
  CheckCircle2,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { useAppStore } from "@/lib/store";
import { api, type HistoryDetailResponse, type HistoryListResponse } from "@/lib/api-client";
import { KpiCard } from "@/components/soc/kpi-card";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { StatusDot } from "@/components/soc/status-dot";
import { AuthWarning } from "@/components/soc/auth-warning";
import { ExportMenu } from "@/components/soc/export-menu";
import { TimelineScrubber } from "@/components/soc/timeline-scrubber";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { severityColor, SEVERITY_ORDER } from "@/lib/constants";
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
// Helpers
// ============================================================

function formatTime(ts: string | Date): string {
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "--:--:--";
    return d.toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return "--:--:--";
  }
}

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

function durationBetween(first: string | Date, last: string | Date | null | undefined): string {
  if (!last) return "—";
  try {
    const a = new Date(first).getTime();
    const b = new Date(last).getTime();
    if (!isFinite(a) || !isFinite(b)) return "—";
    const sec = Math.max(0, Math.round((b - a) / 1000));
    return durationLabel(sec);
  } catch {
    return "—";
  }
}

// The history API returns raw Prisma rows where the target is nested.
// Normalize to the flat MonitoringSessionInfo shape the rest of the UI uses.
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

function normalizeAssessment(raw: unknown): AssessmentResult | null {
  if (!raw) return null;
  const r = raw as Record<string, unknown>;
  const ports = Array.isArray(r.ports) ? r.ports : [];
  const services = Array.isArray(r.services) ? r.services : [];
  // Build a serviceId → name lookup so historical port rows (which store a
  // foreign key in `serviceId`) can be resolved to a human-readable name.
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

function parseRelatedEventIds(ids: string | string[] | null | undefined): string[] {
  if (ids == null) return [];
  if (Array.isArray(ids)) return ids.map(String).filter(Boolean);
  const s = String(ids).trim();
  if (!s) return [];
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

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

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "var(--soc-low)",
  UDP: "var(--soc-medium)",
  HTTP: "var(--soc-success)",
  HTTPS: "var(--soc-info)",
  ICMP: "var(--soc-critical)",
  SSH: "var(--soc-high)",
  FTP: "var(--soc-high)",
  DNS: "var(--soc-info)",
  SMTP: "var(--soc-medium)",
};

function protoColor(p?: string | null): string {
  if (!p) return "var(--muted-foreground)";
  return PROTOCOL_COLORS[p.toUpperCase()] ?? "var(--foreground)";
}

function portAccentColor(port: number): string {
  if (port === 22 || port === 3389) return "var(--soc-medium)";
  if ([80, 443, 8080, 8443].includes(port)) return "var(--soc-low)";
  if ([3306, 5432, 6379, 1433, 27017, 1521].includes(port)) return "var(--soc-critical)";
  if ([21, 23, 445, 139, 137].includes(port)) return "var(--soc-critical)";
  if (port === 53) return "var(--soc-info)";
  return "var(--foreground)";
}

function severityRank(s: Severity): number {
  return SEVERITY_ORDER[s] ?? 0;
}

function sortOffense(list: OffenseScenario[]): OffenseScenario[] {
  return list.slice().sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    const ta = new Date(a.lastObserved).getTime() || 0;
    const tb = new Date(b.lastObserved).getTime() || 0;
    return tb - ta;
  });
}

function sortDefense(list: DefenseScenario[]): DefenseScenario[] {
  return list.slice().sort((a, b) => {
    const sev = severityRank(b.priority) - severityRank(a.priority);
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

function InfoRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="w-[100px] shrink-0 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/70">
        {label}
      </span>
      <span className="min-w-0 flex-1 font-mono-data text-[11px] text-foreground/90">
        {value ?? "—"}
      </span>
    </div>
  );
}

// ============================================================
// Header
// ============================================================

function HistoryHeader({
  onRefresh,
  refreshing,
  statusFilter,
  setStatusFilter,
  targetSearch,
  setTargetSearch,
  pageSize,
  setPageSize,
}: {
  onRefresh: () => void;
  refreshing: boolean;
  statusFilter: string;
  setStatusFilter: (v: string) => void;
  targetSearch: string;
  setTargetSearch: (v: string) => void;
  pageSize: number;
  setPageSize: (v: number) => void;
}) {
  return (
    <div className="shrink-0 border-b border-border/40 bg-card/30 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-md border border-border/60 bg-muted/40">
            <ScrollText className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <h2 className="font-mono-data text-sm font-bold uppercase tracking-wider text-foreground">
              History
            </h2>
            <p className="truncate text-[10px] text-muted-foreground">
              Previous monitoring sessions. History persists across restarts.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <AuthWarning variant="inline" className="hidden md:flex" />
          <Button
            size="sm"
            variant="outline"
            onClick={onRefresh}
            disabled={refreshing}
            className="h-7 gap-1.5 text-[11px]"
          >
            <RefreshCw className={cn("h-3 w-3", refreshing && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>
      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5">
          <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
            Status
          </span>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="h-7 w-[140px] text-[11px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="completed">Completed</SelectItem>
              <SelectItem value="stopped">Stopped</SelectItem>
              <SelectItem value="error">Error</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="relative flex items-center">
          <Search className="absolute left-2 h-3 w-3 text-muted-foreground" />
          <Input
            placeholder="Filter by target…"
            value={targetSearch}
            onChange={(e) => setTargetSearch(e.target.value)}
            className="h-7 w-[200px] pl-7 text-[11px]"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <span className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
            Page
          </span>
          <Select value={String(pageSize)} onValueChange={(v) => setPageSize(Number(v))}>
            <SelectTrigger className="h-7 w-[80px] text-[11px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="10">10</SelectItem>
              <SelectItem value="20">20</SelectItem>
              <SelectItem value="50">50</SelectItem>
              <SelectItem value="100">100</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// Summary row
// ============================================================

function SummaryRow({
  total,
  totalEvents,
  totalAlerts,
}: {
  total: number;
  totalEvents: number;
  totalAlerts: number;
}) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
      <KpiCard
        label="Total Sessions"
        value={total}
        icon={ScrollText}
        accent="default"
        sublabel="In current page"
      />
      <KpiCard
        label="Total Events"
        value={totalEvents}
        icon={Activity}
        accent="low"
        sublabel="Sum of current page"
      />
      <KpiCard
        label="Total Alerts"
        value={totalAlerts}
        icon={AlertTriangle}
        accent="high"
        sublabel="Sum of current page"
      />
    </div>
  );
}

// ============================================================
// Sessions table
// ============================================================

function SessionsTable({
  sessions,
  loading,
  onOpen,
}: {
  sessions: MonitoringSessionInfo[];
  loading: boolean;
  onOpen: (s: MonitoringSessionInfo) => void;
}) {
  if (loading) {
    return (
      <div className="overflow-hidden rounded-lg border border-border/40 bg-card/30">
        <div className="space-y-0">
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-11 w-full rounded-none" />
          ))}
        </div>
      </div>
    );
  }
  if (sessions.length === 0) return null;
  return (
    <div className="overflow-hidden rounded-lg border border-border/40 bg-card/30">
      <div className="soc-scrollbar max-h-[calc(100vh-380px)] min-h-[200px] overflow-auto">
        <table className="w-full table-fixed border-collapse text-[11px]">
          <colgroup>
            <col className="w-[170px]" />
            <col className="w-[120px]" />
            <col className="w-[140px]" />
            <col className="w-[140px]" />
            <col className="w-[70px]" />
            <col className="w-[90px]" />
            <col className="w-[60px]" />
            <col className="w-[60px]" />
            <col className="w-auto" />
            <col className="w-[80px]" />
          </colgroup>
          <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur-sm">
            <tr className="border-b border-border/50">
              {["Assessment ID", "Target", "Start", "End", "Dur", "Status", "Evts", "Alrts", "Risk Summary", "Actions"].map(
                (h) => (
                  <th
                    key={h}
                    className="px-2 py-2 text-left font-mono-data text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/80"
                  >
                    {h}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr
                key={s.id}
                onClick={() => onOpen(s)}
                className="group cursor-pointer border-b border-border/20 transition-colors hover:bg-[color:var(--soc-low)]/5 last:border-b-0"
              >
                <td className="truncate px-2 py-2 font-mono-data text-[10px] text-[color:var(--soc-low)] group-hover:underline">
                  <span title={s.id}>{s.id.slice(0, 16)}…</span>
                </td>
                <td className="truncate px-2 py-2 font-mono-data text-[10px] text-foreground/90" title={s.targetAddress}>
                  {s.targetAddress}
                </td>
                <td className="px-2 py-2 font-mono-data text-[10px] text-muted-foreground" title={formatDateTime(s.startedAt)}>
                  {formatDateTime(s.startedAt)}
                </td>
                <td className="px-2 py-2 font-mono-data text-[10px] text-muted-foreground" title={formatDateTime(s.endedAt)}>
                  {s.endedAt ? formatDateTime(s.endedAt) : "—"}
                </td>
                <td className="px-2 py-2 font-mono-data text-[10px] text-muted-foreground">
                  {durationLabel(s.durationSec)}
                </td>
                <td className="px-2 py-2">
                  <StatusDot status={s.status} label={s.status.toUpperCase()} className="text-[9px]" />
                </td>
                <td className="px-2 py-2 font-mono-data text-[10px] text-foreground/90">
                  {s.eventCount}
                </td>
                <td className="px-2 py-2 font-mono-data text-[10px] text-foreground/90">
                  {s.alertCount}
                </td>
                <td className="truncate px-2 py-2 text-[10px] text-muted-foreground" title={s.riskSummary ?? ""}>
                  {s.riskSummary ?? "—"}
                </td>
                <td className="px-2 py-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={(e) => {
                      e.stopPropagation();
                      onOpen(s);
                    }}
                    className="h-6 gap-1 px-2 text-[10px] text-muted-foreground hover:text-[color:var(--soc-low)]"
                  >
                    <Eye className="h-3 w-3" />
                    View
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="font-mono-data text-[10px] text-muted-foreground">
        Showing <span className="text-foreground/90">{from}–{to}</span> of{" "}
        <span className="text-foreground/90">{total}</span> · Page{" "}
        <span className="text-foreground/90">{page}</span> /{" "}
        <span className="text-foreground/90">{totalPages}</span>
      </span>
      <div className="flex items-center gap-1">
        <Button
          size="sm"
          variant="outline"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          className="h-7 gap-1 px-2 text-[11px]"
        >
          <ChevronLeft className="h-3 w-3" />
          Prev
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
          className="h-7 gap-1 px-2 text-[11px]"
        >
          Next
          <ChevronRight className="h-3 w-3" />
        </Button>
      </div>
    </div>
  );
}

// ============================================================
// Empty state
// ============================================================

function NoHistoryEmptyState() {
  const setView = useAppStore((s) => s.setView);
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 py-12 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full border border-border/40 bg-muted/30">
        <ScrollText className="h-8 w-8 text-muted-foreground/60" />
      </div>
      <div>
        <h3 className="font-mono-data text-base font-bold uppercase tracking-wider text-foreground">
          No Monitoring Sessions Yet
        </h3>
        <p className="mx-auto mt-1.5 max-w-md text-sm text-muted-foreground">
          Start monitoring in Live Monitor to create history. Completed sessions
          are persisted in the database and survive restarts.
        </p>
      </div>
      <Button size="sm" className="gap-1.5" onClick={() => setView("monitor")}>
        <Activity className="h-4 w-4" />
        Go to Live Monitor
      </Button>
    </div>
  );
}

// ============================================================
// Detail dialog — tabs
// ============================================================

function OverviewTab({
  session,
  assessment,
}: {
  session: MonitoringSessionInfo;
  assessment: AssessmentResult | null;
}) {
  const ports = assessment?.ports ?? [];
  const services = assessment?.services ?? [];
  return (
    <div className="flex flex-col gap-4">
      <section>
        <SectionLabel>Session Information</SectionLabel>
        <div className="mt-1.5 grid grid-cols-1 gap-x-4 gap-y-1.5 rounded-md border border-border/40 bg-card/30 p-3 sm:grid-cols-2">
          <InfoRow label="Target" value={session.targetAddress} />
          <InfoRow label="Mode" value={session.mode.toUpperCase()} />
          <InfoRow label="Status" value={session.status.toUpperCase()} />
          <InfoRow label="Start" value={formatDateTime(session.startedAt)} />
          <InfoRow label="End" value={formatDateTime(session.endedAt)} />
          <InfoRow label="Duration" value={durationLabel(session.durationSec)} />
          <InfoRow label="Events" value={session.eventCount} />
          <InfoRow label="Alerts" value={session.alertCount} />
          <div className="col-span-1 sm:col-span-2">
            <div className="mb-0.5 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/70">
              Risk Summary
            </div>
            <div className="font-mono-data text-[11px] text-foreground/90">
              {session.riskSummary ?? "—"}
            </div>
          </div>
        </div>
      </section>

      {assessment && (
        <section>
          <SectionLabel>Assessment</SectionLabel>
          <div className="mt-1.5 grid grid-cols-1 gap-x-4 gap-y-1.5 rounded-md border border-border/40 bg-card/30 p-3 sm:grid-cols-2">
            <InfoRow label="Reachability" value={assessment.reachability} />
            <InfoRow label="Hostname" value={assessment.hostname} />
            <InfoRow label="OS Guess" value={assessment.osGuess} />
            <InfoRow label="Latency" value={assessment.latencyMs != null ? `${assessment.latencyMs} ms` : "—"} />
          </div>
        </section>
      )}

      <section className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
          <div className="border-b border-border/40 px-3 py-1.5">
            <SectionLabel>Open Ports ({ports.length})</SectionLabel>
          </div>
          <div className="soc-scrollbar max-h-60 overflow-y-auto">
            {ports.length === 0 ? (
              <div className="px-3 py-4 text-center text-[11px] text-muted-foreground">
                No open ports recorded.
              </div>
            ) : (
              <table className="w-full text-[11px]">
                <thead className="sticky top-0 bg-card/95">
                  <tr className="border-b border-border/40 text-left font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
                    <th className="px-2 py-1.5">Port</th>
                    <th className="px-2 py-1.5">Proto</th>
                    <th className="px-2 py-1.5">State</th>
                    <th className="px-2 py-1.5">Service</th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map((p) => (
                    <tr key={p.id} className="border-b border-border/20 last:border-b-0">
                      <td className="px-2 py-1 font-mono-data" style={{ color: portAccentColor(p.number) }}>
                        {p.number}
                      </td>
                      <td className="px-2 py-1 font-mono-data text-muted-foreground">{p.protocol}</td>
                      <td className="px-2 py-1 text-muted-foreground">{p.state}</td>
                      <td className="px-2 py-1 font-mono-data">{p.serviceName ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
        <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
          <div className="border-b border-border/40 px-3 py-1.5">
            <SectionLabel>Services ({services.length})</SectionLabel>
          </div>
          <div className="soc-scrollbar max-h-60 overflow-y-auto">
            {services.length === 0 ? (
              <div className="px-3 py-4 text-center text-[11px] text-muted-foreground">
                No service details recorded.
              </div>
            ) : (
              <table className="w-full text-[11px]">
                <thead className="sticky top-0 bg-card/95">
                  <tr className="border-b border-border/40 text-left font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
                    <th className="px-2 py-1.5">Name</th>
                    <th className="px-2 py-1.5">Port</th>
                    <th className="px-2 py-1.5">Product</th>
                    <th className="px-2 py-1.5">Version</th>
                  </tr>
                </thead>
                <tbody>
                  {services.map((s) => (
                    <tr key={s.id} className="border-b border-border/20 last:border-b-0">
                      <td className="px-2 py-1 font-mono-data text-foreground/90">{s.name}</td>
                      <td className="px-2 py-1 font-mono-data text-muted-foreground">{s.port}</td>
                      <td className="px-2 py-1 text-muted-foreground">{s.product ?? "—"}</td>
                      <td className="px-2 py-1 text-muted-foreground">{s.version ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

function EventsTab({
  events,
  eventsTotal,
  targetLabel,
}: {
  events: SecurityEvent[];
  eventsTotal: number;
  targetLabel: string;
}) {
  const [page, setPage] = useState(1);
  const [scrubbedEvents, setScrubbedEvents] = useState<SecurityEvent[] | null>(null);
  const pageSize = 50;

  // Use scrubbed events if scrubbing has been activated, otherwise all events
  const displayEvents = scrubbedEvents ?? events;
  const totalPages = Math.max(1, Math.ceil(displayEvents.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const slice = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return displayEvents.slice(start, start + pageSize);
  }, [displayEvents, currentPage]);

  const handleScrub = useCallback((filtered: SecurityEvent[]) => {
    setScrubbedEvents(filtered.length === events.length ? null : filtered);
    setPage(1);
  }, [events.length]);

  const handleResetScrub = useCallback(() => {
    setScrubbedEvents(null);
    setPage(1);
  }, []);

  return (
    <div className="flex flex-col gap-3">
      <TimelineScrubber events={events} onScrub={handleScrub} />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SectionLabel>
            Event Log ({displayEvents.length} shown · {eventsTotal} total
            {scrubbedEvents && scrubbedEvents.length < events.length ? ` · filtered from ${events.length}` : ""})
          </SectionLabel>
          {scrubbedEvents && (
            <button
              onClick={handleResetScrub}
              className="rounded-sm border border-border/40 px-1.5 py-0.5 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground transition-colors hover:bg-accent/30 hover:text-foreground"
            >
              Reset
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono-data text-[9px] text-muted-foreground">
            Page {currentPage} / {totalPages}
          </span>
          <ExportMenu events={displayEvents} targetLabel={targetLabel} size="sm" />
        </div>
      </div>
      <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
        <div className="soc-scrollbar max-h-[460px] overflow-y-auto">
          <table className="w-full table-fixed border-collapse text-[10px]">
            <colgroup>
              <col className="w-[80px]" />
              <col className="w-[150px]" />
              <col className="w-[150px]" />
              <col className="w-[60px]" />
              <col className="w-[120px]" />
              <col className="w-[70px]" />
              <col className="w-[70px]" />
            </colgroup>
            <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur-sm">
              <tr className="border-b border-border/50">
                {["Time", "Source", "Destination", "Proto", "Event", "Severity", "Status"].map((h) => (
                  <th key={h} className="px-2 py-1.5 text-left font-mono-data text-[9px] font-semibold uppercase tracking-wider text-muted-foreground/80">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {slice.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-3 py-6 text-center text-[11px] text-muted-foreground">
                    No events recorded for this session.
                  </td>
                </tr>
              ) : (
                slice.map((e) => (
                  <tr key={e.id} className="border-b border-border/20 last:border-b-0 hover:bg-muted/20">
                    <td className="px-2 py-1 font-mono-data text-[9px] text-muted-foreground" title={formatDateTime(e.timestamp)}>
                      {formatTime(e.timestamp)}
                    </td>
                    <td className="truncate px-2 py-1 font-mono-data text-[10px] text-foreground/90" title={e.sourceIp ?? "?"}>
                      {e.sourceIp ?? "?"}
                      {e.sourcePort ? `:${e.sourcePort}` : ""}
                    </td>
                    <td className="truncate px-2 py-1 font-mono-data text-[10px] text-foreground/90" title={`${e.destIp ?? "?"}:${e.destPort ?? ""}`}>
                      {e.destIp ?? "?"}
                      {e.destPort ? `:${e.destPort}` : ""}
                    </td>
                    <td className="px-2 py-1">
                      <span
                        className="rounded-sm border px-1 py-0.5 font-mono-data text-[9px] uppercase"
                        style={{
                          color: protoColor(e.protocol),
                          borderColor: `color-mix(in oklch, ${protoColor(e.protocol)} 40%, transparent)`,
                          backgroundColor: `color-mix(in oklch, ${protoColor(e.protocol)} 12%, transparent)`,
                        }}
                      >
                        {e.protocol ?? "?"}
                      </span>
                    </td>
                    <td className="px-2 py-1 text-foreground/80">
                      <div className="flex items-center gap-1">
                        <span className="font-mono-data text-[9px] text-muted-foreground">[{e.eventType}]</span>
                        {e.isDemo && (
                          <span className="rounded-sm border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-1 font-mono-data text-[8px] font-bold uppercase text-[color:var(--soc-medium)]">
                            Demo
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 truncate text-[10px]" title={e.message}>
                        {e.message}
                      </div>
                    </td>
                    <td className="px-2 py-1">
                      <SeverityBadge severity={e.severity} size="sm" />
                    </td>
                    <td className="px-2 py-1 text-muted-foreground">
                      {e.status}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      <div className="flex items-center justify-end gap-1">
        <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)} className="h-7 gap-1 px-2 text-[11px]">
          <ChevronLeft className="h-3 w-3" /> Prev
        </Button>
        <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="h-7 gap-1 px-2 text-[11px]">
          Next <ChevronRight className="h-3 w-3" />
        </Button>
      </div>
    </div>
  );
}

function AlertStatusBadge({ status }: { status: string }) {
  if (status === "acknowledged") {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider"
        style={{
          color: "var(--soc-medium)",
          borderColor: "color-mix(in oklch, var(--soc-medium) 40%, transparent)",
          backgroundColor: "color-mix(in oklch, var(--soc-medium) 12%, transparent)",
        }}
      >
        <Eye className="h-2.5 w-2.5" />
        ACK
      </span>
    );
  }
  if (status === "resolved") {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider"
        style={{
          color: "var(--soc-success)",
          borderColor: "color-mix(in oklch, var(--soc-success) 40%, transparent)",
          backgroundColor: "color-mix(in oklch, var(--soc-success) 12%, transparent)",
        }}
      >
        <CheckCircle className="h-2.5 w-2.5" />
        Resolved
      </span>
    );
  }
  return null;
}

type AlertStatus = "active" | "acknowledged" | "resolved";

function AlertActionButtons({
  alert,
  sessionId,
  onUpdated,
}: {
  alert: SecurityAlert;
  sessionId: string;
  onUpdated: (alertId: string, status: AlertStatus) => void;
}) {
  const [busy, setBusy] = useState(false);

  const handleUpdate = async (newStatus: AlertStatus) => {
    if (busy) return;
    setBusy(true);
    try {
      await api.updateAlertStatus(sessionId, alert.alertId, newStatus);
      onUpdated(alert.alertId, newStatus);
      const verb =
        newStatus === "acknowledged"
          ? "acknowledged"
          : newStatus === "resolved"
            ? "resolved"
            : "reopened";
      toast.success(`Alert ${verb}.`, {
        description: alert.ruleName,
      });
    } catch (err) {
      const e = err as Error & { status?: number };
      if (!e.status) {
        toast.error("Unable to connect to monitoring service.", {
          description: "Please check that the monitor service is running.",
        });
      } else if (e.status === 404) {
        toast.error("Alert not found.", {
          description: "It may have been removed from the database.",
        });
      } else {
        toast.error(e.message || "Unable to update alert status.");
      }
    } finally {
      setBusy(false);
    }
  };

  const btnCls =
    "inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider transition-colors disabled:opacity-50 disabled:cursor-not-allowed";

  if (alert.status === "active") {
    return (
      <div className="flex shrink-0 items-center gap-1">
        <button
          type="button"
          disabled={busy}
          onClick={() => handleUpdate("acknowledged")}
          className={cn(btnCls, "hover:bg-[color:var(--soc-medium)]/15")}
          style={{
            color: "var(--soc-medium)",
            borderColor: "color-mix(in oklch, var(--soc-medium) 40%, transparent)",
          }}
          title="Acknowledge this alert"
        >
          <Eye className="h-2.5 w-2.5" />
          Ack
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => handleUpdate("resolved")}
          className={cn(btnCls, "hover:bg-[color:var(--soc-success)]/15")}
          style={{
            color: "var(--soc-success)",
            borderColor: "color-mix(in oklch, var(--soc-success) 40%, transparent)",
          }}
          title="Mark this alert as resolved"
        >
          <CheckCircle className="h-2.5 w-2.5" />
          Resolve
        </button>
      </div>
    );
  }

  if (alert.status === "acknowledged") {
    return (
      <div className="flex shrink-0 items-center gap-1">
        <button
          type="button"
          disabled={busy}
          onClick={() => handleUpdate("resolved")}
          className={cn(btnCls, "hover:bg-[color:var(--soc-success)]/15")}
          style={{
            color: "var(--soc-success)",
            borderColor: "color-mix(in oklch, var(--soc-success) 40%, transparent)",
          }}
          title="Mark this alert as resolved"
        >
          <CheckCircle className="h-2.5 w-2.5" />
          Resolve
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => handleUpdate("active")}
          className={cn(btnCls, "text-muted-foreground hover:text-foreground")}
          title="Reopen this alert"
        >
          <RotateCcw className="h-2.5 w-2.5" />
          Reopen
        </button>
      </div>
    );
  }

  // resolved
  return (
    <div className="flex shrink-0 items-center gap-1">
      <button
        type="button"
        disabled={busy}
        onClick={() => handleUpdate("active")}
        className={cn(btnCls, "text-muted-foreground hover:text-foreground")}
        title="Reopen this alert"
      >
        <RotateCcw className="h-2.5 w-2.5" />
        Reopen
      </button>
    </div>
  );
}

function alertAccentColor(alert: SecurityAlert): string {
  if (alert.status === "resolved") return "var(--soc-success)";
  if (alert.status === "acknowledged") return "var(--soc-medium)";
  return severityColor(alert.severity);
}

function AlertCard({
  alert,
  sessionId,
  onUpdated,
}: {
  alert: SecurityAlert;
  sessionId: string;
  onUpdated: (alertId: string, status: AlertStatus) => void;
}) {
  const accent = alertAccentColor(alert);
  const opacityCls =
    alert.status === "resolved"
      ? "opacity-50"
      : alert.status === "acknowledged"
        ? "opacity-80"
        : "opacity-100";
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-md border bg-card/40 p-3 pl-3.5 transition-all",
        opacityCls,
      )}
      style={{ borderColor: `color-mix(in oklch, ${accent} 30%, transparent)` }}
    >
      <div className="absolute left-0 top-0 h-full w-1" style={{ backgroundColor: accent }} aria-hidden />
      <div className="flex flex-wrap items-center gap-1.5">
        <SeverityBadge severity={alert.severity} size="sm" />
        <AlertStatusBadge status={alert.status} />
        <span
          className={cn(
            "font-mono-data text-[10px] font-semibold text-foreground",
            alert.status === "resolved" && "line-through decoration-muted-foreground/60",
          )}
        >
          {alert.ruleName}
        </span>
        <span className="font-mono-data text-[9px] text-muted-foreground">{alert.alertId}</span>
        <span className="ml-auto font-mono-data text-[9px] text-muted-foreground" title={formatDateTime(alert.timestamp)}>
          {formatTime(alert.timestamp)}
        </span>
      </div>
      <p className="mt-1 text-[11px] leading-snug text-foreground/80">{alert.message}</p>
      <div className="mt-1.5 flex items-center gap-3 font-mono-data text-[9px] text-muted-foreground">
        <span>Rule: {alert.ruleId}</span>
        <span>Conf: {alert.confidence}%</span>
      </div>
      {alert.recommendedAction && (
        <div className="mt-1.5 rounded-sm border border-[color:var(--soc-success)]/30 bg-[color:var(--soc-success)]/10 px-2 py-1 text-[10px] text-[color:var(--soc-success)]">
          <span className="font-mono-data font-semibold uppercase">Action:</span>{" "}
          {alert.recommendedAction}
        </div>
      )}
      <div className="mt-2 flex items-center justify-end gap-2 border-t border-border/30 pt-1.5">
        <AlertActionButtons alert={alert} sessionId={sessionId} onUpdated={onUpdated} />
      </div>
    </div>
  );
}

function AlertsTab({
  alerts,
  sessionId,
  targetLabel,
}: {
  alerts: SecurityAlert[];
  sessionId: string;
  targetLabel: string;
}) {
  const [localAlerts, setLocalAlerts] = useState<SecurityAlert[]>(alerts);

  // Sync local state when the parent's alerts list changes (e.g. on refetch).
  useEffect(() => {
    setLocalAlerts(alerts);
  }, [alerts]);

  const handleUpdated = useCallback((alertId: string, status: AlertStatus) => {
    setLocalAlerts((prev) =>
      prev.map((a) => (a.alertId === alertId ? { ...a, status } : a)),
    );
  }, []);

  const counts = useMemo(() => {
    let active = 0;
    let ack = 0;
    let resolved = 0;
    for (const a of localAlerts) {
      if (a.status === "active") active++;
      else if (a.status === "acknowledged") ack++;
      else if (a.status === "resolved") resolved++;
    }
    return { active, ack, resolved, total: localAlerts.length };
  }, [localAlerts]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
        <SectionLabel>Alerts ({localAlerts.length})</SectionLabel>
        <span className="ml-auto flex items-center gap-2">
          <span title="Open (active) alerts">
            <span className="text-[color:var(--soc-critical)]">{counts.active}</span> open
          </span>
          <span className="text-muted-foreground/40">·</span>
          <span title="Acknowledged alerts">
            <span className="text-[color:var(--soc-medium)]">{counts.ack}</span> ack
          </span>
          <span className="text-muted-foreground/40">·</span>
          <span title="Resolved alerts">
            <span className="text-[color:var(--soc-success)]">{counts.resolved}</span> resolved
          </span>
          <ExportMenu alerts={localAlerts} targetLabel={targetLabel} size="sm" />
        </span>
      </div>
      {localAlerts.length === 0 ? (
        <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border/50 bg-card/30 px-4 py-8 text-[11px] text-muted-foreground">
          <CheckCircle2 className="h-4 w-4 opacity-50" />
          No alerts were recorded for this session.
        </div>
      ) : (
        <div className="soc-scrollbar max-h-[540px] space-y-2 overflow-y-auto pr-1">
          {localAlerts.map((a) => (
            <AlertCard
              key={a.id}
              alert={a}
              sessionId={sessionId}
              onUpdated={handleUpdated}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function OffenseScenarioCard({ scenario }: { scenario: OffenseScenario }) {
  const sev = scenario.severity;
  const color = severityColor(sev);
  const steps = parseAttackPath(scenario.attackPath);
  return (
    <div
      className="offense-surface relative flex flex-col overflow-hidden rounded-lg border bg-card/40 p-3 pl-4"
      style={{ borderColor: `color-mix(in oklch, ${color} 30%, transparent)` }}
    >
      <div className="absolute left-0 top-0 h-full w-1" style={{ backgroundColor: color }} aria-hidden />
      <div className="flex flex-wrap items-center gap-1.5">
        <SeverityBadge severity={sev} size="sm" />
        <StatusDot status={scenario.status} label={scenario.status.toUpperCase()} className="text-[9px]" />
        {scenario.techniqueMitre && (
          <span
            className="rounded-sm border px-1 py-0.5 font-mono-data text-[9px] font-bold"
            style={{
              color,
              borderColor: `color-mix(in oklch, ${color} 40%, transparent)`,
              backgroundColor: `color-mix(in oklch, ${color} 12%, transparent)`,
            }}
          >
            {scenario.techniqueMitre}
          </span>
        )}
      </div>
      <h4 className="mt-1.5 truncate font-mono-data text-[12px] font-bold leading-tight text-foreground" title={scenario.title}>
        {scenario.title}
      </h4>
      <div className="mt-0.5 truncate font-mono-data text-[9px] text-muted-foreground">
        {scenario.scenarioId} · {scenario.category}
      </div>
      {scenario.potentialImpact && (
        <p className="mt-1.5 text-[10px] leading-snug text-foreground/70">
          {scenario.potentialImpact}
        </p>
      )}
      {steps.length > 0 && (
        <div className="mt-2">
          <SectionLabel>Attack Path</SectionLabel>
          <div className="mt-1 flex flex-col gap-0.5">
            {steps.map((s, i) => (
              <div key={i} className="flex flex-col">
                <div className="flex items-center gap-1.5">
                  <span
                    className="flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-sm font-mono-data text-[8px] font-bold"
                    style={{
                      color,
                      backgroundColor: `color-mix(in oklch, ${color} 15%, transparent)`,
                      border: `1px solid color-mix(in oklch, ${color} 35%, transparent)`,
                    }}
                  >
                    {i + 1}
                  </span>
                  <span className="text-[10px] text-foreground/80">{s}</span>
                </div>
                {i < steps.length - 1 && (
                  <div className="ml-1.5 flex h-2.5 items-center">
                    <ArrowDown className="h-2.5 w-2.5 text-muted-foreground/50" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="mt-2 flex items-center gap-3 border-t border-border/40 pt-1.5 font-mono-data text-[9px] text-muted-foreground">
        <span>Conf {scenario.confidence}%</span>
        <span>Evts {scenario.eventCount}</span>
        <span>Sources {scenario.sourceCount}</span>
      </div>
    </div>
  );
}

function OffenseTab({
  scenarios,
  onGoToOffense,
}: {
  scenarios: OffenseScenario[];
  onGoToOffense: () => void;
}) {
  const sorted = useMemo(() => sortOffense(scenarios), [scenarios]);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <SectionLabel>Offense Scenarios ({sorted.length})</SectionLabel>
        <Button
          size="sm"
          variant="outline"
          onClick={onGoToOffense}
          className="h-7 gap-1.5 text-[10px]"
        >
          <Swords className="h-3 w-3" />
          View in Offense
        </Button>
      </div>
      {sorted.length === 0 ? (
        <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border/50 bg-card/30 px-4 py-8 text-[11px] text-muted-foreground">
          No offense scenarios were recorded for this session.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
          {sorted.map((s) => (
            <OffenseScenarioCard key={s.scenarioId} scenario={s} />
          ))}
        </div>
      )}
    </div>
  );
}

function DefenseScenarioCard({ scenario }: { scenario: DefenseScenario }) {
  const color = severityColor(scenario.priority);
  return (
    <div
      className="defense-surface relative flex flex-col overflow-hidden rounded-lg border bg-card/40 p-3 pl-4"
      style={{ borderColor: `color-mix(in oklch, ${color} 30%, transparent)` }}
    >
      <div className="absolute left-0 top-0 h-full w-1" style={{ backgroundColor: color }} aria-hidden />
      <div className="flex flex-wrap items-center gap-1.5">
        <SeverityBadge severity={scenario.priority} size="sm" label={scenario.priority.toUpperCase()} />
        <StatusDot status={scenario.status} label={scenario.status.toUpperCase()} className="text-[9px]" />
        {scenario.relatedOffenseId && (
          <span className="rounded-sm border border-[color:var(--soc-critical)]/30 bg-[color:var(--soc-critical)]/10 px-1 py-0.5 font-mono-data text-[8px] font-bold uppercase text-[color:var(--soc-critical)]">
            {scenario.relatedOffenseId}
          </span>
        )}
      </div>
      <h4 className="mt-1.5 truncate font-mono-data text-[12px] font-bold leading-tight text-foreground" title={scenario.title}>
        {scenario.title}
      </h4>
      <div className="mt-0.5 truncate font-mono-data text-[9px] text-muted-foreground">
        {scenario.scenarioId} · {scenario.category}
      </div>
      {scenario.recommendedAction && (
        <div className="mt-1.5 rounded-sm border border-[color:var(--soc-success)]/30 bg-[color:var(--soc-success)]/10 px-2 py-1 text-[10px] text-[color:var(--soc-success)]">
          <span className="font-mono-data font-semibold uppercase">Action:</span>{" "}
          {scenario.recommendedAction}
        </div>
      )}
      <div className="mt-2 grid grid-cols-2 gap-x-2 gap-y-1 text-[10px] text-muted-foreground">
        {scenario.detect && (
          <div className="col-span-2">
            <span className="font-mono-data text-[9px] uppercase text-[color:var(--soc-low)]">Detect: </span>
            {scenario.detect}
          </div>
        )}
        {scenario.prevent && (
          <div className="col-span-2">
            <span className="font-mono-data text-[9px] uppercase text-[color:var(--soc-low)]">Prevent: </span>
            {scenario.prevent}
          </div>
        )}
      </div>
    </div>
  );
}

function DefenseTab({
  scenarios,
  onGoToDefense,
}: {
  scenarios: DefenseScenario[];
  onGoToDefense: () => void;
}) {
  const sorted = useMemo(() => sortDefense(scenarios), [scenarios]);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <SectionLabel>Defense Scenarios ({sorted.length})</SectionLabel>
        <Button
          size="sm"
          variant="outline"
          onClick={onGoToDefense}
          className="h-7 gap-1.5 text-[10px]"
        >
          <Shield className="h-3 w-3" />
          View in Defense
        </Button>
      </div>
      {sorted.length === 0 ? (
        <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border/50 bg-card/30 px-4 py-8 text-[11px] text-muted-foreground">
          No defense scenarios were recorded for this session.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
          {sorted.map((s) => (
            <DefenseScenarioCard key={s.scenarioId} scenario={s} />
          ))}
        </div>
      )}
    </div>
  );
}

function ActionsTab({
  session,
  onClose,
}: {
  session: MonitoringSessionInfo;
  onClose: () => void;
}) {
  const setView = useAppStore((s) => s.setView);
  const [generating, setGenerating] = useState(false);
  const handleGenerate = async () => {
    setGenerating(true);
    try {
      await api.generateReport(session.id);
      toast.success("Report generated. View it in the Reports view.");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to generate report.";
      toast.error(msg);
    } finally {
      setGenerating(false);
    }
  };
  return (
    <div className="flex flex-col gap-3">
      <SectionLabel>Actions</SectionLabel>
      <div className="rounded-md border border-border/40 bg-card/30 p-3">
        <div className="flex items-start gap-2">
          <FileText className="mt-0.5 h-4 w-4 shrink-0 text-[color:var(--soc-low)]" />
          <div className="min-w-0 flex-1">
            <div className="font-mono-data text-[11px] font-semibold text-foreground">
              Generate Professional Report
            </div>
            <p className="mt-0.5 text-[10px] text-muted-foreground">
              Produce a complete PDF-format security monitoring report from this
              session, including executive summary, assessment details, monitoring
              statistics, security findings, scenario analysis, recommendations,
              and a technical appendix.
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={handleGenerate} disabled={generating} className="h-7 gap-1.5 text-[11px]">
                {generating ? <RefreshCw className="h-3 w-3 animate-spin" /> : <FileText className="h-3 w-3" />}
                {generating ? "Generating…" : "Generate Report"}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  onClose();
                  setView("reports");
                }}
                className="h-7 gap-1.5 text-[11px]"
              >
                Go to Reports
                <ArrowRight className="h-3 w-3" />
              </Button>
            </div>
          </div>
        </div>
      </div>
      <div className="rounded-md border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/5 p-3">
        <div className="flex items-start gap-2">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-[color:var(--soc-medium)]" />
          <div>
            <div className="font-mono-data text-[10px] font-semibold uppercase tracking-wider text-[color:var(--soc-medium)]">
              Defensive Analysis
            </div>
            <p className="mt-0.5 text-[10px] leading-snug text-muted-foreground">
              Scenario data is derived from observed telemetry and detected
              patterns. It does NOT confirm a successful attack. Correlate with
              authorized scope and additional evidence before action.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function DetailDialog({
  session,
  open,
  onOpenChange,
}: {
  session: MonitoringSessionInfo | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const [detail, setDetail] = useState<HistoryDetailResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const setHistoricalSession = useAppStore((s) => s.setHistoricalSession);
  const setView = useAppStore((s) => s.setView);

  useEffect(() => {
    if (!open || !session) {
      setDetail(null);
      setError(null);
      return;
    }
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.getHistoryDetail(session.id);
        if (cancelled) return;
        const normalized: HistoryDetailResponse = {
          session: normalizeSession(res.session),
          assessment: normalizeAssessment(res.assessment),
          events: (res.events ?? []).map(normalizeEvent),
          alerts: (res.alerts ?? []).map(normalizeAlert),
          offenseScenarios: (res.offenseScenarios ?? []).map(normalizeOffenseScenario),
          defenseScenarios: (res.defenseScenarios ?? []).map(normalizeDefenseScenario),
        };
        setDetail(normalized);
      } catch (e) {
        if (cancelled) return;
        const msg = e instanceof Error ? e.message : "Failed to load session detail.";
        setError(msg);
        toast.error(msg);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [open, session]);

  const eventsTotal = (detail?.events?.length ?? 0);
  const dialogSession = session;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] max-w-5xl gap-0 overflow-y-auto p-0 sm:max-w-5xl">
        <DialogHeader className="border-b border-border/40 px-4 py-3 text-left">
          <DialogTitle className="flex items-center gap-2 font-mono-data text-sm uppercase tracking-wider">
            <ScrollText className="h-4 w-4 text-[color:var(--soc-low)]" />
            Historical Session Detail
            {dialogSession && (
              <span className="font-mono-data text-[10px] font-normal text-muted-foreground">
                {dialogSession.id}
              </span>
            )}
          </DialogTitle>
          <DialogDescription className="text-[10px] uppercase tracking-wider text-muted-foreground">
            Persistent record of a previously completed monitoring session.
          </DialogDescription>
        </DialogHeader>
        <div className="p-4">
          {loading ? (
            <div className="space-y-2">
              {[0, 1, 2, 3, 4].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : error ? (
            <div className="rounded-md border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 px-3 py-3 text-[11px] text-[color:var(--soc-critical)]">
              {error}
            </div>
          ) : detail && dialogSession ? (
            <Tabs defaultValue="overview" className="gap-3">
              <TabsList className="bg-card/40">
                <TabsTrigger value="overview" className="text-[11px]">Overview</TabsTrigger>
                <TabsTrigger value="events" className="text-[11px]">
                  Events ({detail.events.length})
                </TabsTrigger>
                <TabsTrigger value="alerts" className="text-[11px]">
                  Alerts ({detail.alerts.length})
                </TabsTrigger>
                <TabsTrigger value="offense" className="text-[11px]">
                  Offense ({detail.offenseScenarios.length})
                </TabsTrigger>
                <TabsTrigger value="defense" className="text-[11px]">
                  Defense ({detail.defenseScenarios.length})
                </TabsTrigger>
                <TabsTrigger value="actions" className="text-[11px]">Actions</TabsTrigger>
              </TabsList>
              <TabsContent value="overview">
                <OverviewTab session={detail.session} assessment={detail.assessment} />
              </TabsContent>
              <TabsContent value="events">
                <EventsTab events={detail.events} eventsTotal={eventsTotal} targetLabel={detail.session.targetAddress || detail.target?.address || "session"} />
              </TabsContent>
              <TabsContent value="alerts">
                <AlertsTab alerts={detail.alerts} sessionId={detail.session.id} targetLabel={detail.session.targetAddress || detail.target?.address || "session"} />
              </TabsContent>
              <TabsContent value="offense">
                <OffenseTab
                  scenarios={detail.offenseScenarios}
                  onGoToOffense={() => {
                    setHistoricalSession(detail.session);
                    onOpenChange(false);
                    setView("offense");
                  }}
                />
              </TabsContent>
              <TabsContent value="defense">
                <DefenseTab
                  scenarios={detail.defenseScenarios}
                  onGoToDefense={() => {
                    setHistoricalSession(detail.session);
                    onOpenChange(false);
                    setView("defense");
                  }}
                />
              </TabsContent>
              <TabsContent value="actions">
                <ActionsTab
                  session={detail.session}
                  onClose={() => onOpenChange(false)}
                />
              </TabsContent>
            </Tabs>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ============================================================
// Main View
// ============================================================

export function HistoryView() {
  const [sessions, setSessions] = useState<MonitoringSessionInfo[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [statusFilter, setStatusFilter] = useState("all");
  const [targetSearch, setTargetSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<MonitoringSessionInfo | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  // Debounce target search
  const [searchInput, setSearchInput] = useState("");
  useEffect(() => {
    const id = setTimeout(() => setTargetSearch(searchInput.trim()), 350);
    return () => clearTimeout(id);
  }, [searchInput]);

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1);
  }, [statusFilter, targetSearch, pageSize]);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res: HistoryListResponse = await api.getHistory({
        page,
        pageSize,
        status: statusFilter === "all" ? undefined : statusFilter,
        target: targetSearch || undefined,
      });
      const normalized = (res.sessions ?? []).map(normalizeSession);
      setSessions(normalized);
      setTotal(res.total ?? 0);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to load history.";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchHistory();
  }, [page, pageSize, statusFilter, targetSearch]);

  const handleOpen = (s: MonitoringSessionInfo) => {
    setSelected(s);
    setDialogOpen(true);
  };

  const totals = useMemo(() => {
    let totalEvents = 0;
    let totalAlerts = 0;
    for (const s of sessions) {
      totalEvents += s.eventCount;
      totalAlerts += s.alertCount;
    }
    return { totalEvents, totalAlerts };
  }, [sessions]);

  const showEmpty = !loading && !error && sessions.length === 0;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <HistoryHeader
        onRefresh={() => void fetchHistory()}
        refreshing={loading}
        statusFilter={statusFilter}
        setStatusFilter={setStatusFilter}
        targetSearch={searchInput}
        setTargetSearch={setSearchInput}
        pageSize={pageSize}
        setPageSize={setPageSize}
      />

      <div className="shrink-0 border-b border-border/40 px-3 py-3">
        <SummaryRow
          total={total}
          totalEvents={totals.totalEvents}
          totalAlerts={totals.totalAlerts}
        />
      </div>

      <div className="soc-scrollbar min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
        {showEmpty ? (
          <NoHistoryEmptyState />
        ) : (
          <div className="flex flex-col gap-3 p-3">
            {error && (
              <div className="flex items-center gap-2 rounded-md border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 px-3 py-2 text-[11px] text-[color:var(--soc-critical)]">
                <XCircle className="h-3.5 w-3.5" />
                {error}
              </div>
            )}
            <SessionsTable
              sessions={sessions}
              loading={loading}
              onOpen={handleOpen}
            />
            {sessions.length > 0 && (
              <Pagination
                page={page}
                pageSize={pageSize}
                total={total}
                onPage={setPage}
              />
            )}
          </div>
        )}
      </div>

      <DetailDialog
        session={selected}
        open={dialogOpen}
        onOpenChange={setDialogOpen}
      />
    </div>
  );
}
