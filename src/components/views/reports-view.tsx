"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  FileText,
  RefreshCw,
  Plus,
  Download,
  Eye,
  AlertTriangle,
  Clock,
  Server,
  Activity,
  ShieldAlert,
  Swords,
  Shield,
  CheckCircle2,
  XCircle,
  ScrollText,
  type LucideIcon,
} from "lucide-react";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { useAppStore } from "@/lib/store";
import { api, type ReportDetailResponse, type ReportListResponse } from "@/lib/api-client";
import type { ReportData } from "@/lib/monitoring/report";
import { KpiCard } from "@/components/soc/kpi-card";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { AuthWarning } from "@/components/soc/auth-warning";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  AUTHORIZED_SCOPE_NOTICE,
  severityColor,
  SEVERITY_ORDER,
  DETECTION_RULES,
  RULES_BY_ID,
} from "@/lib/constants";
import type {
  Severity,
  SecurityAlert,
  OffenseScenario,
  DefenseScenario,
  ReportInfo,
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

function formatDate(ts: string | Date | null | undefined): string {
  if (ts == null) return "—";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return "----/--/--";
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())}`;
  } catch {
    return "----/--/--";
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

function normalizeReportInfo(raw: unknown): ReportInfo {
  const r = raw as Record<string, unknown>;
  return {
    id: String(r.id),
    reportId: String(r.reportId),
    sessionId: r.sessionId ? String(r.sessionId) : null,
    target: String(r.target ?? "—"),
    title: String(r.title ?? ""),
    generatedAt: typeof r.generatedAt === "string" ? r.generatedAt : new Date(r.generatedAt as Date).toISOString(),
    riskLevel: (r.riskLevel as Severity) ?? "info",
    eventCount: Number(r.eventCount ?? 0),
    alertCount: Number(r.alertCount ?? 0),
    scenarioCount: Number(r.scenarioCount ?? 0),
    pdfUrl: r.pdfUrl ? String(r.pdfUrl) : null,
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

function normalizeReportData(raw: unknown): ReportData | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const session = r.session as Record<string, unknown> | undefined;
  const target = r.target as Record<string, unknown> | undefined;
  const assessment = r.assessment as Record<string, unknown> | undefined;
  const eventsSummary = r.eventsSummary as Record<string, unknown> | undefined;
  const bySeverity = (eventsSummary?.bySeverity ?? {}) as Record<string, number>;
  if (!session) return null;
  return {
    session: {
      id: String(session.id),
      targetAddress: String(session.targetAddress ?? ""),
      mode: String(session.mode ?? "demo"),
      status: String(session.status ?? "completed"),
      startedAt: typeof session.startedAt === "string" ? session.startedAt : new Date(session.startedAt as Date).toISOString(),
      endedAt: session.endedAt
        ? typeof session.endedAt === "string"
          ? session.endedAt
          : new Date(session.endedAt as Date).toISOString()
        : null,
      durationSec: Number(session.durationSec ?? 0),
      eventCount: Number(session.eventCount ?? 0),
      alertCount: Number(session.alertCount ?? 0),
      riskSummary: session.riskSummary ? String(session.riskSummary) : null,
    },
    target: {
      address: String(target?.address ?? ""),
      targetType: String(target?.targetType ?? "unknown"),
      isLab: Boolean(target?.isLab ?? true),
      hostname: (target?.hostname as string | null) ?? null,
    },
    assessment: (assessment as AssessmentResult) ?? null,
    eventsSummary: {
      total: Number(eventsSummary?.total ?? 0),
      bySeverity: {
        critical: Number(bySeverity.critical ?? 0),
        high: Number(bySeverity.high ?? 0),
        medium: Number(bySeverity.medium ?? 0),
        low: Number(bySeverity.low ?? 0),
        info: Number(bySeverity.info ?? 0),
      },
    },
    alerts: (r.alerts as SecurityAlert[]) ?? [],
    offenseScenarios: ((r.offenseScenarios as OffenseScenario[]) ?? []).map((s) => ({
      ...s,
      relatedEventIds: parseRelatedEventIds(
        (s as unknown as { relatedEventIds: string | string[] }).relatedEventIds,
      ),
      attackPath: s.attackPath ?? null,
    })),
    defenseScenarios: ((r.defenseScenarios as DefenseScenario[]) ?? []).map((s) => ({
      ...s,
      relatedEventIds: parseRelatedEventIds(
        (s as unknown as { relatedEventIds: string | string[] }).relatedEventIds,
      ),
    })),
    timeline: (r.timeline as { time: string; count: number }[]) ?? [],
    topSourceIps: (r.topSourceIps as { key: string; count: number }[]) ?? [],
    topDestPorts: (r.topDestPorts as { key: string; count: number }[]) ?? [],
    riskSummary: String(r.riskSummary ?? ""),
    recommendations: (r.recommendations as string[]) ?? [],
    generatedAt: typeof r.generatedAt === "string" ? r.generatedAt : new Date(r.generatedAt as Date).toISOString(),
  };
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
        <span className="truncate font-mono-data" title={typeof value === "string" ? value : undefined}>
          {value ?? "—"}
        </span>
      </div>
    </div>
  );
}

// ============================================================
// Header
// ============================================================

function ReportsHeader({
  onRefresh,
  refreshing,
  onGenerate,
  generating,
  canGenerate,
}: {
  onRefresh: () => void;
  refreshing: boolean;
  onGenerate: () => void;
  generating: boolean;
  canGenerate: boolean;
}) {
  return (
    <div className="shrink-0 border-b border-border/40 bg-card/30 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-md border border-border/60 bg-muted/40">
            <FileText className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <h2 className="font-mono-data text-sm font-bold uppercase tracking-wider text-foreground">
              Reports
            </h2>
            <p className="truncate text-[10px] text-muted-foreground">
              Professional security monitoring reports.
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
          <Button
            size="sm"
            onClick={onGenerate}
            disabled={!canGenerate || generating}
            className="h-7 gap-1.5 text-[11px]"
            title={canGenerate ? "Generate from active session" : "No active monitoring session"}
          >
            {generating ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
            Generate from Active
          </Button>
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
  mostRecent,
  avgRisk,
}: {
  total: number;
  mostRecent: string;
  avgRisk: string;
}) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
      <KpiCard label="Total Reports" value={total} icon={FileText} accent="default" />
      <KpiCard label="Most Recent" value={mostRecent} icon={Clock} accent="low" sublabel="Generated at" />
      <KpiCard label="Avg Risk Level" value={avgRisk} icon={AlertTriangle} accent="high" sublabel="Across all reports" />
    </div>
  );
}

// ============================================================
// Reports list (left panel)
// ============================================================

function ReportListRow({
  report,
  selected,
  onSelect,
}: {
  report: ReportInfo;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      onClick={onSelect}
      className={cn(
        "group relative w-full overflow-hidden rounded-md border bg-card/40 p-2.5 pl-3 text-left transition-all hover:bg-card/60",
        selected
          ? "border-[color:var(--soc-low)]/50 bg-[color:var(--soc-low)]/5"
          : "border-border/40",
      )}
    >
      {selected && (
        <div
          className="absolute left-0 top-0 h-full w-1"
          style={{ backgroundColor: "var(--soc-low)" }}
          aria-hidden
        />
      )}
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono-data text-[10px] font-semibold text-foreground" title={report.reportId}>
          {report.reportId}
        </span>
        <SeverityBadge severity={report.riskLevel} size="sm" />
      </div>
      <div className="mt-1 truncate font-mono-data text-[10px] text-muted-foreground" title={report.target}>
        {report.target}
      </div>
      <div className="mt-0.5 font-mono-data text-[9px] text-muted-foreground">
        {formatDateTime(report.generatedAt)}
      </div>
      <div className="mt-1.5 flex items-center gap-2 font-mono-data text-[9px] text-muted-foreground">
        <span>Evts {report.eventCount}</span>
        <span>Alrts {report.alertCount}</span>
        <span>Scen {report.scenarioCount}</span>
      </div>
    </button>
  );
}

function ReportList({
  reports,
  loading,
  selectedId,
  onSelect,
}: {
  reports: ReportInfo[];
  loading: boolean;
  selectedId: string | null;
  onSelect: (r: ReportInfo) => void;
}) {
  if (loading) {
    return (
      <div className="space-y-2">
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-20 w-full" />
        ))}
      </div>
    );
  }
  if (reports.length === 0) return null;
  return (
    <div className="space-y-2">
      {reports.map((r) => (
        <ReportListRow
          key={r.id}
          report={r}
          selected={selectedId === r.id}
          onSelect={() => onSelect(r)}
        />
      ))}
    </div>
  );
}

// ============================================================
// Right panel — report preview
// ============================================================

function PreviewSection({
  label,
  icon: Icon,
  children,
}: {
  label: string;
  icon: LucideIcon;
  children: ReactNode;
}) {
  return (
    <section className="overflow-hidden rounded-md border border-border/40 bg-card/30">
      <div className="flex items-center gap-2 border-b border-border/40 bg-card/40 px-3 py-2">
        <Icon className="h-3.5 w-3.5 text-muted-foreground" />
        <h4 className="font-mono-data text-[11px] font-semibold uppercase tracking-wider text-foreground">
          {label}
        </h4>
      </div>
      <div className="p-3">{children}</div>
    </section>
  );
}

function StatBox({ label, value, color }: { label: string; value: ReactNode; color?: string }) {
  return (
    <div className="rounded-md border border-border/40 bg-card/40 p-2">
      <div className="font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
        {label}
      </div>
      <div className="mt-0.5 font-mono-data text-sm font-bold" style={color ? { color } : undefined}>
        {value}
      </div>
    </div>
  );
}

function ReportPreview({
  report,
  data,
}: {
  report: ReportInfo;
  data: ReportData | null;
}) {
  // Hooks must be called unconditionally — compute memos with null-safe fallbacks.
  const offenseScenarios = data?.offenseScenarios ?? [];
  const defenseScenarios = data?.defenseScenarios ?? [];
  const alerts = data?.alerts ?? [];
  const timeline = data?.timeline ?? [];
  const sortedOffense = useMemo(() => sortOffense(offenseScenarios), [offenseScenarios]);
  const sortedDefense = useMemo(() => sortDefense(defenseScenarios), [defenseScenarios]);
  const firedRules = useMemo(() => {
    const ids = new Set<string>();
    for (const a of alerts) ids.add(a.ruleId);
    return Array.from(ids).map((id) => RULES_BY_ID[id]).filter(Boolean);
  }, [alerts]);
  const timelineData = useMemo(
    () =>
      timeline.map((t) => ({
        t: formatTime(t.time),
        v: t.count,
      })),
    [timeline],
  );

  if (!data) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 px-6 py-12 text-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-full border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/10">
          <AlertTriangle className="h-7 w-7 text-[color:var(--soc-medium)]" />
        </div>
        <div>
          <h4 className="font-mono-data text-sm font-semibold uppercase tracking-wider text-foreground">
            Report Data Unavailable
          </h4>
          <p className="mx-auto mt-1.5 max-w-md text-xs text-muted-foreground">
            The underlying monitoring session for this report could not be
            located. The session may have been deleted from the database. The
            report row remains as a historical record.
          </p>
        </div>
      </div>
    );
  }

  const sev = report.riskLevel;
  const riskColor = severityColor(sev);
  const isDemoSession = data.session.mode === "demo";

  return (
    <div className="flex flex-col gap-3">
      {/* Cover / header */}
      <div
        className="relative overflow-hidden rounded-md border bg-card/40 p-3"
        style={{ borderColor: `color-mix(in oklch, ${riskColor} 35%, transparent)` }}
      >
        <div className="absolute left-0 top-0 h-full w-1" style={{ backgroundColor: riskColor }} aria-hidden />
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={sev} size="md" label={`RISK · ${sev.toUpperCase()}`} />
          <span className="font-mono-data text-[10px] text-muted-foreground">{report.reportId}</span>
          <span className="ml-auto font-mono-data text-[10px] text-muted-foreground">
            Generated {formatDateTime(report.generatedAt)}
          </span>
        </div>
        <h3 className="mt-2 font-mono-data text-base font-bold leading-tight text-foreground">
          LiveSOC Security Monitoring Report
        </h3>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          Target: <span className="font-mono-data text-foreground/90">{data.session.targetAddress}</span>{" "}
          · Mode: <span className="font-mono-data text-foreground/90">{data.session.mode.toUpperCase()}</span>{" "}
          · Duration: <span className="font-mono-data text-foreground/90">{durationLabel(data.session.durationSec)}</span>
        </p>
      </div>

      {/* Executive Summary */}
      <PreviewSection label="Executive Summary" icon={FileText}>
        <p className="text-[11px] leading-relaxed text-foreground/80">
          This report summarizes security monitoring observations for target{" "}
          <span className="font-mono-data text-foreground">{data.session.targetAddress}</span>{" "}
          collected between <span className="font-mono-data">{formatDateTime(data.session.startedAt)}</span>{" "}
          and{" "}
          <span className="font-mono-data">
            {data.session.endedAt ? formatDateTime(data.session.endedAt) : "session in progress"}
          </span>{" "}
          ({durationLabel(data.session.durationSec)}). During this period the
          platform recorded{" "}
          <span className="font-mono-data text-foreground">{data.eventsSummary.total}</span>{" "}
          telemetry events and{" "}
          <span className="font-mono-data text-foreground">{data.session.alertCount}</span>{" "}
          detection alerts, leading to{" "}
          <span className="font-mono-data text-foreground">{data.offenseScenarios.length}</span>{" "}
          potential offense scenario{data.offenseScenarios.length === 1 ? "" : "s"} and{" "}
          <span className="font-mono-data text-foreground">{data.defenseScenarios.length}</span>{" "}
          defense scenario{data.defenseScenarios.length === 1 ? "" : "s"}.
        </p>
        <p className="mt-2 text-[11px] leading-relaxed text-foreground/80">
          The overall risk level is{" "}
          <span className="font-mono-data font-bold" style={{ color: riskColor }}>
            {sev.toUpperCase()}
          </span>
          . Scenario findings represent potential attack patterns derived from
          observed telemetry — they do NOT confirm successful attacks.
        </p>
        <div className="mt-2 flex items-start gap-2 rounded-md border border-[color:var(--soc-medium)]/30 bg-[color:var(--soc-medium)]/5 px-2.5 py-1.5 text-[10px] text-[color:var(--soc-medium)]">
          <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
          <span>{AUTHORIZED_SCOPE_NOTICE}</span>
        </div>
      </PreviewSection>

      {/* Target Information */}
      <PreviewSection label="Target Information" icon={Server}>
        <div className="grid grid-cols-2 gap-x-3 gap-y-2 sm:grid-cols-4">
          <MetaField label="Address" value={data.target.address} />
          <MetaField label="Type" value={data.target.targetType} />
          <MetaField label="Hostname" value={data.target.hostname} />
          <MetaField
            label="Authorized Lab"
            value={data.target.isLab ? "Yes" : "No"}
          />
        </div>
      </PreviewSection>

      {/* Assessment Details */}
      <PreviewSection label="Initial Assessment Details" icon={Activity}>
        <div className="grid grid-cols-2 gap-x-3 gap-y-2 sm:grid-cols-4">
          <MetaField label="Reachability" value={data.assessment?.reachability ?? "—"} />
          <MetaField label="Latency" value={data.assessment?.latencyMs != null ? `${data.assessment.latencyMs} ms` : "—"} />
          <MetaField label="Hostname" value={data.assessment?.hostname ?? "—"} />
          <MetaField label="OS Guess" value={data.assessment?.osGuess ?? "—"} />
        </div>
        <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-2">
          <div className="overflow-hidden rounded-md border border-border/40 bg-card/30">
            <div className="border-b border-border/40 px-2 py-1">
              <SectionLabel>Open Ports ({data.assessment?.ports.length ?? 0})</SectionLabel>
            </div>
            <div className="soc-scrollbar max-h-40 overflow-y-auto">
              {(data.assessment?.ports ?? []).length === 0 ? (
                <div className="px-2 py-3 text-center text-[10px] text-muted-foreground">
                  No open ports recorded.
                </div>
              ) : (
                <table className="w-full text-[10px]">
                  <thead className="sticky top-0 bg-card/95">
                    <tr className="border-b border-border/40 text-left font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
                      <th className="px-2 py-1">Port</th>
                      <th className="px-2 py-1">Proto</th>
                      <th className="px-2 py-1">State</th>
                      <th className="px-2 py-1">Service</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data.assessment?.ports ?? []).map((p) => (
                      <tr key={p.id} className="border-b border-border/20 last:border-b-0">
                        <td className="px-2 py-1 font-mono-data">{p.number}</td>
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
            <div className="border-b border-border/40 px-2 py-1">
              <SectionLabel>Services ({data.assessment?.services.length ?? 0})</SectionLabel>
            </div>
            <div className="soc-scrollbar max-h-40 overflow-y-auto">
              {(data.assessment?.services ?? []).length === 0 ? (
                <div className="px-2 py-3 text-center text-[10px] text-muted-foreground">
                  No service details recorded.
                </div>
              ) : (
                <table className="w-full text-[10px]">
                  <thead className="sticky top-0 bg-card/95">
                    <tr className="border-b border-border/40 text-left font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground/70">
                      <th className="px-2 py-1">Name</th>
                      <th className="px-2 py-1">Port</th>
                      <th className="px-2 py-1">Product</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data.assessment?.services ?? []).map((s) => (
                      <tr key={s.id} className="border-b border-border/20 last:border-b-0">
                        <td className="px-2 py-1 font-mono-data">{s.name}</td>
                        <td className="px-2 py-1 font-mono-data text-muted-foreground">{s.port}</td>
                        <td className="px-2 py-1 text-muted-foreground">{[s.product, s.version].filter(Boolean).join(" ") || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
        <div className="mt-2 text-[10px] italic text-muted-foreground">
          The assessment above reflects an initial discovery scan conducted at the
          start of the session. Live monitoring results (events, alerts,
          scenarios) are reported in subsequent sections.
        </div>
      </PreviewSection>

      {/* Monitoring Summary */}
      <PreviewSection label="Live Monitoring Summary" icon={Activity}>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
          <StatBox label="Total Events" value={data.eventsSummary.total} />
          <StatBox label="Critical" value={data.eventsSummary.bySeverity.critical} color="var(--soc-critical)" />
          <StatBox label="High" value={data.eventsSummary.bySeverity.high} color="var(--soc-high)" />
          <StatBox label="Medium" value={data.eventsSummary.bySeverity.medium} color="var(--soc-medium)" />
          <StatBox label="Low" value={data.eventsSummary.bySeverity.low} color="var(--soc-low)" />
        </div>
        <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3">
          <StatBox label="Duration" value={durationLabel(data.session.durationSec)} />
          <StatBox label="Alerts" value={data.session.alertCount} color="var(--soc-high)" />
          <StatBox label="Offense Scenarios" value={data.offenseScenarios.length} color="var(--soc-critical)" />
        </div>
      </PreviewSection>

      {/* Security Findings */}
      <PreviewSection label="Security Findings (Alerts)" icon={AlertTriangle}>
        {data.alerts.length === 0 ? (
          <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border/50 px-4 py-6 text-[11px] text-muted-foreground">
            <CheckCircle2 className="h-4 w-4 opacity-50" />
            No alerts were triggered during this session.
          </div>
        ) : (
          <div className="soc-scrollbar max-h-72 space-y-1.5 overflow-y-auto pr-1">
            {data.alerts.map((a) => {
              const color = severityColor(a.severity);
              return (
                <div
                  key={a.id}
                  className="relative overflow-hidden rounded-md border bg-card/40 p-2 pl-3"
                  style={{ borderColor: `color-mix(in oklch, ${color} 30%, transparent)` }}
                >
                  <div className="absolute left-0 top-0 h-full w-1" style={{ backgroundColor: color }} aria-hidden />
                  <div className="flex flex-wrap items-center gap-1.5">
                    <SeverityBadge severity={a.severity} size="sm" />
                    <span className="font-mono-data text-[10px] font-semibold text-foreground">{a.ruleName}</span>
                    <span className="font-mono-data text-[9px] text-muted-foreground">{a.alertId}</span>
                    <span className="ml-auto font-mono-data text-[9px] text-muted-foreground">
                      {formatTime(a.timestamp)}
                    </span>
                  </div>
                  <p className="mt-0.5 text-[10px] leading-snug text-foreground/80">{a.message}</p>
                  {a.recommendedAction && (
                    <div className="mt-1 text-[10px] text-[color:var(--soc-success)]">
                      <span className="font-mono-data font-semibold uppercase">Action:</span>{" "}
                      {a.recommendedAction}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </PreviewSection>

      {/* Offense Analysis */}
      <PreviewSection label="Offense Analysis" icon={Swords}>
        {sortedOffense.length === 0 ? (
          <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border/50 px-4 py-6 text-[11px] text-muted-foreground">
            No potential offense scenarios were derived from this session.
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
            {sortedOffense.map((s) => {
              const color = severityColor(s.severity);
              const steps = parseAttackPath(s.attackPath);
              return (
                <div
                  key={s.scenarioId}
                  className="relative overflow-hidden rounded-md border bg-card/40 p-2 pl-3"
                  style={{ borderColor: `color-mix(in oklch, ${color} 30%, transparent)` }}
                >
                  <div className="absolute left-0 top-0 h-full w-1" style={{ backgroundColor: color }} aria-hidden />
                  <div className="flex flex-wrap items-center gap-1.5">
                    <SeverityBadge severity={s.severity} size="sm" />
                    {s.techniqueMitre && (
                      <span
                        className="rounded-sm border px-1 py-0.5 font-mono-data text-[9px] font-bold"
                        style={{
                          color,
                          borderColor: `color-mix(in oklch, ${color} 40%, transparent)`,
                          backgroundColor: `color-mix(in oklch, ${color} 12%, transparent)`,
                        }}
                      >
                        {s.techniqueMitre}
                      </span>
                    )}
                  </div>
                  <div className="mt-1 truncate font-mono-data text-[11px] font-semibold text-foreground" title={s.title}>
                    {s.title}
                  </div>
                  <div className="mt-0.5 font-mono-data text-[9px] text-muted-foreground">
                    {s.scenarioId} · {s.category} · Conf {s.confidence}%
                  </div>
                  {s.potentialImpact && (
                    <p className="mt-1 text-[10px] leading-snug text-foreground/70">{s.potentialImpact}</p>
                  )}
                  {steps.length > 0 && (
                    <div className="mt-1 font-mono-data text-[9px] text-muted-foreground">
                      Path: {steps.join(" → ")}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
        <div className="mt-2 text-[10px] italic text-muted-foreground">
          Scenarios represent potential attack patterns derived from observed
          telemetry and exposed services. They do NOT confirm successful attacks.
        </div>
      </PreviewSection>

      {/* Defense Analysis */}
      <PreviewSection label="Defense Analysis" icon={Shield}>
        {sortedDefense.length === 0 ? (
          <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border/50 px-4 py-6 text-[11px] text-muted-foreground">
            No defense scenarios were derived from this session.
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
            {sortedDefense.map((s) => {
              const color = severityColor(s.priority);
              return (
                <div
                  key={s.scenarioId}
                  className="relative overflow-hidden rounded-md border bg-card/40 p-2 pl-3"
                  style={{ borderColor: `color-mix(in oklch, ${color} 30%, transparent)` }}
                >
                  <div className="absolute left-0 top-0 h-full w-1" style={{ backgroundColor: color }} aria-hidden />
                  <div className="flex flex-wrap items-center gap-1.5">
                    <SeverityBadge severity={s.priority} size="sm" label={s.priority.toUpperCase()} />
                    {s.relatedOffenseId && (
                      <span className="font-mono-data text-[9px] text-[color:var(--soc-critical)]">
                        Addresses {s.relatedOffenseId}
                      </span>
                    )}
                  </div>
                  <div className="mt-1 truncate font-mono-data text-[11px] font-semibold text-foreground" title={s.title}>
                    {s.title}
                  </div>
                  {s.recommendedAction && (
                    <p className="mt-1 text-[10px] leading-snug text-[color:var(--soc-success)]">
                      <span className="font-mono-data font-semibold uppercase">Action:</span>{" "}
                      {s.recommendedAction}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </PreviewSection>

      {/* Risk Summary */}
      <PreviewSection label="Risk Summary" icon={ShieldAlert}>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <StatBox label="Risk Level" value={sev.toUpperCase()} color={riskColor} />
          <StatBox label="Total Alerts" value={data.session.alertCount} />
          <StatBox label="Offense Scenarios" value={data.offenseScenarios.length} />
          <StatBox label="Top Source IPs" value={data.topSourceIps.length} />
        </div>
        <p className="mt-2 text-[11px] leading-relaxed text-foreground/80">{data.riskSummary}</p>
        {(data.topSourceIps.length > 0 || data.topDestPorts.length > 0) && (
          <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <SectionLabel>Top Source IPs</SectionLabel>
              <div className="mt-1 space-y-0.5">
                {data.topSourceIps.map((s) => (
                  <div key={s.key} className="flex items-center justify-between font-mono-data text-[10px]">
                    <span className="text-foreground/90">{s.key}</span>
                    <span className="text-muted-foreground">{s.count}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <SectionLabel>Top Destination Ports</SectionLabel>
              <div className="mt-1 space-y-0.5">
                {data.topDestPorts.map((s) => (
                  <div key={s.key} className="flex items-center justify-between font-mono-data text-[10px]">
                    <span className="text-foreground/90">:{s.key}</span>
                    <span className="text-muted-foreground">{s.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </PreviewSection>

      {/* Detection Timeline */}
      <PreviewSection label="Detection Timeline" icon={Activity}>
        {timelineData.length === 0 ? (
          <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border/50 px-4 py-6 text-[11px] text-muted-foreground">
            No timeline data available.
          </div>
        ) : (
          <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="reportTimeline" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--soc-low)" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="var(--soc-low)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border)" strokeOpacity={0.2} vertical={false} />
                <XAxis
                  dataKey="t"
                  tick={{ fill: "var(--muted-foreground)", fontSize: 9, fontFamily: "var(--font-mono-data)" }}
                  tickLine={{ stroke: "var(--border)" }}
                  axisLine={{ stroke: "var(--border)" }}
                  interval="preserveStartEnd"
                  minTickGap={30}
                />
                <YAxis
                  tick={{ fill: "var(--muted-foreground)", fontSize: 9, fontFamily: "var(--font-mono-data)" }}
                  tickLine={{ stroke: "var(--border)" }}
                  axisLine={{ stroke: "var(--border)" }}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "var(--card)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    fontSize: 11,
                  }}
                  labelStyle={{ color: "var(--foreground)", fontFamily: "var(--font-mono-data)" }}
                />
                <Area
                  type="monotone"
                  dataKey="v"
                  name="Events"
                  stroke="var(--soc-low)"
                  strokeWidth={1.5}
                  fill="url(#reportTimeline)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
        <div className="mt-1 font-mono-data text-[9px] text-muted-foreground">
          {timelineData.length} 5-second buckets · max {Math.max(0, ...timelineData.map((d) => d.v))} evts/bucket
        </div>
      </PreviewSection>

      {/* Recommendations */}
      <PreviewSection label="Recommendations" icon={CheckCircle2}>
        {data.recommendations.length === 0 ? (
          <div className="text-[11px] text-muted-foreground">
            No specific recommendations were generated. Apply general hardening
            practices within your authorized operational scope.
          </div>
        ) : (
          <ol className="ml-4 list-decimal space-y-1 text-[11px] leading-relaxed text-foreground/80">
            {data.recommendations.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ol>
        )}
      </PreviewSection>

      {/* Technical Appendix */}
      <PreviewSection label="Technical Appendix" icon={ScrollText}>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <div>
            <SectionLabel>Detection Rules Fired ({firedRules.length})</SectionLabel>
            <div className="mt-1.5 space-y-1">
              {firedRules.length === 0 ? (
                <div className="text-[10px] text-muted-foreground">No detection rules fired.</div>
              ) : (
                firedRules.map((r) => {
                  const color = severityColor(r.severity);
                  return (
                    <div key={r.ruleId} className="rounded-sm border border-border/40 bg-card/30 px-2 py-1">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="rounded-sm px-1 py-0.5 font-mono-data text-[9px] font-bold"
                          style={{
                            color,
                            backgroundColor: `color-mix(in oklch, ${color} 15%, transparent)`,
                          }}
                        >
                          {r.ruleId}
                        </span>
                        <span className="font-mono-data text-[10px] font-semibold text-foreground">{r.name}</span>
                      </div>
                      <div className="mt-0.5 text-[10px] text-muted-foreground">
                        {r.conditions}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
          <div>
            <SectionLabel>All Detection Rules Reference</SectionLabel>
            <div className="mt-1.5 grid grid-cols-1 gap-0.5">
              {DETECTION_RULES.map((r) => (
                <div key={r.ruleId} className="flex items-center justify-between font-mono-data text-[9px]">
                  <span className="text-muted-foreground">
                    {r.ruleId} · {r.name}
                  </span>
                  <span style={{ color: severityColor(r.severity) }}>{r.severity.toUpperCase()}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="mt-3">
          <SectionLabel>Event Log Summary</SectionLabel>
          <div className="mt-1.5 grid grid-cols-2 gap-2 sm:grid-cols-5">
            <StatBox label="Total" value={data.eventsSummary.total} />
            <StatBox label="Critical" value={data.eventsSummary.bySeverity.critical} color="var(--soc-critical)" />
            <StatBox label="High" value={data.eventsSummary.bySeverity.high} color="var(--soc-high)" />
            <StatBox label="Medium" value={data.eventsSummary.bySeverity.medium} color="var(--soc-medium)" />
            <StatBox label="Low / Info" value={data.eventsSummary.bySeverity.low + data.eventsSummary.bySeverity.info} color="var(--soc-low)" />
          </div>
          <div className="mt-2 text-[10px] italic text-muted-foreground">
            Detailed per-event records are preserved in the monitoring database
            and surfaced in the Alerts and Scenario sections of this report.
            Contact your administrator for raw event export.
          </div>
        </div>
      </PreviewSection>

      {/* Footer */}
      <div className="rounded-md border border-border/40 bg-card/20 px-3 py-2 text-center text-[10px] text-muted-foreground">
        <span className="font-mono-data font-semibold uppercase tracking-wider">LiveSOC</span>{" "}
        · Security Monitoring Report · {report.reportId} · Generated {formatDateTime(report.generatedAt)}
        {isDemoSession && (
          <span className="ml-2 rounded-sm border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-1 py-0.5 font-mono-data text-[9px] font-bold uppercase text-[color:var(--soc-medium)]">
            Contains Demo Telemetry
          </span>
        )}
      </div>
    </div>
  );
}

// ============================================================
// Empty states
// ============================================================

function NoReportsEmptyState() {
  const setView = useAppStore((s) => s.setView);
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 py-12 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full border border-border/40 bg-muted/30">
        <FileText className="h-8 w-8 text-muted-foreground/60" />
      </div>
      <div>
        <h3 className="font-mono-data text-base font-bold uppercase tracking-wider text-foreground">
          No Reports Yet
        </h3>
        <p className="mx-auto mt-1.5 max-w-md text-sm text-muted-foreground">
          Generate a report from a monitoring session. Reports persist in the
          database and survive restarts.
        </p>
      </div>
      <Button size="sm" className="gap-1.5" onClick={() => setView("monitor")}>
        <Activity className="h-4 w-4" />
        Go to Live Monitor
      </Button>
    </div>
  );
}

function NoSelectionState() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-full border border-border/40 bg-muted/30">
        <Eye className="h-7 w-7 text-muted-foreground/60" />
      </div>
      <div>
        <h4 className="font-mono-data text-sm font-semibold uppercase tracking-wider text-foreground/80">
          Select a Report
        </h4>
        <p className="mx-auto mt-1.5 max-w-sm text-xs text-muted-foreground">
          Choose a report from the list to view its full content. Use{" "}
          <span className="font-mono-data text-foreground">Download PDF</span>{" "}
          to save it as a printable document.
        </p>
      </div>
    </div>
  );
}

// ============================================================
// PDF print (open new window with print-optimized HTML)
// ============================================================

function buildReportHtml(report: ReportInfo, data: ReportData): string {
  const sev = report.riskLevel;
  const riskColor = severityColor(sev);
  const sortedOffense = sortOffense(data.offenseScenarios);
  const sortedDefense = sortDefense(data.defenseScenarios);
  const firedRules = Array.from(new Set(data.alerts.map((a) => a.ruleId)))
    .map((id) => RULES_BY_ID[id])
    .filter(Boolean);
  const escapeHtml = (s: string) =>
    s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  const e = escapeHtml;
  const portsRows = (data.assessment?.ports ?? [])
    .map(
      (p) =>
        `<tr><td>${p.number}</td><td>${e(p.protocol)}</td><td>${e(p.state)}</td><td>${e(p.serviceName ?? "—")}</td></tr>`,
    )
    .join("");
  const servicesRows = (data.assessment?.services ?? [])
    .map(
      (s) =>
        `<tr><td>${e(s.name)}</td><td>${s.port}</td><td>${e(s.product ?? "—")}</td><td>${e(s.version ?? "—")}</td></tr>`,
    )
    .join("");
  const alertsHtml = data.alerts
    .map((a) => {
      const c = severityColor(a.severity);
      return `<div class="alert" style="border-color:${c}">
        <div class="alert-h"><span class="sev" style="background:${c}">${a.severity.toUpperCase()}</span>
          <strong>${e(a.ruleName)}</strong>
          <span class="mid">${e(a.alertId)}</span>
          <span class="ts">${e(formatTime(a.timestamp))}</span></div>
        <div class="alert-b">${e(a.message)}</div>
        ${a.recommendedAction ? `<div class="alert-a">Action: ${e(a.recommendedAction)}</div>` : ""}
      </div>`;
    })
    .join("");
  const offenseHtml = sortedOffense
    .map((s) => {
      const c = severityColor(s.severity);
      const steps = parseAttackPath(s.attackPath).join(" → ");
      return `<div class="scn" style="border-color:${c}">
        <div class="scn-h"><span class="sev" style="background:${c}">${s.severity.toUpperCase()}</span>
          ${s.techniqueMitre ? `<span class="mitre" style="border-color:${c};color:${c}">${e(s.techniqueMitre)}</span>` : ""}
          <strong>${e(s.title)}</strong></div>
        <div class="scn-m">${e(s.scenarioId)} · ${e(s.category)} · Conf ${s.confidence}%</div>
        ${s.potentialImpact ? `<div class="scn-b">${e(s.potentialImpact)}</div>` : ""}
        ${steps ? `<div class="scn-p">Path: ${e(steps)}</div>` : ""}
      </div>`;
    })
    .join("");
  const defenseHtml = sortedDefense
    .map((s) => {
      const c = severityColor(s.priority);
      return `<div class="scn" style="border-color:${c}">
        <div class="scn-h"><span class="sev" style="background:${c}">${s.priority.toUpperCase()}</span>
          <strong>${e(s.title)}</strong></div>
        ${s.recommendedAction ? `<div class="scn-a">Action: ${e(s.recommendedAction)}</div>` : ""}
      </div>`;
    })
    .join("");
  const recsHtml = data.recommendations.length
    ? `<ol>${data.recommendations.map((r) => `<li>${e(r)}</li>`).join("")}</ol>`
    : "<p>No specific recommendations were generated.</p>";
  const rulesHtml = firedRules.length
    ? firedRules
        .map(
          (r) =>
            `<div class="rule"><span class="rid" style="background:${severityColor(r.severity)}">${e(r.ruleId)}</span> <strong>${e(r.name)}</strong> — ${e(r.conditions)}</div>`,
        )
        .join("")
    : "<p>No detection rules fired.</p>";
  const topSrc = data.topSourceIps
    .map((s) => `<li>${e(s.key)} — ${s.count}</li>`)
    .join("");
  const topDst = data.topDestPorts
    .map((s) => `<li>:${e(s.key)} — ${s.count}</li>`)
    .join("");
  const sevCounts = data.eventsSummary.bySeverity;

  return `<!doctype html>
<html><head><meta charset="utf-8">
<title>LiveSOC Report ${e(report.reportId)}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; font-size: 11pt; line-height: 1.45; }
  h1 { font-size: 18pt; margin: 0 0 4pt 0; color: #0f172a; }
  h2 { font-size: 12pt; text-transform: uppercase; letter-spacing: 0.05em; margin: 18pt 0 6pt 0; padding-bottom: 3pt; border-bottom: 2px solid ${riskColor}; color: #0f172a; }
  h3 { font-size: 11pt; margin: 10pt 0 4pt 0; color: #1e293b; }
  p { margin: 4pt 0; }
  .mono { font-family: "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace; font-size: 9.5pt; }
  .cover { border-left: 4px solid ${riskColor}; padding: 8pt 12pt; background: #f8fafc; border-radius: 3pt; margin-bottom: 10pt; }
  .cover .meta { font-size: 9.5pt; color: #475569; margin-top: 3pt; }
  .risk-pill { display: inline-block; background: ${riskColor}; color: #fff; padding: 2pt 8pt; border-radius: 3pt; font-size: 9pt; font-weight: 700; letter-spacing: 0.06em; }
  .notice { border: 1px solid #f59e0b; background: #fef3c7; color: #92400e; padding: 6pt 10pt; border-radius: 3pt; font-size: 9.5pt; margin: 8pt 0; }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6pt; margin: 6pt 0; }
  .stat { border: 1px solid #e2e8f0; border-radius: 3pt; padding: 6pt 8pt; background: #f8fafc; }
  .stat .l { font-size: 8pt; text-transform: uppercase; letter-spacing: 0.06em; color: #64748b; }
  .stat .v { font-family: "JetBrains Mono", monospace; font-size: 13pt; font-weight: 700; margin-top: 2pt; }
  table { width: 100%; border-collapse: collapse; margin: 4pt 0; font-size: 9.5pt; }
  th { background: #f1f5f9; text-align: left; padding: 4pt 6pt; border-bottom: 1px solid #cbd5e1; font-size: 8.5pt; text-transform: uppercase; letter-spacing: 0.04em; color: #475569; }
  td { padding: 3pt 6pt; border-bottom: 1px solid #e2e8f0; }
  .alert { border-left: 4px solid #888; padding: 5pt 8pt; margin: 4pt 0; background: #f8fafc; border-radius: 2pt; }
  .alert .alert-h { font-size: 10pt; }
  .alert .alert-b { font-size: 9.5pt; color: #334155; margin-top: 2pt; }
  .alert .alert-a { font-size: 9pt; color: #047857; margin-top: 2pt; }
  .alert .sev, .scn .sev { display: inline-block; color: #fff; padding: 1pt 6pt; border-radius: 2pt; font-size: 8pt; font-weight: 700; letter-spacing: 0.05em; margin-right: 4pt; }
  .alert .ts, .alert .mid { color: #64748b; font-family: "JetBrains Mono", monospace; font-size: 8.5pt; margin-left: 4pt; }
  .scn { border-left: 4px solid #888; padding: 5pt 8pt; margin: 4pt 0; background: #f8fafc; border-radius: 2pt; }
  .scn .scn-h { font-size: 10pt; }
  .scn .scn-m { font-family: "JetBrains Mono", monospace; font-size: 8.5pt; color: #64748b; margin-top: 1pt; }
  .scn .scn-b { font-size: 9.5pt; color: #334155; margin-top: 2pt; }
  .scn .scn-p { font-family: "JetBrains Mono", monospace; font-size: 8.5pt; color: #64748b; margin-top: 2pt; }
  .scn .scn-a { font-size: 9.5pt; color: #047857; margin-top: 2pt; }
  .scn .mitre { display: inline-block; border: 1px solid #888; padding: 0 4pt; border-radius: 2pt; font-size: 8pt; font-weight: 700; margin-right: 4pt; font-family: "JetBrains Mono", monospace; }
  .scn-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4pt; }
  .rule { font-size: 9.5pt; margin: 2pt 0; }
  .rule .rid { display: inline-block; color: #fff; padding: 1pt 5pt; border-radius: 2pt; font-size: 8pt; font-weight: 700; margin-right: 4pt; font-family: "JetBrains Mono", monospace; }
  ol { padding-left: 16pt; }
  .footer { border-top: 1px solid #cbd5e1; margin-top: 14pt; padding-top: 6pt; font-size: 8.5pt; color: #64748b; text-align: center; }
  .tag { display: inline-block; border: 1px solid #f59e0b; background: #fef3c7; color: #92400e; padding: 1pt 6pt; border-radius: 2pt; font-size: 8pt; font-weight: 700; letter-spacing: 0.05em; margin-left: 6pt; }
  .small-italic { font-size: 9pt; font-style: italic; color: #64748b; margin-top: 4pt; }
  @media print { body { font-size: 10pt; } h2 { page-break-after: avoid; } .alert, .scn { page-break-inside: avoid; } }
</style></head>
<body>
  <div class="cover">
    <h1>LiveSOC Security Monitoring Report</h1>
    <div class="meta">
      <span class="risk-pill">RISK · ${sev.toUpperCase()}</span>
      &nbsp; <span class="mono">${e(report.reportId)}</span>
      &nbsp; Generated ${e(formatDateTime(report.generatedAt))}
    </div>
    <div class="meta">
      Target: <span class="mono">${e(data.session.targetAddress)}</span>
      &nbsp; Mode: <span class="mono">${e(data.session.mode.toUpperCase())}</span>
      &nbsp; Duration: <span class="mono">${durationLabel(data.session.durationSec)}</span>
    </div>
  </div>

  <div class="notice">⚠ ${AUTHORIZED_SCOPE_NOTICE}</div>

  <h2>1. Executive Summary</h2>
  <p>This report summarizes security monitoring observations for target <span class="mono">${e(data.session.targetAddress)}</span> collected between <span class="mono">${e(formatDateTime(data.session.startedAt))}</span> and <span class="mono">${data.session.endedAt ? e(formatDateTime(data.session.endedAt)) : "session in progress"}</span> (${durationLabel(data.session.durationSec)}). During this period the platform recorded <strong>${data.eventsSummary.total}</strong> telemetry events and <strong>${data.session.alertCount}</strong> detection alerts, leading to <strong>${data.offenseScenarios.length}</strong> potential offense scenario(s) and <strong>${data.defenseScenarios.length}</strong> defense scenario(s).</p>
  <p>The overall risk level is <strong style="color:${riskColor}">${sev.toUpperCase()}</strong>. Scenario findings represent potential attack patterns derived from observed telemetry — they do NOT confirm successful attacks.</p>

  <h2>2. Target Information</h2>
  <table>
    <tr><th>Address</th><td class="mono">${e(data.target.address)}</td><th>Type</th><td>${e(data.target.targetType)}</td></tr>
    <tr><th>Hostname</th><td>${e(data.target.hostname ?? "—")}</td><th>Authorized Lab</th><td>${data.target.isLab ? "Yes" : "No"}</td></tr>
  </table>

  <h2>3. Initial Assessment Details</h2>
  <table>
    <tr><th>Reachability</th><td>${e(data.assessment?.reachability ?? "—")}</td><th>Latency</th><td>${data.assessment?.latencyMs != null ? data.assessment.latencyMs + " ms" : "—"}</td></tr>
    <tr><th>Hostname</th><td>${e(data.assessment?.hostname ?? "—")}</td><th>OS Guess</th><td>${e(data.assessment?.osGuess ?? "—")}</td></tr>
  </table>
  <h3>Open Ports (${data.assessment?.ports.length ?? 0})</h3>
  <table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead><tbody>${portsRows || '<tr><td colspan="4">No open ports recorded.</td></tr>'}</tbody></table>
  <h3>Services (${data.assessment?.services.length ?? 0})</h3>
  <table><thead><tr><th>Name</th><th>Port</th><th>Product</th><th>Version</th></tr></thead><tbody>${servicesRows || '<tr><td colspan="4">No service details recorded.</td></tr>'}</tbody></table>
  <p class="small-italic">The assessment above reflects an initial discovery scan conducted at the start of the session. Live monitoring results are reported in subsequent sections.</p>

  <h2>4. Live Monitoring Summary</h2>
  <div class="grid">
    <div class="stat"><div class="l">Total Events</div><div class="v">${data.eventsSummary.total}</div></div>
    <div class="stat"><div class="l">Critical</div><div class="v" style="color:${severityColor("critical")}">${sevCounts.critical}</div></div>
    <div class="stat"><div class="l">High</div><div class="v" style="color:${severityColor("high")}">${sevCounts.high}</div></div>
    <div class="stat"><div class="l">Medium</div><div class="v" style="color:${severityColor("medium")}">${sevCounts.medium}</div></div>
    <div class="stat"><div class="l">Low</div><div class="v" style="color:${severityColor("low")}">${sevCounts.low}</div></div>
    <div class="stat"><div class="l">Info</div><div class="v" style="color:${severityColor("info")}">${sevCounts.info}</div></div>
    <div class="stat"><div class="l">Alerts</div><div class="v">${data.session.alertCount}</div></div>
    <div class="stat"><div class="l">Scenarios</div><div class="v">${data.offenseScenarios.length}</div></div>
  </div>

  <h2>5. Security Findings (Alerts)</h2>
  ${data.alerts.length === 0 ? '<p>No alerts were triggered during this session.</p>' : alertsHtml}

  <h2>6. Offense Analysis</h2>
  ${sortedOffense.length === 0 ? '<p>No potential offense scenarios were derived from this session.</p>' : `<div class="scn-grid">${offenseHtml}</div>`}
  <p class="small-italic">Scenarios represent potential attack patterns derived from observed telemetry and exposed services. They do NOT confirm successful attacks.</p>

  <h2>7. Defense Analysis</h2>
  ${sortedDefense.length === 0 ? '<p>No defense scenarios were derived from this session.</p>' : `<div class="scn-grid">${defenseHtml}</div>`}

  <h2>8. Risk Summary</h2>
  <p><strong>Risk Level: <span style="color:${riskColor}">${sev.toUpperCase()}</span></strong> &nbsp; Total Alerts: ${data.session.alertCount} &nbsp; Offense Scenarios: ${data.offenseScenarios.length}</p>
  <p>${e(data.riskSummary)}</p>
  ${topSrc ? `<h3>Top Source IPs</h3><ul class="mono">${topSrc}</ul>` : ""}
  ${topDst ? `<h3>Top Destination Ports</h3><ul class="mono">${topDst}</ul>` : ""}

  <h2>9. Recommendations</h2>
  ${recsHtml}

  <h2>10. Technical Appendix — Detection Rules Fired</h2>
  ${rulesHtml}
  <h3>All Detection Rules Reference</h3>
  <table><thead><tr><th>Rule ID</th><th>Name</th><th>Severity</th><th>Conditions</th></tr></thead><tbody>
    ${DETECTION_RULES.map((r) => `<tr><td class="mono">${e(r.ruleId)}</td><td>${e(r.name)}</td><td style="color:${severityColor(r.severity)}">${r.severity.toUpperCase()}</td><td>${e(r.conditions)}</td></tr>`).join("")}
  </tbody></table>

  <div class="footer">
    LiveSOC · Security Monitoring Report · <span class="mono">${e(report.reportId)}</span> · Generated ${e(formatDateTime(report.generatedAt))}
    ${data.session.mode === "demo" ? '<span class="tag">Contains Demo Telemetry</span>' : ""}
  </div>
</body></html>`;
}

function printReport(report: ReportInfo, data: ReportData) {
  const html = buildReportHtml(report, data);
  const w = window.open("", "_blank", "width=900,height=700");
  if (!w) {
    toast.error("Pop-up blocked. Please allow pop-ups for this site to print reports.");
    return;
  }
  w.document.open();
  w.document.write(html);
  w.document.close();
  // Give the new window a moment to render before triggering print.
  setTimeout(() => {
    try {
      w.focus();
      w.print();
    } catch {
      /* ignore */
    }
  }, 400);
}

// ============================================================
// Main view
// ============================================================

export function ReportsView() {
  const sessionId = useAppStore((s) => s.sessionId);
  const status = useAppStore((s) => s.status);
  const [reports, setReports] = useState<ReportInfo[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ReportInfo | null>(null);
  const [detail, setDetail] = useState<ReportDetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);

  const monitorActive = status === "monitoring" || status === "scanning" || status === "initializing";

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const res: ReportListResponse = await api.getReports({ page: 1, pageSize: 100 });
      const normalized = (res.reports ?? []).map(normalizeReportInfo);
      setReports(normalized);
      setTotal(res.total ?? 0);
      // Auto-select the most recent report if nothing is selected
      setSelected((prev) => prev ?? normalized[0] ?? null);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to load reports.";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchReports();
  }, []);

  // Fetch detail when selection changes
  useEffect(() => {
    if (!selected) {
      setDetail(null);
      setDetailError(null);
      return;
    }
    let cancelled = false;
    const run = async () => {
      setDetailLoading(true);
      setDetailError(null);
      try {
        const res = await api.getReport(selected.reportId);
        if (cancelled) return;
        setDetail({
          report: normalizeReportInfo(res.report),
          summary: res.summary,
          data: res.data,
        });
      } catch (e) {
        if (cancelled) return;
        const msg = e instanceof Error ? e.message : "Failed to load report.";
        setDetailError(msg);
        toast.error(msg);
      } finally {
        if (!cancelled) setDetailLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [selected]);

  const handleGenerate = async () => {
    if (!sessionId) {
      toast.error("No active monitoring session to generate a report from.");
      return;
    }
    setGenerating(true);
    try {
      const res = await api.generateReport(sessionId);
      const newReport = normalizeReportInfo(res.report);
      toast.success(`Report ${newReport.reportId} generated.`);
      // Refresh list + auto-select the new report
      await fetchReports();
      setSelected(newReport);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to generate report.";
      toast.error(msg);
    } finally {
      setGenerating(false);
    }
  };

  const handlePrint = () => {
    if (!detail?.report) return;
    const data = normalizeReportData(detail.data);
    if (!data) {
      toast.error("Report data is unavailable for download.");
      return;
    }
    printReport(detail.report, data);
  };

  const mostRecentLabel = reports.length > 0 ? formatDateTime(reports[0].generatedAt) : "—";
  const avgRiskLabel = useMemo(() => {
    if (reports.length === 0) return "—";
    const ranks = reports.map((r) => SEVERITY_ORDER[r.riskLevel] ?? 0);
    const avg = ranks.reduce((a, b) => a + b, 0) / ranks.length;
    // Pick the nearest severity label
    const entries = Object.entries(SEVERITY_ORDER) as [Severity, number][];
    let nearest = entries[0][0];
    let nearestDiff = Infinity;
    for (const [s, v] of entries) {
      const diff = Math.abs(v - avg);
      if (diff < nearestDiff) {
        nearestDiff = diff;
        nearest = s;
      }
    }
    return nearest.toUpperCase();
  }, [reports]);

  const reportData = detail ? normalizeReportData(detail.data) : null;
  const showEmpty = !loading && !error && reports.length === 0;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <ReportsHeader
        onRefresh={() => void fetchReports()}
        refreshing={loading}
        onGenerate={handleGenerate}
        generating={generating}
        canGenerate={!!sessionId && monitorActive}
      />

      <div className="shrink-0 border-b border-border/40 px-3 py-3">
        <SummaryRow total={total} mostRecent={mostRecentLabel} avgRisk={avgRiskLabel} />
      </div>

      <div className="soc-scrollbar min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
        {showEmpty ? (
          <NoReportsEmptyState />
        ) : (
          <div className="grid grid-cols-1 gap-3 p-3 lg:grid-cols-3">
            {/* Left: list */}
            <div className="lg:col-span-1">
              {error && (
                <div className="mb-2 flex items-center gap-2 rounded-md border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 px-3 py-2 text-[11px] text-[color:var(--soc-critical)]">
                  <XCircle className="h-3.5 w-3.5" />
                  {error}
                </div>
              )}
              <div className="mb-2 flex items-center justify-between">
                <SectionLabel>Reports ({reports.length})</SectionLabel>
              </div>
              <ReportList
                reports={reports}
                loading={loading}
                selectedId={selected?.id ?? null}
                onSelect={setSelected}
              />
            </div>

            {/* Right: detail */}
            <div className="lg:col-span-2">
              {!selected ? (
                <NoSelectionState />
              ) : detailLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-32 w-full" />
                  <Skeleton className="h-48 w-full" />
                  <Skeleton className="h-32 w-full" />
                </div>
              ) : detailError ? (
                <div className="flex items-center gap-2 rounded-md border border-[color:var(--soc-critical)]/40 bg-[color:var(--soc-critical)]/10 px-3 py-2 text-[11px] text-[color:var(--soc-critical)]">
                  <XCircle className="h-3.5 w-3.5" />
                  {detailError}
                </div>
              ) : detail ? (
                <div className="flex flex-col gap-3">
                  {/* Action bar */}
                  <div className="flex items-center justify-between gap-2 rounded-md border border-border/40 bg-card/30 px-3 py-2">
                    <div className="min-w-0">
                      <div className="truncate font-mono-data text-[11px] font-semibold text-foreground">
                        {detail.report.reportId}
                      </div>
                      <div className="truncate font-mono-data text-[9px] text-muted-foreground">
                        {detail.report.title}
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Button
                        size="sm"
                        onClick={handlePrint}
                        disabled={!reportData}
                        className="h-7 gap-1.5 text-[11px]"
                        title={reportData ? "Open print dialog (save as PDF)" : "Report data unavailable"}
                      >
                        <Download className="h-3 w-3" />
                        Download PDF
                      </Button>
                    </div>
                  </div>
                  {detail.report && (
                    <ReportPreview report={detail.report} data={reportData} />
                  )}
                </div>
              ) : null}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
