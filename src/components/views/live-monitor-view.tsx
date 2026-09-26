"use client";

import { useMemo, useState, useCallback, type ReactNode } from "react";
import {
  Activity,
  Square,
  Pause,
  Play,
  Trash2,
  Search,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Shield,
  Network as NetworkIcon,
  AlertTriangle,
  AlertOctagon,
  AlertCircle,
  ShieldAlert,
  Zap,
  Gauge,
  Server,
  Info,
  CheckCircle,
  CheckCheck,
  ShieldCheck,
  RotateCcw,
  Eye,
  Layers,
  AlignJustify,
  LucideIcon,
} from "lucide-react";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import { useAppStore } from "@/lib/store";
import { api } from "@/lib/api-client";
import { Panel } from "@/components/soc/panel";
import { KpiCard } from "@/components/soc/kpi-card";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { StatusDot } from "@/components/soc/status-dot";
import { AuthWarning } from "@/components/soc/auth-warning";
import { EventDetailDrawer } from "@/components/soc/event-detail-drawer";
import { ExportMenu } from "@/components/soc/export-menu";
import { ThreatMapPanel } from "@/components/soc/threat-map-panel";
import { RiskGaugePanel } from "@/components/soc/risk-gauge-panel";
import { MitreMatrixPanel } from "@/components/soc/mitre-matrix-panel";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { severityColor, SEVERITY_ORDER } from "@/lib/constants";
import type {
  Severity,
  SecurityEvent,
  SecurityAlert,
  ServiceInfo,
  TopItem,
  ProtocolDistribution,
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

function portAccentColor(port: number): string {
  if (port === 22 || port === 3389) return "var(--soc-medium)";
  if ([80, 443, 8080, 8443].includes(port)) return "var(--soc-low)";
  if ([3306, 5432, 6379, 1433, 27017, 1521].includes(port)) return "var(--soc-critical)";
  if ([21, 23, 445, 139, 137].includes(port)) return "var(--soc-critical)";
  if (port === 53) return "var(--soc-info)";
  return "var(--foreground)";
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
  return PROTOCOL_COLORS[p.toUpperCase()] ?? "var(--soc-low)";
}

function protoBadgeStyle(p?: string | null): React.CSSProperties {
  const c = protoColor(p);
  return { color: c, backgroundColor: `color-mix(in oklch, ${c} 15%, transparent)` };
}

function statusIsActive(status: string): boolean {
  return (
    status === "monitoring" ||
    status === "scanning" ||
    status === "initializing" ||
    status === "reconnecting"
  );
}

const SEV_FILTERS: Array<{ key: Severity | "all"; label: string }> = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "info", label: "Info" },
];

const EVENT_TYPES: string[] = [
  "all",
  "connection",
  "auth_failure",
  "http_request",
  "port_probe",
  "service_access",
  "firewall_deny",
  "log_entry",
];

function fmt(n: number | undefined | null): string {
  if (n == null) return "—";
  return n.toLocaleString();
}

// ============================================================
// Sub-components
// ============================================================

function EmptyHint({ text = "No data yet" }: { text?: string }) {
  return (
    <div className="flex h-full items-center justify-center font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/60">
      {text}
    </div>
  );
}

function ChartTooltip({
  active,
  payload,
  label,
  color,
}: {
  active?: boolean;
  payload?: Array<{ value?: number; name?: string }>;
  label?: string;
  color?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-md border border-border/60 bg-popover px-2 py-1 text-xs shadow-md">
      {label && (
        <div className="font-mono-data text-[9px] text-muted-foreground">{label}</div>
      )}
      <div
        className="font-mono-data font-bold"
        style={{ color: color ?? "var(--foreground)" }}
      >
        {payload[0]?.value ?? "—"}
      </div>
    </div>
  );
}

function MiniAreaChart({
  data,
  color,
  id,
}: {
  data: { t: string; v: number }[];
  color: string;
  id: string;
}) {
  if (!data || data.length === 0) return <EmptyHint />;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.45} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="t" hide />
        <YAxis hide domain={[0, "auto"]} />
        <Tooltip
          content={<ChartTooltip color={color} />}
          cursor={{ stroke: color, strokeOpacity: 0.3, strokeWidth: 1 }}
        />
        <Area
          type="monotone"
          dataKey="v"
          stroke={color}
          strokeWidth={1.5}
          fill={`url(#${id})`}
          isAnimationActive={false}
          dot={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function BarList({
  items,
  colorFn,
  format,
}: {
  items: TopItem[];
  colorFn?: (key: string) => string;
  format?: (key: string) => string;
}) {
  const capped = items.slice(0, 6);
  if (capped.length === 0) return <EmptyHint />;
  const max = Math.max(1, ...capped.map((i) => i.count));
  return (
    <div className="flex h-full flex-col justify-center gap-1.5">
      {capped.map((item, i) => {
        const color = colorFn ? colorFn(item.key) : "var(--soc-low)";
        return (
          <div
            key={`${item.key}-${i}`}
            className="flex items-center gap-2 text-[11px]"
          >
            <span
              className="w-24 shrink-0 truncate font-mono-data text-muted-foreground"
              title={item.key}
            >
              {format ? format(item.key) : item.key}
            </span>
            <div className="relative h-2 flex-1 overflow-hidden rounded-sm bg-muted/30">
              <div
                className="absolute inset-y-0 left-0 rounded-sm"
                style={{
                  width: `${(item.count / max) * 100}%`,
                  backgroundColor: color,
                }}
              />
            </div>
            <span className="w-8 shrink-0 text-right font-mono-data font-semibold">
              {item.count}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function RecentConnections({ items }: { items: SecurityEvent[] }) {
  const capped = items.slice(0, 7);
  if (capped.length === 0) return <EmptyHint />;
  return (
    <div className="flex h-full flex-col justify-center gap-1">
      {capped.map((c) => (
        <div key={c.id} className="flex items-center gap-2 text-[10px]">
          <span className="w-12 shrink-0 font-mono-data text-muted-foreground">
            {formatTime(c.timestamp)}
          </span>
          <span className="flex-1 truncate font-mono-data">
            {c.sourceIp ?? "?"}
            <span className="text-muted-foreground">:</span>
            {c.sourcePort ?? "?"}
            <span className="mx-1 text-muted-foreground">→</span>
            {c.destIp ?? "?"}
            <span className="text-muted-foreground">:</span>
            {c.destPort ?? "?"}
          </span>
          <span
            className="shrink-0 rounded px-1 py-0.5 font-mono-data text-[8px] uppercase"
            style={protoBadgeStyle(c.protocol)}
          >
            {c.protocol?.toUpperCase() ?? "?"}
          </span>
        </div>
      ))}
    </div>
  );
}

function MiniStat({
  label,
  value,
  active,
}: {
  label: string;
  value?: number;
  active?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-md border border-border/40 bg-card/40 px-2.5 py-1.5">
      <span className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <span className="flex items-center gap-1.5 font-mono-data text-sm font-bold">
        {active && (
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-[color:var(--soc-success)] live-pulse" />
        )}
        {value != null ? value.toLocaleString() : "—"}
      </span>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-md border border-border/40 bg-card/30 p-2.5">
      <div className="mb-2 font-mono-data text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {title}
      </div>
      <div className="h-[130px]">{children}</div>
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono = true,
  color,
}: {
  label: string;
  value?: string | number | null;
  mono?: boolean;
  color?: string;
}) {
  return (
    <>
      <div className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div
        className={cn("truncate", mono && "font-mono-data")}
        style={color ? { color } : undefined}
        title={value != null ? String(value) : undefined}
      >
        {value != null && value !== "" ? value : "—"}
      </div>
    </>
  );
}

// ============================================================
// Target Control Bar
// ============================================================

function TargetControlBar() {
  const sessionId = useAppStore((s) => s.sessionId);
  const status = useAppStore((s) => s.status);
  const targetAddress = useAppStore((s) => s.targetAddress);
  const connected = useAppStore((s) => s.connected);
  const mode = useAppStore((s) => s.mode);
  const startSession = useAppStore((s) => s.startSession);
  const stopSession = useAppStore((s) => s.stopSession);
  const resetSession = useAppStore((s) => s.resetSession);
  const setStatus = useAppStore((s) => s.setStatus);
  const setKpi = useAppStore((s) => s.setKpi);
  const setNetworkActivity = useAppStore((s) => s.setNetworkActivity);
  const setOffenseScenarios = useAppStore((s) => s.setOffenseScenarios);
  const setDefenseScenarios = useAppStore((s) => s.setDefenseScenarios);

  const [targetInput, setTargetInput] = useState("192.168.1.100");
  const [modeInput, setModeInput] = useState<"demo" | "live">("demo");
  const [busy, setBusy] = useState(false);

  const isActive = statusIsActive(status);

  const handleStart = async () => {
    const t = targetInput.trim();
    if (!t) {
      toast.error("Enter a target IP or domain.");
      return;
    }
    setBusy(true);
    setStatus("initializing");
    try {
      const res = await api.startMonitoring(t, modeInput);
      const resolvedTarget = res.session.targetAddress || t;
      startSession({
        sessionId: res.sessionId,
        targetAddress: resolvedTarget,
        mode: res.session.mode,
        assessment: res.assessment,
      });
      toast.success(`Monitoring started on ${resolvedTarget}`);
      // Seed initial status snapshot (WS will stream updates afterwards)
      try {
        const st = await api.getStatus(res.sessionId);
        if (st.kpi) setKpi(st.kpi);
        if (st.networkActivity) setNetworkActivity(st.networkActivity);
        if (st.offenseScenarios?.length) setOffenseScenarios(st.offenseScenarios);
        if (st.defenseScenarios?.length) setDefenseScenarios(st.defenseScenarios);
      } catch {
        /* best-effort seeding; WS will provide live updates */
      }
    } catch (err) {
      const e = err as Error & { status?: number; code?: string };
      if (e.code === "INVALID_TARGET") {
        toast.error("Target is unreachable.");
      } else if (e.code === "START_FAILED") {
        toast.error("Initial assessment failed.");
      } else if (e.code === "UNREACHABLE" || !e.status) {
        toast.error("Unable to connect to monitoring service.");
      } else {
        toast.error(e.message || "Unable to start monitoring.");
      }
      setStatus("ready");
    } finally {
      setBusy(false);
    }
  };

  const handleStop = async () => {
    if (!sessionId) return;
    setBusy(true);
    try {
      await api.stopMonitoring(sessionId);
      stopSession();
      toast.success("Monitoring session saved to history.");
      window.setTimeout(() => resetSession(), 1000);
    } catch (err) {
      const e = err as Error & { status?: number; code?: string };
      if (e.code === "UNREACHABLE" || !e.status) {
        toast.error("Unable to connect to monitoring service.");
      } else {
        toast.error(e.message || "Failed to stop monitoring.");
      }
      stopSession();
      window.setTimeout(() => resetSession(), 1000);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={`flex shrink-0 flex-wrap items-center gap-2 border-b bg-card/40 px-3 py-2 backdrop-blur-md ${isActive ? "border-[color:var(--soc-low)]/40 active-border" : "border-border/60"}`}>
      <div className="flex items-center gap-2">
        <span className="font-mono-data text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Target
        </span>
        <Input
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
          placeholder="IP or domain"
          disabled={isActive || busy}
          className="h-8 w-[200px] font-mono-data text-sm sm:w-[280px]"
          onKeyDown={(e) => {
            if (e.key === "Enter" && !isActive && !busy) handleStart();
          }}
          aria-label="Monitoring target IP or domain"
        />
      </div>

      <Select
        value={modeInput}
        onValueChange={(v) => setModeInput(v as "demo" | "live")}
        disabled={isActive || busy}
      >
        <SelectTrigger size="sm" className="h-8 w-full font-mono-data text-xs sm:w-[260px]">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="demo">Demo Mode (Simulated Telemetry)</SelectItem>
          <SelectItem value="live">Live Mode (Real Telemetry)</SelectItem>
        </SelectContent>
      </Select>

      {!isActive ? (
        <Button
          onClick={handleStart}
          disabled={busy}
          size="sm"
          className="h-8 gap-1.5"
        >
          <Activity className="h-3.5 w-3.5" />
          {busy ? "STARTING…" : "START MONITORING"}
        </Button>
      ) : (
        <Button
          onClick={handleStop}
          disabled={busy}
          size="sm"
          variant="destructive"
          className="h-8 gap-1.5"
        >
          <Square className="h-3.5 w-3.5 fill-current" />
          {busy ? "STOPPING…" : "STOP MONITORING"}
        </Button>
      )}

      {isActive && (
        <div className="flex flex-wrap items-center gap-3 pl-1">
          <div className="flex items-center gap-1.5">
            <span className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
              Active
            </span>
            <span className="font-mono-data text-xs font-semibold">
              {targetAddress}
            </span>
          </div>
          <StatusDot
            status={status}
            pulse={isActive}
            label={status.toUpperCase()}
            className="text-[10px]"
          />
          <StatusDot
            status={connected ? "connected" : "disconnected"}
            pulse={connected}
            label={connected ? "LIVE" : "RECONNECTING"}
            className="text-[10px]"
          />
          {mode === "demo" && (
            <span className="rounded-sm border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider text-[color:var(--soc-medium)]">
              Demo
            </span>
          )}
        </div>
      )}

      <div className="ml-auto hidden items-center md:flex">
        <AuthWarning />
      </div>
    </div>
  );
}

// ============================================================
// Assessment Panel
// ============================================================

function AssessmentPanel() {
  const assessment = useAppStore((s) => s.assessment);
  const targetAddress = useAppStore((s) => s.targetAddress);
  const [open, setOpen] = useState(true);

  const servicesByPort = useMemo(() => {
    const m = new Map<number, ServiceInfo>();
    if (!assessment) return m;
    for (const s of assessment.services) m.set(s.port, s);
    return m;
  }, [assessment]);

  if (!assessment) return null;

  const portCount = assessment.ports.length;
  const portRowsHeight = portCount > 8 ? "max-h-[200px] overflow-y-auto soc-scrollbar" : "";

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div className="overflow-hidden rounded-lg border border-border/60 bg-card/50 backdrop-blur-sm">
        <CollapsibleTrigger className="flex w-full items-center justify-between gap-2 border-b border-border/50 bg-card/30 px-4 py-2.5 transition-colors hover:bg-accent/30">
          <div className="flex min-w-0 items-center gap-2">
            {open ? (
              <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
            )}
            <span className="font-mono-data text-xs font-semibold uppercase tracking-wider">
              Initial Assessment
            </span>
            <span className="truncate font-mono-data text-[10px] text-muted-foreground">
              {assessment.reachability} · {portCount} open port{portCount === 1 ? "" : "s"}
            </span>
          </div>
          {assessment.status && (
            <span className="shrink-0 rounded-sm border border-[color:var(--soc-success)]/40 bg-[color:var(--soc-success)]/10 px-1.5 py-0.5 font-mono-data text-[9px] font-bold uppercase tracking-wider text-[color:var(--soc-success)]">
              {assessment.status}
            </span>
          )}
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="grid grid-cols-1 lg:grid-cols-2 lg:divide-x lg:divide-border/40">
            {/* Target Information */}
            <div className="p-3">
              <div className="mb-2.5 font-mono-data text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                Target Information
              </div>
              <div className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[11px]">
                <InfoRow label="Target" value={targetAddress || assessment.targetId} />
                <InfoRow label="Reachability" value={assessment.reachability} />
                <InfoRow label="Hostname" value={assessment.hostname} />
                <InfoRow label="OS Guess" value={assessment.osGuess} />
                <InfoRow
                  label="Latency"
                  value={assessment.latencyMs != null ? `${assessment.latencyMs} ms` : null}
                />
                <InfoRow label="Assessment" value={assessment.status} color="var(--soc-success)" />
                <InfoRow label="Open Ports" value={portCount} color="var(--soc-low)" />
              </div>
            </div>

            {/* Open Ports & Services */}
            <div className="p-3">
              <div className="mb-2.5 font-mono-data text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                Open Ports & Services
              </div>
              {portCount === 0 ? (
                <EmptyHint text="No open ports detected" />
              ) : (
                <div className={portRowsHeight}>
                  <table className="w-full text-[11px]">
                    <thead className="sticky top-0 bg-card/90 backdrop-blur-sm">
                      <tr className="border-b border-border/40 text-left font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                        <th className="px-2 py-1 font-medium">Port</th>
                        <th className="px-2 py-1 font-medium">Proto</th>
                        <th className="px-2 py-1 font-medium">State</th>
                        <th className="px-2 py-1 font-medium">Service</th>
                        <th className="px-2 py-1 font-medium">Product</th>
                        <th className="px-2 py-1 font-medium">Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {assessment.ports.map((p) => {
                        const svc = servicesByPort.get(p.number);
                        return (
                          <tr
                            key={p.id}
                            className="border-b border-border/20 hover:bg-accent/20 transition-colors"
                          >
                            <td
                              className="px-2 py-1 font-mono-data font-bold"
                              style={{ color: portAccentColor(p.number) }}
                            >
                              {p.number}
                            </td>
                            <td className="px-2 py-1 font-mono-data uppercase text-[10px]">
                              {p.protocol}
                            </td>
                            <td className="px-2 py-1 font-mono-data text-[10px]">{p.state}</td>
                            <td className="px-2 py-1 truncate" title={svc?.name ?? p.serviceName ?? ""}>
                              {svc?.name ?? p.serviceName ?? "—"}
                            </td>
                            <td className="px-2 py-1 font-mono-data text-[10px] truncate" title={svc?.product ?? ""}>
                              {svc?.product ?? "—"}
                            </td>
                            <td className="px-2 py-1 font-mono-data text-[10px] truncate" title={svc?.version ?? ""}>
                              {svc?.version ?? "—"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}

// ============================================================
// KPI Grid
// ============================================================

interface KpiCardDef {
  label: string;
  value: string;
  icon: LucideIcon;
  accent: "default" | "critical" | "high" | "medium" | "low" | "info" | "success";
  live: boolean;
}

function KpiGrid() {
  const kpi = useAppStore((s) => s.kpi);
  const status = useAppStore((s) => s.status);
  const isActive = statusIsActive(status);

  const cards: KpiCardDef[] = [
    { label: "Events", value: fmt(kpi?.events), icon: Activity, accent: "default", live: isActive },
    { label: "Critical", value: fmt(kpi?.critical), icon: AlertOctagon, accent: "critical", live: false },
    { label: "High", value: fmt(kpi?.high), icon: AlertTriangle, accent: "high", live: false },
    { label: "Medium", value: fmt(kpi?.medium), icon: AlertCircle, accent: "medium", live: false },
    { label: "Low", value: fmt(kpi?.low), icon: ShieldAlert, accent: "low", live: false },
    { label: "Info", value: fmt(kpi?.info), icon: Info, accent: "info", live: false },
    { label: "Active Conns", value: fmt(kpi?.activeConnections), icon: NetworkIcon, accent: "default", live: isActive },
    { label: "Events/Sec", value: fmt(kpi?.eventsPerSec), icon: Zap, accent: "default", live: isActive },
    { label: "Traffic KB/s", value: fmt(kpi?.trafficRate), icon: Gauge, accent: "default", live: isActive },
    { label: "Open Ports", value: fmt(kpi?.openPorts), icon: Server, accent: "default", live: false },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-10">
      {cards.map((c) => (
        <KpiCard
          key={c.label}
          label={c.label}
          value={c.value}
          icon={c.icon}
          accent={c.accent}
          live={c.live}
        />
      ))}
    </div>
  );
}

// ============================================================
// Live Security Log
// ============================================================

function LiveSecurityLog() {
  const events = useAppStore((s) => s.events);
  const paused = useAppStore((s) => s.paused);
  const setPaused = useAppStore((s) => s.setPaused);
  const clearLiveView = useAppStore((s) => s.clearLiveView);

  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events
      .filter((e) => {
        if (sevFilter !== "all" && e.severity !== sevFilter) return false;
        if (typeFilter !== "all" && e.eventType !== typeFilter) return false;
        if (q) {
          const hay = `${e.sourceIp ?? ""} ${e.destIp ?? ""} ${e.message}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      })
      .slice(0, 200);
  }, [events, sevFilter, typeFilter, search]);

  const relatedEvents = useMemo(() => {
    if (!selectedEvent) return [];
    return events
      .filter(
        (e) =>
          e.eventId !== selectedEvent.eventId &&
          ((e.sourceIp && e.sourceIp === selectedEvent.sourceIp) ||
            (e.destPort && e.destPort === selectedEvent.destPort)),
      )
      .slice(0, 30);
  }, [selectedEvent, events]);

  const handleEventClick = useCallback((e: SecurityEvent) => {
    setSelectedEvent(e);
    setDrawerOpen(true);
    useAppStore.getState().setSelectedEvent(e.eventId);
  }, []);

  const selectedEventId = useAppStore((s) => s.selectedEventId);

  return (
    <Panel
      title="Live Security Log"
      icon={<Activity className="h-4 w-4" />}
      className="h-full"
      bodyClassName="flex min-h-0 flex-col"
      actions={
        <>
          <Button
            size="sm"
            variant="outline"
            className="h-7 gap-1 px-2 text-[11px]"
            onClick={() => setPaused(!paused)}
            aria-label={paused ? "Resume stream" : "Pause stream"}
          >
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="h-7 gap-1 px-2 text-[11px]"
            onClick={() => {
              clearLiveView();
              toast.success("Live view cleared. History preserved.");
            }}
            aria-label="Clear live view"
          >
            <Trash2 className="h-3 w-3" />
            Clear
          </Button>
          <ExportMenu
            events={events.slice(0, 500)}
            targetLabel={useAppStore.getState().targetAddress || "live"}
            size="sm"
          />
        </>
      }
    >
      {/* Filters row */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border/40 px-3 py-2">
        <div className="flex flex-wrap items-center gap-1">
          {SEV_FILTERS.map((f) => {
            const active = sevFilter === f.key;
            const sc = f.key !== "all" ? severityColor(f.key) : undefined;
            return (
              <button
                key={f.key}
                type="button"
                onClick={() => setSevFilter(f.key)}
                className={cn(
                  "rounded-sm border px-1.5 py-0.5 font-mono-data text-[10px] uppercase tracking-wider transition-colors",
                  active
                    ? "text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground",
                )}
                style={
                  active && sc
                    ? {
                        color: sc,
                        borderColor: `color-mix(in oklch, ${sc} 40%, transparent)`,
                        backgroundColor: `color-mix(in oklch, ${sc} 12%, transparent)`,
                      }
                    : active
                      ? { borderColor: "var(--border)", backgroundColor: "var(--accent)" }
                      : undefined
                }
              >
                {f.label}
              </button>
            );
          })}
        </div>

        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger size="sm" className="h-7 w-[150px] text-[11px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {EVENT_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t === "all" ? "All Types" : t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <div className="relative min-w-[140px] flex-1">
          <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search source / dest / message…"
            className="h-7 pl-7 text-[11px]"
            aria-label="Search events"
          />
        </div>
      </div>

      {/* Table */}
      <div className="soc-scrollbar max-h-[420px] min-h-0 flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="flex min-h-[200px] flex-col items-center justify-center gap-2 py-8 text-muted-foreground">
            <span className="relative inline-flex h-2 w-2">
              <span className="absolute inline-block h-full w-full rounded-full bg-[color:var(--soc-low)] live-pulse" />
            </span>
            <span className="font-mono-data text-xs uppercase tracking-wider">
              Waiting for telemetry…
            </span>
          </div>
        ) : (
          <table className="w-full text-[11px]">
            <thead className="sticky top-0 z-10 bg-card/90 backdrop-blur-sm">
              <tr className="border-b border-border/50 text-left font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
                <th className="px-2 py-1.5 font-medium">Time</th>
                <th className="px-2 py-1.5 font-medium">Source</th>
                <th className="px-2 py-1.5 font-medium">Destination</th>
                <th className="px-2 py-1.5 font-medium">Proto</th>
                <th className="px-2 py-1.5 font-medium">Event</th>
                <th className="px-2 py-1.5 font-medium">Severity</th>
                <th className="px-2 py-1.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => {
                const src = e.sourceIp
                  ? `${e.sourceIp}${e.sourcePort ? `:${e.sourcePort}` : ""}`
                  : "—";
                const dst = e.destIp
                  ? `${e.destIp}${e.destPort ? `:${e.destPort}` : ""}`
                  : e.destPort
                    ? `:${e.destPort}`
                    : "—";
                return (
                  <tr
                    key={e.id}
                    onClick={() => handleEventClick(e)}
                    className={`cursor-pointer border-b border-border/20 transition-colors hover:bg-accent/30 animate-fade-in-up ${
                      selectedEventId === e.eventId
                        ? "bg-[color:var(--soc-low)]/10 ring-1 ring-inset ring-[color:var(--soc-low)]/30"
                        : ""
                    }`}
                  >
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono-data text-muted-foreground">
                      {formatTime(e.timestamp)}
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono-data">{src}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono-data">{dst}</td>
                    <td className="whitespace-nowrap px-2 py-1.5">
                      <span
                        className="rounded px-1 py-0.5 font-mono-data text-[9px] uppercase"
                        style={protoBadgeStyle(e.protocol)}
                      >
                        {e.protocol?.toUpperCase() ?? "?"}
                      </span>
                    </td>
                    <td className="max-w-[280px] px-2 py-1.5">
                      <div className="flex items-center gap-1.5">
                        {e.isDemo && (
                          <span className="shrink-0 rounded-sm border border-[color:var(--soc-medium)]/40 bg-[color:var(--soc-medium)]/10 px-1 py-0.5 font-mono-data text-[8px] font-bold uppercase text-[color:var(--soc-medium)]">
                            Demo
                          </span>
                        )}
                        <span
                          className="truncate"
                          title={`${e.eventType} — ${e.message}`}
                        >
                          <span className="font-mono-data text-[10px] font-semibold text-foreground">
                            {e.eventType}
                          </span>
                          <span className="text-muted-foreground"> {e.message}</span>
                        </span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5">
                      <SeverityBadge severity={e.severity} size="sm" />
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5">
                      <span className="inline-flex items-center gap-1 font-mono-data text-[10px] text-muted-foreground">
                        <span
                          className="inline-block h-1.5 w-1.5 rounded-full"
                          style={{
                            backgroundColor:
                              e.status === "blocked"
                                ? "var(--soc-critical)"
                                : e.status === "allowed"
                                  ? "var(--soc-success)"
                                  : "var(--muted-foreground)",
                          }}
                        />
                        {e.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      <EventDetailDrawer
        event={selectedEvent}
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        relatedEvents={relatedEvents}
      />
    </Panel>
  );
}

// ============================================================
// Network Activity Panel
// ============================================================

function NetworkActivityPanel() {
  const na = useAppStore((s) => s.networkActivity);
  const status = useAppStore((s) => s.status);
  const isActive = statusIsActive(status);

  const protoItems: TopItem[] = useMemo(() => {
    if (!na) return [];
    return na.protocolDistribution.map((p: ProtocolDistribution) => ({
      key: p.protocol,
      count: p.count,
    }));
  }, [na]);

  return (
    <Panel
      title="Live Network Activity"
      icon={<NetworkIcon className="h-4 w-4" />}
      bodyClassName="flex flex-col"
    >
      {/* Mini KPIs */}
      <div className="grid grid-cols-2 gap-2 border-b border-border/40 px-3 py-2 sm:grid-cols-4">
        <MiniStat label="Connections" value={na?.connectionCount} active={isActive} />
        <MiniStat label="Conn/Sec" value={na?.connectionsPerSec} active={isActive} />
        <MiniStat label="Request Rate" value={na?.requestRate} active={isActive} />
        <MiniStat label="Traffic KB/s" value={na?.trafficRate} active={isActive} />
      </div>

      {/* Charts grid */}
      <div className="grid grid-cols-1 gap-3 p-3 md:grid-cols-2">
        <ChartCard title="Events / Sec">
          {na ? (
            <MiniAreaChart
              data={na.eventsPerSecTimeline}
              color="var(--soc-low)"
              id="events-area"
            />
          ) : (
            <Skeleton className="h-full w-full" />
          )}
        </ChartCard>

        <ChartCard title="Traffic Rate (KB/s)">
          {na ? (
            <MiniAreaChart
              data={na.trafficTimeline}
              color="var(--soc-info)"
              id="traffic-area"
            />
          ) : (
            <Skeleton className="h-full w-full" />
          )}
        </ChartCard>

        <ChartCard title="Protocol Distribution">
          {na ? (
            <BarList items={protoItems} colorFn={protoColor} />
          ) : (
            <Skeleton className="h-full w-full" />
          )}
        </ChartCard>

        <ChartCard title="Top Source IPs">
          {na ? (
            <BarList items={na.topSourceIps} />
          ) : (
            <Skeleton className="h-full w-full" />
          )}
        </ChartCard>

        <ChartCard title="Top Destination Ports">
          {na ? (
            <BarList items={na.topDestPorts} format={(k) => `:${k}`} />
          ) : (
            <Skeleton className="h-full w-full" />
          )}
        </ChartCard>

        <ChartCard title="Recent Connections">
          {na ? (
            <RecentConnections items={na.recentConnections} />
          ) : (
            <Skeleton className="h-full w-full" />
          )}
        </ChartCard>
      </div>
    </Panel>
  );
}

// ============================================================
// Live Alerts
// ============================================================

type AlertStatusFilter = "all" | "active" | "acknowledged" | "resolved";
type AlertStatus = "active" | "acknowledged" | "resolved";

const ALERT_STATUS_FILTERS: Array<{ key: AlertStatusFilter; label: string }> = [
  { key: "all", label: "All" },
  { key: "active", label: "Active" },
  { key: "acknowledged", label: "Acknowledged" },
  { key: "resolved", label: "Resolved" },
];

function alertAccentColor(alert: SecurityAlert): string {
  if (alert.status === "resolved") return "var(--soc-success)";
  if (alert.status === "acknowledged") return "var(--soc-medium)";
  return severityColor(alert.severity);
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

function AlertActionButtons({
  alert,
  sessionId,
  onUpdated,
}: {
  alert: SecurityAlert;
  sessionId: string | null;
  onUpdated: (alertId: string, status: AlertStatus) => void;
}) {
  const [busy, setBusy] = useState(false);

  const handleUpdate = async (newStatus: AlertStatus) => {
    if (!sessionId || busy) return;
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
      const msg = e.message || "Unable to update alert status.";
      if (!e.status) {
        toast.error("Unable to connect to monitoring service.", {
          description: "Please check that the monitor service is running.",
        });
      } else if (e.status === 404) {
        toast.error("Alert not found.", {
          description: "It may have been purged from the live session.",
        });
      } else {
        toast.error(msg);
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

// ============================================================
// Alert grouping (FEATURE-GROUP)
// ============================================================

interface AlertGroup {
  ruleId: string;
  ruleName: string;
  alerts: SecurityAlert[]; // filtered + sorted newest-first
  count: number;
  openCount: number;
  ackCount: number;
  resolvedCount: number;
  topOpenSeverity: Severity; // highest severity among OPEN (active) alerts
  topOverallSeverity: Severity; // highest severity across all alerts in group
  firstObserved: string; // ISO timestamp (oldest)
  lastObserved: string; // ISO timestamp (newest)
  durationSec: number;
}

// Cap the number of AlertCards rendered inside an expanded group to keep the
// DOM light during burst attacks (e.g. 100 SSH auth failures).
const MAX_GROUP_CARDS = 50;

function formatDuration(sec: number): string {
  if (sec < 1) return "0s";
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem ? `${h}h ${rem}m` : `${h}h`;
}

// AlertCard — extracted from the original inline JSX so it can be reused by
// both the grouped (expanded) view and the individual (grouping OFF) view.
function AlertCard({
  alert,
  sessionId,
  onUpdated,
  className,
}: {
  alert: SecurityAlert;
  sessionId: string | null;
  onUpdated: (alertId: string, status: AlertStatus) => void;
  className?: string;
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
        "relative overflow-hidden rounded-md border border-border/40 bg-card/40 p-2.5 pl-3 transition-all hover:bg-accent/30",
        opacityCls,
        className,
      )}
    >
      <div
        className="absolute left-0 top-0 h-full w-0.5"
        style={{ backgroundColor: accent }}
      />
      <div className="flex items-center gap-2">
        <SeverityBadge severity={alert.severity} size="sm" />
        <AlertStatusBadge status={alert.status} />
        <span
          className={cn(
            "flex-1 truncate font-mono-data text-xs font-bold",
            alert.status === "resolved" && "line-through decoration-muted-foreground/60",
          )}
          title={alert.ruleName}
        >
          {alert.ruleName}
        </span>
        <span className="shrink-0 font-mono-data text-[9px] text-muted-foreground">
          {alert.alertId}
        </span>
      </div>
      <div className="mt-1 text-[11px] leading-snug text-foreground/80">
        {alert.message}
      </div>
      <div className="mt-1.5 flex items-center gap-3 text-[10px] text-muted-foreground">
        <span className="font-mono-data">CONF {alert.confidence}%</span>
        {alert.recommendedAction && (
          <span className="truncate" title={alert.recommendedAction}>
            → {alert.recommendedAction}
          </span>
        )}
        <span className="ml-auto whitespace-nowrap font-mono-data">
          {formatTime(alert.timestamp)}
        </span>
      </div>
      <div className="mt-1.5 flex items-center justify-end gap-2 border-t border-border/30 pt-1.5">
        <AlertActionButtons
          alert={alert}
          sessionId={sessionId}
          onUpdated={onUpdated}
        />
      </div>
    </div>
  );
}

// Bulk Ack / Resolve buttons shown inside each group header.
// Uses Promise.allSettled for parallel PATCH round-trips + partial-failure
// reporting.
function BulkActionButtons({
  group,
  sessionId,
  onUpdated,
}: {
  group: AlertGroup;
  sessionId: string | null;
  onUpdated: (alertId: string, status: AlertStatus) => void;
}) {
  const [busyAck, setBusyAck] = useState(false);
  const [busyResolve, setBusyResolve] = useState(false);

  const handleBulk = async (status: "acknowledged" | "resolved") => {
    if (!sessionId) return;
    const isAck = status === "acknowledged";
    if (isAck ? busyAck : busyResolve) return;
    if (isAck) setBusyAck(true);
    else setBusyResolve(true);
    try {
      // Ack All → only active alerts; Resolve All → all unresolved alerts.
      const targets = group.alerts.filter((a) =>
        isAck ? a.status === "active" : a.status !== "resolved",
      );
      if (targets.length === 0) {
        toast.message(
          isAck
            ? "No active alerts to acknowledge."
            : "No unresolved alerts to resolve.",
          { description: group.ruleName },
        );
        return;
      }
      const results = await Promise.allSettled(
        targets.map((a) =>
          api.updateAlertStatus(sessionId, a.alertId, status).then(() => {
            onUpdated(a.alertId, status);
            return a.alertId;
          }),
        ),
      );
      const ok = results.filter((r) => r.status === "fulfilled").length;
      const fail = results.length - ok;
      if (fail === 0) {
        toast.success(
          `${isAck ? "Acknowledged" : "Resolved"} ${ok} alert${ok === 1 ? "" : "s"}.`,
          { description: group.ruleName },
        );
      } else {
        toast.warning(
          `${isAck ? "Acknowledged" : "Resolved"} ${ok} of ${results.length} alerts.`,
          { description: `${fail} failed · ${group.ruleName}` },
        );
      }
    } catch {
      toast.error(
        isAck ? "Unable to acknowledge alerts." : "Unable to resolve alerts.",
        { description: "Please check that the monitor service is running." },
      );
    } finally {
      if (isAck) setBusyAck(false);
      else setBusyResolve(false);
    }
  };

  const btnCls =
    "inline-flex items-center gap-1 rounded-sm border px-1.5 h-7 font-mono-data text-[11px] font-bold uppercase tracking-wider transition-colors disabled:opacity-50 disabled:cursor-not-allowed";

  return (
    <div className="flex items-center gap-1">
      <button
        type="button"
        disabled={busyAck || busyResolve}
        onClick={(e) => {
          e.stopPropagation();
          void handleBulk("acknowledged");
        }}
        className={cn(btnCls, "hover:bg-[color:var(--soc-medium)]/15")}
        style={{
          color: "var(--soc-medium)",
          borderColor: "color-mix(in oklch, var(--soc-medium) 40%, transparent)",
        }}
        title={`Acknowledge all ${group.openCount} active alert(s) in this group`}
      >
        {busyAck ? (
          <Activity className="h-3 w-3 animate-pulse" />
        ) : (
          <CheckCheck className="h-3 w-3" />
        )}
        Ack All{group.openCount > 0 ? ` (${group.openCount})` : ""}
      </button>
      <button
        type="button"
        disabled={busyAck || busyResolve}
        onClick={(e) => {
          e.stopPropagation();
          void handleBulk("resolved");
        }}
        className={cn(btnCls, "hover:bg-[color:var(--soc-success)]/15")}
        style={{
          color: "var(--soc-success)",
          borderColor: "color-mix(in oklch, var(--soc-success) 40%, transparent)",
        }}
        title={`Resolve all ${group.count - group.resolvedCount} unresolved alert(s) in this group`}
      >
        {busyResolve ? (
          <Activity className="h-3 w-3 animate-pulse" />
        ) : (
          <ShieldCheck className="h-3 w-3" />
        )}
        Resolve All
      </button>
    </div>
  );
}

// Group header card (collapsed mode shows this alone; expanded mode shows this
// + the list of AlertCards below it).
function GroupHeaderCard({
  group,
  expanded,
  sessionId,
  onToggle,
  onUpdated,
}: {
  group: AlertGroup;
  expanded: boolean;
  sessionId: string | null;
  onToggle: () => void;
  onUpdated: (alertId: string, status: AlertStatus) => void;
}) {
  const topSev: Severity =
    group.openCount > 0 ? group.topOpenSeverity : group.topOverallSeverity;
  const accent = severityColor(topSev);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onToggle}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onToggle();
        }
      }}
      className="group relative cursor-pointer overflow-hidden rounded-md border border-border/50 bg-card/50 p-2.5 pl-3 transition-all hover:border-border/80 hover:bg-accent/30"
    >
      <div
        className="absolute left-0 top-0 h-full w-1"
        style={{ backgroundColor: accent }}
      />

      {/* Row 1: ruleId + top severity badge */}
      <div className="flex items-center gap-2">
        <span
          className="font-mono-data text-[10px] font-bold uppercase tracking-wider"
          style={{ color: accent }}
        >
          {group.ruleId}
        </span>
        <SeverityBadge severity={topSev} size="sm" />
      </div>

      {/* Row 2: rule name */}
      <div
        className="mt-1 truncate font-mono-data text-xs font-bold"
        title={group.ruleName}
      >
        {group.ruleName}
      </div>

      {/* Row 3: count + status summary */}
      <div className="mt-1 flex flex-wrap items-center gap-2 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
        <span className="font-bold" style={{ color: accent }}>
          {group.count} alerts
        </span>
        <span className="text-muted-foreground/40">·</span>
        <span title="Active (open) alerts in group">
          <span className="text-[color:var(--soc-critical)]">{group.openCount}</span> active
        </span>
        <span className="text-muted-foreground/40">·</span>
        <span title="Acknowledged alerts in group">
          <span className="text-[color:var(--soc-medium)]">{group.ackCount}</span> ack
        </span>
        <span className="text-muted-foreground/40">·</span>
        <span title="Resolved alerts in group">
          <span className="text-[color:var(--soc-success)]">{group.resolvedCount}</span> resolved
        </span>
      </div>

      {/* Row 4: first→last observed + duration */}
      <div className="mt-1 flex items-center gap-2 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
        <span title="First → last observed (this group)">
          {formatTime(group.firstObserved)} → {formatTime(group.lastObserved)}
        </span>
        <span className="text-muted-foreground/40">·</span>
        <span title="Burst duration">{formatDuration(group.durationSec)}</span>
      </div>

      {/* Row 5: bulk actions + chevron toggle */}
      <div className="mt-1.5 flex items-center gap-1.5 border-t border-border/30 pt-1.5">
        <BulkActionButtons
          group={group}
          sessionId={sessionId}
          onUpdated={onUpdated}
        />
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          className="ml-auto inline-flex h-5 w-5 items-center justify-center rounded-sm text-muted-foreground transition-colors hover:bg-accent/40 hover:text-foreground"
          title={expanded ? "Collapse group" : "Expand group"}
          aria-label={expanded ? "Collapse group" : "Expand group"}
          aria-expanded={expanded}
        >
          {expanded ? (
            <ChevronUp className="h-3.5 w-3.5" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5" />
          )}
        </button>
      </div>
    </div>
  );
}

function LiveAlerts() {
  const alerts = useAppStore((s) => s.alerts);
  const sessionId = useAppStore((s) => s.sessionId);
  const updateAlertStatus = useAppStore((s) => s.updateAlertStatus);

  const [statusFilter, setStatusFilter] = useState<AlertStatusFilter>("all");
  // FEATURE-GROUP: grouping toggle (default ON). When OFF, all alerts render as
  // individual cards (the pre-grouping behavior).
  const [groupByRule, setGroupByRule] = useState(true);
  // Set of ruleIds currently expanded in the grouped view.
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(
    () => new Set(),
  );

  const filtered = useMemo(() => {
    const list =
      statusFilter === "all"
        ? alerts
        : alerts.filter((a) => a.status === statusFilter);
    return list.slice(0, 100);
  }, [alerts, statusFilter]);

  // Open (active) counts — what the SOC operator still needs to triage.
  // NOTE: these count badges are unaffected by grouping mode (they always
  // reflect the full alerts list, not the filtered view).
  const openCounts = useMemo(() => {
    const c: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const a of alerts) {
      if (a.status === "active") c[a.severity]++;
    }
    return c;
  }, [alerts]);

  // Total counts (all statuses) — shown as small text below the open badges.
  const totalCounts = useMemo(() => {
    const c: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    let total = 0;
    let active = 0;
    let ack = 0;
    let resolved = 0;
    for (const a of alerts) {
      c[a.severity]++;
      total++;
      if (a.status === "active") active++;
      else if (a.status === "acknowledged") ack++;
      else if (a.status === "resolved") resolved++;
    }
    return { c, total, active, ack, resolved };
  }, [alerts]);

  // FEATURE-GROUP: build groups from the (status-filtered) alerts list.
  // Empty groups are naturally hidden — if no alerts in a group survive the
  // filter, that ruleId won't appear in the map.
  const groups = useMemo<AlertGroup[]>(() => {
    const map = new Map<string, SecurityAlert[]>();
    for (const a of filtered) {
      const arr = map.get(a.ruleId) ?? [];
      arr.push(a);
      map.set(a.ruleId, arr);
    }
    const result: AlertGroup[] = [];
    for (const [ruleId, alertsInGroup] of map.entries()) {
      // Sort newest-first within each group.
      const sorted = [...alertsInGroup].sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      );
      let openCount = 0;
      let ackCount = 0;
      let resolvedCount = 0;
      let topOpenSeverity: Severity = "info";
      let topOverallSeverity: Severity = "info";
      const timestamps = sorted.map((a) => new Date(a.timestamp).getTime());
      const firstTs = timestamps.length ? Math.min(...timestamps) : Date.now();
      const lastTs = timestamps.length ? Math.max(...timestamps) : Date.now();
      for (const a of sorted) {
        if (SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[topOverallSeverity]) {
          topOverallSeverity = a.severity;
        }
        if (a.status === "active") {
          openCount++;
          if (SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[topOpenSeverity]) {
            topOpenSeverity = a.severity;
          }
        } else if (a.status === "acknowledged") ackCount++;
        else if (a.status === "resolved") resolvedCount++;
      }
      result.push({
        ruleId,
        ruleName: sorted[0]?.ruleName ?? ruleId,
        alerts: sorted,
        count: sorted.length,
        openCount,
        ackCount,
        resolvedCount,
        topOpenSeverity,
        topOverallSeverity,
        firstObserved: new Date(firstTs).toISOString(),
        lastObserved: new Date(lastTs).toISOString(),
        durationSec: Math.max(0, Math.round((lastTs - firstTs) / 1000)),
      });
    }
    // Sort: highest OPEN severity first (most urgent triage queue at top),
    // tie-break on total count desc (noisiest burst second).
    result.sort((a, b) => {
      const sevDiff =
        SEVERITY_ORDER[b.topOpenSeverity] - SEVERITY_ORDER[a.topOpenSeverity];
      if (sevDiff !== 0) return sevDiff;
      return b.count - a.count;
    });
    return result;
  }, [filtered]);

  const toggleGroup = useCallback((ruleId: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(ruleId)) next.delete(ruleId);
      else next.add(ruleId);
      return next;
    });
  }, []);

  const handleUpdated = useCallback(
    (alertId: string, status: AlertStatus) =>
      updateAlertStatus(alertId, status),
    [updateAlertStatus],
  );

  return (
    <Panel
      title="Live Alerts"
      icon={<AlertTriangle className="h-4 w-4" />}
      className="h-full"
      bodyClassName="flex min-h-0 flex-col"
      actions={
        <div className="flex items-center gap-1.5">
          {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
            <span
              key={s}
              className="rounded-sm border px-1.5 py-0.5 font-mono-data text-[10px] font-bold uppercase"
              style={{
                color: severityColor(s),
                borderColor: `color-mix(in oklch, ${severityColor(s)} 40%, transparent)`,
                backgroundColor: `color-mix(in oklch, ${severityColor(s)} 12%, transparent)`,
              }}
              title={`${openCounts[s]} open ${s} alerts`}
            >
              {openCounts[s]}
            </span>
          ))}
          {/* Group by Rule toggle (FEATURE-GROUP) */}
          <button
            type="button"
            onClick={() => setGroupByRule((v) => !v)}
            className={cn(
              "inline-flex h-6 items-center gap-1 rounded-sm border px-1.5 font-mono-data text-[9px] font-bold uppercase tracking-wider transition-colors",
              groupByRule
                ? "text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
            style={
              groupByRule
                ? {
                    color: "var(--soc-info)",
                    borderColor:
                      "color-mix(in oklch, var(--soc-info) 40%, transparent)",
                    backgroundColor:
                      "color-mix(in oklch, var(--soc-info) 12%, transparent)",
                  }
                : undefined
            }
            title={
              groupByRule
                ? "Alerts grouped by rule. Click to show all individually."
                : "Alerts shown individually. Click to group by rule."
            }
            aria-pressed={groupByRule}
          >
            {groupByRule ? (
              <Layers className="h-3 w-3" />
            ) : (
              <AlignJustify className="h-3 w-3" />
            )}
            {groupByRule ? "Grouped" : "List"}
          </button>
          <ExportMenu
            alerts={alerts.slice(0, 200)}
            targetLabel={useAppStore.getState().targetAddress || "live"}
            size="sm"
          />
        </div>
      }
    >
      {/* Status filter row + total counts */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border/40 px-3 py-2">
        <div className="flex flex-wrap items-center gap-1">
          {ALERT_STATUS_FILTERS.map((f) => {
            const active = statusFilter === f.key;
            let color: string | undefined;
            if (f.key === "active") color = "var(--soc-critical)";
            else if (f.key === "acknowledged") color = "var(--soc-medium)";
            else if (f.key === "resolved") color = "var(--soc-success)";
            return (
              <button
                key={f.key}
                type="button"
                onClick={() => setStatusFilter(f.key)}
                className={cn(
                  "rounded-sm border px-1.5 py-0.5 font-mono-data text-[10px] uppercase tracking-wider transition-colors",
                  active
                    ? "text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground",
                )}
                style={
                  active && color
                    ? {
                        color,
                        borderColor: `color-mix(in oklch, ${color} 40%, transparent)`,
                        backgroundColor: `color-mix(in oklch, ${color} 12%, transparent)`,
                      }
                    : active
                      ? { borderColor: "var(--border)", backgroundColor: "var(--accent)" }
                      : undefined
                }
              >
                {f.label}
              </button>
            );
          })}
        </div>
        <div className="ml-auto flex items-center gap-2 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
          <span title="Open (active) alerts">
            <span className="text-[color:var(--soc-critical)]">{totalCounts.active}</span> open
          </span>
          <span className="text-muted-foreground/40">·</span>
          <span title="Acknowledged alerts">
            <span className="text-[color:var(--soc-medium)]">{totalCounts.ack}</span> ack
          </span>
          <span className="text-muted-foreground/40">·</span>
          <span title="Resolved alerts">
            <span className="text-[color:var(--soc-success)]">{totalCounts.resolved}</span> resolved
          </span>
          <span className="text-muted-foreground/40">·</span>
          <span title="Total alerts in this session">{totalCounts.total} total</span>
        </div>
      </div>

      <div className="soc-scrollbar max-h-[300px] min-h-0 flex-1 overflow-y-auto p-2">
        {filtered.length === 0 ? (
          <div className="flex min-h-[160px] flex-col items-center justify-center gap-2 py-6 text-muted-foreground">
            <Shield className="h-6 w-6 opacity-40" />
            <span className="max-w-[220px] text-center font-mono-data text-[10px] uppercase tracking-wider">
              {alerts.length === 0
                ? "No alerts. Detection rules are monitoring telemetry…"
                : "No alerts match this filter."}
            </span>
          </div>
        ) : groupByRule ? (
          // Grouped mode: each ruleId → one expandable card.
          <div className="flex flex-col gap-2">
            {groups.map((g) => {
              // Smart collapse: single-alert groups render as a plain
              // AlertCard (no chevron, no group header).
              if (g.count === 1) {
                return (
                  <AlertCard
                    key={g.ruleId}
                    alert={g.alerts[0]}
                    sessionId={sessionId}
                    onUpdated={handleUpdated}
                  />
                );
              }
              const expanded = expandedGroups.has(g.ruleId);
              return (
                <div key={g.ruleId} className="flex flex-col gap-2">
                  <GroupHeaderCard
                    group={g}
                    expanded={expanded}
                    sessionId={sessionId}
                    onToggle={() => toggleGroup(g.ruleId)}
                    onUpdated={handleUpdated}
                  />
                  {expanded && (
                    <div className="ml-2 flex flex-col gap-2 border-l-2 border-border/40 pl-2">
                      {g.alerts.slice(0, MAX_GROUP_CARDS).map((a) => (
                        <AlertCard
                          key={a.id}
                          alert={a}
                          sessionId={sessionId}
                          onUpdated={handleUpdated}
                          className="animate-fade-in-up"
                        />
                      ))}
                      {g.alerts.length > MAX_GROUP_CARDS && (
                        <div className="rounded-sm border border-dashed border-border/50 px-2 py-1 text-center font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
                          +{g.alerts.length - MAX_GROUP_CARDS} more in this group
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          // Individual mode (grouping OFF): the pre-grouping behavior.
          <div className="flex flex-col gap-2">
            {filtered.map((a) => (
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
    </Panel>
  );
}

// ============================================================
// Main View
// ============================================================

function ThreatMapSection() {
  const events = useAppStore((s) => s.events);
  const targetAddress = useAppStore((s) => s.targetAddress);
  const status = useAppStore((s) => s.status);
  const active = status === "monitoring" || status === "scanning" || status === "initializing";
  return (
    <ThreatMapPanel events={events} targetAddress={targetAddress || "—"} active={active} />
  );
}

function RiskGaugeSection() {
  const alerts = useAppStore((s) => s.alerts);
  return <RiskGaugePanel alerts={alerts} />;
}

function MitreMatrixSection() {
  const scenarios = useAppStore((s) => s.offenseScenarios);
  return <MitreMatrixPanel scenarios={scenarios} />;
}

export function LiveMonitorView() {
  return (
    <div className="flex h-full flex-col overflow-hidden">
      <TargetControlBar />
      <div className="soc-scrollbar flex-1 overflow-y-auto overflow-x-hidden p-3">
        <div className="flex flex-col gap-3">
          <AssessmentPanel />
          <KpiGrid />
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
            <div className="min-h-0 lg:col-span-8">
              <LiveSecurityLog />
            </div>
            <div className="min-h-0 lg:col-span-4">
              <LiveAlerts />
            </div>
          </div>
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
            <NetworkActivityPanel />
            <ThreatMapSection />
          </div>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <RiskGaugeSection />
            <MitreMatrixSection />
          </div>
        </div>
      </div>
    </div>
  );
}
