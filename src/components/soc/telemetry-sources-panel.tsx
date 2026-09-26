"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api-client";
import { useAppStore } from "@/lib/store";
import { Panel } from "@/components/soc/panel";
import { Radio, CheckCircle2, XCircle, AlertTriangle, MinusCircle } from "lucide-react";

interface SourceStatus {
  name: string;
  displayName: string;
  sourceType: string;
  status: string;
  reason?: string;
}

const STATUS_CONFIG: Record<string, { color: string; icon: typeof CheckCircle2; label: string }> = {
  CONNECTED: { color: "var(--soc-success)", icon: CheckCircle2, label: "Connected" },
  DISCONNECTED: { color: "var(--soc-high)", icon: XCircle, label: "Disconnected" },
  UNAVAILABLE: { color: "var(--muted-foreground)", icon: MinusCircle, label: "Unavailable" },
  ERROR: { color: "var(--soc-critical)", icon: AlertTriangle, label: "Error" },
  NOT_CONFIGURED: { color: "var(--muted-foreground)", icon: MinusCircle, label: "Not Configured" },
};

export function TelemetrySourcesPanel() {
  const sessionId = useAppStore((s) => s.sessionId);
  const status = useAppStore((s) => s.status);
  const mode = useAppStore((s) => s.mode);
  const [sources, setSources] = useState<SourceStatus[]>([]);

  const isActive = status === "monitoring" || status === "scanning" || status === "initializing";

  useEffect(() => {
    if (!sessionId || !isActive) {
      return;
    }
    let cancelled = false;
    const fetchSources = async () => {
      try {
        const res = await api.getTelemetrySources(sessionId);
        if (!cancelled) setSources(res.sources);
      } catch {
        if (!cancelled) setSources([]);
      }
    };
    fetchSources();
    // Poll every 10s while active
    const id = setInterval(fetchSources, 10000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [sessionId, isActive]);

  if (!isActive) return null;

  const connectedCount = sources.filter((s) => s.status === "CONNECTED").length;
  const overallStatus: "CONNECTED" | "PARTIAL" | "NO_TELEMETRY" | "DEMO_MODE" =
    mode === "demo"
      ? "DEMO_MODE"
      : connectedCount === 0
        ? "NO_TELEMETRY"
        : connectedCount < sources.length
          ? "PARTIAL"
          : "CONNECTED";

  const overallConfig = {
    CONNECTED: { color: "var(--soc-success)", label: "CONNECTED" },
    PARTIAL: { color: "var(--soc-medium)", label: "PARTIAL" },
    NO_TELEMETRY: { color: "var(--soc-critical)", label: "NO TELEMETRY" },
    DEMO_MODE: { color: "var(--soc-medium)", label: "DEMO MODE" },
  }[overallStatus];

  return (
    <Panel
      title="Telemetry Sources"
      subtitle={`${connectedCount}/${sources.length} sources connected`}
      icon={<Radio className="h-4 w-4" />}
      bodyClassName="p-3"
    >
      <div className="space-y-2">
        {/* Overall status badge */}
        <div className="flex items-center justify-between rounded-md border border-border/40 bg-background/30 px-3 py-2">
          <span className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
            Telemetry Status
          </span>
          <span
            className="flex items-center gap-1.5 rounded-sm border px-2 py-0.5 font-mono-data text-[10px] font-bold uppercase tracking-wider"
            style={{
              color: overallConfig.color,
              borderColor: `color-mix(in oklch, ${overallConfig.color} 40%, transparent)`,
              backgroundColor: `color-mix(in oklch, ${overallConfig.color} 12%, transparent)`,
            }}
          >
            <span
              className="inline-block h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: overallConfig.color }}
            />
            {overallConfig.label}
          </span>
        </div>

        {/* Source list */}
        {sources.length === 0 ? (
          <div className="rounded-md border border-dashed border-border/50 bg-card/20 px-3 py-4 text-center">
            <p className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/60">
              {mode === "live" ? "Waiting for telemetry sources…" : "Initializing…"}
            </p>
          </div>
        ) : (
          <div className="space-y-1">
            {sources.map((src) => {
              const cfg = STATUS_CONFIG[src.status] ?? STATUS_CONFIG.UNAVAILABLE;
              const Icon = cfg.icon;
              return (
                <div
                  key={src.name}
                  className="flex items-center justify-between rounded-md border border-border/30 bg-card/20 px-2.5 py-1.5"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Icon className="h-3 w-3 shrink-0" style={{ color: cfg.color }} />
                    <span className="truncate text-xs text-foreground/80">
                      {src.displayName}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span
                      className="font-mono-data text-[9px] uppercase tracking-wider"
                      style={{ color: cfg.color }}
                      title={src.reason}
                    >
                      {cfg.label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Ingestion hint for live mode */}
        {mode === "live" && (
          <div className="rounded-md border border-[color:var(--soc-low)]/20 bg-[color:var(--soc-low)]/5 px-2.5 py-1.5 text-[9px] text-muted-foreground leading-relaxed">
            <strong className="text-foreground/80">Real telemetry:</strong> POST events to{" "}
            <code className="font-mono-data text-[color:var(--soc-low)]">/api/ingest</code>{" "}
            with <code className="font-mono-data">sessionId</code>. See{" "}
            <code className="font-mono-data">GET /api/ingest</code> for schema.
          </div>
        )}
      </div>
    </Panel>
  );
}
