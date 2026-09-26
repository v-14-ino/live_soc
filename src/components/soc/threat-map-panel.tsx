"use client";

import { useMemo } from "react";
import type { SecurityEvent, Severity } from "@/lib/types";
import { severityColor } from "@/lib/constants";
import { Panel } from "@/components/soc/panel";
import { Globe, Crosshair } from "lucide-react";

interface ThreatMapPanelProps {
  events: SecurityEvent[];
  targetAddress: string;
  active: boolean;
}

interface SourceNode {
  ip: string;
  x: number;
  y: number;
  count: number;
  topSeverity: Severity;
  lastSeen: number;
}

// Deterministic pseudo-random based on string hash (stable node positions)
function hashStr(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967295;
}

const SEV_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function ThreatMapPanel({ events, targetAddress, active }: ThreatMapPanelProps) {
  const sources = useMemo<SourceNode[]>(() => {
    const map = new Map<
      string,
      { count: number; topSeverity: Severity; lastSeen: number }
    >();
    const now = Date.now();
    for (const e of events) {
      if (!e.sourceIp) continue;
      const existing = map.get(e.sourceIp);
      const t = new Date(e.timestamp).getTime();
      if (existing) {
        existing.count++;
        existing.lastSeen = Math.max(existing.lastSeen, t);
        if (SEV_RANK[e.severity] > SEV_RANK[existing.topSeverity]) {
          existing.topSeverity = e.severity;
        }
      } else {
        map.set(e.sourceIp, {
          count: 1,
          topSeverity: e.severity,
          lastSeen: t,
        });
      }
    }
    // Position nodes in a circle around the center target
    const arr = Array.from(map.entries()).map(([ip, info], i) => {
      const angle = (i / Math.max(1, map.size)) * Math.PI * 2 - Math.PI / 2;
      // Use hash for slight radius variation so nodes don't all sit on exact circle
      const r = 0.38 + hashStr(ip) * 0.06;
      return {
        ip,
        x: 0.5 + Math.cos(angle) * r,
        y: 0.5 + Math.sin(angle) * r,
        count: info.count,
        topSeverity: info.topSeverity,
        lastSeen: info.lastSeen,
      };
    });
    // Sort by count desc so larger nodes are drawn first (behind)
    arr.sort((a, b) => b.count - a.count);
    return arr.slice(0, 12); // cap at 12 source nodes
  }, [events]);

  const recentConnections = useMemo(() => {
    // Show animated pulses for the most recent events
    return events
      .filter((e) => e.sourceIp && Date.now() - new Date(e.timestamp).getTime() < 10000)
      .slice(0, 8);
  }, [events]);

  const targetX = 0.5;
  const targetY = 0.5;

  return (
    <Panel
      title="Threat Map"
      subtitle="Source IP activity around target"
      icon={<Globe className="h-4 w-4" />}
      className="h-full"
      bodyClassName="p-3"
    >
      <div className="relative aspect-[16/9] w-full overflow-hidden rounded-md border border-border/40 bg-background/40 soc-grid-bg">
        {/* Radar rings */}
        <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          <defs>
            <radialGradient id="threatmap-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="var(--soc-low)" stopOpacity="0.15" />
              <stop offset="100%" stopColor="var(--soc-low)" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="conn-critical" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--soc-critical)" stopOpacity="0.1" />
              <stop offset="100%" stopColor="var(--soc-critical)" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="conn-high" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--soc-high)" stopOpacity="0.1" />
              <stop offset="100%" stopColor="var(--soc-high)" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="conn-medium" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--soc-medium)" stopOpacity="0.1" />
              <stop offset="100%" stopColor="var(--soc-medium)" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="conn-low" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--soc-low)" stopOpacity="0.1" />
              <stop offset="100%" stopColor="var(--soc-low)" stopOpacity="0.8" />
            </linearGradient>
          </defs>

          {/* Background glow */}
          <rect x="0" y="0" width="100" height="100" fill="url(#threatmap-glow)" />

          {/* Radar rings */}
          {[15, 30, 45].map((r) => (
            <circle
              key={r}
              cx="50"
              cy="50"
              r={r}
              fill="none"
              stroke="var(--border)"
              strokeWidth="0.2"
              strokeDasharray="1 2"
              opacity="0.5"
            />
          ))}
          {/* Cross hairs */}
          <line x1="50" y1="5" x2="50" y2="95" stroke="var(--border)" strokeWidth="0.15" opacity="0.3" />
          <line x1="5" y1="50" x2="95" y2="50" stroke="var(--border)" strokeWidth="0.15" opacity="0.3" />

          {/* Connection lines from sources to target */}
          {sources.map((s) => {
            const color = severityColor(s.topSeverity);
            const gradientId = `conn-${s.topSeverity}`;
            const x1 = s.x * 100;
            const y1 = s.y * 100;
            const x2 = targetX * 100;
            const y2 = targetY * 100;
            const opacity = Math.min(0.9, 0.3 + s.count / 50);
            return (
              <g key={`line-${s.ip}`}>
                <line
                  x1={x1}
                  y1={y1}
                  x2={x2}
                  y2={y2}
                  stroke={`url(#${gradientId})`}
                  strokeWidth={Math.min(2.5, 0.3 + s.count / 20)}
                  opacity={opacity}
                />
                {/* Animated pulse along the line for recent activity */}
                {active && s.count > 0 && (
                  <circle r="0.8" fill={color} opacity="0.9">
                    <animateMotion
                      dur={`${2 + hashStr(s.ip) * 2}s`}
                      repeatCount="indefinite"
                      path={`M ${x1} ${y1} L ${x2} ${y2}`}
                    />
                    <animate
                      attributeName="opacity"
                      values="0;0.9;0"
                      dur={`${2 + hashStr(s.ip) * 2}s`}
                      repeatCount="indefinite"
                    />
                  </circle>
                )}
              </g>
            );
          })}

          {/* Source nodes */}
          {sources.map((s) => {
            const color = severityColor(s.topSeverity);
            const radius = Math.min(3.5, 1.2 + s.count / 15);
            return (
              <g key={`node-${s.ip}`}>
                {/* Glow ring */}
                <circle
                  cx={s.x * 100}
                  cy={s.y * 100}
                  r={radius + 1.5}
                  fill={color}
                  opacity="0.15"
                />
                {/* Core node */}
                <circle
                  cx={s.x * 100}
                  cy={s.y * 100}
                  r={radius}
                  fill={color}
                  opacity="0.9"
                  stroke="var(--background)"
                  strokeWidth="0.3"
                />
                {/* Pulse for active sources */}
                {active && (
                  <circle
                    cx={s.x * 100}
                    cy={s.y * 100}
                    r={radius}
                    fill="none"
                    stroke={color}
                    strokeWidth="0.4"
                    opacity="0.6"
                  >
                    <animate
                      attributeName="r"
                      values={`${radius};${radius + 3};${radius}`}
                      dur="2s"
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="opacity"
                      values="0.6;0;0.6"
                      dur="2s"
                      repeatCount="indefinite"
                    />
                  </circle>
                )}
              </g>
            );
          })}

          {/* Target node (center) */}
          <g>
            <circle cx="50" cy="50" r="6" fill="var(--soc-low)" opacity="0.15" />
            <circle cx="50" cy="50" r="4" fill="var(--soc-low)" opacity="0.3" />
            <circle
              cx="50"
              cy="50"
              r="2.5"
              fill="var(--soc-low)"
              stroke="var(--background)"
              strokeWidth="0.4"
            />
            {/* Crosshair on target */}
            <circle
              cx="50"
              cy="50"
              r="5"
              fill="none"
              stroke="var(--soc-low)"
              strokeWidth="0.3"
              opacity="0.6"
            >
              {active && (
                <animate
                  attributeName="r"
                  values="5;9;5"
                  dur="2.5s"
                  repeatCount="indefinite"
                />
              )}
              {active && (
                <animate
                  attributeName="opacity"
                  values="0.6;0;0.6"
                  dur="2.5s"
                  repeatCount="indefinite"
                />
              )}
            </circle>
          </g>
        </svg>

        {/* Target label */}
        <div className="absolute left-1/2 top-1/2 -translate-x-1/2 translate-y-6 text-center">
          <div className="flex items-center justify-center gap-1 font-mono-data text-[10px] font-semibold text-[color:var(--soc-low)]">
            <Crosshair className="h-2.5 w-2.5" />
            {targetAddress}
          </div>
        </div>

        {/* Source IP labels (top 5) */}
        {sources.slice(0, 6).map((s) => (
          <div
            key={`label-${s.ip}`}
            className="pointer-events-none absolute font-mono-data text-[9px] text-muted-foreground"
            style={{
              left: `${s.x * 100}%`,
              top: `${s.y * 100}%`,
              transform: "translate(-50%, -140%)",
            }}
          >
            <span
              className="rounded-sm px-1 py-0.5"
              style={{
                color: severityColor(s.topSeverity),
                backgroundColor: "color-mix(in oklch, var(--background) 80%, transparent)",
              }}
            >
              {s.ip}
            </span>
          </div>
        ))}

        {/* Empty state overlay */}
        {sources.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <Globe className="mx-auto h-8 w-8 text-muted-foreground/30" />
              <p className="mt-2 font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground/60">
                Waiting for source activity…
              </p>
            </div>
          </div>
        )}

        {/* Scanline overlay when active */}
        {active && <div className="pointer-events-none absolute inset-0 scanline opacity-30" />}
      </div>

      {/* Legend */}
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono-data text-[9px] uppercase tracking-wider text-muted-foreground">
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--soc-low)" }} />
          Target
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--soc-critical)" }} />
          Critical source
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--soc-high)" }} />
          High
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--soc-medium)" }} />
          Medium
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--soc-low)" }} />
          Low/Info
        </span>
        <span className="ml-auto">
          {sources.length} source{sources.length !== 1 ? "s" : ""} · {recentConnections.length} recent
        </span>
      </div>
    </Panel>
  );
}
