"use client";

import { useMemo } from "react";
import type { SecurityAlert, Severity } from "@/lib/types";
import { severityColor, SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/constants";
import { Panel } from "@/components/soc/panel";
import { ShieldAlert, TrendingUp, TrendingDown, Minus } from "lucide-react";

interface RiskGaugePanelProps {
  alerts: SecurityAlert[];
  className?: string;
}

// ============================================================
// Risk Gauge — animated SVG gauge showing current risk level
//
// Computes a risk score (0-100) from active alerts:
//   critical=25, high=15, medium=8, low=3, info=1 each
//   capped at 100. Maps to severity bands:
//   0-20 LOW (cyan), 21-40 MEDIUM (amber), 41-70 HIGH (orange),
//   71-100 CRITICAL (red)
// ============================================================

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 1,
};

function scoreToSeverity(score: number): Severity {
  if (score >= 71) return "critical";
  if (score >= 41) return "high";
  if (score >= 21) return "medium";
  return "low";
}

export function RiskGaugePanel({ alerts, className }: RiskGaugePanelProps) {
  const { score, level, counts, trend } = useMemo(() => {
    const active = alerts.filter((a) => a.status === "active");
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    let raw = 0;
    for (const a of active) {
      counts[a.severity]++;
      raw += SEVERITY_WEIGHT[a.severity];
    }
    const score = Math.min(100, raw);
    const level = scoreToSeverity(score);
    // Simple trend: compare last-5 alerts vs previous-5 by severity
    const recent = active.slice(0, 5);
    const older = active.slice(5, 10);
    const avgRecent = recent.length ? recent.reduce((s, a) => s + SEVERITY_ORDER[a.severity], 0) / recent.length : 0;
    const avgOlder = older.length ? older.reduce((s, a) => s + SEVERITY_ORDER[a.severity], 0) / older.length : 0;
    let trend: "up" | "down" | "flat" = "flat";
    if (avgRecent > avgOlder + 0.5) trend = "up";
    else if (avgRecent < avgOlder - 0.5) trend = "down";
    return { score, level, counts, trend };
  }, [alerts]);

  const color = severityColor(level);
  const radius = 70;
  const circumference = Math.PI * radius; // half-circle
  const arcOffset = circumference * (1 - score / 100);

  const trendIcon = trend === "up" ? <TrendingUp className="h-3.5 w-3.5" /> : trend === "down" ? <TrendingDown className="h-3.5 w-3.5" /> : <Minus className="h-3.5 w-3.5" />;
  const trendColor = trend === "up" ? "var(--soc-critical)" : trend === "down" ? "var(--soc-success)" : "var(--muted-foreground)";
  const trendLabel = trend === "up" ? "Rising" : trend === "down" ? "Falling" : "Stable";

  return (
    <Panel
      title="Risk Gauge"
      subtitle="Live risk score from active alerts"
      icon={<ShieldAlert className="h-4 w-4" />}
      className={className}
      bodyClassName="p-4"
    >
      <div className="flex flex-col items-center gap-3">
        {/* SVG Gauge */}
        <div className="relative">
          <svg width="180" height="110" viewBox="0 0 180 110">
            <defs>
              <linearGradient id="risk-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="var(--soc-low)" />
                <stop offset="35%" stopColor="var(--soc-medium)" />
                <stop offset="65%" stopColor="var(--soc-high)" />
                <stop offset="100%" stopColor="var(--soc-critical)" />
              </linearGradient>
              <filter id="risk-glow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Background arc (muted) */}
            <path
              d={`M 20 90 A ${radius} ${radius} 0 0 1 160 90`}
              fill="none"
              stroke="var(--muted)"
              strokeWidth="12"
              strokeLinecap="round"
            />

            {/* Active arc (colored by score) */}
            <path
              d={`M 20 90 A ${radius} ${radius} 0 0 1 160 90`}
              fill="none"
              stroke={color}
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={arcOffset}
              filter="url(#risk-glow)"
              style={{ transition: "stroke-dashoffset 0.6s ease, stroke 0.3s ease" }}
            />

            {/* Tick marks at 25/50/75 */}
            {[25, 50, 75].map((pct) => {
              const angle = Math.PI - (pct / 100) * Math.PI;
              const x1 = 90 + Math.cos(angle) * (radius - 8);
              const y1 = 90 - Math.sin(angle) * (radius - 8);
              const x2 = 90 + Math.cos(angle) * (radius + 8);
              const y2 = 90 - Math.sin(angle) * (radius + 8);
              return (
                <line
                  key={pct}
                  x1={x1}
                  y1={y1}
                  x2={x2}
                  y2={y2}
                  stroke="var(--border)"
                  strokeWidth="1"
                />
              );
            })}

            {/* Center score text */}
            <text
              x="90"
              y="78"
              textAnchor="middle"
              className="font-mono-data"
              fontSize="32"
              fontWeight="bold"
              fill={color}
              style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "fill 0.3s ease" }}
            >
              {Math.round(score)}
            </text>
            <text
              x="90"
              y="100"
              textAnchor="middle"
              className="font-mono-data"
              fontSize="9"
              fill="var(--muted-foreground)"
              letterSpacing="2"
            >
              / 100
            </text>
          </svg>

          {/* Severity level label */}
          <div className="absolute -bottom-1 left-1/2 -translate-x-1/2">
            <span
              className="rounded-sm border px-2 py-0.5 font-mono-data text-[10px] font-bold uppercase tracking-wider"
              style={{ color, borderColor: `color-mix(in oklch, ${color} 40%, transparent)`, backgroundColor: `color-mix(in oklch, ${color} 12%, transparent)` }}
            >
              {SEVERITY_LABEL[level]}
            </span>
          </div>
        </div>

        {/* Trend indicator */}
        <div className="flex items-center gap-1.5 font-mono-data text-[10px] uppercase tracking-wider" style={{ color: trendColor }}>
          {trendIcon}
          <span>{trendLabel}</span>
          <span className="text-muted-foreground/40">·</span>
          <span className="text-muted-foreground">last {Math.min(10, alerts.filter(a => a.status === "active").length)} alerts</span>
        </div>

        {/* Severity breakdown */}
        <div className="grid w-full grid-cols-5 gap-1.5">
          {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
            <div
              key={s}
              className="rounded-md border border-border/40 bg-background/30 p-1.5 text-center"
              style={counts[s] > 0 ? { borderColor: `color-mix(in oklch, ${severityColor(s)} 30%, transparent)` } : undefined}
            >
              <div
                className="font-mono-data text-lg font-bold leading-none"
                style={{ color: counts[s] > 0 ? severityColor(s) : "var(--muted-foreground)" }}
              >
                {counts[s]}
              </div>
              <div className="mt-1 font-mono-data text-[8px] uppercase tracking-wider text-muted-foreground">
                {SEVERITY_LABEL[s].slice(0, 4)}
              </div>
            </div>
          ))}
        </div>

        {/* Active alert count */}
        <div className="flex items-center gap-2 font-mono-data text-[10px] text-muted-foreground">
          <span className="text-foreground font-semibold">
            {alerts.filter((a) => a.status === "active").length}
          </span>
          <span>active of</span>
          <span className="text-foreground font-semibold">{alerts.length}</span>
          <span>total alerts</span>
        </div>
      </div>
    </Panel>
  );
}
