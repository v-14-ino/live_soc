"use client";

import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import type { LucideIcon } from "lucide-react";
import type { Severity } from "@/lib/types";

interface KpiCardProps {
  label: string;
  value: string | number;
  icon?: LucideIcon;
  severity?: Severity;
  sublabel?: string;
  className?: string;
  accent?: "default" | "critical" | "high" | "medium" | "low" | "info" | "success";
  live?: boolean;
}

const accentColor = {
  default: "var(--foreground)",
  critical: "var(--soc-critical)",
  high: "var(--soc-high)",
  medium: "var(--soc-medium)",
  low: "var(--soc-low)",
  info: "var(--soc-info)",
  success: "var(--soc-success)",
};

const accentGlow: Partial<Record<NonNullable<KpiCardProps["accent"]>, string>> = {
  critical: "glow-critical",
  high: "glow-high",
  medium: "glow-medium",
  low: "glow-low",
};

function parseNumericValue(value: string | number): number {
  if (typeof value === "number") return value;
  const n = Number(String(value).replace(/[^\d.-]/g, ""));
  return Number.isFinite(n) ? n : 0;
}

export function KpiCard({
  label,
  value,
  icon: Icon,
  sublabel,
  className,
  accent = "default",
  live = false,
}: KpiCardProps) {
  const color = accentColor[accent];
  const numericValue = parseNumericValue(value);
  const glowClass = accentGlow[accent];
  const hasGlow = glowClass && numericValue > 0;

  return (
    <Card
      className={cn(
        "card-hover group relative overflow-hidden border-border/60 bg-card/60 p-3 backdrop-blur-sm",
        hasGlow && glowClass,
        className,
      )}
    >
      {/* Top gradient line — subtle accent-color strip across the top */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px opacity-70 transition-opacity duration-200 group-hover:opacity-100"
        style={{
          background: `linear-gradient(90deg, transparent, ${color}, transparent)`,
        }}
      />
      {/* Left accent bar — brightens on hover */}
      <div
        className="absolute left-0 top-0 h-full w-0.5 opacity-80 transition-all duration-200 group-hover:opacity-100 group-hover:w-[3px]"
        style={{ backgroundColor: color, boxShadow: `0 0 6px -1px ${color}` }}
      />
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
            {label}
          </div>
          <div
            className="font-mono-data-lg mt-1 text-2xl font-bold leading-none tabular-nums transition-all duration-200"
            style={{
              color,
              textShadow: hasGlow
                ? `0 0 8px color-mix(in oklch, ${color} 35%, transparent)`
                : "none",
            }}
          >
            {value}
          </div>
          {sublabel && (
            <div className="mt-1 truncate text-[10px] text-muted-foreground">
              {sublabel}
            </div>
          )}
        </div>
        {Icon && (
          <Icon
            className="h-4 w-4 shrink-0 opacity-60 transition-opacity duration-200 group-hover:opacity-90"
            style={{ color }}
          />
        )}
        {live && (
          <span
            className="absolute right-2 top-2 inline-block h-1.5 w-1.5 rounded-full live-pulse"
            style={{ color: "var(--soc-success)", backgroundColor: "var(--soc-success)" }}
          />
        )}
      </div>
    </Card>
  );
}
