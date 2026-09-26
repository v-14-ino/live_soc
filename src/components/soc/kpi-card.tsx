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
  return (
    <Card
      className={cn(
        "relative overflow-hidden border-border/60 bg-card/60 p-3 backdrop-blur-sm",
        className,
      )}
    >
      <div
        className="absolute left-0 top-0 h-full w-0.5"
        style={{ backgroundColor: color }}
      />
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="font-mono-data text-[10px] uppercase tracking-wider text-muted-foreground">
            {label}
          </div>
          <div
            className="mt-1 font-mono-data text-2xl font-bold leading-none"
            style={{ color }}
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
            className="h-4 w-4 shrink-0 opacity-60"
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
