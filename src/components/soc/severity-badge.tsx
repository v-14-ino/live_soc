"use client";

import { cn } from "@/lib/utils";
import { SEVERITY_LABEL } from "@/lib/constants";
import type { Severity } from "@/lib/types";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
  size?: "sm" | "md" | "lg";
  label?: string;
}

const severityClass: Record<Severity, string> = {
  critical:
    "bg-[color:var(--soc-critical)]/15 text-[color:var(--soc-critical)] border-[color:var(--soc-critical)]/40",
  high: "bg-[color:var(--soc-high)]/15 text-[color:var(--soc-high)] border-[color:var(--soc-high)]/40",
  medium:
    "bg-[color:var(--soc-medium)]/15 text-[color:var(--soc-medium)] border-[color:var(--soc-medium)]/40",
  low: "bg-[color:var(--soc-low)]/15 text-[color:var(--soc-low)] border-[color:var(--soc-low)]/40",
  info: "bg-[color:var(--soc-info)]/15 text-[color:var(--soc-info)] border-[color:var(--soc-info)]/40",
};

const sizeClass = {
  sm: "text-[10px] px-1.5 py-0.5",
  md: "text-xs px-2 py-0.5",
  lg: "text-sm px-2.5 py-1",
};

export function SeverityBadge({
  severity,
  className,
  size = "md",
  label,
}: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm border font-mono-data font-semibold uppercase tracking-wider",
        severityClass[severity],
        sizeClass[size],
        className,
      )}
    >
      <span
        className="inline-block h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: "currentColor" }}
      />
      {label ?? SEVERITY_LABEL[severity]}
    </span>
  );
}
