"use client";

import { cn } from "@/lib/utils";
import type { MonitorStatus, ScenarioStatus } from "@/lib/types";

interface StatusDotProps {
  status: MonitorStatus | ScenarioStatus | "connected" | "disconnected" | "online";
  className?: string;
  pulse?: boolean;
  label?: string;
}

const statusColor: Record<string, string> = {
  // monitor
  ready: "var(--muted-foreground)",
  initializing: "var(--soc-medium)",
  scanning: "var(--soc-medium)",
  monitoring: "var(--soc-success)",
  reconnecting: "var(--soc-high)",
  stopped: "var(--muted-foreground)",
  completed: "var(--soc-low)",
  error: "var(--soc-critical)",
  // scenario
  active: "var(--soc-success)",
  inactive: "var(--muted-foreground)",
  resolved: "var(--soc-low)",
  // connection
  connected: "var(--soc-success)",
  disconnected: "var(--soc-critical)",
  online: "var(--soc-success)",
};

export function StatusDot({
  status,
  className,
  pulse = false,
  label,
}: StatusDotProps) {
  const color = statusColor[status] ?? "var(--muted-foreground)";
  const shouldPulse =
    pulse ||
    status === "monitoring" ||
    status === "active" ||
    status === "scanning" ||
    status === "initializing";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 font-mono-data text-xs uppercase tracking-wider",
        className,
      )}
      style={{ color }}
    >
      <span className="relative inline-flex h-2 w-2 items-center justify-center">
        {/* Expanding ring (only when pulsing) */}
        {shouldPulse && (
          <span
            className="dot-ring absolute inset-0 rounded-full"
            style={{ color }}
            aria-hidden="true"
          />
        )}
        {/* Core dot — gets a subtle glow when pulsing */}
        <span
          className={cn(
            "relative inline-block h-2 w-2 rounded-full transition-transform duration-200",
            shouldPulse && "pulse-glow",
          )}
          style={{
            backgroundColor: color,
            boxShadow: shouldPulse
              ? `0 0 6px -1px ${color}, 0 0 2px ${color}`
              : `0 0 4px -2px ${color}`,
          }}
        />
      </span>
      {label && <span>{label}</span>}
    </span>
  );
}
